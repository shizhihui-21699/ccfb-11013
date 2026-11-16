#include "device/updater.h"

#include <algorithm>
#include <cstring>

#include "package/delta.h"

namespace ota {
namespace {

// Hashes while forwarding bytes to flash, so a huge image never needs to be
// held in RAM on the device side.
class HashedSink {
 public:
  HashedSink(SlotStore& slots, uint32_t slot, uint64_t limit)
      : slots_(slots), slot_(slot), limit_(limit) {}

  Status operator()(std::span<const uint8_t> bytes) {
    if (written_ + bytes.size() > limit_)
      return fail(Error::SlotTooSmall, "image exceeds slot capacity");
    Status s = slots_.program_image_chunk(slot_, written_, bytes);
    if (!s) return s;
    hash_.update(bytes);
    written_ += bytes.size();
    return Status{};
  }

  uint64_t written() const { return written_; }
  crypto::Digest digest() { return hash_.finish(); }

 private:
  SlotStore& slots_;
  uint32_t slot_;
  uint64_t limit_;
  uint64_t written_ = 0;
  crypto::Sha256 hash_;
};

}  // namespace

struct Updater::Impl {
  Flash& flash;
  DeviceConfig config;
  Layout layout;
  SlotStore slots;
  MonotonicCounter counter;
  MetaLog meta;

  Impl(Flash& f, DeviceConfig c)
      : flash(f),
        config(std::move(c)),
        layout(Layout::make(f.size(), f.sector_size())),
        slots(f, layout),
        counter(f, layout.counter_sector[0] * layout.sector_size,
                layout.counter_sector[1] * layout.sector_size),
        meta(f, layout.meta_sector[0] * layout.sector_size,
             layout.meta_sector[1] * layout.sector_size) {}
};

Updater::Updater(Flash& flash, DeviceConfig config)
    : impl_(new Impl(flash, std::move(config))) {
  crypto::init();
}

Updater::~Updater() = default;

uint64_t Updater::counter_value() const {
  auto v = impl_->counter.read();
  return v ? v.value().installed : 0;
}

uint64_t Updater::booted_floor() const {
  auto v = impl_->counter.read();
  return v ? v.value().booted : 0;
}

Status Updater::check_policy(const pkg::Manifest& m) const {
  if (!m.device_id.empty() && m.device_id != impl_->config.device_id)
    return fail(Error::Incompatible,
                "package is for device '" + m.device_id + "', this is '" +
                    impl_->config.device_id + "'");
  if (impl_->config.hw_revision < m.hw_min || impl_->config.hw_revision > m.hw_max)
    return fail(Error::Incompatible, "hardware revision outside package range");
  return Status{};
}

Result<uint32_t> Updater::target_slot() const {
  auto m = impl_->meta.read();
  if (!m) return m.failure();
  if (!m.value()) return uint32_t{0};
  return uint32_t{1 - m.value()->active_slot};
}

std::optional<uint32_t> Updater::same_version_slot(uint64_t version) const {
  for (uint32_t s = 0; s < 2; ++s) {
    auto rec = impl_->slots.ready_record(s);
    if (!rec || !rec.value()) continue;
    auto man = pkg::parse_manifest_bytes(rec.value()->manifest);
    if (!man || man.value().target_version != version) continue;
    auto v = impl_->slots.verify_slot(s, impl_->config.public_key);
    if (v) return s;
  }
  return std::nullopt;
}

Status Updater::provision(std::span<const uint8_t> package, uint64_t now_unix) {
  auto counter = impl_->counter.read();
  if (!counter) return counter.failure();
  if (counter.value().installed != 0 || counter.value().booted != 0)
    return fail(Error::AlreadyInitialized, "device already provisioned");
  auto existing_meta = impl_->meta.read();
  if (!existing_meta) return existing_meta.failure();
  if (existing_meta.value()) return fail(Error::AlreadyInitialized, "device already provisioned");

  auto pkg = pkg::parse_and_verify(package, impl_->config.public_key);
  if (!pkg) return pkg.failure();
  if (pkg.value().header.is_delta()) return fail(Error::InvalidArgument, "provision with a full package");
  Status pol = check_policy(pkg.value().manifest);
  if (!pol) return pol;
  if (pkg.value().manifest.target_version == 0)
    return fail(Error::ManifestInvalid, "bootstrap version must be > 0");

  const auto& p = pkg.value();
  SlotRecord rec;
  rec.state = SlotState::Ready;
  rec.image_size = p.payload.size();
  rec.generation = 1;
  rec.installed_at = now_unix;
  rec.manifest.assign(p.manifest_bytes.begin(), p.manifest_bytes.end());
  rec.signature = p.signature;
  Status s = impl_->slots.write_slot(0, rec, p.payload);
  if (!s) return s;
  s = impl_->counter.initialize(p.manifest.target_version);
  if (!s) return s;
  BootMeta m;
  m.active_slot = 0;
  m.active_version = p.manifest.target_version;
  m.pending_slot = std::nullopt;
  m.trial_remaining = 0;
  return impl_->meta.write(m);
}

Result<InstallReport> Updater::install(std::span<const uint8_t> package, uint64_t now_unix) {
  auto pkg = pkg::parse_package(package);
  if (!pkg) return pkg.failure();
  Status pol = check_policy(pkg.value().manifest);
  if (!pol) return pol.failure();

  auto counter = impl_->counter.read();
  if (!counter) return counter.failure();
  uint64_t target_version = pkg.value().manifest.target_version;
  if (target_version < counter.value().installed)
    return fail(Error::RollbackRejected,
                "target version " + std::to_string(target_version) +
                    " is below the installed floor " +
                    std::to_string(counter.value().installed));

  auto m = impl_->meta.read();
  if (!m) return m.failure();
  if (!m.value())
    return fail(Error::NotFound, "device is not provisioned (no active slot)");

  // Equal to the counter is allowed only when the target slot already holds a
  // verified image at that version. That happens when an install was torn
  // after the counter commit but before the metadata step, so the counter must
  // stay usable for the retry; it cannot open a downgrade path, because a
  // package claiming an old version still has to be signed and the signed
  // manifest is what fixes the version.
  if (target_version == counter.value().installed) {
    auto same_slot = same_version_slot(target_version);
    if (!same_slot)
      return fail(Error::RollbackRejected,
                  "version " + std::to_string(target_version) +
                      " equals the counter but no verified image at that version exists");
  }

  InstallReport report;
  report.version = target_version;
  report.delta = pkg.value().header.is_delta();

  if (!pkg.value().header.is_delta()) {
    auto full = install_full(pkg.value(), now_unix);
    if (!full) return full.failure();
    return full;
  }
  return install_delta(pkg.value(), now_unix);
}

Result<InstallReport> Updater::install_full(const pkg::ParsedPackage& pkg, uint64_t now_unix) {
  auto slot = target_slot();
  if (!slot) return slot.failure();
  uint32_t target = slot.value();
  uint64_t capacity = impl_->slots.image_capacity(target);
  if (pkg.payload.size() > capacity)
    return fail(Error::SlotTooSmall, "image does not fit in slot");

  auto m = impl_->meta.read();
  if (!m || !m.value()) return fail(Error::NotFound, "no metadata");
  uint32_t active = m.value()->active_slot;

  // Never install over the slot we are currently running.
  if (target == active)
    return fail(Error::Busy, "target slot is the active slot");

  // Verify the signature over (manifest, payload) BEFORE writing flash.
  Status sig = pkg::verify_signature(pkg, pkg.payload, impl_->config.public_key);
  if (!sig) return sig.failure();

  Status s = impl_->slots.erase_slot(target);
  if (!s) return s.failure();
  HashedSink sink(impl_->slots, target, capacity);
  s = sink(pkg.payload);
  if (!s) return s.failure();
  auto digest = sink.digest();
  const auto& e = pkg.manifest.entries.at(0);
  if (sink.written() != e.image_size || !crypto::constant_time_equal(digest, e.image_sha256)) {
    impl_->slots.invalidate(target);
    return fail(Error::ImageHashMismatch, "written image does not match signed hash");
  }

  InstallReport report;
  report.slot = target;
  report.version = pkg.manifest.target_version;
  report.image_size = sink.written();
  report.delta = false;
  Status fin = finish_install(target, pkg, pkg.manifest.target_version, now_unix);
  if (!fin) return fin.failure();
  report.counter_advanced = true;
  return report;
}

Result<InstallReport> Updater::install_delta(const pkg::ParsedPackage& pkg, uint64_t now_unix) {
  auto m = impl_->meta.read();
  if (!m || !m.value()) return fail(Error::NotFound, "no metadata");
  uint32_t active = m.value()->active_slot;

  // The delta must apply to exactly the running image: its signed source hash
  // must equal the hash of the active slot's verified image.
  auto active_verified = impl_->slots.verify_slot(active, impl_->config.public_key);
  if (!active_verified)
    return fail(active_verified.failure().code,
                "active image is not verifiable: " + active_verified.failure().message);
  uint64_t source_version = pkg.manifest.source_version;
  if (source_version != active_verified.value().manifest.target_version)
    return fail(Error::DeltaSourceMismatch,
                "delta is for version " + std::to_string(source_version) + ", device runs " +
                    std::to_string(active_verified.value().manifest.target_version));

  auto source = impl_->slots.read_image(active, active_verified.value().image_size);
  if (!source) return source.failure();
  auto source_hash = crypto::sha256(source.value());
  if (!crypto::constant_time_equal(source_hash, pkg.manifest.source_image_sha256))
    return fail(Error::DeltaSourceMismatch, "device image does not match the signed delta source");

  auto slot = target_slot();
  if (!slot) return slot.failure();
  uint32_t target = slot.value();
  uint64_t capacity = impl_->slots.image_capacity(target);
  if (pkg.manifest.entries.at(0).image_size > capacity)
    return fail(Error::SlotTooSmall, "reconstructed image does not fit in slot");

  Status s = impl_->slots.erase_slot(target);
  if (!s) return s.failure();
  HashedSink sink(impl_->slots, target, capacity);
  Status applied = delta::apply(pkg.payload, std::span<const uint8_t>(source.value()),
                                pkg.manifest.entries.at(0).image_size,
                                [&](std::span<const uint8_t> b) { return sink(b); });
  if (!applied) {
    impl_->slots.invalidate(target);
    return applied.failure();
  }
  auto digest = sink.digest();
  const auto& e = pkg.manifest.entries.at(0);
  if (sink.written() != e.image_size || !crypto::constant_time_equal(digest, e.image_sha256)) {
    impl_->slots.invalidate(target);
    return fail(Error::ImageHashMismatch, "reconstructed image does not match signed hash");
  }

  InstallReport report;
  report.slot = target;
  report.version = pkg.manifest.target_version;
  report.image_size = sink.written();
  report.delta = true;
  Status fin = finish_install(target, pkg, pkg.manifest.target_version, now_unix);
  if (!fin) return fin.failure();
  report.counter_advanced = true;
  return report;
}

Status Updater::finish_install(uint32_t slot, const pkg::ParsedPackage& pkg,
                               uint64_t target_version, uint64_t installed_at) {
  // 1. Signed install record (Ready) into the target slot.
  SlotRecord rec;
  rec.state = SlotState::Ready;
  rec.image_size = pkg.manifest.entries.at(0).image_size;
  // Generation is informational only; derive it from what is already on flash
  // so it keeps increasing across reboots instead of restarting from zero.
  uint64_t generation = 0;
  for (uint32_t s = 0; s < 2; ++s) {
    auto existing = impl_->slots.read_record(s);
    if (existing && existing.value()) generation = std::max(generation, existing.value()->generation);
  }
  rec.generation = generation + 1;
  rec.installed_at = installed_at;
  rec.manifest.assign(pkg.manifest_bytes.begin(), pkg.manifest_bytes.end());
  rec.signature = pkg.signature;
  Status s = impl_->slots.write_record(slot, rec);
  if (!s) return s;

  // 2. Re-verify what actually landed in flash before trusting the install.
  //    This catches flash faults and any bookkeeping mistake, and is exactly
  //    what the bootloader will do at the next boot.
  auto verified = impl_->slots.verify_slot(slot, impl_->config.public_key);
  if (!verified) {
    impl_->slots.invalidate(slot);
    return fail(verified.failure().code, "post-write verification failed: " +
                                            verified.failure().message);
  }
  if (verified.value().manifest.target_version != target_version) {
    impl_->slots.invalidate(slot);
    return fail(Error::ManifestInvalid, "post-write version disagrees with package");
  }

  // 3. Advance the installed floor BEFORE the metadata step. If power dies
  //    during the metadata write the floor is already past the old version, so
  //    a retry of this package must still be possible; that is why install()
  //    accepts target == installed floor when the target slot holds a verified
  //    image at that version (which it does at this point).
  Status commit = impl_->counter.advance_installed(target_version);
  auto now = impl_->counter.read();
  bool counter_ok = commit.ok() ||
                    (commit.code == Error::RollbackRejected && now.ok() &&
                     now.value().installed == target_version);
  if (!counter_ok) {
    // The slot is fully written and verified but the device is not allowed to
    // move to it. Leave it Ready (harmless: metadata does not point at it) and
    // surface the error.
    return commit;
  }

  // 4. Metadata: pending trial boot; active slot untouched.
  auto m = impl_->meta.read();
  if (!m || !m.value()) return fail(Error::NotFound, "no metadata");
  BootMeta meta = *m.value();
  meta.pending_slot = slot;
  meta.pending_version = target_version;
  meta.trial_remaining = impl_->config.trial_boots;
  return impl_->meta.write(meta);
}

Result<BootDecision> Updater::select_boot() {
  auto m = impl_->meta.read();
  if (!m) return m.failure();
  auto counter = impl_->counter.read();
  if (!counter) return counter.failure();
  const uint64_t boot_floor = counter.value().booted;

  BootMeta meta;
  bool have_meta = m.value().has_value();
  if (have_meta) meta = *m.value();

  // A slot is bootable iff it verifies AND its signed version is not below the
  // booted floor. The floor check is what stops an attacker with flash-write
  // access from copying an older, validly-signed image back into a slot.
  // The floor only moves up when an image has booted and been confirmed, so
  // during a trial the previous "last known good" image is still bootable.
  auto try_slot = [&](uint32_t s, uint64_t* version_out) -> bool {
    auto v = impl_->slots.verify_slot(s, impl_->config.public_key);
    if (!v) return false;
    uint64_t ver = v.value().manifest.target_version;
    if (ver < boot_floor) return false;
    if (version_out) *version_out = ver;
    return true;
  };

  BootDecision d;

  if (!have_meta) {
    // Power was lost before the first metadata write. Recover by picking the
    // highest-version slot that verifies and meets the boot floor.
    std::optional<uint32_t> best;
    uint64_t best_version = 0;
    for (uint32_t s = 0; s < 2; ++s) {
      uint64_t ver = 0;
      if (!try_slot(s, &ver)) continue;
      if (!best || ver > best_version) {
        best = s;
        best_version = ver;
      }
    }
    if (!best) return fail(Error::NoValidSlot, "no slot verifies and no metadata exists");
    BootMeta fresh;
    fresh.active_slot = *best;
    fresh.active_version = best_version;
    fresh.pending_slot = std::nullopt;
    fresh.trial_remaining = 0;
    Status s = impl_->meta.write(fresh);
    if (!s) return s.failure();
    d.outcome = BootOutcome::BootedActive;
    d.slot = *best;
    d.version = best_version;
    return d;
  }

  if (meta.pending_slot) {
    uint32_t p = *meta.pending_slot;
    uint64_t pending_version = 0;
    bool pending_ok = meta.trial_remaining > 0 && try_slot(p, &pending_version);
    if (!pending_ok) {
      // Trial exhausted, or the image no longer verifies / is below the floor.
      meta.pending_slot = std::nullopt;
      meta.pending_version = 0;
      meta.trial_remaining = 0;
      Status s = impl_->meta.write(meta);
      if (!s) return s.failure();
      uint64_t active_version = 0;
      if (!try_slot(meta.active_slot, &active_version))
        return fail(Error::NoValidSlot, "pending slot failed and active slot is not bootable");
      d.outcome = BootOutcome::RevertedPending;
      d.slot = meta.active_slot;
      d.version = active_version;
      d.trial_remaining = 0;
      return d;
    }
    // Consume a trial BEFORE booting so a crash during the trial still counts.
    --meta.trial_remaining;
    Status s = impl_->meta.write(meta);
    if (!s) return s.failure();
    d.outcome = BootOutcome::BootedTrial;
    d.slot = p;
    d.version = pending_version;  // from the verified manifest, not metadata
    d.trial_remaining = meta.trial_remaining;
    return d;
  }

  uint64_t active_version = 0;
  if (!try_slot(meta.active_slot, &active_version)) {
    // The recorded active slot is unusable; try the other one before giving up.
    uint32_t other = 1 - meta.active_slot;
    uint64_t other_version = 0;
    if (try_slot(other, &other_version)) {
      meta.active_slot = other;
      meta.active_version = other_version;
      Status s = impl_->meta.write(meta);
      if (!s) return s.failure();
      d.outcome = BootOutcome::BootedActive;
      d.slot = other;
      d.version = other_version;
      return d;
    }
    return fail(Error::NoValidSlot, "active slot is not bootable and no fallback exists");
  }
  d.outcome = BootOutcome::BootedActive;
  d.slot = meta.active_slot;
  d.version = active_version;
  return d;
}

Status Updater::confirm_boot() {
  auto m = impl_->meta.read();
  if (!m) return m.failure();
  if (!m.value()) return fail(Error::NotFound, "no metadata");
  BootMeta meta = *m.value();
  if (!meta.pending_slot) return Status{};  // already confirmed / nothing pending
  uint32_t promoted = *meta.pending_slot;
  // Take the version from the verified slot, never from unsigned metadata.
  auto verified = impl_->slots.verify_slot(promoted, impl_->config.public_key);
  if (!verified) return verified.failure();
  uint64_t version = verified.value().manifest.target_version;
  meta.active_slot = promoted;
  meta.active_version = version;
  meta.pending_slot = std::nullopt;
  meta.pending_version = 0;
  meta.trial_remaining = 0;
  Status s = impl_->meta.write(meta);
  if (!s) return s;
  // Confirmed healthy: this version becomes the boot floor, so no older
  // (even validly signed) image can be made to boot from here on.
  return impl_->counter.mark_booted(version);
}

Status Updater::mark_unhealthy() {
  auto m = impl_->meta.read();
  if (!m) return m.failure();
  if (!m.value()) return fail(Error::NotFound, "no metadata");
  BootMeta meta = *m.value();
  if (!meta.pending_slot) return Status{};
  meta.pending_slot = std::nullopt;
  meta.pending_version = 0;
  meta.trial_remaining = 0;
  return impl_->meta.write(meta);
}

Result<DeviceStatus> Updater::status() const {
  DeviceStatus st;
  auto m = impl_->meta.read();
  if (!m) return m.failure();
  if (m.value()) {
    st.active_slot = m.value()->active_slot;
    st.active_version = m.value()->active_version;
    st.pending_slot = m.value()->pending_slot;
    st.pending_version = m.value()->pending_version;
    st.trial_remaining = m.value()->trial_remaining;
  }
  auto c = impl_->counter.read();
  if (!c) return c.failure();
  st.counter = c.value().installed;
  st.booted_floor = c.value().booted;
  for (uint32_t s = 0; s < 2; ++s) {
    st.slot_version[s] = std::nullopt;
    st.slot_state[s] = std::nullopt;
    auto rec = impl_->slots.read_record(s);
    if (!rec) return rec.failure();
    if (rec.value()) {
      st.slot_state[s] = rec.value()->state;
      auto man = pkg::parse_manifest_bytes(rec.value()->manifest);
      if (man) st.slot_version[s] = man.value().target_version;
    }
    auto v = impl_->slots.verify_slot(s, impl_->config.public_key);
    st.slot_verifies[s] = static_cast<bool>(v);
  }
  return st;
}

}  // namespace ota
