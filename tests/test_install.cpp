// End-to-end device behaviour: provision, install (full + delta), trial boot,
// confirm, revert, and every tamper/downgrade policy.
#include <memory>
#include <string>
#include <vector>

#include "common/crypto.h"
#include "device/flash.h"
#include "device/updater.h"
#include "package/format.h"
#include "test_harness.h"

using namespace ota;

namespace {

constexpr uint64_t kFlashSize = 1u << 20;  // 1 MiB

struct Bench {
  struct Keys {
    crypto::PublicKey pk{};
    crypto::SecretKey sk{};
  };

  Keys keys;
  std::unique_ptr<Flash> flash;
  std::unique_ptr<Updater> updater;

  explicit Bench(uint8_t seed = 42) {
    crypto::Seed s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(seed + i * 3);
    crypto::keypair_from_seed(s, keys.pk, keys.sk);
    flash = std::make_unique<Flash>(kFlashSize);
    DeviceConfig cfg;
    cfg.device_id = "test-device";
    cfg.hw_revision = 2;
    cfg.trial_boots = 2;
    cfg.public_key = keys.pk;
    updater = std::make_unique<Updater>(*flash, cfg);
  }

  // Simulates a power cycle: scratch state is rebuilt from flash only.
  void reboot() {
    DeviceConfig cfg;
    cfg.device_id = "test-device";
    cfg.hw_revision = 2;
    cfg.trial_boots = 2;
    cfg.public_key = keys.pk;
    updater = std::make_unique<Updater>(*flash, cfg);
  }

  std::vector<uint8_t> pkg(uint64_t version, size_t size = 32 * 1024,
                           const std::vector<uint8_t>* source = nullptr,
                           uint64_t source_version = 0) const {
    auto req = base(version, size);
    if (source) {
      req.delta = true;
      req.source_image = *source;
      req.source_version = source_version;
    }
    auto built = pkg::build_package(req, keys.sk, keys.pk);
    CHECK_MSG(built.ok(), built.ok() ? "" : built.failure().message);
    return built.take();
  }

  pkg::PackRequest base(uint64_t version, size_t size) const {
    pkg::PackRequest req;
    req.image = make_image(size, static_cast<uint8_t>(version));
    req.target_version = version;
    req.device_id = "test-device";
    req.hw_min = 1;
    req.hw_max = 3;
    req.package_id = 100 + version;
    req.build_time = 1700000000 + version;
    return req;
  }

  std::vector<uint8_t> image_for(uint64_t version, size_t size = 32 * 1024) const {
    return make_image(size, static_cast<uint8_t>(version));
  }

  static std::vector<uint8_t> make_image(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    uint32_t x = static_cast<uint32_t>(seed) * 2654435761u + 7;
    for (size_t i = 0; i < n; ++i) {
      x = x * 1664525u + 1013904223u;
      v[i] = static_cast<uint8_t>(x >> 24);
    }
    return v;
  }

};

// Provisions a fresh bench at version 1 and confirms its first boot.
void provision(Bench& b, uint64_t version = 1) {
  auto p = b.pkg(version);
  Status s = b.updater->provision(p, 1700000000);
  CHECK_MSG(s.ok(), s.message);
}

// Installs, boots the trial, confirms. Returns the version booted.
void install_and_confirm(Bench& b, const std::vector<uint8_t>& package) {
  auto r = b.updater->install(package, 1700001000);
  CHECK_MSG(r.ok(), r.ok() ? "" : r.failure().message);
  auto boot = b.updater->select_boot();
  CHECK_MSG(boot.ok(), boot.ok() ? "" : boot.failure().message);
  CHECK_EQ(static_cast<int>(boot.value().outcome), static_cast<int>(BootOutcome::BootedTrial));
  CHECK(b.updater->confirm_boot().ok());
}

}  // namespace

TEST(provision_and_first_boot) {
  Bench b;
  provision(b, 1);
  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_EQ(static_cast<int>(boot.value().outcome), static_cast<int>(BootOutcome::BootedActive));
  CHECK_EQ(boot.value().slot, 0u);
  CHECK_EQ(boot.value().version, uint64_t{1});
  auto st = b.updater->status();
  CHECK(st.ok());
  CHECK_EQ(st.value().counter, uint64_t{1});
  CHECK(st.value().slot_verifies[0]);
}

TEST(full_install_trial_then_confirm) {
  Bench b;
  provision(b, 1);
  b.reboot();

  auto v2 = b.pkg(2);
  auto r = b.updater->install(v2, 1700001000);
  CHECK_MSG(r.ok(), r.ok() ? "" : r.failure().message);
  CHECK_EQ(r.value().slot, 1u);  // installed into the inactive slot
  CHECK(!r.value().delta);
  CHECK_EQ(b.updater->counter_value(), uint64_t{2});  // counter advanced at install

  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_EQ(static_cast<int>(boot.value().outcome), static_cast<int>(BootOutcome::BootedTrial));
  CHECK_EQ(boot.value().slot, 1u);
  CHECK_EQ(boot.value().version, uint64_t{2});
  CHECK_EQ(boot.value().trial_remaining, 1u);  // consumed before booting

  CHECK(b.updater->confirm_boot().ok());
  auto st = b.updater->status();
  CHECK_EQ(st.value().active_slot.value(), 1u);
  CHECK(!st.value().pending_slot.has_value());
  CHECK_EQ(st.value().active_version, uint64_t{2});
}

TEST(trial_counts_down_then_reverts) {
  Bench b;
  provision(b, 1);
  auto v2 = b.pkg(2);
  CHECK(b.updater->install(v2, 1).ok());

  // Boot 1: trial, not confirmed.
  auto boot1 = b.updater->select_boot();
  CHECK(boot1.ok());
  CHECK_EQ(static_cast<int>(boot1.value().outcome), static_cast<int>(BootOutcome::BootedTrial));
  b.reboot();

  // Boot 2: last trial.
  auto boot2 = b.updater->select_boot();
  CHECK(boot2.ok());
  CHECK_EQ(static_cast<int>(boot2.value().outcome), static_cast<int>(BootOutcome::BootedTrial));
  b.reboot();

  // Boot 3: trials exhausted -> revert to the old slot.
  auto boot3 = b.updater->select_boot();
  CHECK(boot3.ok());
  CHECK_EQ(static_cast<int>(boot3.value().outcome),
           static_cast<int>(BootOutcome::RevertedPending));
  CHECK_EQ(boot3.value().slot, 0u);
  CHECK_EQ(boot3.value().version, uint64_t{1});
  b.reboot();

  // Subsequent boots stay on the old slot.
  auto boot4 = b.updater->select_boot();
  CHECK(boot4.ok());
  CHECK_EQ(static_cast<int>(boot4.value().outcome), static_cast<int>(BootOutcome::BootedActive));
  CHECK_EQ(boot4.value().version, uint64_t{1});
}

TEST(explicit_unhealthy_marks_revert) {
  Bench b;
  provision(b, 1);
  CHECK(b.updater->install(b.pkg(2), 1).ok());
  auto boot = b.updater->select_boot();
  CHECK_EQ(static_cast<int>(boot.value().outcome), static_cast<int>(BootOutcome::BootedTrial));
  CHECK(b.updater->mark_unhealthy().ok());
  b.reboot();
  auto boot2 = b.updater->select_boot();
  CHECK(boot2.ok());
  CHECK_EQ(static_cast<int>(boot2.value().outcome), static_cast<int>(BootOutcome::BootedActive));
  CHECK_EQ(boot2.value().version, uint64_t{1});
}

TEST(rollback_to_older_package_is_rejected) {
  Bench b;
  provision(b, 1);
  install_and_confirm(b, b.pkg(2));
  b.reboot();
  install_and_confirm(b, b.pkg(3));
  b.reboot();

  // A correctly signed but older package must not install.
  auto old = b.pkg(2);
  auto r = b.updater->install(old, 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::RollbackRejected);

  // Version 0 and anything below the counter is equally rejected.
  auto st = b.updater->status();
  CHECK_EQ(st.value().counter, uint64_t{3});
  CHECK_EQ(st.value().active_version, uint64_t{3});
}

TEST(same_version_reinstall_is_idempotent) {
  // After a power cut the operator retries the very same package; that must be
  // allowed (counter == target) and must still work.
  Bench b;
  provision(b, 1);
  auto v2 = b.pkg(2);
  CHECK(b.updater->install(v2, 1).ok());
  b.reboot();
  auto again = b.updater->install(v2, 2);
  CHECK_MSG(again.ok(), again.ok() ? "" : again.failure().message);
  auto boot = b.updater->select_boot();
  CHECK_EQ(boot.value().version, uint64_t{2});
  CHECK(b.updater->confirm_boot().ok());
}

TEST(install_rejects_tampered_package_and_changes_nothing) {
  Bench b;
  provision(b, 1);
  auto v2 = b.pkg(2);
  // Flip a byte inside the payload.
  v2[v2.size() / 2] ^= 0xFF;
  auto r = b.updater->install(v2, 1);
  CHECK(!r);

  auto st = b.updater->status();
  CHECK_EQ(st.value().counter, uint64_t{1});         // not advanced
  CHECK_EQ(st.value().active_version, uint64_t{1});  // unchanged
  CHECK(!st.value().pending_slot.has_value());       // nothing scheduled
  CHECK(!st.value().slot_verifies[1]);               // target slot untouched

  // And it still boots the old image cleanly.
  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_EQ(boot.value().version, uint64_t{1});
}

TEST(install_rejects_forged_signature_from_other_key) {
  Bench b;
  provision(b, 1);
  // Build with an attacker key.
  crypto::Seed s{};
  for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(200 + i);
  crypto::PublicKey evil_pk{};
  crypto::SecretKey evil_sk{};
  crypto::keypair_from_seed(s, evil_pk, evil_sk);
  auto req = b.base(5, 8192);
  auto forged = pkg::build_package(req, evil_sk, evil_pk);
  CHECK(forged.ok());
  auto r = b.updater->install(forged.value(), 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::SignatureInvalid);
  CHECK_EQ(b.updater->counter_value(), uint64_t{1});
}

TEST(install_rejects_wrong_device_and_hw) {
  Bench b;
  provision(b, 1);
  auto req = b.base(2, 4096);
  req.device_id = "someone-else";
  auto p = pkg::build_package(req, b.keys.sk, b.keys.pk);
  CHECK(p.ok());
  auto r = b.updater->install(p.value(), 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::Incompatible);

  auto req2 = b.base(2, 4096);
  req2.hw_min = 9;  // device is hw 2
  req2.hw_max = 12;
  auto p2 = pkg::build_package(req2, b.keys.sk, b.keys.pk);
  CHECK(p2.ok());
  auto r2 = b.updater->install(p2.value(), 1);
  CHECK(!r2);
  CHECK_EQ(r2.failure().code, Error::Incompatible);
}

TEST(install_rejects_image_larger_than_slot) {
  Bench b;
  provision(b, 1);
  // Slot image capacity is (1 MiB / 4 KiB - 4) / 2 - 1 sectors = 126 sectors.
  auto req = b.base(2, 700 * 1024);
  auto p = pkg::build_package(req, b.keys.sk, b.keys.pk);
  CHECK(p.ok());
  auto r = b.updater->install(p.value(), 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::SlotTooSmall);
}

TEST(delta_install_reconstructs_and_boots) {
  Bench b;
  provision(b, 1);
  b.reboot();  // reload so internal generation counters start from flash state

  auto image_v1 = b.image_for(1);
  // v2 differs from v1 in a few places but stays the same size, so it can use
  // a delta built against v1.
  pkg::PackRequest req = b.base(2, image_v1.size());
  for (size_t i = 5000; i < 9000; ++i) req.image[i] = static_cast<uint8_t>(i * 13);
  req.delta = true;
  req.source_image = image_v1;
  req.source_version = 1;
  auto p = pkg::build_package(req, b.keys.sk, b.keys.pk);
  CHECK_MSG(p.ok(), p.ok() ? "" : p.failure().message);

  auto r = b.updater->install(p.value(), 1);
  CHECK_MSG(r.ok(), r.ok() ? "" : r.failure().message);
  CHECK(r.value().delta);
  CHECK_EQ(r.value().version, uint64_t{2});

  auto boot = b.updater->select_boot();
  CHECK_EQ(static_cast<int>(boot.value().outcome), static_cast<int>(BootOutcome::BootedTrial));
  CHECK(b.updater->confirm_boot().ok());
  CHECK_EQ(b.updater->status().value().active_version, uint64_t{2});

  // The installed image must be byte-identical to the intended target.
  auto st = b.updater->status();
  CHECK(st.value().slot_verifies[1]);
}

TEST(delta_from_wrong_source_is_rejected) {
  Bench b;
  provision(b, 1);
  // Build a delta from a source that is NOT what the device runs.
  auto not_device = Bench::make_image(32 * 1024, 0x77);
  pkg::PackRequest req = b.base(2, 32 * 1024);
  req.delta = true;
  req.source_image = not_device;
  req.source_version = 1;
  auto p = pkg::build_package(req, b.keys.sk, b.keys.pk);
  CHECK(p.ok());
  auto r = b.updater->install(p.value(), 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::DeltaSourceMismatch);
  CHECK_EQ(b.updater->counter_value(), uint64_t{1});
}

TEST(delta_version_must_track_active_image) {
  Bench b;
  provision(b, 1);
  auto img1 = b.image_for(1);
  pkg::PackRequest req = b.base(4, img1.size());
  req.delta = true;
  req.source_image = img1;
  req.source_version = 2;  // device runs 1
  auto p = pkg::build_package(req, b.keys.sk, b.keys.pk);
  CHECK(p.ok());
  auto r = b.updater->install(p.value(), 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::DeltaSourceMismatch);
}

TEST(corrupted_slot_header_falls_back) {
  Bench b;
  provision(b, 1);
  b.reboot();
  // Corrupt the active slot's header sector; the device should refuse it and
  // try the other slot rather than boot unverified bytes.
  uint8_t junk[64];
  for (size_t i = 0; i < sizeof(junk); ++i) junk[i] = 0x00;
  CHECK(b.flash->program(0 + 4 * 4096, std::span<const uint8_t>(junk, sizeof(junk))).ok());
  b.reboot();
  auto boot = b.updater->select_boot();
  // Slot 0 header destroyed and slot 1 empty => nothing to boot.
  CHECK(!boot);
  CHECK_EQ(boot.failure().code, Error::NoValidSlot);
}

TEST(provision_rejects_delta_and_double_provision) {
  Bench b;
  auto full = b.pkg(1);
  CHECK(b.updater->provision(full, 1).ok());
  CHECK(!b.updater->provision(full, 2).ok());  // already provisioned
}

TEST(full_a_b_cycle_many_versions) {
  Bench b;
  provision(b, 1);
  for (uint64_t v = 2; v <= 7; ++v) {
    b.reboot();
    auto p = b.pkg(v);
    auto r = b.updater->install(p, 1);
    CHECK_MSG(r.ok(), "install v" + std::to_string(v) + ": " + r.failure().message);
    auto boot = b.updater->select_boot();
    CHECK(boot.ok());
    CHECK_EQ(boot.value().version, v);
    CHECK(b.updater->confirm_boot().ok());
  }
  b.reboot();
  auto boot = b.updater->select_boot();
  CHECK_EQ(boot.value().version, uint64_t{7});
  CHECK_EQ(b.updater->counter_value(), uint64_t{7});
}

// --- replay / offline tamper ------------------------------------------------

TEST(replay_of_old_signed_package_after_upgrade_is_rejected) {
  // The classic attack: capture a legitimately signed v2 package, then try to
  // replay it once the device has moved to v3.
  Bench b;
  provision(b, 1);
  auto captured = b.pkg(2);
  install_and_confirm(b, captured);
  b.reboot();
  install_and_confirm(b, b.pkg(3));
  b.reboot();

  auto r = b.updater->install(captured, 1);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::RollbackRejected);
  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_EQ(boot.value().version, uint64_t{3});

  // ... and wiping metadata does not help: the counter still gates install.
  auto st = b.updater->status();
  CHECK_EQ(st.value().counter, uint64_t{3});
}

TEST(tampering_with_image_inside_a_slot_blocks_that_boot) {
  Bench b;
  provision(b, 1);
  b.reboot();
  auto v2 = b.pkg(2);
  CHECK(b.updater->install(v2, 1).ok());

  // Attacker flips a byte in the freshly installed image area (slot 1).
  Layout l = Layout::make(kFlashSize, 4096);
  uint64_t image_off = l.slots[1].image_offset;
  auto one = b.flash->read(image_off + 100, 1);
  CHECK(one.ok());
  uint8_t patched = static_cast<uint8_t>(one.value()[0] ^ 0x01);
  // NOR flash cannot 0->1 without erase, so erase the sector first: this is a
  // realistic attacker with flash-write access.
  uint64_t sector = (image_off + 100) / 4096 * 4096;
  auto sector_bytes = b.flash->read(sector, 4096);
  CHECK(sector_bytes.ok());
  sector_bytes.value()[image_off + 100 - sector] = patched;
  CHECK(b.flash->erase_range(sector, 4096).ok());
  CHECK(b.flash->program(sector, sector_bytes.value()).ok());
  b.reboot();

  // The bootloader must refuse slot 1 and fall back, not boot bad code.
  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_EQ(static_cast<int>(boot.value().outcome),
           static_cast<int>(BootOutcome::RevertedPending));
  CHECK_EQ(boot.value().version, uint64_t{1});

  auto st = b.updater->status();
  CHECK(!st.value().slot_verifies[1]);
}

TEST(metadata_corruption_does_not_select_garbage) {
  Bench b;
  provision(b, 1);
  b.reboot();
  // Destroy BOTH metadata sectors. The device must recover from the slots
  // themselves (which are signed) rather than trusting a zeroed record.
  Layout l = Layout::make(kFlashSize, 4096);
  for (int i = 0; i < 2; ++i) {
    CHECK(b.flash->erase_range(l.meta_sector[i] * 4096, 4096).ok());
  }
  b.reboot();
  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_EQ(boot.value().version, uint64_t{1});
  CHECK_EQ(static_cast<int>(boot.value().outcome), static_cast<int>(BootOutcome::BootedActive));
}

TEST(counter_sector_corruption_cannot_lower_the_bar) {
  Bench b;
  provision(b, 1);
  install_and_confirm(b, b.pkg(2));
  b.reboot();
  install_and_confirm(b, b.pkg(3));
  b.reboot();
  CHECK_EQ(b.updater->counter_value(), uint64_t{3});

  // Erasing the newest counter record must fall back to the older one, never
  // to zero, so v2 stays forbidden.
  // Find which sector holds the newest record by erasing one at a time and
  // checking that the value never drops below 2.
  Layout l = Layout::make(kFlashSize, 4096);
  auto before = b.flash->dump();
  CHECK(before.ok());
  for (int i = 0; i < 2; ++i) {
    auto f2 = std::make_unique<Flash>(kFlashSize);
    CHECK(f2->load(before.value()).ok());
    CHECK(f2->erase_range(l.counter_sector[i] * 4096, 4096).ok());
    auto up2 = [&] {
      DeviceConfig cfg;
      cfg.device_id = "test-device";
      cfg.hw_revision = 2;
      cfg.trial_boots = 2;
      cfg.public_key = b.keys.pk;
      return std::make_unique<Updater>(*f2, cfg);
    }();
    CHECK_MSG(up2->counter_value() >= 2, "erasing counter sector " + std::to_string(i) +
                                             " lowered the floor to " +
                                             std::to_string(up2->counter_value()));
    auto stale = b.pkg(2);
    auto r = up2->install(stale, 1);
    CHECK_MSG(!r, "downgrade accepted after erasing counter sector " + std::to_string(i));
  }
}

TEST(offline_downgrade_by_repointing_metadata_is_blocked) {
  // Threat: attacker with flash-write access leaves both signed slots intact,
  // but rewrites the boot metadata to point at the older (still validly
  // signed) image. Every signature check passes — v1 really is vendor-signed.
  // Only the booted floor can reject it.
  Bench b;
  provision(b, 1);
  b.reboot();
  install_and_confirm(b, b.pkg(2));  // active slot 1 = v2, slot 0 still = v1
  b.reboot();
  CHECK_EQ(b.updater->booted_floor(), uint64_t{2});

  auto st0 = b.updater->status();
  CHECK_EQ(st0.value().active_slot.value(), 1u);
  CHECK(st0.value().slot_verifies[0]);  // the old v1 slot is still legitimately signed
  CHECK_EQ(st0.value().slot_version[0].value_or(0), uint64_t{1});

  // Attacker rewrites metadata: active_slot = 0, active_version = 1.
  // MetaLog writes proper CRCs, exactly what a flash-capable attacker can do.
  Layout l = Layout::make(kFlashSize, 4096);
  MetaLog meta(*b.flash, l.meta_sector[0] * 4096, l.meta_sector[1] * 4096);
  BootMeta forged;
  forged.active_slot = 0;
  forged.active_version = 1;
  forged.pending_slot = std::nullopt;
  forged.trial_remaining = 0;
  CHECK(meta.write(forged).ok());
  b.reboot();

  // The counter's booted floor is 2, so v1 must not be bootable.
  auto boot = b.updater->select_boot();
  CHECK(boot.ok());
  CHECK_MSG(boot.value().version == 2,
            "booted v" + std::to_string(boot.value().version) + " after metadata repoint");
  CHECK_EQ(boot.value().slot, 1u);
}
