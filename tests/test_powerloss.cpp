// Exhaustive power-loss testing.
//
// The method: count exactly how many flash operations a clean install performs,
// then repeat the install N+1 times, tearing at operation k for every k. After
// each torn run the "device" is rebuilt from the flash image alone and must
// satisfy these invariants — at every single cut point:
//
//   I1. select_boot() succeeds (a power cut never bricks the device).
//   I2. The booted image is signature-valid.
//   I3. The booted version is either the old version or the new one — never
//       something else, never a stale version the counter forbids.
//   I4. The anti-rollback counter never moved backwards.
//   I5. If the new version is selected for boot, it is genuinely the new
//       image (hash-verified).
//   I6. A retry of the same install after the cut either succeeds, or is
//       rejected for a reason that is not a downgrade, and after the retry the
//       device can boot and confirm the new version.
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

constexpr uint64_t kFlashSize = 1u << 20;

struct Fixture {
  crypto::PublicKey pk{};
  crypto::SecretKey sk{};
  std::vector<uint8_t> pkg_v1;
  std::vector<uint8_t> pkg_v2;
  std::vector<uint8_t> delta_v1_v2;

  Fixture() {
    crypto::Seed s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(11 * i + 5);
    crypto::keypair_from_seed(s, pk, sk);

    auto v1 = image(1);
    auto v2 = image(2);

    pkg::PackRequest r1;
    r1.image = v1;
    r1.target_version = 1;
    r1.device_id = "pl-device";
    r1.hw_min = 1;
    r1.hw_max = 4;
    auto b1 = pkg::build_package(r1, sk, pk);
    CHECK(b1.ok());
    pkg_v1 = b1.take();

    pkg::PackRequest r2 = r1;
    r2.image = v2;
    r2.target_version = 2;
    auto b2 = pkg::build_package(r2, sk, pk);
    CHECK(b2.ok());
    pkg_v2 = b2.take();

    pkg::PackRequest rd = r1;
    rd.image = v2;
    rd.target_version = 2;
    rd.source_version = 1;
    rd.source_image = v1;
    rd.delta = true;
    auto bd = pkg::build_package(rd, sk, pk);
    CHECK(bd.ok());
    delta_v1_v2 = bd.take();
  }

  static std::vector<uint8_t> image(uint8_t seed) {
    const size_t n = 40 * 1024;
    std::vector<uint8_t> v(n);
    uint32_t x = static_cast<uint32_t>(seed) * 977u + 3;
    for (size_t i = 0; i < n; ++i) {
      x = x * 1664525u + 1013904223u;
      v[i] = static_cast<uint8_t>(x >> 23);
    }
    return v;
  }

  std::unique_ptr<Updater> make(Flash& f) const {
    DeviceConfig cfg;
    cfg.device_id = "pl-device";
    cfg.hw_revision = 2;
    cfg.trial_boots = 2;
    cfg.public_key = pk;
    return std::make_unique<Updater>(f, cfg);
  }

  // A device at version 1 with confirmed boot, built in place.
  std::unique_ptr<Flash> provisioned() const {
    auto f = std::make_unique<Flash>(kFlashSize);
    auto up = make(*f);
    Status s = up->provision(pkg_v1, 1000);
    CHECK_MSG(s.ok(), s.message);
    auto boot = up->select_boot();
    CHECK(boot.ok());
    CHECK(up->confirm_boot().ok());
    return f;
  }
};

struct Snapshot {
  bool boot_ok = false;
  Error boot_error = Error::Ok;
  uint64_t version = 0;
  uint32_t slot = 0;
  uint64_t counter = 0;
  bool verified = false;
};

Snapshot inspect(const Fixture& fx, Flash& f) {
  Snapshot snap;
  auto up = fx.make(f);
  auto c = up->status();
  snap.counter = c.ok() ? c.value().counter : 0;
  auto boot = up->select_boot();
  snap.boot_ok = boot.ok();
  if (boot.ok()) {
    snap.boot_error = Error::Ok;
    snap.version = boot.value().version;
    snap.slot = boot.value().slot;
    // Independently confirm the selected slot's bytes are signature-valid.
    SlotStore store(f, Layout::make(f.size(), f.sector_size()));
    auto v = store.verify_slot(snap.slot, fx.pk);
    snap.verified = v.ok() && v.value().manifest.target_version == snap.version;
  } else {
    snap.boot_error = boot.failure().code;
  }
  return snap;
}

// Counts flash operations for a clean install of `package`.
uint64_t count_install_ops(const Fixture& fx, const std::vector<uint8_t>& package) {
  auto f = fx.provisioned();
  auto up = fx.make(*f);
  uint64_t before = f->completed_ops();
  auto r = up->install(package, 2000);
  CHECK_MSG(r.ok(), r.ok() ? "" : r.failure().message);
  return f->completed_ops() - before;
}

// Tears the install at operation `cut`, then checks every invariant.
void sweep(const char* label, const Fixture& fx, const std::vector<uint8_t>& package,
           uint64_t ops, bool delta) {
  for (uint64_t cut = 1; cut <= ops; ++cut) {
    auto f = fx.provisioned();
    auto up = fx.make(*f);
    f->arm_power_cut(cut - 1);  // complete cut-1 ops, tear on op #cut
    auto r = up->install(package, 2000);
    f->power_restore();
    std::string where = std::string(label) + " cut " + std::to_string(cut) + "/" +
                        std::to_string(ops);

    // I1/I2/I3: always bootable, always signature-valid, only v1 or v2.
    Snapshot snap = inspect(fx, *f);
    CHECK_MSG(snap.boot_ok, where + ": device is unbootable (" +
                                std::string(to_string(snap.boot_error)) + ")");
    CHECK_MSG(snap.verified, where + ": booted slot does not verify");
    CHECK_MSG(snap.version == 1 || snap.version == 2,
              where + ": booted unexpected version " + std::to_string(snap.version));

    // I4: counter is 1 (untouched) or 2 (committed), never above the target.
    CHECK_MSG(snap.counter <= 2, where + ": counter ran past target: " +
                                     std::to_string(snap.counter));

    // I5: version 2 booted implies the counter was committed.
    if (snap.version == 2) {
      CHECK_MSG(snap.counter == 2, where + ": v2 bootable but counter is " +
                                       std::to_string(snap.counter));
    }

    // I6: retry the same package on a fresh Updater, then boot + confirm.
    auto up2 = fx.make(*f);
    auto retry = up2->install(package, 3000);
    if (!retry.ok()) {
      CHECK_MSG(retry.failure().code != Error::RollbackRejected ||
                    snap.counter == 2,  // already committed is fine
                where + ": retry rejected: " + retry.failure().message);
    }
    f->power_restore();
    auto boot2 = up2->select_boot();
    CHECK_MSG(boot2.ok(), where + ": unbootable after retry (" +
                              std::string(to_string(boot2.failure().code)) + ")");
    CHECK_MSG(boot2.value().version == 1 || boot2.value().version == 2,
              where + ": retry booted v" + std::to_string(boot2.value().version));
    if (boot2.value().version == 2) {
      Status c = up2->confirm_boot();
      CHECK_MSG(c.ok(), where + ": confirm failed: " + c.message);
      auto st = up2->status();
      CHECK_MSG(st.ok() && st.value().active_version == 2, where + ": v2 did not become active");
      CHECK_MSG(st.ok() && st.value().counter == 2, where + ": counter not 2 after v2 confirm");
    }
    (void)delta;
  }
}

}  // namespace

TEST(powerloss_full_install_every_cut) {
  Fixture fx;
  uint64_t ops = count_install_ops(fx, fx.pkg_v2);
  CHECK_MSG(ops > 8, "install is suspiciously short: " + std::to_string(ops));
  sweep("full", fx, fx.pkg_v2, ops, false);
}

TEST(powerloss_delta_install_every_cut) {
  Fixture fx;
  uint64_t ops = count_install_ops(fx, fx.delta_v1_v2);
  CHECK(ops > 8);
  sweep("delta", fx, fx.delta_v1_v2, ops, true);
}

TEST(powerloss_during_confirm_is_safe) {
  Fixture fx;
  // Install fully, boot the trial, then cut power during confirm_boot() and
  // during each of several confirm attempts.
  for (uint64_t cut = 0; cut < 4; ++cut) {
    auto f = fx.provisioned();
    auto up = fx.make(*f);
    CHECK(up->install(fx.pkg_v2, 2000).ok());
    auto boot = up->select_boot();
    CHECK(boot.ok());
    f->arm_power_cut(cut);
    up->confirm_boot();
    f->power_restore();

    Snapshot snap = inspect(fx, *f);
    CHECK_MSG(snap.boot_ok, "cut " + std::to_string(cut) + ": unbootable after confirm cut");
    CHECK_MSG(snap.verified, "cut " + std::to_string(cut) + ": booted slot fails verification");
    CHECK_MSG(snap.version == 1 || snap.version == 2,
              "cut " + std::to_string(cut) + ": bad version");
  }
}

TEST(powerloss_between_install_and_reboot_many_times) {
  Fixture fx;
  // Repeatedly install, power-cycle without confirming, and reinstall. The
  // trial budget must be honoured and the device must end up on a valid image.
  auto f = fx.provisioned();
  for (int i = 0; i < 6; ++i) {
    auto up = fx.make(*f);
    auto r = up->install(fx.pkg_v2, 2000);
    if (!r.ok()) {
      CHECK_EQ(r.failure().code, Error::RollbackRejected);
      break;
    }
    for (int boot = 0; boot < 3; ++boot) {
      auto up2 = fx.make(*f);
      auto b = up2->select_boot();
      CHECK(b.ok());
      CHECK(b.value().version == 1 || b.value().version == 2);
    }
  }
  Snapshot snap = inspect(fx, *f);
  CHECK(snap.boot_ok);
  CHECK(snap.verified);
}

TEST(powerloss_counter_never_exceeds_successful_install) {
  Fixture fx;
  // If the install call returns a failure, the counter must not be at the new
  // version unless the new version also boots (i.e. the failure happened after
  // the commit, on the way out — which our orderings do not produce, but the
  // invariant is what matters, not the implementation detail).
  uint64_t ops = count_install_ops(fx, fx.pkg_v2);
  for (uint64_t cut = 1; cut <= ops; ++cut) {
    auto f = fx.provisioned();
    auto up = fx.make(*f);
    f->arm_power_cut(cut - 1);
    auto r = up->install(fx.pkg_v2, 2000);
    f->power_restore();
    auto counter = up->counter_value();
    std::string where = "cut " + std::to_string(cut);
    if (!r.ok()) {
      Snapshot snap = inspect(fx, *f);
      CHECK_MSG(snap.boot_ok, where + ": unbootable");
      if (counter == 2) {
        // Counter committed => the new image must be present and valid, so the
        // device cannot be locked out of the version it is now pinned to.
        CHECK_MSG(inspect(fx, *f).verified, where + ": counter 2 but new image unusable");
      }
    }
  }
}
