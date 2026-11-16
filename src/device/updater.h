// Device-side update agent: install, boot selection, trial confirmation,
// automatic rollback.
//
// Install flow (crash-safe at every step):
//   1. Parse + verify the package. Signature failure => nothing is touched.
//   2. Policy checks: device id, hw range, target_version > monotonic counter.
//   3. Install into the slot that is NOT active (A/B).
//      Full package: stream payload into the target slot, hash as we go.
//      Delta: verify the source image matches the signed source hash, apply
//      the delta stream into the target slot, hash as we go.
//   4. Compare the streamed hash with the signed image hash; mismatch =>
//      invalidate the target slot, never advance the counter.
//   5. Write the signed install record (Ready) into the target slot.
//   6. Commit metadata: pending=target, trial=N, active stays put.
//   7. Commit the monotonic counter to target_version.
//   8. On reboot, the bootloader selects `pending` for a trial boot.
//   9. Application calls confirm_boot() once it is healthy (network up,
//      self-test passed). Without it, trials run out and the device reverts.
//
// Ordering rationale: the counter is advanced LAST. A power cut before step 7
// leaves the old active slot bootable and the counter unchanged, so the same
// package can simply be re-installed. A power cut after step 7 leaves a
// pending slot that will be verified at boot; if it is unusable the device
// reverts to the (older, still signature-valid) active slot, which is allowed
// because the counter only gates *installing*, not *booting what is already
// verified on flash*.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/crypto.h"
#include "common/status.h"
#include "device/counter.h"
#include "device/flash.h"
#include "device/layout.h"
#include "device/meta.h"
#include "device/slot.h"
#include "package/format.h"

namespace ota {

struct DeviceConfig {
  std::string device_id = "sim-device";
  uint32_t hw_revision = 1;
  uint32_t trial_boots = 2;  // boot attempts granted to a freshly installed slot
  crypto::PublicKey public_key{};
};

enum class BootOutcome {
  BootedActive,    // normal boot of the active slot
  BootedTrial,     // first/next trial boot of the pending slot
  RevertedPending, // pending slot failed verification; fell back to active
  NoBootableSlot,  // neither slot verifies: unrecoverable without recovery mode
};

struct BootDecision {
  BootOutcome outcome = BootOutcome::NoBootableSlot;
  uint32_t slot = 0;
  uint64_t version = 0;
  uint32_t trial_remaining = 0;
};

struct InstallReport {
  uint32_t slot = 0;
  uint64_t version = 0;
  uint64_t image_size = 0;
  bool delta = false;
  bool counter_advanced = false;
};

struct DeviceStatus {
  std::optional<uint32_t> active_slot;
  std::optional<uint32_t> pending_slot;
  uint64_t active_version = 0;
  uint64_t pending_version = 0;
  uint32_t trial_remaining = 0;
  uint64_t counter = 0;
  uint64_t booted_floor = 0;
  std::optional<uint64_t> slot_version[2];
  std::optional<SlotState> slot_state[2];
  bool slot_verifies[2] = {false, false};
};

class Updater {
 public:
  Updater(Flash& flash, DeviceConfig config);
  ~Updater();
  Updater(const Updater&) = delete;
  Updater& operator=(const Updater&) = delete;

  // Provisions a factory-fresh device: installs a signed bootstrap image into
  // slot 0 (claims the newest installed_at), sets counter and metadata.
  Status provision(std::span<const uint8_t> package, uint64_t now_unix);

  // Installs a package (full or delta). Returns before any state change when
  // verification/policy rejects it.
  Result<InstallReport> install(std::span<const uint8_t> package, uint64_t now_unix);

  // Called by the bootloader on every boot. Consumes one trial if booting a
  // pending slot, and reverts when the pending slot is unusable or out of
  // trials.
  Result<BootDecision> select_boot();

  // Called by the application once the running image is healthy.
  Status confirm_boot();

  // Called by the application when it detects it is unhealthy. Volatile-marker
  // variant of a crash: the next boot must not retry this slot.
  Status mark_unhealthy();

  Result<DeviceStatus> status() const;

  uint64_t counter_value() const;
  uint64_t booted_floor() const;

 private:
  Result<InstallReport> install_full(const pkg::ParsedPackage& pkg, uint64_t now_unix);
  Result<InstallReport> install_delta(const pkg::ParsedPackage& pkg, uint64_t now_unix);
  Status check_policy(const pkg::Manifest& manifest) const;
  Status finish_install(uint32_t slot, const pkg::ParsedPackage& pkg, uint64_t target_version,
                        uint64_t installed_at);
  Result<uint32_t> target_slot() const;
  // Slot holding a signature-verified image at `version`, if any. Used to make
  // installs idempotent after a power cut without weakening anti-rollback.
  std::optional<uint32_t> same_version_slot(uint64_t version) const;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ota
