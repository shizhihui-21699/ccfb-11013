// Boot metadata: which slot is active, which is on trial, and the trial budget.
//
// Two sectors hold the same fixed-size record in a ping-pong pattern, exactly
// like the counter: update = erase the older record, program the new one with
// seq+1, CRC-check it, and only then is the update considered done. A torn
// update therefore always leaves the previous state readable.
//
// Integrity: CRC-32, not a MAC. Nothing here is a security boundary:
// * which slot boots is a function of the signed slot contents, and the boot
//   path re-verifies the signature of whatever it is about to run;
// * the anti-rollback floor is the monotonic counter, which lives in its own
//   sectors and is cross-checked against the signed manifest;
// * flipping `active_slot` in metadata can select only the other slot, and both
//   slots are signature-verified before use.
// CRC is enough to detect the failure mode that actually matters — torn writes
// from power loss.
#pragma once

#include <cstdint>
#include <optional>

#include "common/status.h"
#include "device/flash.h"

namespace ota {

struct BootMeta {
  uint32_t active_slot = 0;
  std::optional<uint32_t> pending_slot;  // slot under trial
  uint32_t trial_remaining = 0;          // boot attempts left before revert
  uint64_t active_version = 0;
  uint64_t pending_version = 0;
};

class MetaLog {
 public:
  static constexpr size_t kRecordSize = 40;

  MetaLog(Flash& flash, uint64_t sector_a, uint64_t sector_b);

  // Latest valid record. `empty` when both sectors are blank or corrupt.
  Result<std::optional<BootMeta>> read() const;
  Status write(const BootMeta& meta);

 private:
  struct Stamped {
    uint32_t seq = 0;
    BootMeta meta;
    bool valid = false;
  };
  Result<Stamped> read_at(uint64_t sector) const;
  Status write_at(uint64_t sector, uint32_t seq, const BootMeta& meta);

  Flash& flash_;
  uint64_t sector_a_;
  uint64_t sector_b_;
};

}  // namespace ota
