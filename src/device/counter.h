// Monotonic counter (anti-rollback), emulated on two flash sectors.
//
// Two independent floors, because "don't install old code" and "don't boot old
// code" are different questions:
//
//   installed floor — highest version ever installed. Advanced by install(),
//                     after the image is written and verified.
//   booted floor    — highest version that has booted and been confirmed
//                     healthy. Advanced only by confirm_boot().
//
// Why both: a single install-only floor lets an attacker with flash-write
// access copy an *older, still-validly-signed* image into a slot and repoint
// the metadata at it. verify_slot() would pass, because the old image really
// was signed by the vendor. Comparing the verified image's version against the
// booted floor rejects that.
//
// Why the booted floor is not advanced at install time: the A/B trial needs to
// fall back to the previous (lower-versioned) image while the new one is under
// trial. Until the new image is confirmed, the old one is still the last known
// good, and the booted floor still equals the old version, so the fallback is
// allowed. Once the new image is confirmed the floor moves up and the old
// version is locked out for good.
//
// Storage: two sectors, each holding the same record, so erasing either one
// cannot lower a floor. Alternating (log-style) storage would put the newest
// value in exactly one sector and turn a single erase into a one-step rollback.
//
//   magic "CTR1" | u32 seq | u64 installed | u64 booted | u32 reserved | u32 crc32
#pragma once

#include <cstdint>
#include <span>

#include "common/status.h"
#include "device/flash.h"

namespace ota {

struct CounterValue {
  uint64_t installed = 0;
  uint64_t booted = 0;
};

class MonotonicCounter {
 public:
  static constexpr size_t kRecordSize = 32;

  MonotonicCounter(Flash& flash, uint64_t sector_a, uint64_t sector_b);

  // Per-floor max over the valid records; both zero on a blank part.
  Result<CounterValue> read() const;

  // Both floors zero => factory blank. Provisions both floors to `value`.
  Status initialize(uint64_t value);

  // Raises the installed floor. Refuses value <= installed (RollbackRejected).
  Status advance_installed(uint64_t value);

  // Raises the booted floor. Refuses value <= booted, and refuses a value above
  // the installed floor (you cannot claim to have confirmed what was never
  // installed).
  Status mark_booted(uint64_t value);

 private:
  struct Record {
    bool valid = false;
    uint32_t seq = 0;
    CounterValue value;
  };

  Result<Record> read_at(uint64_t sector) const;
  Status write_at(uint64_t sector, uint32_t seq, const CounterValue& value);
  Result<Record> newer(const Record& a, const Record& b) const;

  Flash& flash_;
  uint64_t sector_a_;
  uint64_t sector_b_;
};

}  // namespace ota
