#include "device/counter.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "common/bytes.h"
#include "common/crc32.h"

namespace ota {

namespace {
constexpr std::array<uint8_t, 4> kMagic = {'C', 'T', 'R', '1'};
}  // namespace

MonotonicCounter::MonotonicCounter(Flash& flash, uint64_t sector_a, uint64_t sector_b)
    : flash_(flash), sector_a_(sector_a), sector_b_(sector_b) {}

Result<MonotonicCounter::Record> MonotonicCounter::read_at(uint64_t sector) const {
  auto raw = flash_.read(sector, kRecordSize);
  if (!raw) return raw.failure();
  Record r;
  const uint8_t* p = raw.value().data();
  if (std::memcmp(p, kMagic.data(), 4) != 0) return r;  // blank / not yet written
  uint32_t stored_crc = load_u32(p + 28);
  if (crc32(std::span<const uint8_t>(p, 28)) != stored_crc) return r;
  r.valid = true;
  r.seq = load_u32(p + 4);
  r.value.installed = load_u64(p + 8);
  r.value.booted = load_u64(p + 16);
  return r;
}

Status MonotonicCounter::write_at(uint64_t sector, uint32_t seq, const CounterValue& value) {
  uint8_t rec[kRecordSize] = {};
  std::memcpy(rec, kMagic.data(), 4);
  store_u32(rec + 4, seq);
  store_u64(rec + 8, value.installed);
  store_u64(rec + 16, value.booted);
  // bytes 24..27 reserved (zero)
  store_u32(rec + 28, crc32(std::span<const uint8_t>(rec, 28)));
  Status s = flash_.erase_range(sector, kRecordSize);
  if (!s) return s;
  return flash_.program(sector, std::span<const uint8_t>(rec));
}

Result<MonotonicCounter::Record> MonotonicCounter::newer(const Record& a,
                                                         const Record& b) const {
  if (a.valid && b.valid) return a.seq >= b.seq ? a : b;
  if (a.valid) return a;
  return b;
}

Result<CounterValue> MonotonicCounter::read() const {
  auto a = read_at(sector_a_);
  if (!a) return a.failure();
  auto b = read_at(sector_b_);
  if (!b) return b.failure();
  // Per-floor maximum over both records. With identical mirrored copies this
  // is just the value; it also means one stale/corrupt sector can never lower
  // either floor.
  CounterValue v;
  if (a.value().valid) v = a.value().value;
  if (b.value().valid) {
    v.installed = std::max(v.installed, b.value().value.installed);
    v.booted = std::max(v.booted, b.value().value.booted);
  }
  return v;
}

Status MonotonicCounter::initialize(uint64_t value) {
  auto current = read();
  if (!current) return current.failure();
  if (current.value().installed != 0 || current.value().booted != 0)
    return fail(Error::AlreadyInitialized, "counter already provisioned");
  if (value == 0) return fail(Error::InvalidArgument, "counter value must be > 0");
  CounterValue v{value, value};
  Status s = write_at(sector_a_, 1, v);
  if (!s) return s;
  return write_at(sector_b_, 1, v);
}

Status MonotonicCounter::advance_installed(uint64_t value) {
  auto a = read_at(sector_a_);
  if (!a) return a.failure();
  auto b = read_at(sector_b_);
  if (!b) return b.failure();
  auto cur = read();
  if (!cur) return cur.failure();
  if (value <= cur.value().installed)
    return fail(Error::RollbackRejected, "installed floor is " +
                                             std::to_string(cur.value().installed) +
                                             ", cannot move to " + std::to_string(value));
  uint32_t seq = 0;
  if (a.value().valid) seq = std::max(seq, a.value().seq);
  if (b.value().valid) seq = std::max(seq, b.value().seq);
  CounterValue next = cur.value();
  next.installed = value;
  bool a_done = a.value().valid && a.value().value.installed >= value;
  bool b_done = b.value().valid && b.value().value.installed >= value;
  if (!a_done) {
    Status s = write_at(sector_a_, seq + 1, next);
    if (!s) return s;
  }
  if (!b_done) {
    Status s = write_at(sector_b_, seq + 1, next);
    if (!s) return s;
  }
  return Status{};
}

Status MonotonicCounter::mark_booted(uint64_t value) {
  auto a = read_at(sector_a_);
  if (!a) return a.failure();
  auto b = read_at(sector_b_);
  if (!b) return b.failure();
  auto cur = read();
  if (!cur) return cur.failure();
  if (value > cur.value().installed)
    return fail(Error::InvalidArgument, "cannot confirm version " + std::to_string(value) +
                                            " above the installed floor " +
                                            std::to_string(cur.value().installed));
  if (value <= cur.value().booted) return Status{};  // already at or above this floor
  uint32_t seq = 0;
  if (a.value().valid) seq = std::max(seq, a.value().seq);
  if (b.value().valid) seq = std::max(seq, b.value().seq);
  CounterValue next = cur.value();
  next.booted = value;
  Status s = write_at(sector_a_, seq + 1, next);
  if (!s) return s;
  return write_at(sector_b_, seq + 1, next);
}

}  // namespace ota
