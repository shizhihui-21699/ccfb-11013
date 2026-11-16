#include "device/meta.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "common/bytes.h"
#include "common/crc32.h"

namespace ota {
namespace {
constexpr std::array<uint8_t, 4> kMagic = {'M', 'E', 'T', 'A'};
constexpr uint32_t kNoPending = 0xFFFFFFFFu;
}  // namespace

MetaLog::MetaLog(Flash& flash, uint64_t sector_a, uint64_t sector_b)
    : flash_(flash), sector_a_(sector_a), sector_b_(sector_b) {}

Result<MetaLog::Stamped> MetaLog::read_at(uint64_t sector) const {
  auto raw = flash_.read(sector, kRecordSize);
  if (!raw) return raw.failure();
  Stamped s;
  const uint8_t* p = raw.value().data();
  if (std::memcmp(p, kMagic.data(), 4) != 0) return s;
  uint32_t crc = load_u32(p + 36);
  if (crc32(std::span<const uint8_t>(p, 36)) != crc) return s;
  s.seq = load_u32(p + 4);
  s.meta.active_slot = load_u32(p + 8);
  uint32_t pending = load_u32(p + 12);
  s.meta.trial_remaining = load_u32(p + 16);
  s.meta.active_version = load_u64(p + 20);
  s.meta.pending_version = load_u64(p + 28);
  s.meta.pending_slot = (pending == kNoPending) ? std::nullopt
                                                 : std::optional<uint32_t>(pending);
  s.valid = true;
  return s;
}

Status MetaLog::write_at(uint64_t sector, uint32_t seq, const BootMeta& meta) {
  uint8_t rec[kRecordSize] = {};
  std::memcpy(rec, kMagic.data(), 4);
  store_u32(rec + 4, seq);
  store_u32(rec + 8, meta.active_slot);
  store_u32(rec + 12, meta.pending_slot.value_or(kNoPending));
  store_u32(rec + 16, meta.trial_remaining);
  store_u64(rec + 20, meta.active_version);
  store_u64(rec + 28, meta.pending_version);
  store_u32(rec + 36, crc32(std::span<const uint8_t>(rec, 36)));
  Status s = flash_.erase_range(sector, kRecordSize);
  if (!s) return s;
  return flash_.program(sector, std::span<const uint8_t>(rec));
}

Result<std::optional<BootMeta>> MetaLog::read() const {
  auto a = read_at(sector_a_);
  if (!a) return a.failure();
  auto b = read_at(sector_b_);
  if (!b) return b.failure();
  const Stamped& sa = a.value();
  const Stamped& sb = b.value();
  if (sa.valid && sb.valid) return sa.seq >= sb.seq ? std::optional<BootMeta>(sa.meta)
                                                    : std::optional<BootMeta>(sb.meta);
  if (sa.valid) return std::optional<BootMeta>(sa.meta);
  if (sb.valid) return std::optional<BootMeta>(sb.meta);
  return std::optional<BootMeta>{};
}

Status MetaLog::write(const BootMeta& meta) {
  auto a = read_at(sector_a_);
  if (!a) return a.failure();
  auto b = read_at(sector_b_);
  if (!b) return b.failure();
  const Stamped& sa = a.value();
  const Stamped& sb = b.value();
  // Erase the older copy; never erase the newest valid record in place.
  uint32_t seq = 0;
  uint64_t target = sector_a_;
  if (sa.valid && sb.valid) {
    seq = std::max(sa.seq, sb.seq);
    target = (sa.seq >= sb.seq) ? sector_b_ : sector_a_;
  } else if (sa.valid) {
    seq = sa.seq;
    target = sector_b_;
  } else if (sb.valid) {
    seq = sb.seq;
    target = sector_a_;
  }
  return write_at(target, seq + 1, meta);
}

}  // namespace ota
