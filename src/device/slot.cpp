#include "device/slot.h"

#include <algorithm>
#include <cstring>

#include "common/bytes.h"
#include "common/crc32.h"

namespace ota {
namespace {
constexpr std::array<uint8_t, 4> kMagic = {'S', 'L', 'O', 'T'};
constexpr uint32_t kHeaderFormat = 1;
constexpr size_t kFixed = 48;
}  // namespace

SlotStore::SlotStore(Flash& flash, const Layout& layout) : flash_(flash), layout_(layout) {}

uint64_t SlotStore::image_capacity(uint32_t slot) const {
  return layout_.slots.at(slot).image_capacity;
}

const SlotRegion& SlotStore::region(uint32_t slot) const { return layout_.slots.at(slot); }

Result<std::optional<SlotRecord>> SlotStore::read_record(uint32_t slot) const {
  const SlotRegion& r = region(slot);
  auto raw = flash_.read(r.header_offset, layout_.sector_size);
  if (!raw) return raw.failure();
  const auto& b = raw.value();
  size_t crc_off = layout_.sector_size - 4;
  if (std::memcmp(b.data(), kMagic.data(), 4) != 0) return std::optional<SlotRecord>{};
  if (crc32(std::span<const uint8_t>(b.data(), crc_off)) != load_u32(b.data() + crc_off))
    return std::optional<SlotRecord>{};

  uint32_t fmt = load_u32(b.data() + 4);
  uint32_t record_size = load_u32(b.data() + 8);
  if (fmt != kHeaderFormat) return std::optional<SlotRecord>{};
  if (record_size < kFixed + 100 + pkg::kSignatureSize || record_size > crc_off)
    return std::optional<SlotRecord>{};

  SlotRecord rec;
  rec.state = static_cast<SlotState>(load_u32(b.data() + 12));
  rec.image_size = load_u64(b.data() + 16);
  rec.generation = load_u64(b.data() + 24);
  rec.installed_at = load_u64(b.data() + 32);
  rec.flags = load_u32(b.data() + 40);
  if (rec.state != SlotState::Writing && rec.state != SlotState::Ready &&
      rec.state != SlotState::Bad)
    return std::optional<SlotRecord>{};
  if (rec.image_size > r.image_capacity) return std::optional<SlotRecord>{};
  size_t manifest_size = record_size - kFixed - pkg::kSignatureSize;
  if (manifest_size > pkg::kMaxSlotManifest) return std::optional<SlotRecord>{};
  rec.manifest.assign(b.begin() + static_cast<std::ptrdiff_t>(kFixed),
                      b.begin() + static_cast<std::ptrdiff_t>(kFixed + manifest_size));
  std::memcpy(rec.signature.data(), b.data() + kFixed + manifest_size, pkg::kSignatureSize);
  return std::optional<SlotRecord>(std::move(rec));
}

Result<std::optional<SlotRecord>> SlotStore::ready_record(uint32_t slot) const {
  auto rec = read_record(slot);
  if (!rec) return rec.failure();
  if (!rec.value() || rec.value()->state != SlotState::Ready)
    return std::optional<SlotRecord>{};
  return rec;
}

Result<std::vector<uint8_t>> SlotStore::read_image(uint32_t slot, uint64_t size) const {
  std::vector<uint8_t> out(static_cast<size_t>(size));
  Status s = read_image_into(slot, size, std::span<uint8_t>(out));
  if (!s) return s;
  return out;
}

Status SlotStore::read_image_into(uint32_t slot, uint64_t size, std::span<uint8_t> out) const {
  const SlotRegion& r = region(slot);
  if (size > r.image_capacity || size != out.size())
    return fail(Error::FlashRange, "image size outside slot capacity");
  return flash_.read_into(r.image_offset, out);
}

Status SlotStore::invalidate(uint32_t slot) {
  return flash_.erase_range(region(slot).header_offset, layout_.sector_size);
}

Status SlotStore::erase_slot(uint32_t slot) {
  const SlotRegion& r = region(slot);
  Status s = flash_.erase_range(r.header_offset, layout_.sector_size);
  if (!s) return s;
  return flash_.erase_range(r.image_offset, r.image_capacity);
}

Status SlotStore::program_image_chunk(uint32_t slot, uint64_t offset,
                                      std::span<const uint8_t> data) {
  const SlotRegion& r = region(slot);
  if (offset > r.image_capacity || data.size() > r.image_capacity - offset)
    return fail(Error::SlotTooSmall, "image exceeds slot capacity");
  return flash_.program(r.image_offset + offset, data);
}

Status SlotStore::write_record(uint32_t slot, const SlotRecord& record) {
  const SlotRegion& r = region(slot);
  if (record.manifest.size() > pkg::kMaxSlotManifest)
    return fail(Error::InvalidArgument, "manifest too large for slot header");
  if (record.image_size > r.image_capacity)
    return fail(Error::SlotTooSmall, "image exceeds slot capacity");
  size_t crc_off = layout_.sector_size - 4;
  size_t record_size = kFixed + record.manifest.size() + pkg::kSignatureSize;
  if (record_size > crc_off)
    return fail(Error::InvalidArgument, "manifest too large for slot header");

  std::vector<uint8_t> sector(layout_.sector_size, 0);
  std::memcpy(sector.data(), kMagic.data(), 4);
  store_u32(sector.data() + 4, kHeaderFormat);
  store_u32(sector.data() + 8, static_cast<uint32_t>(record_size));
  store_u32(sector.data() + 12, static_cast<uint32_t>(record.state));
  store_u64(sector.data() + 16, record.image_size);
  store_u64(sector.data() + 24, record.generation);
  store_u64(sector.data() + 32, record.installed_at);
  store_u32(sector.data() + 40, record.flags);
  std::memcpy(sector.data() + kFixed, record.manifest.data(), record.manifest.size());
  std::memcpy(sector.data() + kFixed + record.manifest.size(), record.signature.data(),
              pkg::kSignatureSize);
  store_u32(sector.data() + crc_off, crc32(std::span<const uint8_t>(sector.data(), crc_off)));
  Status s = flash_.erase_range(r.header_offset, layout_.sector_size);
  if (!s) return s;
  return flash_.program(r.header_offset, sector);
}

Status SlotStore::set_state(uint32_t slot, SlotState state) {
  auto rec = read_record(slot);
  if (!rec) return rec.failure();
  if (!rec.value()) return fail(Error::NotFound, "slot has no record");
  SlotRecord r = std::move(*rec.value());
  r.state = state;
  return write_record(slot, r);
}

Status SlotStore::write_slot(uint32_t slot, const SlotRecord& record,
                             std::span<const uint8_t> image) {
  const SlotRegion& r = region(slot);
  if (image.size() > r.image_capacity) return fail(Error::SlotTooSmall, "image exceeds slot");
  SlotRecord rec = record;
  rec.image_size = image.size();
  // Erase both regions. If power dies before anything is written the slot is
  // simply empty, and the active slot was never touched.
  Status s = erase_slot(slot);
  if (!s) return s;
  constexpr size_t kChunk = 16 * 1024;
  for (size_t off = 0; off < image.size(); off += kChunk) {
    size_t n = std::min(kChunk, image.size() - off);
    s = flash_.program(r.image_offset + off, image.subspan(off, n));
    if (!s) return s;
  }
  // Record last with its final state, so a crash mid-install leaves the slot
  // without a bootable record (and its previous record was erased).
  rec.state = record.state;
  return write_record(slot, rec);
}

Result<VerifiedSlot> SlotStore::verify_slot(uint32_t slot, const crypto::PublicKey& pk) const {
  auto rec = read_record(slot);
  if (!rec) return rec.failure();
  if (!rec.value()) return fail(Error::NotFound, "slot has no valid record");
  const SlotRecord& r = *rec.value();

  auto man = pkg::parse_manifest_bytes(r.manifest);
  if (!man) return man.failure();
  Status cs = pkg::check_manifest_image(man.value(), r.image_size);
  if (!cs) return cs;

  auto image = read_image(slot, r.image_size);
  if (!image) return image.failure();
  auto actual_hash = crypto::sha256(image.value());
  const auto& e = man.value().entries.at(0);
  if (!crypto::constant_time_equal(actual_hash, e.image_sha256))
    return fail(Error::ImageHashMismatch, "stored image does not match signed hash");

  auto digest = pkg::image_digest(std::span<const uint8_t>(r.manifest),
                                 std::span<const uint8_t>(image.value()));
  if (!crypto::verify_detached(r.signature,
                               std::span<const uint8_t>(digest.data(), digest.size()), pk))
    return fail(Error::SignatureInvalid, "stored signature does not verify");

  VerifiedSlot v;
  v.manifest = man.take();
  v.manifest_bytes = r.manifest;
  v.signature = r.signature;
  v.image_size = r.image_size;
  v.generation = r.generation;
  return v;
}

}  // namespace ota
