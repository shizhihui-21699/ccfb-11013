// SPDX-License-Identifier: MIT
#include "bootctl.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "crc32.h"
#include "flash.h"
#include "sha256.h"

namespace ota {
namespace {

// 记录布局：0..15 头部（magic/format/size/record_seq），
// 16..31 状态字段（counter/active_slot/boot_attempts），32.. 两个槽元数据。
constexpr size_t kStateFieldsOff = 16;
constexpr size_t kSlotMetaOff = 32;
static_assert(kSlotMetaOff + 2 * 120 + 4 <= kBootRecordCrcOff, "引导记录布局溢出");

}  // namespace

const char* slot_state_name(SlotState s) {
  switch (s) {
    case SlotState::kEmpty:
      return "empty";
    case SlotState::kPending:
      return "pending";
    case SlotState::kGood:
      return "good";
    case SlotState::kBad:
      return "bad";
  }
  return "?";
}

// ---------------- BootState ----------------

Bytes BootState::serialize() const {
  Bytes out(kBootRecordSize, 0);
  std::memcpy(out.data(), kBootMagic, 4);
  put_u16(out.data() + 4, kBootFormat);
  put_u16(out.data() + 6, kBootRecordSize);
  put_u64(out.data() + 8, record_seq);
  put_u64(out.data() + kStateFieldsOff, counter);
  out[kStateFieldsOff + 8] = active_slot;
  out[kStateFieldsOff + 9] = boot_attempts;
  // kStateFieldsOff+10..15 保留为 0

  for (int i = 0; i < 2; ++i) {
    size_t o = kSlotMetaOff + i * 120;
    out[o] = static_cast<uint8_t>(slots[i].state);
    out[o + 1] = 0;
    out[o + 2] = 0;
    out[o + 3] = 0;
    put_u64(out.data() + o + 4, slots[i].seq);
    put_u64(out.data() + o + 12, slots[i].image_size);
    std::memcpy(out.data() + o + 20, slots[i].image_hash.data(), 32);
    std::memcpy(out.data() + o + 52, slots[i].version, sizeof(slots[i].version));
    // o+84 .. o+119 保留
  }
  uint32_t c = Crc32::compute(out.data(), kBootRecordCrcOff);
  put_u32(out.data() + kBootRecordCrcOff, c);
  return out;
}

BootState BootState::parse(const uint8_t* data, size_t len) {
  if (len != kBootRecordSize) fail(OtaError::kMetadata, "引导记录长度错误");
  if (std::memcmp(data, kBootMagic, 4) != 0) fail(OtaError::kMetadata, "引导记录魔数错误");
  if (get_u16(data + 4) != kBootFormat) fail(OtaError::kMetadata, "引导记录版本不支持");
  if (get_u16(data + 6) != kBootRecordSize) fail(OtaError::kMetadata, "引导记录尺寸字段错误");
  if (Crc32::compute(data, kBootRecordCrcOff) != get_u32(data + kBootRecordCrcOff)) {
    fail(OtaError::kMetadata, "引导记录 CRC 错误");
  }

  BootState s;
  s.record_seq = get_u64(data + 8);
  s.counter = get_u64(data + kStateFieldsOff);
  s.active_slot = data[kStateFieldsOff + 8];
  s.boot_attempts = data[kStateFieldsOff + 9];
  if (s.active_slot > 1) fail(OtaError::kMetadata, "active_slot 非法");
  if (s.boot_attempts > kMaxBootAttempts) fail(OtaError::kMetadata, "boot_attempts 非法");
  if (!is_zero(data + kStateFieldsOff + 10, 6)) fail(OtaError::kMetadata, "保留字段非零");

  for (int i = 0; i < 2; ++i) {
    size_t o = kSlotMetaOff + i * 120;
    uint8_t st = data[o];
    if (st > static_cast<uint8_t>(SlotState::kBad)) fail(OtaError::kMetadata, "槽状态非法");
    s.slots[i].state = static_cast<SlotState>(st);
    s.slots[i].seq = get_u64(data + o + 4);
    s.slots[i].image_size = get_u64(data + o + 12);
    std::memcpy(s.slots[i].image_hash.data(), data + o + 20, 32);
    std::memcpy(s.slots[i].version, data + o + 52, sizeof(s.slots[i].version));
    if (s.slots[i].version[31] != '\0') fail(OtaError::kMetadata, "版本字段未终止");
  }
  return s;
}

uint32_t BootState::crc() const {
  Bytes b = serialize();
  return get_u32(b.data() + kBootRecordCrcOff);
}

// ---------------- BootControl ----------------

BootControl::BootControl(SimFlash* flash, uint64_t offset, uint32_t sectors)
    : flash_(flash), offset_(offset), sectors_(sectors) {
  if (sectors == 0) fail(OtaError::kMetadata, "引导记录区至少 1 个扇区");
  uint64_t bytes = static_cast<uint64_t>(sectors) * flash->sector_size();
  if (offset > flash->size() || bytes > flash->size() - offset) {
    fail(OtaError::kFlashRange, "引导记录区越界");
  }
}

uint64_t BootControl::record_offset(uint32_t index) const {
  return offset_ + static_cast<uint64_t>(index) * kBootRecordSize;
}

size_t BootControl::valid_record_count() const {
  size_t n = 0;
  for (uint32_t i = 0; i < record_capacity(); ++i) {
    Bytes rec = flash_->read(record_offset(i), kBootRecordSize);
    if (std::memcmp(rec.data(), kBootMagic, 4) == 0 &&
        Crc32::compute(rec.data(), kBootRecordCrcOff) == get_u32(rec.data() + kBootRecordCrcOff)) {
      ++n;
    }
  }
  return n;
}

BootState BootControl::load() const {
  BootState best;
  bool found = false;
  for (uint32_t i = 0; i < record_capacity(); ++i) {
    Bytes rec = flash_->read(record_offset(i), kBootRecordSize);
    if (std::memcmp(rec.data(), kBootMagic, 4) != 0) continue;
    try {
      BootState s = BootState::parse(rec.data(), rec.size());
      if (!found || s.record_seq >= best.record_seq) {
        best = s;
        found = true;
      }
    } catch (const OtaError&) {
      // 撕裂或损坏的记录：忽略，继续找更早的有效记录。
    }
  }
  if (!found) {
    BootState s;
    s.record_seq = 0;
    return s;
  }
  return best;
}

namespace {

// 返回 record_seq 最大的那条有效记录所在的记录槽下标；没有有效记录返回 -1。
int32_t newest_record_index(SimFlash* flash, uint64_t base, uint32_t capacity) {
  int32_t best = -1;
  uint64_t best_seq = 0;
  bool found = false;
  for (uint32_t i = 0; i < capacity; ++i) {
    Bytes rec = flash->read(base + static_cast<uint64_t>(i) * kBootRecordSize, kBootRecordSize);
    if (std::memcmp(rec.data(), kBootMagic, 4) != 0) continue;
    try {
      BootState s = BootState::parse(rec.data(), rec.size());
      if (!found || s.record_seq > best_seq) {
        best = static_cast<int32_t>(i);
        best_seq = s.record_seq;
        found = true;
      }
    } catch (const OtaError&) {
    }
  }
  return best;
}

}  // namespace

BootState BootControl::commit(const BootState& state) {
  BootState next = state;
  next.record_seq = state.record_seq + 1;

  uint32_t capacity = record_capacity();
  int32_t target = -1;
  for (uint32_t i = 0; i < capacity; ++i) {
    if (flash_->is_erased(record_offset(i), kBootRecordSize)) {
      target = static_cast<int32_t>(i);
      break;
    }
  }

  if (target < 0) {
    // 环满：只擦除不含“最新有效记录”的扇区，最新状态始终有一份完好的
    // 拷贝在闪存上。任何一次擦除中途断电，load() 仍能找回最新记录。
    int32_t newest = newest_record_index(flash_, offset_, capacity);
    uint32_t per_sector = flash_->sector_size() / kBootRecordSize;
    uint32_t keep_sector = (newest < 0) ? UINT32_MAX
                                        : static_cast<uint32_t>(newest) / per_sector;
    for (uint32_t s = 0; s < sectors_; ++s) {
      if (s == keep_sector) continue;
      flash_->erase_sector(offset_ + static_cast<uint64_t>(s) * flash_->sector_size());
    }
    // 现在从被擦除的区域里挑第一个槽（避开保留扇区）。
    // 保留扇区保留着最新记录，其余扇区已擦除，从 0 号或保留扇区之后开始均可。
    uint32_t start = (keep_sector == 0) ? per_sector : 0;
    target = static_cast<int32_t>(start);
  }

  Bytes rec = next.serialize();
  flash_->program(record_offset(static_cast<uint32_t>(target)), rec.data(), rec.size());
  return next;
}

// ---------------- ImageHeader ----------------

Bytes ImageHeader::serialize() const {
  Bytes out(kSize, 0);
  std::memcpy(out.data(), "OTIM", 4);
  put_u16(out.data() + 4, kBootFormat);
  put_u16(out.data() + 6, static_cast<uint16_t>(kSize));
  put_u64(out.data() + 8, seq);
  put_u64(out.data() + 16, image_size);
  std::memcpy(out.data() + 24, image_hash.data(), 32);
  std::memcpy(out.data() + 56, version.data(), version.size());
  std::memcpy(out.data() + 88, product.data(), product.size());
  std::memcpy(out.data() + 112, hardware.data(), hardware.size());
  put_u32(out.data() + kSize - 4, Crc32::compute(out.data(), kSize - 4));
  return out;
}

ImageHeader ImageHeader::parse(const uint8_t* data, size_t len) {
  if (len < kSize) fail(OtaError::kMetadata, "镜像头过短");
  if (std::memcmp(data, "OTIM", 4) != 0) fail(OtaError::kMetadata, "镜像头魔数错误");
  if (get_u16(data + 4) != kBootFormat) fail(OtaError::kMetadata, "镜像头版本不支持");
  if (get_u16(data + 6) != kSize) fail(OtaError::kMetadata, "镜像头尺寸错误");
  if (Crc32::compute(data, kSize - 4) != get_u32(data + kSize - 4)) {
    fail(OtaError::kMetadata, "镜像头 CRC 错误");
  }
  ImageHeader h;
  h.seq = get_u64(data + 8);
  h.image_size = get_u64(data + 16);
  std::memcpy(h.image_hash.data(), data + 24, 32);
  std::memcpy(h.version.data(), data + 56, h.version.size());
  std::memcpy(h.product.data(), data + 88, h.product.size());
  std::memcpy(h.hardware.data(), data + 112, h.hardware.size());
  return h;
}

// ---------------- DeviceLayout ----------------

DeviceLayout DeviceLayout::make(uint64_t flash_size, uint64_t slot_size, uint32_t sector_size) {
  if (sector_size == 0 || slot_size % sector_size != 0) {
    fail(OtaError::kFlashRange, "槽大小必须按扇区对齐");
  }
  DeviceLayout l;
  l.sector_size = sector_size;
  l.boot_meta_sectors = 8;
  l.boot_meta_offset = 0;
  uint64_t meta_bytes = static_cast<uint64_t>(l.boot_meta_sectors) * sector_size;
  l.slot_offset[0] = meta_bytes;
  l.slot_offset[1] = meta_bytes + slot_size;
  l.slot_size[0] = slot_size;
  l.slot_size[1] = slot_size;
  l.boot_meta_offset = 0;
  uint64_t need = meta_bytes + 2 * slot_size;
  if (need > flash_size) fail(OtaError::kNoSpace, "闪存容量不足以容纳元数据 + 两个槽");
  return l;
}

uint64_t DeviceLayout::total_needed() const {
  uint64_t meta = static_cast<uint64_t>(boot_meta_sectors) * sector_size;
  return meta + slot_size[0] + slot_size[1];
}

}  // namespace ota
