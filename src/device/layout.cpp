#include "device/layout.h"

#include "common/status.h"

namespace ota {

Layout Layout::make(uint64_t flash_size, uint32_t sector_size) {
  Layout l;
  l.flash_size = flash_size;
  l.sector_size = sector_size;
  uint64_t sectors = flash_size / sector_size;
  // 4 sectors of metadata/counter, the rest split evenly between the slots.
  uint64_t per_slot = (sectors - 4) / 2;
  l.counter_sector[0] = 0;
  l.counter_sector[1] = 1;
  l.meta_sector[0] = 2;
  l.meta_sector[1] = 3;
  for (size_t i = 0; i < 2; ++i) {
    uint64_t first = 4 + static_cast<uint64_t>(i) * per_slot;
    l.slots[i].header_offset = first * sector_size;
    l.slots[i].image_offset = (first + 1) * sector_size;
    l.slots[i].image_capacity = (per_slot - 1) * sector_size;
  }
  return l;
}

bool Layout::consistent() const {
  if (flash_size == 0 || sector_size == 0 || flash_size % sector_size != 0) return false;
  if (flash_size / sector_size < 8) return false;
  auto aligned = [&](uint64_t v) { return v % sector_size == 0; };
  for (size_t i = 0; i < 2; ++i) {
    if (!aligned(slots[i].header_offset) || !aligned(slots[i].image_offset)) return false;
    if (slots[i].image_offset <= slots[i].header_offset) return false;
    if (slots[i].image_capacity == 0 || slots[i].image_capacity % sector_size != 0) return false;
    if (slots[i].image_offset + slots[i].image_capacity > flash_size) return false;
    if (!aligned(counter_sector[i] * sector_size)) return false;
    if (!aligned(meta_sector[i] * sector_size)) return false;
  }
  // Slots must not overlap each other or the metadata area.
  if (slots[0].image_offset + slots[0].image_capacity > slots[1].header_offset) return false;
  if (meta_sector[1] >= slots[0].header_offset / sector_size) return false;
  return true;
}

}  // namespace ota
