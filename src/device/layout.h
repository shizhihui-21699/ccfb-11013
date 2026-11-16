// Flash layout for the emulated device.
//
//   sector 0        counter A   (32-byte record)
//   sector 1        counter B   (32-byte record)
//   sector 2        metadata A  (44-byte MAC-free record, CRC protected)
//   sector 3        metadata B
//   +---------------+---------------------------------------+
//   | slot 0 header | slot 0 image  (cap = 125 sectors)     |
//   +---------------+---------------------------------------+
//   | slot 1 header | slot 1 image                          |
//   +---------------+---------------------------------------+
//
// Counters and metadata use two ping-pong sectors so every update is
// crash-safe: the older copy is erased and rewritten, the newer copy is never
// touched until the replacement has been fully programmed and CRC-checked.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ota {

struct SlotRegion {
  uint64_t header_offset = 0;
  uint64_t image_offset = 0;
  uint64_t image_capacity = 0;
};

struct Layout {
  uint32_t sector_size = 4096;
  uint64_t flash_size = 1u << 20;
  uint64_t counter_sector[2] = {0, 1};
  uint64_t meta_sector[2] = {2, 3};
  std::array<SlotRegion, 2> slots{};

  static Layout make(uint64_t flash_size = 1u << 20, uint32_t sector_size = 4096);
  // Validates that region boundaries are consistent; used by tests too.
  bool consistent() const;
};

}  // namespace ota
