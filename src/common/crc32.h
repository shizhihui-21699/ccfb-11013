// CRC-32 (IEEE 802.3). Used to make flash records self-checking so a torn
// write is always detected instead of being interpreted as data.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace ota {

namespace detail {
inline constexpr std::array<uint32_t, 256> make_crc32_table() {
  std::array<uint32_t, 256> t{};
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    t[i] = c;
  }
  return t;
}
inline constexpr auto kCrc32Table = make_crc32_table();
}  // namespace detail

inline uint32_t crc32(std::span<const uint8_t> data) {
  uint32_t c = 0xFFFFFFFFu;
  for (uint8_t b : data) c = detail::kCrc32Table[(c ^ b) & 0xFFu] ^ (c >> 8);
  return c ^ 0xFFFFFFFFu;
}

}  // namespace ota
