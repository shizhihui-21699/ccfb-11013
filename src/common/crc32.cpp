// SPDX-License-Identifier: MIT
#include "crc32.h"

namespace ota {

void Crc32::update(const void* data, size_t len) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  uint32_t crc = crc_;
  for (size_t i = 0; i < len; ++i) {
    crc ^= p[i];
    for (int b = 0; b < 8; ++b) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  crc_ = crc;
}

}  // namespace ota
