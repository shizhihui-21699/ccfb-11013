// SPDX-License-Identifier: MIT
// CRC-32 (IEEE 802.3, 反射多项式 0xEDB88320)，用于元数据断电撕裂检测。
// 它不是安全校验，只用于发现写到一半的元数据扇区。
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota {

class Crc32 {
 public:
  Crc32() : crc_(0xFFFFFFFFu) {}
  void update(const void* data, size_t len);
  uint32_t finish() const { return crc_ ^ 0xFFFFFFFFu; }

  static uint32_t compute(const void* data, size_t len) {
    Crc32 c;
    c.update(data, len);
    return c.finish();
  }

 private:
  uint32_t crc_;
};

}  // namespace ota
