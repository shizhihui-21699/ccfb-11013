// SPDX-License-Identifier: MIT
// 自包含 SHA-256（FIPS 180-4），流式接口，设备端不依赖 OpenSSL。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "bytes.h"

namespace ota {

class Sha256 {
 public:
  Sha256();
  void update(const void* data, size_t len);
  void update(const Bytes& data) { update(data.data(), data.size()); }
  Hash256 finish();  // 可调用多次，返回当前摘要的拷贝

  static Hash256 hash(const void* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.finish();
  }
  static Hash256 hash(const Bytes& data) { return hash(data.data(), data.size()); }

 private:
  void transform(const uint8_t block[64]);

  uint32_t state_[8];
  uint64_t bitlen_;
  uint8_t buffer_[64];
  size_t buffer_len_;
};

}  // namespace ota
