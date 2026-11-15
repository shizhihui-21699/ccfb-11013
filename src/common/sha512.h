// SPDX-License-Identifier: MIT
// 自包含 SHA-512（FIPS 180-4），Ed25519 内部哈希使用。
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ota {

using Hash512 = std::array<uint8_t, 64>;

class Sha512 {
 public:
  Sha512();
  void update(const void* data, size_t len);
  Hash512 finish();

  static Hash512 hash(const void* data, size_t len) {
    Sha512 h;
    h.update(data, len);
    return h.finish();
  }

 private:
  void transform(const uint8_t block[128]);

  uint64_t state_[8];
  uint64_t bitlen_lo_;
  uint64_t bitlen_hi_;
  uint8_t buffer_[128];
  size_t buffer_len_;
};

}  // namespace ota
