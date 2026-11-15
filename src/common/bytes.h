// SPDX-License-Identifier: MIT
// 基础字节工具：小端读写、十六进制、固定长度字段比较、异常类型。
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace ota {

using Bytes = std::vector<uint8_t>;
using Hash256 = std::array<uint8_t, 32>;
using Signature = std::array<uint8_t, 64>;
using KeyId = std::array<uint8_t, 16>;

// 升级流程中所有可预期的失败都以 OtaError 抛出；调用方（引导器/升级器）
// 捕获后转成状态码，绝不把半成品当作成功。
class OtaError : public std::runtime_error {
 public:
  enum Code {
    kBadFormat = 1,
    kBadSignature,
    kBadHash,
    kUnsupported,
    kProductMismatch,
    kHardwareMismatch,
    kAntiRollback,
    kNoSpace,
    kBadDelta,
    kBaseMismatch,
    kMetadata,
    kFlashRange,
    kFlashEraseRequired,
    kFlashBitViolation,
    kFlashProtected,
    kIo,
  };

  OtaError(Code code, const std::string& what) : std::runtime_error(what), code_(code) {}
  Code code() const noexcept { return code_; }

 private:
  Code code_;
};

[[noreturn]] inline void fail(OtaError::Code code, const std::string& msg) {
  throw OtaError(code, msg);
}

inline uint16_t get_u16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint32_t get_u32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t get_u64(const uint8_t* p) {
  return static_cast<uint64_t>(get_u32(p)) | (static_cast<uint64_t>(get_u32(p + 4)) << 32);
}
inline void put_u16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}
inline void put_u32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}
inline void put_u64(uint8_t* p, uint64_t v) {
  put_u32(p, static_cast<uint32_t>(v));
  put_u32(p + 4, static_cast<uint32_t>(v >> 32));
}

inline std::string to_hex(const uint8_t* data, size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string s;
  s.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    s[2 * i] = kHex[data[i] >> 4];
    s[2 * i + 1] = kHex[data[i] & 0x0F];
  }
  return s;
}
template <size_t N>
inline std::string to_hex(const std::array<uint8_t, N>& a) {
  return to_hex(a.data(), a.size());
}

inline bool is_zero(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (data[i] != 0) return false;
  }
  return true;
}
template <size_t N>
inline bool is_zero(const std::array<uint8_t, N>& a) {
  return is_zero(a.data(), a.size());
}

// 定长 ASCII 字段：以 NUL 填充，比较时只认完整相等（不做前缀匹配，
// 避免 "dev" 匹配到 "device"）。
template <size_t N>
inline std::array<char, N> fixed_string(const std::string& s, const char* field_name) {
  if (s.size() >= N) {
    fail(OtaError::kBadFormat, std::string(field_name) + " 过长（上限 " + std::to_string(N - 1) + " 字节）");
  }
  std::array<char, N> out{};
  std::memcpy(out.data(), s.data(), s.size());
  return out;
}

template <size_t N>
inline std::string from_fixed_string(const std::array<char, N>& a) {
  size_t n = 0;
  while (n < N && a[n] != '\0') ++n;
  return std::string(a.data(), n);
}

// 在 std::string 与 Hash256 之间转换，便于测试与工具代码书写。
inline Bytes to_bytes(const Hash256& h) { return Bytes(h.begin(), h.end()); }

inline Hash256 hash_from_hex(const std::string& hex, const char* what = "哈希") {
  if (hex.size() != 64) fail(OtaError::kBadFormat, std::string(what) + " 必须是 64 个十六进制字符");
  Hash256 h{};
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < 32; ++i) {
    int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) fail(OtaError::kBadFormat, std::string(what) + " 含非十六进制字符");
    h[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return h;
}

// 安全的整数加法/乘法：溢出时返回 false，解析不可信包时必须使用。
inline bool add_overflow(uint64_t a, uint64_t b, uint64_t* out) {
  if (a > UINT64_MAX - b) return false;
  *out = a + b;
  return true;
}
inline bool mul_overflow(uint64_t a, uint64_t b, uint64_t* out) {
  if (a != 0 && b > UINT64_MAX / a) return false;
  *out = a * b;
  return true;
}

}  // namespace ota
