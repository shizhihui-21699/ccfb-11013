// Little-endian helpers plus small reader/writer utilities used by every
// serialized structure (package header, manifest, delta stream, flash records).
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ota {

inline void store_u16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}
inline void store_u32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}
inline void store_u64(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}

inline uint16_t load_u16(const uint8_t* p) {
  return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                               static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8));
}
inline uint32_t load_u32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t load_u64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) v = (v << 8) | static_cast<uint64_t>(p[i]);
  return v;
}

// Serializes into an existing vector; keeps offsets easy to reason about.
class Writer {
 public:
  explicit Writer(std::vector<uint8_t>& out) : out_(out) {}

  void u8(uint8_t v) { out_.push_back(v); }
  void u16(uint16_t v) {
    uint8_t b[2];
    store_u16(b, v);
    out_.insert(out_.end(), b, b + 2);
  }
  void u32(uint32_t v) {
    uint8_t b[4];
    store_u32(b, v);
    out_.insert(out_.end(), b, b + 4);
  }
  void u64(uint64_t v) {
    uint8_t b[8];
    store_u64(b, v);
    out_.insert(out_.end(), b, b + 8);
  }
  void bytes(std::span<const uint8_t> b) { out_.insert(out_.end(), b.begin(), b.end()); }
  void zeros(size_t n) { out_.insert(out_.end(), n, uint8_t{0}); }
  size_t size() const { return out_.size(); }

 private:
  std::vector<uint8_t>& out_;
};

// Bounds-checked reader. Every accessor returns 0 once the buffer is exhausted
// and ok() then reports false; callers check ok() in one place.
class Reader {
 public:
  explicit Reader(std::span<const uint8_t> d) : data_(d) {}

  bool ok() const { return ok_; }
  bool at_end() const { return ok_ && pos_ == data_.size(); }
  size_t remaining() const { return ok_ ? data_.size() - pos_ : 0; }
  const uint8_t* cursor() const { return data_.data() + pos_; }

  uint8_t u8() {
    if (!take(1)) return 0;
    return data_[pos_++];
  }
  uint16_t u16() {
    if (!take(2)) return 0;
    uint16_t v = load_u16(data_.data() + pos_);
    pos_ += 2;
    return v;
  }
  uint32_t u32() {
    if (!take(4)) return 0;
    uint32_t v = load_u32(data_.data() + pos_);
    pos_ += 4;
    return v;
  }
  uint64_t u64() {
    if (!take(8)) return 0;
    uint64_t v = load_u64(data_.data() + pos_);
    pos_ += 8;
    return v;
  }
  std::span<const uint8_t> bytes(size_t n) {
    if (!take(n)) return {};
    auto s = data_.subspan(pos_, n);
    pos_ += n;
    return s;
  }
  void skip(size_t n) {
    if (take(n)) pos_ += n;
  }

 private:
  bool take(size_t n) {
    if (!ok_) return false;
    if (n > data_.size() - pos_) {
      ok_ = false;
      return false;
    }
    return true;
  }

  std::span<const uint8_t> data_;
  size_t pos_ = 0;
  bool ok_ = true;
};

}  // namespace ota
