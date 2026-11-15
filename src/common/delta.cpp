// SPDX-License-Identifier: MIT
#include "delta.h"

#include <cstring>
#include <unordered_map>

#include "package.h"
#include "sha256.h"

namespace ota {
namespace {

constexpr uint8_t kOpCopy = 1;
constexpr uint8_t kOpSeek = 2;
constexpr uint8_t kOpLiteral = 3;
constexpr uint8_t kOpEnd = 4;

void push_varint(Bytes* out, uint64_t v) {
  while (v >= 0x80) {
    out->push_back(static_cast<uint8_t>(v) | 0x80);
    v >>= 7;
  }
  out->push_back(static_cast<uint8_t>(v));
}

// 读取 varint，最多 10 字节；越界或过长返回 false。
bool read_varint(const uint8_t* data, size_t len, size_t* pos, uint64_t* out) {
  uint64_t v = 0;
  int shift = 0;
  while (true) {
    if (*pos >= len) return false;
    if (shift > 63) return false;
    uint8_t b = data[(*pos)++];
    v |= static_cast<uint64_t>(b & 0x7F) << shift;
    if ((b & 0x80) == 0) break;
    shift += 7;
  }
  *out = v;
  return true;
}

uint32_t rolling_hash(const uint8_t* p, size_t block) {
  // FNV-1a 变体后用乘法混淆，16 位截断。碰撞由逐字节 memcmp 兜底。
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < block; ++i) {
    h = (h ^ p[i]) * 16777619u;
  }
  return (h ^ (h >> 16)) & 0xFFFFu;
}

}  // namespace

Bytes delta_create(const Bytes& base, const Bytes& target, const DeltaOptions& opt) {
  if (base.size() > kMaxImageSize || target.size() > kMaxImageSize) {
    fail(OtaError::kUnsupported, "镜像超过差分上限");
  }
  if (opt.block_size < 4 || opt.block_size > 32) {
    fail(OtaError::kBadFormat, "block_size 需在 4..32");
  }
  if (target.empty()) fail(OtaError::kBadFormat, "target 不能为空");
  const size_t W = opt.block_size;

  // 建立 base 的块索引。同一哈希只保留最早位置，后续用线性探测向前扫描
  // 会漏掉部分匹配，但不会产出错误结果（应用端只校验结果）。
  std::unordered_map<uint32_t, std::vector<size_t>> index;
  if (base.size() >= W) {
    index.reserve(base.size() / 4 + 1);
    for (size_t i = 0; i + W <= base.size(); ++i) {
      index[rolling_hash(base.data() + i, W)].push_back(i);
    }
  }

  Bytes ops;
  std::vector<uint8_t> literal;
  auto flush_literal = [&]() {
    if (literal.empty()) return;
    ops.push_back(kOpLiteral);
    push_varint(&ops, literal.size());
    ops.insert(ops.end(), literal.begin(), literal.end());
    literal.clear();
  };

  size_t pos = 0;          // target 游标
  size_t base_cursor = 0;  // 设备端应用时的 base 读取游标（顺序语义）
  while (pos < target.size()) {
    bool matched = false;
    if (pos + W <= target.size() && !index.empty()) {
      auto it = index.find(rolling_hash(target.data() + pos, W));
      if (it != index.end()) {
        size_t best_len = 0;
        size_t best_off = 0;
        for (size_t candidate : it->second) {
          if (std::memcmp(base.data() + candidate, target.data() + pos, W) != 0) continue;
          size_t max_len = std::min(opt.max_copy, std::min(target.size() - pos,
                                                           base.size() - candidate));
          size_t l = W;
          while (l < max_len && base[candidate + l] == target[pos + l]) ++l;
          if (l > best_len) {
            best_len = l;
            best_off = candidate;
          }
          if (best_len == max_len) break;
        }
        // 只有当 COPY 指令（op+offset/len 变长）比字面量更省时才采用。
        size_t copy_cost = 1 + 10 + 10;
        if (best_len > 0 && best_len >= opt.min_copy_savings + copy_cost / 4) {
          // 命中但 base_cursor 已是 best_off，则无需 SEEK。
          if (base_cursor != best_off) {
            ops.push_back(kOpSeek);
            push_varint(&ops, best_off);
            base_cursor = best_off;
          }
          flush_literal();
          ops.push_back(kOpCopy);
          push_varint(&ops, best_len);
          pos += best_len;
          base_cursor += best_len;
          matched = true;
        }
      }
    }
    if (!matched) {
      literal.push_back(target[pos]);
      ++pos;
      if (literal.size() >= 65536) flush_literal();
    }
  }
  flush_literal();
  ops.push_back(kOpEnd);

  Bytes out(kDeltaHeaderSize, 0);
  std::memcpy(out.data(), kDeltaMagic, 4);
  put_u16(out.data() + 4, kFormatVersion);
  out[6] = 1;  // 操作码版本
  out[7] = static_cast<uint8_t>(W);
  put_u64(out.data() + 8, base.size());
  put_u64(out.data() + 16, target.size());
  out.insert(out.end(), ops.begin(), ops.end());
  return out;
}

Bytes delta_apply(const Bytes& base, const Bytes& patch, uint64_t expected_target_size,
                  const Bytes& expected_target_hash) {
  if (patch.size() < kDeltaHeaderSize) fail(OtaError::kBadDelta, "补丁过短");
  if (std::memcmp(patch.data(), kDeltaMagic, 4) != 0) fail(OtaError::kBadDelta, "补丁魔数错误");
  if (get_u16(patch.data() + 4) != kFormatVersion) fail(OtaError::kUnsupported, "补丁版本不支持");
  uint64_t base_size = get_u64(patch.data() + 8);
  uint64_t target_size = get_u64(patch.data() + 16);
  if (base_size != base.size()) fail(OtaError::kBaseMismatch, "补丁声明的 base 大小不符");
  if (target_size != expected_target_size) fail(OtaError::kBaseMismatch, "目标大小与清单不符");
  if (target_size > kMaxImageSize) fail(OtaError::kUnsupported, "目标镜像过大");

  Bytes out;
  out.reserve(static_cast<size_t>(target_size));
  size_t cursor = 0;  // base 读取游标
  size_t pos = kDeltaHeaderSize;
  bool ended = false;

  while (pos < patch.size()) {
    uint8_t op = patch[pos++];
    if (op == kOpEnd) {
      ended = true;
      break;
    }
    if (op == kOpCopy) {
      uint64_t n = 0;
      if (!read_varint(patch.data(), patch.size(), &pos, &n)) fail(OtaError::kBadDelta, "COPY 长度损坏");
      if (n == 0) fail(OtaError::kBadDelta, "COPY 长度为 0");
      if (n > base.size() || cursor > base.size() - n) fail(OtaError::kBadDelta, "COPY 越界");
      if (n > target_size - out.size()) fail(OtaError::kBadDelta, "COPY 超出目标大小");
      out.insert(out.end(), base.begin() + cursor, base.begin() + cursor + n);
      cursor += n;
    } else if (op == kOpSeek) {
      uint64_t off = 0;
      if (!read_varint(patch.data(), patch.size(), &pos, &off)) fail(OtaError::kBadDelta, "SEEK 偏移损坏");
      if (off > base.size()) fail(OtaError::kBadDelta, "SEEK 越界");
      cursor = static_cast<size_t>(off);
    } else if (op == kOpLiteral) {
      uint64_t n = 0;
      if (!read_varint(patch.data(), patch.size(), &pos, &n)) fail(OtaError::kBadDelta, "LITERAL 长度损坏");
      if (n > patch.size() - pos) fail(OtaError::kBadDelta, "LITERAL 数据被截断");
      if (n > target_size - out.size()) fail(OtaError::kBadDelta, "LITERAL 超出目标大小");
      out.insert(out.end(), patch.begin() + pos, patch.begin() + pos + n);
      pos += n;
    } else {
      fail(OtaError::kBadDelta, "未知补丁操作码 " + std::to_string(op));
    }
  }
  if (!ended) fail(OtaError::kBadDelta, "补丁缺少 END");
  if (pos != patch.size()) fail(OtaError::kBadDelta, "END 之后还有多余数据");
  if (out.size() != target_size) fail(OtaError::kBadDelta, "补丁输出大小与声明不符");

  if (!expected_target_hash.empty()) {
    if (expected_target_hash.size() != 32) fail(OtaError::kBadFormat, "目标哈希长度错误");
    Hash256 h = Sha256::hash(out);
    if (std::memcmp(h.data(), expected_target_hash.data(), 32) != 0) {
      fail(OtaError::kBadHash, "补丁输出镜像哈希与清单不符");
    }
  }
  return out;
}

}  // namespace ota
