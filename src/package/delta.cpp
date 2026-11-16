#include "package/delta.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>

#include "common/bytes.h"

namespace ota::delta {
namespace {

constexpr size_t kBlock = 16;      // match granularity in the source index
constexpr size_t kMaxChain = 64;   // cap on candidate positions per block hash

}  // namespace

Result<Info> parse_header(std::span<const uint8_t> stream) {
  if (stream.size() < 24) return fail(Error::Malformed, "delta header truncated");
  if (std::memcmp(stream.data(), "DLTA", 4) != 0)
    return fail(Error::Malformed, "delta magic mismatch");
  Reader r(stream.subspan(4));
  Info info;
  info.source_size = 0;
  uint32_t version = r.u32();
  info.source_size = r.u64();
  info.target_size = r.u64();
  if (!r.ok()) return fail(Error::Malformed, "delta header truncated");
  if (version != kVersion)
    return fail(Error::UnsupportedVersion, "delta format " + std::to_string(version));
  return info;
}

Status apply(std::span<const uint8_t> stream, std::span<const uint8_t> source,
             uint64_t expected_target_size, const Sink& sink) {
  auto hdr = parse_header(stream);
  if (!hdr) return hdr.failure();
  if (hdr.value().target_size != expected_target_size)
    return fail(Error::SizeMismatch, "delta target size disagrees with package header");
  if (hdr.value().source_size != source.size())
    return fail(Error::DeltaSourceMismatch, "source size disagrees with delta header");

  Reader r(stream.subspan(24));
  uint64_t produced = 0;
  std::vector<uint8_t> carry;
  carry.reserve(64 * 1024);

  auto flush = [&]() -> Status {
    if (carry.empty()) return Status{};
    Status s = sink(std::span<const uint8_t>(carry));
    carry.clear();
    return s;
  };
  auto emit = [&](std::span<const uint8_t> b) -> Status {
    produced += b.size();
    if (produced > expected_target_size)
      return fail(Error::SizeMismatch, "delta produces more than the declared target size");
    carry.insert(carry.end(), b.begin(), b.end());
    if (carry.size() >= 64 * 1024) return flush();
    return Status{};
  };

  bool saw_end = false;
  while (r.ok()) {
    uint8_t op = r.u8();
    if (!r.ok()) break;
    if (op == kOpEnd) {
      saw_end = true;
      break;
    }
    if (op == kOpCopy) {
      uint64_t off = r.u64();
      uint64_t len = r.u64();
      if (!r.ok()) return fail(Error::Malformed, "truncated COPY op");
      if (off > source.size() || len > source.size() - off)
        return fail(Error::DeltaInvalid, "COPY range outside source image");
      if (len > expected_target_size - produced)
        return fail(Error::SizeMismatch, "COPY overruns target size");
      Status s = emit(source.subspan(static_cast<size_t>(off), static_cast<size_t>(len)));
      if (!s) return s;
    } else if (op == kOpData) {
      uint32_t len = r.u32();
      if (!r.ok()) return fail(Error::Malformed, "truncated DATA op");
      auto bytes = r.bytes(len);
      if (!r.ok()) return fail(Error::Malformed, "truncated DATA payload");
      Status s = emit(bytes);
      if (!s) return s;
    } else {
      return fail(Error::DeltaInvalid, "unknown delta op " + std::to_string(op));
    }
  }
  if (!r.ok()) return fail(Error::Malformed, "delta stream truncated");
  if (!saw_end) return fail(Error::Malformed, "delta stream missing END");
  if (produced != expected_target_size)
    return fail(Error::SizeMismatch, "delta produced " + std::to_string(produced) +
                                         " of " + std::to_string(expected_target_size) + " bytes");
  return flush();
}

Result<std::vector<uint8_t>> apply_to_buffer(std::span<const uint8_t> stream,
                                             std::span<const uint8_t> source,
                                             uint64_t expected_target_size) {
  if (expected_target_size > kMaxImagedBytes)
    return fail(Error::SizeMismatch,
                "declared target size exceeds the in-memory limit");
  std::vector<uint8_t> out;
  if (expected_target_size <= 64 * 1024 * 1024) {
    out.reserve(static_cast<size_t>(expected_target_size));
  }
  Status s = apply(stream, source, expected_target_size, [&](std::span<const uint8_t> b) {
    out.insert(out.end(), b.begin(), b.end());
    return Status{};
  });
  if (!s) return s.failure();
  return out;
}

std::vector<uint8_t> create(std::span<const uint8_t> source,
                            std::span<const uint8_t> target) {
  std::unordered_map<uint64_t, std::vector<uint32_t>> index;
  if (source.size() >= kBlock) {
    for (size_t pos = 0; pos + kBlock <= source.size(); ++pos) {
      uint64_t h = 1469598103934665603ull;  // FNV-1a over the block
      for (size_t i = 0; i < kBlock; ++i) {
        h ^= source[pos + i];
        h *= 1099511628211ull;
      }
      auto& chain = index[h];
      if (chain.size() < kMaxChain) chain.push_back(static_cast<uint32_t>(pos));
    }
  }

  std::vector<uint8_t> out;
  Writer w(out);
  w.bytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("DLTA"), 4));
  w.u32(kVersion);
  w.u64(source.size());
  w.u64(target.size());

  size_t data_start = 0;
  auto flush_data = [&](size_t end) {
    if (end <= data_start) return;
    w.u8(kOpData);
    w.u32(static_cast<uint32_t>(end - data_start));
    w.bytes(target.subspan(data_start, end - data_start));
    data_start = end;
  };

  size_t pos = 0;
  while (pos < target.size()) {
    uint64_t best_len = 0;
    uint32_t best_off = 0;
    if (pos + kBlock <= target.size()) {
      uint64_t h = 1469598103934665603ull;
      for (size_t i = 0; i < kBlock; ++i) {
        h ^= target[pos + i];
        h *= 1099511628211ull;
      }
      auto it = index.find(h);
      if (it != index.end()) {
        for (uint32_t cand : it->second) {
          size_t len = 0;
          while (pos + len < target.size() && cand + len < source.size() &&
                 target[pos + len] == source[cand + len] && len < (1u << 24)) {
            ++len;
          }
          if (len > best_len) {
            best_len = len;
            best_off = cand;
          }
        }
      }
    }
    if (best_len >= kBlock) {
      flush_data(pos);
      w.u8(kOpCopy);
      w.u64(best_off);
      w.u64(best_len);
      pos += best_len;
      data_start = pos;
    } else {
      ++pos;
    }
  }
  flush_data(target.size());
  w.u8(kOpEnd);
  return out;
}

}  // namespace ota::delta
