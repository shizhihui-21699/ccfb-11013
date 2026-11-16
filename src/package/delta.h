// Delta encoding (format DLTA v1).
//
// A delta is a linear sequence of operations over the *source* image that
// reconstructs the target image:
//
//   header: magic "DLTA" | u32 version | u64 source_size | u64 target_size
//   ops:    op verb, streamed until END
//     COPY (0x01): u64 source_offset | u64 length
//     DATA (0x02): u32 length | length bytes
//     END  (0xFF)
//
// Every COPY range is bounds-checked against the source, every op against the
// declared target size, and the completed reconstruction must be exactly
// target_size bytes. The caller then checks the SHA-256, which is bound into
// the signed package. A hostile delta can therefore neither read outside the
// source nor produce an image that is not the signed target.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include "common/status.h"

namespace ota::delta {

constexpr uint32_t kVersion = 1;
constexpr uint8_t kOpCopy = 0x01;
constexpr uint8_t kOpData = 0x02;
constexpr uint8_t kOpEnd = 0xFF;

// Upper bound on a reconstructed image for in-memory application. The device
// streams instead (bounded by slot capacity); this protects host tools from a
// hostile package that declares an enormous target size.
constexpr uint64_t kMaxImagedBytes = 1ull << 30;  // 1 GiB

struct Info {
  uint64_t source_size = 0;
  uint64_t target_size = 0;
};

// Sink receives reconstructed bytes in order and may fail (used by the device
// module to program flash as the image is produced).
using Sink = std::function<Status(std::span<const uint8_t>)>;

Result<Info> parse_header(std::span<const uint8_t> stream);

// Applies a delta to `source`, streaming output into `sink`, and requires the
// reconstruction to be exactly `expected_target_size` bytes.
Status apply(std::span<const uint8_t> stream, std::span<const uint8_t> source,
             uint64_t expected_target_size, const Sink& sink);

// Convenience wrapper that collects the result in memory.
Result<std::vector<uint8_t>> apply_to_buffer(std::span<const uint8_t> stream,
                                             std::span<const uint8_t> source,
                                             uint64_t expected_target_size);

// Produces a delta from `source` to `target`. Deterministic.
std::vector<uint8_t> create(std::span<const uint8_t> source,
                            std::span<const uint8_t> target);

}  // namespace ota::delta
