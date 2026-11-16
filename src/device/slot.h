// A/B slot storage.
//
// Each slot = one header sector + N image sectors:
//
//   header sector:
//     0    magic "SLOT" | u32 header_format | u32 record_size | u32 state
//     16   u64 image_size | u64 generation | u64 installed_at | u32 flags | u32 reserved
//     48   manifest bytes (manifest_size)
//     ...  signature bytes (64)
//     ...  zeros to sector end - 4
//     sector end - 4: CRC-32 over everything before it
//   image sectors: the image bytes; the rest stays erased.
//
// The header stores the *signed* install record (manifest + signature), so the
// boot path can re-verify Ed25519 over (manifest, image) without the original
// package. The CRC only protects against torn writes; it is not a trust
// boundary. Trust comes from the signature check in verify_slot().
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "common/crypto.h"
#include "common/status.h"
#include "device/flash.h"
#include "device/layout.h"
#include "package/format.h"

namespace ota {

enum class SlotState : uint32_t {
  Empty = 0,
  Writing = 1,  // installation in progress; never booted
  Ready = 2,    // fully written and signature-verified at install time
  Bad = 3,      // known-invalid
};

struct SlotRecord {
  SlotState state = SlotState::Empty;
  uint64_t image_size = 0;
  uint64_t generation = 0;
  uint64_t installed_at = 0;
  uint32_t flags = 0;
  std::vector<uint8_t> manifest;
  crypto::Signature signature{};
};

// What verify_slot() returns on success: the parsed signed manifest and the
// size/version the caller needs.
struct VerifiedSlot {
  pkg::Manifest manifest;
  std::vector<uint8_t> manifest_bytes;
  crypto::Signature signature{};
  uint64_t image_size = 0;
  uint64_t generation = 0;
};

class SlotStore {
 public:
  SlotStore(Flash& flash, const Layout& layout);

  Result<std::optional<SlotRecord>> read_record(uint32_t slot) const;

  Result<std::vector<uint8_t>> read_image(uint32_t slot, uint64_t size) const;
  Status read_image_into(uint32_t slot, uint64_t size, std::span<uint8_t> out) const;

  // Full install: header(state=Writing) -> image chunks -> header(final state).
  Status write_slot(uint32_t slot, const SlotRecord& record, std::span<const uint8_t> image);
  Status write_record(uint32_t slot, const SlotRecord& record);

  // Streaming install used for deltas: erase both regions, stream image bytes,
  // then commit the record.
  Status erase_slot(uint32_t slot);
  Status program_image_chunk(uint32_t slot, uint64_t offset, std::span<const uint8_t> data);
  Status set_state(uint32_t slot, SlotState state);

  Status invalidate(uint32_t slot);

  uint64_t image_capacity(uint32_t slot) const;
  const SlotRegion& region(uint32_t slot) const;

  // Boot-time trust check: re-parses the stored manifest, re-hashes the image
  // from flash and verifies the Ed25519 signature with the pinned key.
  Result<VerifiedSlot> verify_slot(uint32_t slot, const crypto::PublicKey& pk) const;

  // Cheap check to decide whether a slot is worth verifying: a Ready record
  // with a well-formed, in-capacity image size.
  Result<std::optional<SlotRecord>> ready_record(uint32_t slot) const;

 private:
  Flash& flash_;
  const Layout& layout_;
};

}  // namespace ota
