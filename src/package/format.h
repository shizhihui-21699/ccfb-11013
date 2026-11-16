// On-disk OTA package format (v1). This header is the single source of truth
// for byte layout; docs/package-format.md describes the same layout for humans.
//
//   +--------+-----------+----------+-----------+
//   | header |  manifest | payload  | signature |
//   | 512 B  |  variable | variable |   64 B    |
//   +--------+-----------+----------+-----------+
//
// The Ed25519 signature covers SHA-256("OTAP-SIG-v1" || manifest || image),
// where `image` is the *reconstructed target image*, not the payload. That
// choice matters: the device stores manifest + signature + image in the slot
// and can therefore re-verify the signature on every boot without keeping the
// original package. For a full package the payload is the image; for a delta
// package the payload is a delta stream whose output is checked against the
// signed image hash.
//
// The 512-byte header is an untrusted fast index: every value it shares with
// the signed manifest is cross-checked, so a package whose header disagrees
// with its manifest is rejected as malformed.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/crypto.h"
#include "common/status.h"

namespace ota::pkg {

constexpr uint32_t kFormatVersion = 1;
constexpr uint32_t kManifestFormat = 1;

constexpr size_t kHeaderSize = 512;
constexpr size_t kSignatureSize = 64;

constexpr std::array<uint8_t, 4> kHeaderMagic = {'O', 'T', 'A', 'P'};
constexpr std::array<uint8_t, 4> kManifestMagic = {'M', 'F', 'S', 'T'};
constexpr std::array<uint8_t, 4> kDeltaMagic = {'D', 'L', 'T', 'A'};

// Header/manifest flags.
constexpr uint32_t kFlagDelta = 1u << 0;

// Manifest entry types. v1 devices require exactly one firmware image entry.
constexpr uint16_t kEntryFirmware = 1;

// Device-side limit: the slot header sector must hold the whole manifest.
constexpr uint32_t kMaxSlotManifest = 2048;

struct Header {
  uint16_t format_version = kFormatVersion;
  uint32_t flags = 0;
  uint32_t manifest_format = kManifestFormat;
  uint64_t package_id = 0;
  uint64_t target_version = 0;
  uint64_t source_version = 0;
  uint64_t payload_size = 0;
  uint64_t target_image_size = 0;
  uint32_t manifest_size = 0;
  uint64_t build_time = 0;
  crypto::Digest target_image_sha256{};
  crypto::Digest source_image_sha256{};
  std::array<uint8_t, crypto::kKeyIdSize> key_id{};

  bool is_delta() const { return (flags & kFlagDelta) != 0; }
};

struct ImageEntry {
  uint16_t type = kEntryFirmware;
  uint16_t flags = 0;
  uint64_t payload_offset = 0;
  uint64_t payload_size = 0;
  uint64_t image_size = 0;
  crypto::Digest image_sha256{};
};

// The signed metadata block.
struct Manifest {
  uint64_t package_id = 0;
  uint64_t target_version = 0;
  uint64_t source_version = 0;
  uint64_t build_time = 0;
  uint32_t flags = 0;
  uint32_t image_flags = 0;
  uint32_t hw_min = 0;
  uint32_t hw_max = 0xFFFFFFFFu;
  // Hash of the image a delta applies to. All zero for full packages. This is
  // inside the signed block so an attacker cannot redirect a delta at another
  // source image (nor make the header disagree with the signature).
  crypto::Digest source_image_sha256{};
  std::string device_id;
  std::string builder;
  std::vector<ImageEntry> entries;
};

struct PackRequest {
  std::vector<uint8_t> image;  // full target image
  uint64_t target_version = 0;
  std::string device_id;
  uint32_t hw_min = 0;
  uint32_t hw_max = 0xFFFFFFFFu;
  uint64_t package_id = 0;
  uint64_t build_time = 0;
  std::string builder = "otapack/1";

  bool delta = false;
  std::vector<uint8_t> source_image;  // required when delta
  uint64_t source_version = 0;        // required when delta
};

// A parsed, structurally valid package. Byte spans point into the caller's
// buffer, which must outlive this object.
struct ParsedPackage {
  Header header;
  Manifest manifest;
  std::span<const uint8_t> manifest_bytes;
  std::span<const uint8_t> payload;
  crypto::Signature signature{};
};

std::vector<uint8_t> serialize_header(const Header& h);
std::vector<uint8_t> serialize_manifest(const Manifest& m);

// Parses a standalone manifest block (as stored in a slot header).
Result<Manifest> parse_manifest_bytes(std::span<const uint8_t> manifest);

// Re-checks the internal relations of a manifest against an image size
// (the manifest is self-contained; used when re-verifying a slot).
Status check_manifest_image(const Manifest& m, uint64_t image_size);

Result<Header> parse_header_only(std::span<const uint8_t> blob);

// Structure, cross-checks and full-package payload hashing. Does NOT check
// the signature (a delta package cannot be checked without its source image).
Result<ParsedPackage> parse_package(std::span<const uint8_t> blob);

// SHA-256 over the manifest and the reconstructed target image: the exact
// message Ed25519 signs. The device recomputes this from flash on every boot.
crypto::Digest image_digest(std::span<const uint8_t> manifest,
                            std::span<const uint8_t> image);

// Verifies the signature over (manifest, image) and that `image` hashes to the
// manifest's declared image hash. `pk` is the pinned trusted key.
Status verify_signature(const ParsedPackage& p, std::span<const uint8_t> image,
                        const crypto::PublicKey& pk);

// Full verification for packages whose target image is available in memory
// (always true for full packages).
Result<ParsedPackage> parse_and_verify(std::span<const uint8_t> blob,
                                       const crypto::PublicKey& pk);

// Builds a signed package and self-checks it before returning.
Result<std::vector<uint8_t>> build_package(const PackRequest& req,
                                           const crypto::SecretKey& sk,
                                           const crypto::PublicKey& pk);

Result<std::vector<uint8_t>> read_file(const std::string& path);
Status write_file(const std::string& path, std::span<const uint8_t> data);

}  // namespace ota::pkg
