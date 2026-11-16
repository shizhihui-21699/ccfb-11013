#include "package/format.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>

#include "common/bytes.h"
#include "package/delta.h"

namespace ota::pkg {
namespace {

constexpr char kSigDomain[] = "OTAP-SIG-v1";
constexpr size_t kSigDomainLen = sizeof(kSigDomain) - 1;  // without trailing NUL

constexpr size_t kManifestFixed = 100;
constexpr size_t kEntrySize = 96;
constexpr size_t kMaxDeviceId = 96;
constexpr size_t kMaxBuilder = 128;

// Header field offsets, in one place so the serializer and parser cannot drift.
enum : size_t {
  kOffMagic = 0,
  kOffFormatVersion = 4,
  kOffHeaderSize = 6,
  kOffFlags = 8,
  kOffManifestFormat = 12,
  kOffPackageId = 16,
  kOffTargetVersion = 24,
  kOffSourceVersion = 32,
  kOffPayloadSize = 40,
  kOffTargetImageSize = 48,
  kOffManifestSize = 56,
  kOffReserved0 = 60,
  kOffBuildTime = 64,
  kOffTargetSha = 72,
  kOffSourceSha = 104,
  kOffKeyId = 136,
  kOffReserved1 = 144,
};

bool printable(std::span<const uint8_t> s) {
  for (uint8_t c : s)
    if (c < 0x20 || c > 0x7e) return false;
  return true;
}

}  // namespace

std::vector<uint8_t> serialize_header(const Header& h) {
  std::vector<uint8_t> out(kHeaderSize, 0);
  std::memcpy(out.data() + kOffMagic, kHeaderMagic.data(), kHeaderMagic.size());
  store_u16(out.data() + kOffFormatVersion, h.format_version);
  store_u16(out.data() + kOffHeaderSize, static_cast<uint16_t>(kHeaderSize));
  store_u32(out.data() + kOffFlags, h.flags);
  store_u32(out.data() + kOffManifestFormat, h.manifest_format);
  store_u64(out.data() + kOffPackageId, h.package_id);
  store_u64(out.data() + kOffTargetVersion, h.target_version);
  store_u64(out.data() + kOffSourceVersion, h.source_version);
  store_u64(out.data() + kOffPayloadSize, h.payload_size);
  store_u64(out.data() + kOffTargetImageSize, h.target_image_size);
  store_u32(out.data() + kOffManifestSize, h.manifest_size);
  store_u64(out.data() + kOffBuildTime, h.build_time);
  std::memcpy(out.data() + kOffTargetSha, h.target_image_sha256.data(), 32);
  std::memcpy(out.data() + kOffSourceSha, h.source_image_sha256.data(), 32);
  std::memcpy(out.data() + kOffKeyId, h.key_id.data(), crypto::kKeyIdSize);
  return out;
}

std::vector<uint8_t> serialize_manifest(const Manifest& m) {
  std::vector<uint8_t> out;
  Writer w(out);
  w.bytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("MFST"), 4));
  w.u32(kManifestFormat);
  w.u64(m.package_id);
  w.u64(m.target_version);
  w.u64(m.source_version);
  w.u64(m.build_time);
  w.u32(m.flags);
  w.u32(m.image_flags);
  w.u32(m.hw_min);
  w.u32(m.hw_max);
  w.u16(static_cast<uint16_t>(m.device_id.size()));
  w.u16(static_cast<uint16_t>(m.builder.size()));
  w.u32(static_cast<uint32_t>(m.entries.size()));
  w.u32(0);
  w.bytes(m.source_image_sha256);
  w.bytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m.device_id.data()),
                                   m.device_id.size()));
  w.bytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m.builder.data()),
                                   m.builder.size()));
  for (const auto& e : m.entries) {
    w.u16(e.type);
    w.u16(e.flags);
    w.u32(0);
    w.u64(e.payload_offset);
    w.u64(e.payload_size);
    w.u64(e.image_size);
    w.bytes(e.image_sha256);
    w.zeros(32);
  }
  return out;
}

crypto::Digest image_digest(std::span<const uint8_t> manifest,
                            std::span<const uint8_t> image) {
  crypto::Sha256 h;
  h.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kSigDomain), kSigDomainLen));
  const uint8_t sep = 0;
  h.update(std::span<const uint8_t>(&sep, 1));
  h.update(manifest);
  h.update(image);
  return h.finish();
}

Result<Header> parse_header_only(std::span<const uint8_t> blob) {
  if (blob.size() < kHeaderSize)
    return fail(Error::Malformed, "file shorter than 512-byte header");
  const uint8_t* p = blob.data();
  if (std::memcmp(p + kOffMagic, kHeaderMagic.data(), kHeaderMagic.size()) != 0)
    return fail(Error::BadMagic, "not an OTA package (magic mismatch)");
  Header h;
  h.format_version = load_u16(p + kOffFormatVersion);
  uint16_t header_size = load_u16(p + kOffHeaderSize);
  h.flags = load_u32(p + kOffFlags);
  h.manifest_format = load_u32(p + kOffManifestFormat);
  h.package_id = load_u64(p + kOffPackageId);
  h.target_version = load_u64(p + kOffTargetVersion);
  h.source_version = load_u64(p + kOffSourceVersion);
  h.payload_size = load_u64(p + kOffPayloadSize);
  h.target_image_size = load_u64(p + kOffTargetImageSize);
  h.manifest_size = load_u32(p + kOffManifestSize);
  h.build_time = load_u64(p + kOffBuildTime);
  std::memcpy(h.target_image_sha256.data(), p + kOffTargetSha, 32);
  std::memcpy(h.source_image_sha256.data(), p + kOffSourceSha, 32);
  std::memcpy(h.key_id.data(), p + kOffKeyId, crypto::kKeyIdSize);

  if (h.format_version != kFormatVersion)
    return fail(Error::UnsupportedVersion,
                "package format " + std::to_string(h.format_version) + " not supported");
  if (header_size != kHeaderSize) return fail(Error::Malformed, "header size field is not 512");
  if (h.manifest_format != kManifestFormat)
    return fail(Error::UnsupportedVersion, "manifest format not supported");
  if (h.flags & ~kFlagDelta) return fail(Error::Malformed, "unknown header flags");
  // Reserved regions must be zero; this keeps the header canonical.
  for (size_t i = kOffReserved0; i < kOffReserved0 + 4; ++i)
    if (p[i] != 0) return fail(Error::Malformed, "reserved header byte set");
  for (size_t i = kOffReserved1; i < kHeaderSize; ++i)
    if (p[i] != 0) return fail(Error::Malformed, "reserved header byte set");
  if (h.manifest_size < kManifestFixed || h.manifest_size > kMaxSlotManifest)
    return fail(Error::Malformed, "implausible manifest size");
  return h;
}

namespace {

Result<Manifest> parse_manifest(std::span<const uint8_t> m) {
  if (m.size() < kManifestFixed) return fail(Error::Malformed, "manifest truncated");
  if (std::memcmp(m.data(), "MFST", 4) != 0)
    return fail(Error::ManifestInvalid, "manifest magic mismatch");
  Reader r(m);
  r.skip(4);
  uint32_t fmt = r.u32();
  Manifest man;
  man.package_id = r.u64();
  man.target_version = r.u64();
  man.source_version = r.u64();
  man.build_time = r.u64();
  man.flags = r.u32();
  man.image_flags = r.u32();
  man.hw_min = r.u32();
  man.hw_max = r.u32();
  uint16_t device_len = r.u16();
  uint16_t builder_len = r.u16();
  uint32_t entry_count = r.u32();
  r.u32();  // reserved
  auto source_sha = r.bytes(32);
  if (!r.ok()) return fail(Error::Malformed, "manifest truncated");
  std::memcpy(man.source_image_sha256.data(), source_sha.data(), 32);
  if (fmt != kManifestFormat)
    return fail(Error::UnsupportedVersion, "manifest format " + std::to_string(fmt));
  if (man.flags & ~kFlagDelta) return fail(Error::ManifestInvalid, "unknown manifest flags");
  if (device_len > kMaxDeviceId) return fail(Error::ManifestInvalid, "device id too long");
  if (builder_len > kMaxBuilder) return fail(Error::ManifestInvalid, "builder string too long");
  if (entry_count != 1) return fail(Error::ManifestInvalid, "v1 packages carry exactly one image");
  if (man.hw_min > man.hw_max) return fail(Error::ManifestInvalid, "hw range inverted");
  if (man.target_version == 0) return fail(Error::ManifestInvalid, "target version is zero");
  bool delta = (man.flags & kFlagDelta) != 0;
  if (delta && man.source_version >= man.target_version)
    return fail(Error::ManifestInvalid, "delta must upgrade to a newer version");
  if (!delta && man.source_version != 0)
    return fail(Error::ManifestInvalid, "full package declares a source version");
  if (static_cast<uint64_t>(device_len) + builder_len + kEntrySize * entry_count !=
      m.size() - kManifestFixed)
    return fail(Error::ManifestInvalid, "manifest length does not match its fields");
  auto dev = r.bytes(device_len);
  auto bul = r.bytes(builder_len);
  if (!r.ok()) return fail(Error::Malformed, "manifest truncated");
  if (!printable(dev)) return fail(Error::ManifestInvalid, "device id not printable");
  if (!printable(bul)) return fail(Error::ManifestInvalid, "builder string not printable");
  man.device_id.assign(reinterpret_cast<const char*>(dev.data()), dev.size());
  man.builder.assign(reinterpret_cast<const char*>(bul.data()), bul.size());

  for (uint32_t i = 0; i < entry_count; ++i) {
    ImageEntry e;
    e.type = r.u16();
    e.flags = r.u16();
    r.u32();
    e.payload_offset = r.u64();
    e.payload_size = r.u64();
    e.image_size = r.u64();
    auto sha = r.bytes(32);
    auto res = r.bytes(32);
    if (!r.ok()) return fail(Error::Malformed, "manifest entry truncated");
    std::memcpy(e.image_sha256.data(), sha.data(), 32);
    for (uint8_t b : res)
      if (b != 0) return fail(Error::ManifestInvalid, "reserved entry byte set");
    if (e.type != kEntryFirmware)
      return fail(Error::ManifestInvalid, "unsupported image entry type");
    if (e.image_size == 0) return fail(Error::ManifestInvalid, "empty image");
    if (e.payload_offset != 0)
      return fail(Error::ManifestInvalid, "v1 payload must start at offset 0");
    man.entries.push_back(e);
  }
  if (!r.at_end()) return fail(Error::ManifestInvalid, "trailing bytes in manifest");
  return man;
}

// Header/manifest cross-checks. The header is untrusted, so any disagreement
// is a malformed package rather than a preference for one value.
Status cross_check(const Header& h, const Manifest& man, std::span<const uint8_t> manifest_bytes) {
  const ImageEntry& e = man.entries.at(0);
  if (h.package_id != man.package_id) return fail(Error::ManifestInvalid, "package id mismatch");
  if (h.target_version != man.target_version)
    return fail(Error::ManifestInvalid, "target version mismatch");
  if (h.source_version != man.source_version)
    return fail(Error::ManifestInvalid, "source version mismatch");
  if (h.flags != man.flags) return fail(Error::ManifestInvalid, "flags mismatch");
  if (h.build_time != man.build_time) return fail(Error::ManifestInvalid, "build time mismatch");
  if (h.manifest_size != manifest_bytes.size())
    return fail(Error::ManifestInvalid, "manifest size mismatch");
  if (e.payload_size != h.payload_size)
    return fail(Error::ManifestInvalid, "entry payload size disagrees with header");
  if (e.image_size != h.target_image_size)
    return fail(Error::ManifestInvalid, "entry image size disagrees with header");
  if (!crypto::constant_time_equal(e.image_sha256, h.target_image_sha256))
    return fail(Error::ManifestInvalid, "entry image hash disagrees with header");
  if (!crypto::constant_time_equal(man.source_image_sha256, h.source_image_sha256))
    return fail(Error::ManifestInvalid, "source image hash disagrees with header");
  bool delta = (man.flags & kFlagDelta) != 0;
  if (!delta && man.source_image_sha256 != crypto::Digest{})
    return fail(Error::ManifestInvalid, "full package declares a source image hash");
  return Status{};
}

}  // namespace

Result<Manifest> parse_manifest_bytes(std::span<const uint8_t> manifest) {
  return parse_manifest(manifest);
}

Status check_manifest_image(const Manifest& m, uint64_t image_size) {
  if (m.entries.size() != 1) return fail(Error::ManifestInvalid, "manifest must hold one image");
  if (m.entries[0].image_size != image_size)
    return fail(Error::ImageHashMismatch, "manifest image size disagrees with stored image");
  return Status{};
}

Result<ParsedPackage> parse_package(std::span<const uint8_t> blob) {
  auto hdr = parse_header_only(blob);
  if (!hdr) return hdr.failure();
  const Header& h = hdr.value();
  uint64_t manifest_end = static_cast<uint64_t>(kHeaderSize) + h.manifest_size;
  if (manifest_end > blob.size()) return fail(Error::Malformed, "manifest exceeds file");
  if (h.payload_size > blob.size()) return fail(Error::Malformed, "payload exceeds file");
  auto manifest_bytes = blob.subspan(kHeaderSize, h.manifest_size);
  auto payload = blob.subspan(static_cast<size_t>(manifest_end), static_cast<size_t>(h.payload_size));
  uint64_t expected = manifest_end + h.payload_size + kSignatureSize;
  if (expected != blob.size())
    return fail(Error::SizeMismatch,
                "file is " + std::to_string(blob.size()) + " bytes, layout implies " +
                    std::to_string(expected));
  auto man = parse_manifest(manifest_bytes);
  if (!man) return man.failure();
  Status s = cross_check(h, man.value(), manifest_bytes);
  if (!s) return s.failure();

  const ImageEntry& e = man.value().entries.at(0);
  if (!h.is_delta()) {
    if (h.payload_size != e.image_size)
      return fail(Error::SizeMismatch, "full package payload must equal the image");
    if (h.payload_size != h.target_image_size)
      return fail(Error::SizeMismatch, "full package payload must equal the image");
    auto d = crypto::sha256(payload);
    if (!crypto::constant_time_equal(d, e.image_sha256))
      return fail(Error::ImageHashMismatch, "payload does not hash to the declared image");
  } else {
    if (h.source_image_sha256 == crypto::Digest{})
      return fail(Error::ManifestInvalid, "delta package has no source image hash");
    auto info = delta::parse_header(payload);
    if (!info) return info.failure();
    if (info.value().target_size != e.image_size)
      return fail(Error::SizeMismatch, "delta target size disagrees with manifest");
    if (info.value().source_size == 0 || info.value().target_size == 0)
      return fail(Error::DeltaInvalid, "delta declares an empty image");
  }

  ParsedPackage out;
  out.header = h;
  out.manifest = man.take();
  out.manifest_bytes = manifest_bytes;
  out.payload = payload;
  std::memcpy(out.signature.data(), blob.data() + blob.size() - kSignatureSize, kSignatureSize);
  return out;
}

Status verify_signature(const ParsedPackage& p, std::span<const uint8_t> image,
                        const crypto::PublicKey& pk) {
  auto expected_key = crypto::key_id(pk);
  if (!crypto::constant_time_equal(p.header.key_id, expected_key))
    return fail(Error::SignatureInvalid, "package is signed by a different key");
  const ImageEntry& e = p.manifest.entries.at(0);
  if (image.size() != e.image_size)
    return fail(Error::SizeMismatch, "image size does not match signed manifest");
  auto actual = crypto::sha256(image);
  if (!crypto::constant_time_equal(actual, e.image_sha256))
    return fail(Error::ImageHashMismatch, "image does not hash to the signed value");
  auto digest = image_digest(p.manifest_bytes, image);
  if (!crypto::verify_detached(p.signature, std::span<const uint8_t>(digest.data(), digest.size()), pk))
    return fail(Error::SignatureInvalid, "Ed25519 signature verification failed");
  return Status{};
}

Result<ParsedPackage> parse_and_verify(std::span<const uint8_t> blob,
                                       const crypto::PublicKey& pk) {
  auto parsed = parse_package(blob);
  if (!parsed) return parsed.failure();
  if (parsed.value().header.is_delta())
    return fail(Error::InvalidArgument,
                "delta packages can only be verified after reconstruction");
  Status s = verify_signature(parsed.value(), parsed.value().payload, pk);
  if (!s) return s.failure();
  return parsed;
}

Result<std::vector<uint8_t>> build_package(const PackRequest& req,
                                           const crypto::SecretKey& sk,
                                           const crypto::PublicKey& pk) {
  crypto::init();
  if (req.image.empty()) return fail(Error::InvalidArgument, "target image is empty");
  if (req.target_version == 0) return fail(Error::InvalidArgument, "target version must be > 0");
  if (req.device_id.size() > kMaxDeviceId) return fail(Error::InvalidArgument, "device id too long");
  if (req.builder.size() > kMaxBuilder)
    return fail(Error::InvalidArgument, "builder string too long");
  if (req.hw_min > req.hw_max) return fail(Error::InvalidArgument, "hw range inverted");
  if (!printable(std::span<const uint8_t>(
          reinterpret_cast<const uint8_t*>(req.device_id.data()), req.device_id.size())))
    return fail(Error::InvalidArgument, "device id not printable");

  std::vector<uint8_t> payload;
  Manifest man;
  man.package_id = req.package_id;
  man.target_version = req.target_version;
  man.build_time = req.build_time;
  man.hw_min = req.hw_min;
  man.hw_max = req.hw_max;
  man.device_id = req.device_id;
  man.builder = req.builder;
  man.flags = req.delta ? kFlagDelta : 0;

  ImageEntry e;
  e.type = kEntryFirmware;
  e.image_size = req.image.size();
  e.image_sha256 = crypto::sha256(req.image);

  if (req.delta) {
    if (req.source_image.empty())
      return fail(Error::InvalidArgument, "delta package requires a source image");
    if (req.source_version == 0 || req.source_version >= req.target_version)
      return fail(Error::InvalidArgument, "delta source version must be older than target");
    payload = delta::create(req.source_image, req.image);
    man.source_version = req.source_version;
    man.source_image_sha256 = crypto::sha256(req.source_image);
  } else {
    payload = req.image;
  }
  e.payload_size = payload.size();
  man.entries.push_back(e);

  auto manifest = serialize_manifest(man);
  Header h;
  h.flags = man.flags;
  h.package_id = man.package_id;
  h.target_version = man.target_version;
  h.source_version = man.source_version;
  h.payload_size = payload.size();
  h.target_image_size = req.image.size();
  h.manifest_size = static_cast<uint32_t>(manifest.size());
  h.build_time = man.build_time;
  h.target_image_sha256 = e.image_sha256;
  h.source_image_sha256 = man.source_image_sha256;
  h.key_id = crypto::key_id(pk);
  auto header = serialize_header(h);

  auto digest = image_digest(manifest, req.image);
  auto sig = crypto::sign_detached(std::span<const uint8_t>(digest.data(), digest.size()), sk);

  std::vector<uint8_t> blob;
  blob.reserve(header.size() + manifest.size() + payload.size() + kSignatureSize);
  blob.insert(blob.end(), header.begin(), header.end());
  blob.insert(blob.end(), manifest.begin(), manifest.end());
  blob.insert(blob.end(), payload.begin(), payload.end());
  blob.insert(blob.end(), sig.begin(), sig.end());

  // Self-check: for a full package the payload is the image, so verify fully.
  if (!req.delta) {
    auto check = parse_and_verify(blob, pk);
    if (!check)
      return fail(check.failure().code, "self-verification failed: " + check.failure().message);
  } else {
    auto check = parse_package(blob);
    if (!check)
      return fail(check.failure().code, "self-verification failed: " + check.failure().message);
    auto rebuilt = delta::apply_to_buffer(check.value().payload, req.source_image, req.image.size());
    if (!rebuilt)
      return fail(Error::DeltaInvalid,
                  "self-verification failed: " + rebuilt.failure().message);
    Status s = verify_signature(check.value(), rebuilt.value(), pk);
    if (!s) return fail(s.code, "self-verification failed: " + s.message);
    if (!crypto::constant_time_equal(rebuilt.value(), req.image))
      return fail(Error::DeltaInvalid, "self-verification failed: reconstruction differs");
  }
  return blob;
}

Result<std::vector<uint8_t>> read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return fail(Error::NotFound, "cannot open " + path);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (in.bad()) return fail(Error::IoError, "error reading " + path);
  return data;
}

Status write_file(const std::string& path, std::span<const uint8_t> data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return fail(Error::IoError, "cannot create " + path);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  out.flush();
  if (!out) return fail(Error::IoError, "error writing " + path);
  return Status{};
}

}  // namespace ota::pkg
