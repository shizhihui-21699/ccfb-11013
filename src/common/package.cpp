// SPDX-License-Identifier: MIT
#include "package.h"

#include <algorithm>
#include <cstring>
#include <set>

#include "crc32.h"
#include "sha256.h"

namespace ota {
namespace {

constexpr uint8_t kManifestMagic[4] = {'M', 'A', 'N', '1'};
constexpr size_t kManifestHeaderSize = 16;  // magic + version + count + reserved

enum ManifestTag : uint8_t {
  kTagBaseHash = 0x01,
  kTagBaseSeq = 0x02,
  kTagImageVersion = 0x03,
  kTagBuildId = 0x04,
  kTagRollbackFloor = 0x05,
  kTagNotes = 0x06,
  kTagDeltaPatchHash = 0x07,
  kTagTargetImageHash = 0x08,
  kTagTargetImageSize = 0x09,
};

void require(bool cond, OtaError::Code code, const std::string& msg) {
  if (!cond) fail(code, msg);
}

}  // namespace

const char* package_type_name(PackageType type) {
  switch (type) {
    case PackageType::kFull:
      return "full";
    case PackageType::kDelta:
      return "delta";
  }
  return "unknown";
}

// ---------------- Manifest ----------------

Bytes Manifest::serialize() const {
  struct Item {
    uint8_t tag;
    Bytes data;
  };
  std::vector<Item> items;

  auto add_str = [&](uint8_t tag, const std::string& s) {
    if (!s.empty()) items.push_back({tag, Bytes(s.begin(), s.end())});
  };
  auto add_u64 = [&](uint8_t tag, uint64_t v) {
    Bytes b(8);
    put_u64(b.data(), v);
    items.push_back({tag, std::move(b)});
  };

  if (!base_hash.empty()) items.push_back({kTagBaseHash, base_hash});
  add_u64(kTagBaseSeq, base_seq);
  add_str(kTagImageVersion, image_version);
  add_str(kTagBuildId, build_id);
  if (rollback_floor != 0) add_u64(kTagRollbackFloor, rollback_floor);
  add_str(kTagNotes, notes);
  if (!delta_patch_sha256.empty()) items.push_back({kTagDeltaPatchHash, delta_patch_sha256});
  if (!target_image_hash.empty()) items.push_back({kTagTargetImageHash, target_image_hash});
  if (has_target_size) add_u64(kTagTargetImageSize, target_image_size);

  Bytes out(kManifestHeaderSize, 0);
  std::memcpy(out.data(), kManifestMagic, 4);
  put_u16(out.data() + 4, kFormatVersion);
  put_u16(out.data() + 6, static_cast<uint16_t>(items.size()));
  // 8..15 保留，必须为 0

  for (const auto& it : items) {
    require(it.data.size() <= 0xFFFF, OtaError::kBadFormat, "清单条目过长");
    size_t off = out.size();
    out.resize(off + 3 + it.data.size());
    out[off] = it.tag;
    put_u16(out.data() + off + 1, static_cast<uint16_t>(it.data.size()));
    std::memcpy(out.data() + off + 3, it.data.data(), it.data.size());
  }

  require(out.size() <= kMaxManifestSize, OtaError::kBadFormat, "清单超过上限");
  return out;
}

Manifest Manifest::parse(const uint8_t* data, size_t len) {
  require(len >= kManifestHeaderSize, OtaError::kBadFormat, "清单过短");
  require(std::memcmp(data, kManifestMagic, 4) == 0, OtaError::kBadFormat, "清单魔数错误");
  require(get_u16(data + 4) == kFormatVersion, OtaError::kUnsupported, "清单版本不支持");
  require(is_zero(data + 8, 8), OtaError::kBadFormat, "清单保留字节非零");
  uint16_t count = get_u16(data + 6);

  Manifest m;
  std::set<uint8_t> seen;
  size_t off = kManifestHeaderSize;
  for (uint16_t i = 0; i < count; ++i) {
    require(off + 3 <= len, OtaError::kBadFormat, "清单条目头被截断");
    uint8_t tag = data[off];
    uint16_t item_len = get_u16(data + off + 1);
    off += 3;
    require(off + item_len <= len, OtaError::kBadFormat, "清单条目被截断");
    require(seen.insert(tag).second, OtaError::kBadFormat, "清单出现重复标签");
    const uint8_t* p = data + off;

    switch (tag) {
      case kTagBaseHash:
        require(item_len == 32, OtaError::kBadFormat, "base_hash 长度错误");
        m.base_hash.assign(p, p + item_len);
        break;
      case kTagDeltaPatchHash:
        require(item_len == 32, OtaError::kBadFormat, "patch_hash 长度错误");
        m.delta_patch_sha256.assign(p, p + item_len);
        break;
      case kTagBaseSeq:
        require(item_len == 8, OtaError::kBadFormat, "base_seq 长度错误");
        m.base_seq = get_u64(p);
        break;
      case kTagRollbackFloor:
        require(item_len == 8, OtaError::kBadFormat, "rollback_floor 长度错误");
        m.rollback_floor = get_u64(p);
        break;
      case kTagTargetImageHash:
        require(item_len == 32, OtaError::kBadFormat, "target_image_hash 长度错误");
        m.target_image_hash.assign(p, p + item_len);
        break;
      case kTagTargetImageSize:
        require(item_len == 8, OtaError::kBadFormat, "target_image_size 长度错误");
        m.target_image_size = get_u64(p);
        m.has_target_size = true;
        break;
      case kTagImageVersion:
        require(item_len <= 64 && std::memchr(p, '\0', item_len) == nullptr,
                OtaError::kBadFormat, "image_version 非法");
        m.image_version.assign(reinterpret_cast<const char*>(p), item_len);
        break;
      case kTagBuildId:
        require(item_len <= 96 && std::memchr(p, '\0', item_len) == nullptr,
                OtaError::kBadFormat, "build_id 非法");
        m.build_id.assign(reinterpret_cast<const char*>(p), item_len);
        break;
      case kTagNotes:
        require(item_len <= 1024, OtaError::kBadFormat, "notes 过长");
        m.notes.assign(reinterpret_cast<const char*>(p), item_len);
        break;
      default:
        fail(OtaError::kBadFormat, "清单包含未知标签 " + std::to_string(tag));
    }
    off += item_len;
  }
  require(off == len, OtaError::kBadFormat, "清单尾部有多余字节");
  return m;
}

// ---------------- PackageHeader ----------------

Bytes PackageHeader::serialize() const {
  Bytes out(kHeaderSize, 0);
  std::memcpy(out.data() + hdr::kMagic, kMagic, 4);
  put_u16(out.data() + hdr::kFormat, format_version);
  out[hdr::kType] = static_cast<uint8_t>(type);
  out[hdr::kFlags] = flags;
  put_u16(out.data() + hdr::kHeaderLen, kHeaderSize);
  put_u16(out.data() + hdr::kManifestLen, manifest_len);
  put_u32(out.data() + hdr::kPayloadLen, payload_len);
  put_u64(out.data() + hdr::kSeq, seq);
  put_u64(out.data() + hdr::kTimestamp, timestamp);
  std::memcpy(out.data() + hdr::kProduct, product.data(), product.size());
  std::memcpy(out.data() + hdr::kHardware, hardware.data(), hardware.size());
  std::memcpy(out.data() + hdr::kKeyId, key_id.data(), key_id.size());
  std::memcpy(out.data() + hdr::kNonce, nonce.data(), nonce.size());
  std::memcpy(out.data() + hdr::kPayloadHash, payload_hash.data(), payload_hash.size());
  put_u32(out.data() + hdr::kManifestCrc, manifest_crc32);
  // 保留区保持 0
  return out;
}

PackageHeader PackageHeader::parse(const uint8_t* data, size_t len) {
  require(len >= kHeaderSize, OtaError::kBadFormat, "包头过短");
  require(std::memcmp(data, kMagic, 4) == 0, OtaError::kBadFormat, "魔数错误");
  uint16_t format = get_u16(data + hdr::kFormat);
  require(format == kFormatVersion, OtaError::kUnsupported,
          "包格式版本不支持：" + std::to_string(format));
  require(get_u16(data + hdr::kHeaderLen) == kHeaderSize, OtaError::kBadFormat,
          "header_len 不等于 192");
  require(is_zero(data + hdr::kReserved, kHeaderSize - hdr::kReserved),
          OtaError::kBadFormat, "包头保留区非零");
  require(std::memchr(data + hdr::kProduct, '\0', kProductSize) != nullptr,
          OtaError::kBadFormat, "product 未以 NUL 结尾");
  require(std::memchr(data + hdr::kHardware, '\0', kHardwareSize) != nullptr,
          OtaError::kBadFormat, "hardware 未以 NUL 结尾");

  PackageHeader h;
  h.format_version = format;
  uint8_t type = data[hdr::kType];
  require(type <= static_cast<uint8_t>(PackageType::kDelta), OtaError::kUnsupported,
          "未知包类型 " + std::to_string(type));
  h.type = static_cast<PackageType>(type);
  h.flags = data[hdr::kFlags];
  require((h.flags & ~flags::kKnownMask) == 0, OtaError::kUnsupported,
          "包头含未知 flags");
  require(((h.flags & flags::kDelta) != 0) == (h.type == PackageType::kDelta),
          OtaError::kBadFormat, "delta 标志与包类型不一致");
  h.manifest_len = get_u16(data + hdr::kManifestLen);
  h.payload_len = get_u32(data + hdr::kPayloadLen);
  require(h.manifest_len <= kMaxManifestSize, OtaError::kBadFormat, "清单长度超限");
  require(h.payload_len <= kMaxPayloadSize, OtaError::kBadFormat, "载荷长度超限");
  h.seq = get_u64(data + hdr::kSeq);
  h.timestamp = get_u64(data + hdr::kTimestamp);
  std::memcpy(h.product.data(), data + hdr::kProduct, kProductSize);
  std::memcpy(h.hardware.data(), data + hdr::kHardware, kHardwareSize);
  std::memcpy(h.key_id.data(), data + hdr::kKeyId, h.key_id.size());
  std::memcpy(h.nonce.data(), data + hdr::kNonce, kNonceSize);
  std::memcpy(h.payload_hash.data(), data + hdr::kPayloadHash, h.payload_hash.size());
  h.manifest_crc32 = get_u32(data + hdr::kManifestCrc);
  return h;
}

// ---------------- 验证与构建 ----------------

namespace {

// 唯一的验证实现。chunk_size 控制把被签内容喂给流式 Ed25519 验签器的
// 粒度；1 表示逐字节，极大值表示一次性。两者走完全相同的检查顺序。
VerifiedPackage verify_impl(const Bytes& data, const Ed25519PublicKey& public_key,
                            const KeyId& expected_key_id, size_t chunk_size) {
  require(chunk_size > 0, OtaError::kBadFormat, "chunk_size 必须 > 0");
  require(data.size() >= kHeaderSize + kSignatureSize, OtaError::kBadFormat,
          "包小于最小尺寸");
  PackageHeader h = PackageHeader::parse(data.data(), kHeaderSize);
  require(h.total_size() == data.size(), OtaError::kBadFormat,
          "包长度与包头声明不符（声明 " + std::to_string(h.total_size()) + "，实际 " +
              std::to_string(data.size()) + "）");
  require(h.key_id == expected_key_id, OtaError::kBadSignature,
          "key_id 不匹配（可能使用了未授权密钥）");

  const uint8_t* manifest_bytes = data.data() + kHeaderSize;
  require(Crc32::compute(manifest_bytes, h.manifest_len) == h.manifest_crc32,
          OtaError::kBadFormat, "清单 CRC 校验失败");

  uint64_t signed_len = h.signature_offset();
  Signature sig{};
  std::memcpy(sig.data(), data.data() + signed_len, kSignatureSize);

  // 签名覆盖包头、清单与载荷。验签通过前，除魔数/长度/CRC 外一律不信任。
  Ed25519Verifier verifier(public_key, sig);
  for (uint64_t off = 0; off < signed_len;) {
    size_t n = static_cast<size_t>(std::min<uint64_t>(chunk_size, signed_len - off));
    verifier.update(data.data() + off, n);
    off += n;
  }
  require(verifier.finish(), OtaError::kBadSignature, "Ed25519 签名无效");

  // 到此为止包内的字段才可信。解析清单并交叉校验。
  Manifest m = Manifest::parse(manifest_bytes, h.manifest_len);
  const uint8_t* payload = data.data() + h.payload_offset();
  if (h.type == PackageType::kFull) {
    require(m.base_hash.empty() && m.base_seq == 0 && m.delta_patch_sha256.empty(),
            OtaError::kBadFormat, "完整包不应携带差分基准字段");
  } else {
    require(m.base_hash.size() == 32, OtaError::kBadFormat, "差分包缺少 base_hash");
    require(!m.delta_patch_sha256.empty(), OtaError::kBadFormat, "差分包缺少 patch 哈希");
    require(m.target_image_hash.size() == 32 && m.has_target_size,
            OtaError::kBadFormat, "差分包缺少目标镜像哈希/大小");
    require(m.target_image_size > 0 && m.target_image_size <= kMaxImageSize,
            OtaError::kBadFormat, "目标镜像大小非法");
    require(h.payload_len > 0, OtaError::kBadFormat, "差分包载荷为空");
    Hash256 patch_hash = Sha256::hash(payload, h.payload_len);
    require(std::memcmp(patch_hash.data(), m.delta_patch_sha256.data(), 32) == 0,
            OtaError::kBadHash, "patch 流哈希不匹配");
  }
  require(Sha256::hash(payload, h.payload_len) == h.payload_hash, OtaError::kBadHash,
          "载荷 SHA-256 不匹配");

  VerifiedPackage out;
  out.header = h;
  out.manifest = std::move(m);
  out.signature = sig;
  return out;
}

}  // namespace

VerifiedPackage verify_package(const Bytes& data, const Ed25519PublicKey& public_key,
                               const KeyId& expected_key_id) {
  return verify_impl(data, public_key, expected_key_id, data.size() + 1);
}

VerifiedPackage verify_package_streaming(const Bytes& data, const Ed25519PublicKey& public_key,
                                         const KeyId& expected_key_id, size_t chunk_size) {
  return verify_impl(data, public_key, expected_key_id, chunk_size);
}

Bytes PackageBuild::finalize(const Ed25519SecretKey& signing_key) {
  require(header.type == PackageType::kFull || header.type == PackageType::kDelta,
          OtaError::kBadFormat, "包类型非法");
  header.format_version = kFormatVersion;
  header.flags = static_cast<uint8_t>((header.type == PackageType::kDelta) ? flags::kDelta : 0);
  if (header.payload_len == 0) header.payload_len = static_cast<uint32_t>(payload.size());
  require(header.payload_len == payload.size(), OtaError::kBadFormat,
          "payload_len 与实际载荷长度不一致");
  require(header.payload_len > 0, OtaError::kBadFormat, "载荷不能为空");

  header.payload_hash = Sha256::hash(payload);
  if (header.type == PackageType::kDelta) {
    // 补丁流哈希恒等于载荷哈希；构建器若已填写必须一致。
    if (!manifest.delta_patch_sha256.empty()) {
      require(manifest.delta_patch_sha256.size() == 32, OtaError::kBadFormat,
              "patch 哈希长度错误");
      require(std::memcmp(manifest.delta_patch_sha256.data(), header.payload_hash.data(),
                          32) == 0,
              OtaError::kBadHash, "patch 流哈希与载荷不符");
    }
    manifest.delta_patch_sha256.assign(header.payload_hash.begin(), header.payload_hash.end());
  }

  Bytes manifest_bytes = manifest.serialize();
  header.manifest_len = static_cast<uint16_t>(manifest_bytes.size());
  header.manifest_crc32 = Crc32::compute(manifest_bytes.data(), manifest_bytes.size());

  Bytes out = header.serialize();
  out.insert(out.end(), manifest_bytes.begin(), manifest_bytes.end());
  out.insert(out.end(), payload.begin(), payload.end());

  Signature sig;
  ed25519_sign(signing_key, out.data(), out.size(), &sig);
  out.insert(out.end(), sig.begin(), sig.end());
  return out;
}

}  // namespace ota
