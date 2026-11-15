// SPDX-License-Identifier: MIT
// OTAP 包格式（v1）：常量、序列化、解析与签名验证。
//
// 顶层布局：
//   [192 字节包头] [变长清单] [载荷] [64 字节签名]
// 签名位于包尾，覆盖 [0, signature_offset)，因此签名域不在被签内容内，
// 无需清零占位。包头定长 192 字节，设备可先读包头、验签，再流式
// 读取清单与载荷并同步校验 SHA-256。
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "bytes.h"
#include "ed25519.h"

namespace ota {

// ---------- 魔数与常量 ----------
constexpr uint8_t kMagic[4] = {'O', 'T', 'A', 'P'};
constexpr uint16_t kFormatVersion = 1;
constexpr uint16_t kHeaderSize = 192;
constexpr size_t kSignatureSize = 64;
constexpr size_t kMaxManifestSize = 4096;
constexpr size_t kMaxPayloadSize = 64u * 1024u * 1024u;
constexpr uint64_t kMaxImageSize = 64ull * 1024ull * 1024ull;
constexpr size_t kProductSize = 24;
constexpr size_t kHardwareSize = 16;
constexpr size_t kNonceSize = 16;

// 包头字段偏移（小端）。
namespace hdr {
constexpr size_t kMagic = 0;         // 4
constexpr size_t kFormat = 4;        // u16
constexpr size_t kType = 6;          // u8
constexpr size_t kFlags = 7;         // u8
constexpr size_t kHeaderLen = 8;     // u16
constexpr size_t kManifestLen = 10;  // u16
constexpr size_t kPayloadLen = 12;   // u32
constexpr size_t kSeq = 16;          // u64，安全版本号（单调计数器）
constexpr size_t kTimestamp = 24;    // u64，仅审计
constexpr size_t kProduct = 32;      // 24 字节定长 ASCII
constexpr size_t kHardware = 56;     // 16 字节定长 ASCII
constexpr size_t kKeyId = 72;        // 16
constexpr size_t kNonce = 88;        // 16
constexpr size_t kPayloadHash = 104; // 32
constexpr size_t kManifestCrc = 136; // u32
constexpr size_t kReserved = 140;    // 52 字节，全 0，解析时必须为 0
}  // namespace hdr

enum class PackageType : uint8_t {
  kFull = 0,   // 完整镜像
  kDelta = 1,  // 差分包（针对某个 base 镜像）
};

namespace flags {
constexpr uint8_t kInstallToInactive = 0x01;  // 必须安装到非活动槽
constexpr uint8_t kDelta = 0x02;              // 冗余标志，便于快速拒绝
constexpr uint8_t kKnownMask = kInstallToInactive | kDelta;
}  // namespace flags

const char* package_type_name(PackageType type);

// ---------- 清单（manifest） ----------
// 小型 TLV，避免在 MCU 上引入 JSON 解析器。
//   magic "MAN1" | u16 条目数 | 条目...
//   条目: u8 tag | u16 len | bytes
// 标签：
//   0x01 base_hash(32)        差分包：base 镜像 SHA-256
//   0x02 base_seq(u64)        差分包：base 的安全版本号
//   0x03 image_version(str)   人类可读版本
//   0x04 build_id(str)
//   0x05 rollback_floor(u64)  可选；安装后计数器至少抬到该值
//   0x06 notes(str)           可选
//   0x07 delta_patch_sha256(32) 差分包：patch 流 SHA-256
//   0x08 target_image_hash(32)  差分包：应用补丁后的整镜像 SHA-256（必填）
//   0x09 target_image_size(u64) 差分包：应用补丁后的整镜像大小（必填）
// 解析器拒绝重复标签、未知标签与截断数据。
struct Manifest {
  Bytes base_hash;           // 空或 32 字节
  uint64_t base_seq = 0;
  std::string image_version;
  std::string build_id;
  uint64_t rollback_floor = 0;
  std::string notes;
  Bytes delta_patch_sha256;  // 空或 32 字节
  Bytes target_image_hash;   // 空或 32 字节，差分包必填
  uint64_t target_image_size = 0;
  bool has_target_size = false;

  Bytes serialize() const;
  static Manifest parse(const uint8_t* data, size_t len);
};

// ---------- 包头 ----------
struct PackageHeader {
  uint16_t format_version = kFormatVersion;
  PackageType type = PackageType::kFull;
  uint8_t flags = 0;
  uint16_t manifest_len = 0;
  uint32_t payload_len = 0;
  uint64_t seq = 0;
  uint64_t timestamp = 0;
  std::array<char, kProductSize> product{};
  std::array<char, kHardwareSize> hardware{};
  KeyId key_id{};
  std::array<uint8_t, kNonceSize> nonce{};
  Hash256 payload_hash{};
  uint32_t manifest_crc32 = 0;

  Bytes serialize() const;
  static PackageHeader parse(const uint8_t* data, size_t len);

  std::string product_str() const { return from_fixed_string(product); }
  std::string hardware_str() const { return from_fixed_string(hardware); }

  uint64_t payload_offset() const { return uint64_t{kHeaderSize} + manifest_len; }
  uint64_t signature_offset() const { return payload_offset() + payload_len; }
  uint64_t total_size() const { return signature_offset() + kSignatureSize; }
};

// 解析并验证包。data 必须恰好包含 total_size() 字节（多出的字节报错）。
// 校验顺序：定界/魔数/版本/保留位 -> 清单 CRC -> 签名 -> 清单语义 -> 载荷哈希。
// 签名验证通过前，不信任除魔数、长度与 CRC 外的任何字段。
struct VerifiedPackage {
  PackageHeader header;
  Manifest manifest;
  Signature signature{};
};

VerifiedPackage verify_package(const Bytes& data, const Ed25519PublicKey& public_key,
                               const KeyId& expected_key_id);

// 与 verify_package 等价，但按 chunk_size 分块喂给流式 Ed25519 验签器。
// 这是在模拟设备上验证“单遍、常量内存”路径：验签不需要第二个整包缓冲。
// 若实现将来改为真正的边收边验，只需把这里的 data 换成回调/迭代器。
VerifiedPackage verify_package_streaming(const Bytes& data, const Ed25519PublicKey& public_key,
                                         const KeyId& expected_key_id,
                                         size_t chunk_size = 4096);

// 构建器（服务端工具用）。
struct PackageBuild {
  PackageHeader header;
  Manifest manifest;
  Bytes payload;
  Bytes finalize(const Ed25519SecretKey& signing_key);
};

}  // namespace ota
