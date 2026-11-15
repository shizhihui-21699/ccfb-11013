// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>

#include "bytes.h"
#include "ed25519.h"

namespace ota {

// 生成密钥对并把原始私钥（seed||pub，64 字节）以十六进制文本写入；
// 公钥另存。返回私钥（尾部含公钥）。
Ed25519SecretKey generate_keypair(const std::string& secret_path,
                                  const std::string& public_path);

// 读取 64 字节十六进制私钥或 32 字节种子（64 字符 / 128 字符均可）。
Ed25519SecretKey load_secret_key(const std::string& path);
Ed25519PublicKey load_public_key(const std::string& path);
KeyId key_id_for(const Ed25519PublicKey& pub);

std::string read_text_file(const std::string& path);
Bytes read_binary_file(const std::string& path);
void write_text_file(const std::string& path, const std::string& text);
void write_binary_file(const std::string& path, const Bytes& data);

// 包类型 / 选项。
enum class SigningMode : uint8_t {
  kFull = 0,
  kDelta = 1,
};

struct BuildRequest {
  SigningMode mode = SigningMode::kFull;
  Bytes image;                 // 完整包：新镜像；差分包：目标镜像
  Bytes base_image;            // 差分包：旧镜像
  uint64_t seq = 0;
  uint64_t base_seq = 0;       // 差分包：base 镜像的安全版本号
  std::string product;
  std::string hardware;
  std::string version;
  std::string build_id;
  uint64_t rollback_floor = 0;
  std::string notes;
  uint64_t timestamp = 0;
  KeyId key_id{};
  std::array<uint8_t, 16> nonce{};
};

// 生成并返回包字节。
Bytes build_package(const BuildRequest& req, const Ed25519SecretKey& signing_key);

// 审计/调试：解析包头与清单（不验证签名，仅用于展示；签名验证用
// verify_package）。以人类可读形式返回。
std::string describe_package(const Bytes& package);

}  // namespace ota
