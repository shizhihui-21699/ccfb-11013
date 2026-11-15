// SPDX-License-Identifier: MIT
// Ed25519 签名/流式验签。
//
// 实现改编自 TweetNaCl（public domain，Bernstein/van Gastel/Janssen/Lange/
// Schwabe/Wilcox-O'Hearn）。设备端不依赖 OpenSSL，从而可以放进引导器。
//
// 为什么提供流式验签：本格式的签名覆盖“包头 + 清单 + 载荷”整个包体，
// 设备端不可能把几百 KB 的镜像读两遍。Ed25519 验签恰好只需一次
// SHA-512(R || A || M)，因此可以在读取载荷的同时增量计算，最后做两次
// 标量乘法和一次比较。签名则需两遍哈希（R 依赖第一遍结果），
// 但那只在服务端发生，整包本来就在内存里。
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "bytes.h"
#include "sha512.h"

namespace ota {

using Ed25519PublicKey = std::array<uint8_t, 32>;
using Ed25519SecretKey = std::array<uint8_t, 64>;  // seed(32) || public(32)

// 派生公钥：secret_key 的低 32 字节为 seed，高 32 字节会被覆盖为公钥。
Ed25519PublicKey ed25519_public_key(Ed25519SecretKey* secret_key);

Ed25519SecretKey ed25519_keypair_from_seed(const std::array<uint8_t, 32>& seed);

void ed25519_sign(const Ed25519SecretKey& secret_key, const uint8_t* msg, size_t len,
                  Signature* sig);

// 一次性验签。
bool ed25519_verify(const Ed25519PublicKey& public_key, const uint8_t* msg, size_t len,
                    const Signature& sig);

inline bool ed25519_verify(const Ed25519PublicKey& public_key, const Bytes& msg,
                           const Signature& sig) {
  return ed25519_verify(public_key, msg.data(), msg.size(), sig);
}

// 流式验签：init 后任意次 update，最后 finish。所有失败（含公钥/签名
// 格式错误）都只返回 false，不抛异常——不可信输入必须走返回值。
class Ed25519Verifier {
 public:
  Ed25519Verifier(const Ed25519PublicKey& public_key, const Signature& sig);
  void update(const void* data, size_t len);
  void update(const Bytes& data) { update(data.data(), data.size()); }
  bool finish();

 private:
  Ed25519PublicKey pk_{};
  Signature sig_{};
  Sha512 hash_;
  bool finished_ = false;
};

// 从 64 字节原始私钥（seed||pub）解析；若尾部公钥与 seed 不符则返回 false。
bool ed25519_parse_secret(const uint8_t raw[64], Ed25519SecretKey* out);

}  // namespace ota
