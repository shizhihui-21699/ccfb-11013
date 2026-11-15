// SPDX-License-Identifier: MIT
// 测试用公共夹具：临时目录、密钥、镜像、设备初始化。
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

#include "bootctl.h"
#include "device.h"
#include "ed25519.h"
#include "flash.h"
#include "package.h"
#include "packager.h"
#include "sha256.h"

namespace testutil {

// 每个测试独占的临时目录，析构时递归删除。
class TempDir {
 public:
  TempDir() {
    char tmpl[] = "/tmp/ota-test-XXXXXX";
    const char* d = ::mkdtemp(tmpl);
    if (!d) throw std::runtime_error("mkdtemp 失败");
    path_ = d;
  }
  ~TempDir() {
    if (!path_.empty()) {
      std::string cmd = "rm -rf '" + path_ + "'";
      (void)std::system(cmd.c_str());
    }
  }
  std::string file(const std::string& name) const { return path_ + "/" + name; }
  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

struct Fixture {
  static constexpr uint64_t kSlotSize = 256 * 1024;
  static constexpr uint64_t kFlashSize = 1024 * 1024;

  ota::Ed25519SecretKey sk{};
  ota::Ed25519PublicKey pk{};
  ota::KeyId key_id{};
  std::string product = "dev-x";
  std::string hardware = "hw1";

  Fixture() {
    std::array<uint8_t, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i * 7 + 3);
    sk = ota::ed25519_keypair_from_seed(seed);
    std::memcpy(pk.data(), sk.data() + 32, pk.size());
    key_id = ota::key_id_for(pk);
  }

  ota::DeviceConfig config() const {
    ota::DeviceConfig cfg;
    cfg.product = product;
    cfg.hardware = hardware;
    cfg.public_key = pk;
    cfg.key_id = key_id;
    cfg.layout = ota::DeviceLayout::make(kFlashSize, kSlotSize);
    return cfg;
  }

  ota::BuildRequest request(const ota::Bytes& image, uint64_t seq,
                            const std::string& version) const {
    ota::BuildRequest r;
    r.image = image;
    r.seq = seq;
    r.product = product;
    r.hardware = hardware;
    r.version = version;
    r.build_id = "test-" + std::to_string(seq);
    r.key_id = key_id;
    r.timestamp = 1700000000 + seq;
    return r;
  }

  ota::Bytes full_package(const ota::Bytes& image, uint64_t seq,
                          const std::string& version) const {
    return ota::build_package(request(image, seq, version), sk);
  }

  ota::Bytes delta_package(const ota::Bytes& base, uint64_t base_seq, const ota::Bytes& target,
                           uint64_t seq, const std::string& version) const {
    ota::BuildRequest r = request(target, seq, version);
    r.mode = ota::SigningMode::kDelta;
    r.base_image = base;
    r.base_seq = base_seq;
    return ota::build_package(r, sk);
  }
};

// 确定性的“固件镜像”：大部分重复内容 + 局部差异，便于差分。
inline ota::Bytes make_image(size_t size, uint32_t seed) {
  ota::Bytes img(size);
  uint32_t x = seed ? seed : 1;
  for (size_t i = 0; i < size; ++i) {
    if (i % 97 == 0) {
      x ^= x << 13;
      x ^= x >> 17;
      x ^= x << 5;
    }
    img[i] = static_cast<uint8_t>((x + i) & 0xFF);
  }
  // 大段相同区域，让差分有东西可复制。
  for (size_t i = 0; i + 64 <= size; i += 512) {
    std::memset(img.data() + i, 0xA5, 64);
  }
  return img;
}

inline ota::Bytes mutate_slightly(const ota::Bytes& base, uint32_t tag) {
  ota::Bytes out = base;
  if (!out.empty()) {
    for (size_t i = 0; i < out.size(); i += 4096) {
      out[i] ^= static_cast<uint8_t>(tag + i);
    }
    out[out.size() / 2] ^= 0x5A;
  }
  return out;
}

inline ota::Bytes take(const ota::Bytes& b, size_t n) {
  return ota::Bytes(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
}

}  // namespace testutil
