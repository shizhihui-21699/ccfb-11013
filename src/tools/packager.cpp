// SPDX-License-Identifier: MIT
#include "packager.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#include "crc32.h"
#include "delta.h"
#include "package.h"
#include "sha256.h"

namespace ota {
namespace {

Bytes parse_hex(const std::string& text, size_t expected_bytes, const char* what) {
  std::string s;
  for (char c : text) {
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
    s.push_back(c);
  }
  if (s.size() != expected_bytes * 2) {
    fail(OtaError::kBadFormat, std::string(what) + " 必须是 " +
                                   std::to_string(expected_bytes) + " 字节的十六进制");
  }
  Bytes out(expected_bytes);
  for (size_t i = 0; i < expected_bytes; ++i) {
    auto v = [&](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      fail(OtaError::kBadFormat, std::string(what) + " 含非十六进制字符");
    };
    out[i] = static_cast<uint8_t>((v(s[2 * i]) << 4) | v(s[2 * i + 1]));
  }
  return out;
}

}  // namespace

std::string read_text_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail(OtaError::kIo, "无法读取文件 " + path);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

Bytes read_binary_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail(OtaError::kIo, "无法读取文件 " + path);
  return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void write_text_file(const std::string& path, const std::string& text) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail(OtaError::kIo, "无法写入文件 " + path);
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
  if (!out) fail(OtaError::kIo, "写入失败 " + path);
}

void write_binary_file(const std::string& path, const Bytes& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail(OtaError::kIo, "无法写入文件 " + path);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!out) fail(OtaError::kIo, "写入失败 " + path);
}

Ed25519SecretKey generate_keypair(const std::string& secret_path,
                                  const std::string& public_path) {
  // 种子来源：系统 CSPRNG。这里用 /dev/urandom，工具只在服务端运行。
  std::ifstream rng("/dev/urandom", std::ios::binary);
  if (!rng) fail(OtaError::kIo, "无法打开 /dev/urandom");
  std::array<uint8_t, 32> seed{};
  rng.read(reinterpret_cast<char*>(seed.data()), seed.size());
  if (rng.gcount() != static_cast<std::streamsize>(seed.size())) {
    fail(OtaError::kIo, "读取随机数失败");
  }
  Ed25519SecretKey sk = ed25519_keypair_from_seed(seed);
  write_text_file(secret_path, to_hex(sk.data(), sk.size()) + "\n");
  write_text_file(public_path, to_hex(sk.data() + 32, 32) + "\n");
  return sk;
}

Ed25519SecretKey load_secret_key(const std::string& path) {
  std::string text = read_text_file(path);
  Ed25519SecretKey sk{};
  if (text.size() >= 128) {
    Bytes raw = parse_hex(text.substr(0, 128), 64, "私钥");
    if (!ed25519_parse_secret(raw.data(), &sk)) {
      fail(OtaError::kBadFormat, "私钥尾部公钥与其种子不符");
    }
  } else {
    Bytes seed_bytes = parse_hex(text, 32, "私钥种子");
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), seed_bytes.data(), 32);
    sk = ed25519_keypair_from_seed(seed);
  }
  return sk;
}

Ed25519PublicKey load_public_key(const std::string& path) {
  Bytes raw = parse_hex(read_text_file(path), 32, "公钥");
  Ed25519PublicKey pk{};
  std::memcpy(pk.data(), raw.data(), 32);
  return pk;
}

KeyId key_id_for(const Ed25519PublicKey& pub) {
  KeyId id{};
  Hash256 h = Sha256::hash(pub.data(), pub.size());
  // key_id = SHA-256(pub)[0..16)，同时给出可读前缀。
  std::memcpy(id.data(), h.data(), id.size());
  return id;
}

Bytes build_package(const BuildRequest& req, const Ed25519SecretKey& signing_key) {
  PackageBuild b;
  b.header.type = req.mode == SigningMode::kFull ? PackageType::kFull : PackageType::kDelta;
  b.header.seq = req.seq;
  b.header.timestamp = req.timestamp;
  b.header.key_id = req.key_id;
  b.header.nonce = req.nonce;
  b.header.product = fixed_string<kProductSize>(req.product, "product");
  b.header.hardware = fixed_string<kHardwareSize>(req.hardware, "hardware");
  if (req.seq == 0) fail(OtaError::kBadFormat, "seq 必须从 1 开始（0 表示未设置）");

  b.manifest.image_version = req.version;
  b.manifest.build_id = req.build_id;
  b.manifest.rollback_floor = req.rollback_floor;
  b.manifest.notes = req.notes;

  if (req.mode == SigningMode::kFull) {
    if (req.image.empty()) fail(OtaError::kBadFormat, "完整包需要非空镜像");
    b.payload = req.image;
  } else {
    if (req.image.empty()) fail(OtaError::kBadFormat, "差分包需要目标镜像");
    if (req.base_image.empty()) fail(OtaError::kBadFormat, "差分包需要 base 镜像");
    b.payload = delta_create(req.base_image, req.image);
    Hash256 base_hash = Sha256::hash(req.base_image);
    b.manifest.base_hash.assign(base_hash.begin(), base_hash.end());
    b.manifest.base_seq = req.base_seq;
    Hash256 target_hash = Sha256::hash(req.image);
    b.manifest.target_image_hash.assign(target_hash.begin(), target_hash.end());
    b.manifest.target_image_size = req.image.size();
    b.manifest.has_target_size = true;
  }
  return b.finalize(signing_key);
}

std::string describe_package(const Bytes& package) {
  if (package.size() < kHeaderSize + kSignatureSize) {
    fail(OtaError::kBadFormat, "包小于最小尺寸");
  }
  PackageHeader h = PackageHeader::parse(package.data(), kHeaderSize);
  std::ostringstream s;
  s << "format: OTAP v" << h.format_version << "\n";
  s << "type: " << package_type_name(h.type) << "\n";
  s << "seq: " << h.seq << "\n";
  s << "timestamp: " << h.timestamp << "\n";
  s << "product: " << h.product_str() << "\n";
  s << "hardware: " << h.hardware_str() << "\n";
  s << "key_id: " << to_hex(h.key_id) << "\n";
  s << "nonce: " << to_hex(h.nonce.data(), h.nonce.size()) << "\n";
  s << "payload_len: " << h.payload_len << "\n";
  s << "manifest_len: " << h.manifest_len << "\n";
  s << "total_size: " << h.total_size() << "\n";
  s << "payload_sha256: " << to_hex(h.payload_hash) << "\n";
  if (package.size() >= h.payload_offset() && h.manifest_len > 0) {
    Manifest m = Manifest::parse(package.data() + kHeaderSize, h.manifest_len);
    s << "image_version: " << m.image_version << "\n";
    s << "build_id: " << m.build_id << "\n";
    if (m.rollback_floor) s << "rollback_floor: " << m.rollback_floor << "\n";
    if (!m.base_hash.empty()) s << "base_sha256: " << to_hex(m.base_hash.data(), 32) << "\n";
    if (!m.target_image_hash.empty()) {
      s << "target_sha256: " << to_hex(m.target_image_hash.data(), 32) << "\n";
      s << "target_size: " << m.target_image_size << "\n";
    }
    if (!m.notes.empty()) s << "notes: " << m.notes << "\n";
  }
  return s.str();
}

}  // namespace ota
