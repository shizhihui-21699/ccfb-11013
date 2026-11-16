#include "common/crypto.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace ota::crypto {

void init() {
  static const bool ready = [] {
    if (sodium_init() < 0) throw std::runtime_error("libsodium initialisation failed");
    return true;
  }();
  (void)ready;
}

struct Sha256::Impl {
  crypto_hash_sha256_state state{};
};

Sha256::Sha256() : impl_(new Impl()) {
  init();
  if (crypto_hash_sha256_init(&impl_->state) != 0) {
    delete impl_;
    throw std::runtime_error("sha256 init failed");
  }
}

Sha256::~Sha256() { delete impl_; }

void Sha256::update(std::span<const uint8_t> data) {
  if (data.empty()) return;
  if (crypto_hash_sha256_update(&impl_->state, data.data(), data.size()) != 0) {
    throw std::runtime_error("sha256 update failed");
  }
}

Digest Sha256::finish() {
  Digest out{};
  if (crypto_hash_sha256_final(&impl_->state, out.data()) != 0) {
    throw std::runtime_error("sha256 final failed");
  }
  return out;
}

Digest sha256(std::span<const uint8_t> data) {
  init();
  Digest out{};
  crypto_hash_sha256(out.data(), data.data(), data.size());
  return out;
}

std::vector<uint8_t> sha256_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot open " + path);
  Sha256 h;
  std::vector<uint8_t> buf(64 * 1024);
  while (in) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    std::streamsize n = in.gcount();
    if (n > 0) h.update(std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)));
  }
  Digest d = h.finish();
  return std::vector<uint8_t>(d.begin(), d.end());
}

void keypair_from_seed(const Seed& seed, PublicKey& pk, SecretKey& sk) {
  init();
  crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
}

Signature sign_detached(std::span<const uint8_t> message, const SecretKey& sk) {
  Signature sig{};
  if (crypto_sign_detached(sig.data(), nullptr, message.data(), message.size(), sk.data()) != 0) {
    throw std::runtime_error("ed25519 sign failed");
  }
  return sig;
}

bool verify_detached(const Signature& sig, std::span<const uint8_t> message,
                     const PublicKey& pk) {
  return crypto_sign_verify_detached(sig.data(), message.data(), message.size(), pk.data()) == 0;
}

std::array<uint8_t, kKeyIdSize> key_id(const PublicKey& pk) {
  Digest d = sha256(pk);
  std::array<uint8_t, kKeyIdSize> id{};
  std::memcpy(id.data(), d.data(), kKeyIdSize);
  return id;
}

bool constant_time_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) {
  if (a.size() != b.size()) return false;
  return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

int random_bytes(std::span<uint8_t> out) {
  init();
  randombytes_buf(out.data(), out.size());
  return 0;
}

std::string to_hex(std::span<const uint8_t> data) {
  static const char* kHex = "0123456789abcdef";
  std::string s;
  s.reserve(data.size() * 2);
  for (uint8_t b : data) {
    s.push_back(kHex[b >> 4]);
    s.push_back(kHex[b & 0x0f]);
  }
  return s;
}

bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
  if (hex.size() % 2 != 0) return false;
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = val(hex[i]), lo = val(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

}  // namespace ota::crypto
