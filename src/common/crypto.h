// Thin wrapper over libsodium: SHA-256, Ed25519, and constant-time compare.
// Keeping every crypto primitive behind this header means the device module
// has exactly one dependency to audit, and tests can pin expected byte values.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ota::crypto {

using Digest = std::array<uint8_t, 32>;
using PublicKey = std::array<uint8_t, 32>;
using SecretKey = std::array<uint8_t, 64>;
using Seed = std::array<uint8_t, 32>;
using Signature = std::array<uint8_t, 64>;

constexpr size_t kKeyIdSize = 8;

// Must be called once (idempotent) before any other function.
void init();

Digest sha256(std::span<const uint8_t> data);
// Incremental variant for streaming large payloads.
class Sha256 {
 public:
  Sha256();
  ~Sha256();
  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;
  void update(std::span<const uint8_t> data);
  Digest finish();

 private:
  struct Impl;
  Impl* impl_;
};

std::vector<uint8_t> sha256_file(const std::string& path);

// Deterministic key generation from a 32-byte seed (so tests and dev tooling
// reproduce the same keys); production keys come from the seed file, never
// from firmware source.
void keypair_from_seed(const Seed& seed, PublicKey& pk, SecretKey& sk);

Signature sign_detached(std::span<const uint8_t> message, const SecretKey& sk);
bool verify_detached(const Signature& sig, std::span<const uint8_t> message,
                     const PublicKey& pk);

// Human/persistent identifier for a public key: first 8 bytes of its SHA-256.
std::array<uint8_t, kKeyIdSize> key_id(const PublicKey& pk);

bool constant_time_equal(std::span<const uint8_t> a, std::span<const uint8_t> b);

// Fills `out` from the OS CSPRNG. Returns 0 on success.
int random_bytes(std::span<uint8_t> out);

std::string to_hex(std::span<const uint8_t> data);
bool from_hex(const std::string& hex, std::vector<uint8_t>& out);

}  // namespace ota::crypto
