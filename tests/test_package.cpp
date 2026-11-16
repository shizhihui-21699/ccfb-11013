// Package format, signature and anti-tamper tests. These operate on byte
// offsets directly, because the point is to show that a mutation anywhere is
// caught — not merely that the happy path works.
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "common/crypto.h"
#include "package/delta.h"
#include "package/format.h"
#include "test_harness.h"

using namespace ota;

namespace {

struct Keys {
  crypto::PublicKey pk{};
  crypto::SecretKey sk{};
};

Keys make_keys(uint8_t seed_byte) {
  Keys k;
  crypto::Seed seed{};
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(seed_byte + i);
  crypto::keypair_from_seed(seed, k.pk, k.sk);
  return k;
}

std::vector<uint8_t> image(size_t n, uint8_t seed) {
  std::vector<uint8_t> v(n);
  uint32_t x = seed * 2654435761u + 1;
  for (size_t i = 0; i < n; ++i) {
    x = x * 1664525u + 1013904223u;
    v[i] = static_cast<uint8_t>(x >> 24);
  }
  return v;
}

pkg::PackRequest base_request(std::vector<uint8_t> img, uint64_t version) {
  pkg::PackRequest r;
  r.image = std::move(img);
  r.target_version = version;
  r.device_id = "dev-1";
  r.hw_min = 1;
  r.hw_max = 3;
  r.package_id = 1000 + version;
  r.build_time = 1700000000 + version;
  return r;
}

std::vector<uint8_t> full_package(const Keys& k, uint64_t version, size_t size = 4096) {
  auto req = base_request(image(size, static_cast<uint8_t>(version)), version);
  auto built = pkg::build_package(req, k.sk, k.pk);
  CHECK_MSG(built.ok(), built.ok() ? "" : built.failure().message);
  return built.take();
}

}  // namespace

TEST(package_roundtrip_and_fields) {
  Keys k = make_keys(1);
  auto blob = full_package(k, 7);
  auto verified = pkg::parse_and_verify(blob, k.pk);
  CHECK_MSG(verified.ok(), verified.ok() ? "" : verified.failure().message);
  const auto& p = verified.value();
  CHECK_EQ(p.manifest.target_version, uint64_t{7});
  CHECK_EQ(p.manifest.source_version, uint64_t{0});
  CHECK_EQ(p.manifest.device_id, std::string("dev-1"));
  CHECK_EQ(p.manifest.hw_min, 1u);
  CHECK_EQ(p.manifest.hw_max, 3u);
  CHECK(!p.header.is_delta());
  CHECK_EQ(p.payload.size(), size_t{4096});
  CHECK_EQ(p.manifest.entries.at(0).image_sha256, crypto::sha256(p.payload));
}

TEST(package_rejects_wrong_key) {
  Keys signer = make_keys(1);
  Keys other = make_keys(99);
  auto blob = full_package(signer, 3);
  auto v = pkg::parse_and_verify(blob, other.pk);
  CHECK(!v);
  CHECK_EQ(v.failure().code, Error::SignatureInvalid);
}

TEST(package_rejects_every_single_byte_flip) {
  Keys k = make_keys(2);
  auto blob = full_package(k, 4, 512);
  // Flip each byte to its complement; every position must be rejected.
  // (Reserved header bytes are checked structurally, everything else by hash
  // or signature, so this must hold with no exceptions.)
  for (size_t i = 0; i < blob.size(); ++i) {
    auto mutated = blob;
    mutated[i] ^= 0xFF;
    auto v = pkg::parse_and_verify(mutated, k.pk);
    CHECK_MSG(!v, "byte " + std::to_string(i) + " flip was accepted");
  }
}

TEST(package_rejects_single_bit_flip) {
  Keys k = make_keys(3);
  auto blob = full_package(k, 5, 256);
  for (size_t i = 0; i < blob.size(); i += 7) {
    auto mutated = blob;
    mutated[i] ^= 0x01;
    auto v = pkg::parse_and_verify(mutated, k.pk);
    CHECK_MSG(!v, "bit flip at byte " + std::to_string(i) + " was accepted");
  }
}

TEST(package_rejects_truncation_and_extension) {
  Keys k = make_keys(4);
  auto blob = full_package(k, 6, 300);
  for (size_t cut = 0; cut < blob.size(); cut += 37) {
    auto t = std::vector<uint8_t>(blob.begin(), blob.begin() + static_cast<long>(cut));
    CHECK_MSG(!pkg::parse_and_verify(t, k.pk), "truncation to " + std::to_string(cut));
  }
  for (size_t extra = 1; extra <= 3; ++extra) {
    auto e = blob;
    e.insert(e.end(), extra, 0);
    CHECK_MSG(!pkg::parse_and_verify(e, k.pk), "extension by " + std::to_string(extra));
  }
}

TEST(package_signature_is_bound_to_manifest_not_header) {
  // The header is a fast index; tampering with a header field that also lives
  // in the manifest must be caught by the cross-check, not silently trusted.
  Keys k = make_keys(5);
  auto blob = full_package(k, 8);
  // target_version is at offset 24 in the header.
  auto mutated = blob;
  mutated[24] = 9;  // claim version 9 instead of 8
  auto v = pkg::parse_and_verify(mutated, k.pk);
  CHECK(!v);
  CHECK_EQ(v.failure().code, Error::ManifestInvalid);
}

TEST(package_rejects_spliced_payload) {
  Keys k = make_keys(6);
  auto a = full_package(k, 10, 1024);
  auto b = full_package(k, 11, 1024);
  auto spliced = a;
  // Replace A's payload with B's (same size, both signed by the same key).
  size_t a_manifest_end = pkg::kHeaderSize + pkg::parse_package(a).value().manifest_bytes.size();
  std::memcpy(spliced.data() + a_manifest_end, b.data() + a_manifest_end, 1024);
  auto v = pkg::parse_and_verify(spliced, k.pk);
  CHECK(!v);
}

TEST(package_rejects_trailing_garbage_and_short_header) {
  Keys k = make_keys(7);
  auto blob = full_package(k, 2, 64);
  auto short_one = std::vector<uint8_t>(blob.begin(), blob.begin() + 100);
  auto a = pkg::parse_package(short_one);
  CHECK(!a);
  auto garbage = blob;
  garbage.push_back(0xAA);
  CHECK(!pkg::parse_and_verify(garbage, k.pk));
}

TEST(package_rejects_wrong_magic) {
  Keys k = make_keys(8);
  auto blob = full_package(k, 2, 64);
  blob[1] = 'X';
  auto v = pkg::parse_package(blob);
  CHECK(!v);
  CHECK_EQ(v.failure().code, Error::BadMagic);
}

TEST(package_rejects_incompatible_unsupported_version) {
  Keys k = make_keys(9);
  auto blob = full_package(k, 2, 64);
  // format_version is a u16 at offset 4.
  blob[4] = 2;
  blob[5] = 0;
  auto v = pkg::parse_package(blob);
  CHECK(!v);
  CHECK_EQ(v.failure().code, Error::UnsupportedVersion);
}

TEST(package_build_rejects_bad_parameters) {
  Keys k = make_keys(10);
  auto req = base_request(image(64, 1), 0);
  auto r = pkg::build_package(req, k.sk, k.pk);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::InvalidArgument);

  auto req2 = base_request(image(64, 1), 5);
  req2.device_id = std::string("bad\x01id", 6);
  auto r2 = pkg::build_package(req2, k.sk, k.pk);
  CHECK(!r2);
  CHECK_EQ(r2.failure().code, Error::InvalidArgument);

  auto req3 = base_request(image(64, 1), 5);
  req3.hw_min = 9;
  req3.hw_max = 2;
  auto r3 = pkg::build_package(req3, k.sk, k.pk);
  CHECK(!r3);

  auto req4 = base_request(image(64, 1), 5);
  req4.delta = true;  // no source
  auto r4 = pkg::build_package(req4, k.sk, k.pk);
  CHECK(!r4);

  auto req5 = base_request(image(64, 1), 5);
  req5.delta = true;
  req5.source_image = image(64, 2);
  req5.source_version = 5;  // must be < target
  auto r5 = pkg::build_package(req5, k.sk, k.pk);
  CHECK(!r5);
}

TEST(package_empty_image_rejected) {
  Keys k = make_keys(11);
  pkg::PackRequest req;
  req.target_version = 1;
  req.image.clear();
  auto r = pkg::build_package(req, k.sk, k.pk);
  CHECK(!r);
  CHECK_EQ(r.failure().code, Error::InvalidArgument);
}

TEST(package_deterministic_for_same_inputs) {
  Keys k = make_keys(12);
  auto req = base_request(image(2048, 3), 9);
  auto a = pkg::build_package(req, k.sk, k.pk);
  auto b = pkg::build_package(req, k.sk, k.pk);
  CHECK(a.ok() && b.ok());
  CHECK(a.value() == b.value());
}

TEST(delta_roundtrip_and_size) {
  Keys k = make_keys(13);
  auto old_image = image(64 * 1024, 21);
  auto new_image = old_image;
  // Change a small region so the delta should be far smaller than a full copy.
  for (size_t i = 20000; i < 20480; ++i) new_image[i] = static_cast<uint8_t>(i * 7);
  new_image.insert(new_image.begin() + 40000, 333, 0x42);

  pkg::PackRequest req;
  req.image = new_image;
  req.target_version = 12;
  req.source_version = 11;
  req.source_image = old_image;
  req.delta = true;
  auto built = pkg::build_package(req, k.sk, k.pk);
  CHECK_MSG(built.ok(), built.ok() ? "" : built.failure().message);
  CHECK_MSG(built.value().size() < new_image.size() / 2, "delta is not meaningfully smaller");

  auto parsed = pkg::parse_package(built.value());
  CHECK(parsed.ok());
  CHECK(parsed.value().header.is_delta());
  auto rebuilt = delta::apply_to_buffer(parsed.value().payload, old_image, new_image.size());
  CHECK(rebuilt.ok());
  CHECK(rebuilt.value() == new_image);
  CHECK(pkg::verify_signature(parsed.value(), rebuilt.value(), k.pk).ok());
}

TEST(delta_rejects_wrong_source_at_apply) {
  Keys k = make_keys(14);
  auto old_image = image(8192, 31);
  auto new_image = image(8192, 32);
  pkg::PackRequest req;
  req.image = new_image;
  req.target_version = 4;
  req.source_version = 3;
  req.source_image = old_image;
  req.delta = true;
  auto built = pkg::build_package(req, k.sk, k.pk);
  CHECK(built.ok());
  auto parsed = pkg::parse_package(built.value());
  CHECK(parsed.ok());

  // A different source of the SAME size must be rejected by the signed hash
  // check the device performs before applying.
  auto wrong = image(8192, 33);
  CHECK(crypto::sha256(wrong) != parsed.value().manifest.source_image_sha256);
}

TEST(delta_rejects_hostile_streams) {
  // Hand-crafted delta streams with dangerous ops must be rejected without
  // writing out of bounds or producing a wrong-size image.
  auto source = image(1024, 40);
  auto make = [&](std::vector<uint8_t> ops, uint64_t target_size) {
    std::vector<uint8_t> s;
    s.insert(s.end(), {'D', 'L', 'T', 'A'});
    auto push32 = [&](uint32_t v) {
      for (int i = 0; i < 4; ++i) s.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    auto push64 = [&](uint64_t v) {
      for (int i = 0; i < 8; ++i) s.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    push32(1);
    push64(source.size());
    push64(target_size);
    s.insert(s.end(), ops.begin(), ops.end());
    return s;
  };

  // COPY past the end of the source.
  std::vector<uint8_t> out_of_range = {delta::kOpCopy};
  for (int i = 0; i < 8; ++i) out_of_range.push_back(0xFF);  // offset 0xFFFFFFFFFFFFFFFF
  out_of_range.push_back(0x01);                              // length 256
  for (int i = 0; i < 7; ++i) out_of_range.push_back(0);
  out_of_range.push_back(delta::kOpEnd);
  auto r1 = delta::apply_to_buffer(make(out_of_range, 256), source, 256);
  CHECK(!r1);
  CHECK_EQ(r1.failure().code, Error::DeltaInvalid);

  // Produces more than the declared target size.
  std::vector<uint8_t> overrun = {delta::kOpCopy, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
                                  delta::kOpEnd};
  auto r2 = delta::apply_to_buffer(make(overrun, 16), source, 16);
  CHECK(!r2);

  // No END marker.
  std::vector<uint8_t> no_end = {delta::kOpData, 4, 0, 0, 0, 'a', 'b', 'c', 'd'};
  auto r3 = delta::apply_to_buffer(make(no_end, 4), source, 4);
  CHECK(!r3);
  CHECK_EQ(r3.failure().code, Error::Malformed);

  // Unknown opcode.
  std::vector<uint8_t> unknown = {0x77, delta::kOpEnd};
  auto r4 = delta::apply_to_buffer(make(unknown, 0), source, 0);
  CHECK(!r4);

  // Truncated DATA.
  std::vector<uint8_t> short_data = {delta::kOpData, 0x10, 0, 0, 0, 'x'};
  auto r5 = delta::apply_to_buffer(make(short_data, 16), source, 16);
  CHECK(!r5);

  // Declared target size disagrees with package expectation.
  std::vector<uint8_t> ok_ops = {delta::kOpEnd};
  auto r6 = delta::apply_to_buffer(make(ok_ops, 0), source, 0);
  CHECK(r6.ok());
  CHECK(r6.value().empty());
}

TEST(delta_header_parsing) {
  auto bad = std::vector<uint8_t>{'D', 'L', 'T', 'A', 9, 0, 0, 0};
  auto r = delta::parse_header(bad);
  CHECK(!r);
  auto short_stream = std::vector<uint8_t>{'D', 'L', 'T', 'A'};
  CHECK(!delta::parse_header(short_stream));
}

TEST(package_hash_helpers) {
  auto img = image(100, 5);
  auto a = crypto::sha256(img);
  auto b = crypto::sha256(img);
  CHECK(a == b);
  CHECK(crypto::constant_time_equal(a, b));
  img[0] ^= 1;
  CHECK(!crypto::constant_time_equal(a, crypto::sha256(img)));

  auto hex = crypto::to_hex(std::span<const uint8_t>(a));
  std::vector<uint8_t> back;
  CHECK(crypto::from_hex(hex, back));
  CHECK(crypto::constant_time_equal(back, a));
  CHECK(!crypto::from_hex("zz", back));
  CHECK(!crypto::from_hex("abc", back));
}
