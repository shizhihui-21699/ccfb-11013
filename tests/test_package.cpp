// SPDX-License-Identifier: MIT
// 密码学与序列化基础：SHA-2、CRC、Ed25519、包解析。
#include "crc32.h"
#include "ed25519.h"
#include "package.h"
#include "sha256.h"
#include "sha512.h"
#include "test_framework.h"
#include "test_util.h"

using namespace ota;
using testutil::Fixture;

static size_t pkg_manifest_hint(const Bytes& pkg) {
  return get_u16(pkg.data() + hdr::kManifestLen);
}

TEST_CASE(sha256_vectors) {
  CHECK_EQ(to_hex(Sha256::hash((const void*)"abc", 3)),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK_EQ(to_hex(Sha256::hash((const void*)"", 0)),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  // 分段更新必须与一次性哈希一致（跨块边界）。
  Bytes data = testutil::make_image(1000, 7);
  Sha256 streaming;
  streaming.update(data.data(), 1);
  streaming.update(data.data() + 1, 511);
  streaming.update(data.data() + 512, data.size() - 512);
  CHECK(streaming.finish() == Sha256::hash(data));
}

TEST_CASE(sha512_vectors) {
  CHECK_EQ(to_hex(Sha512::hash((const void*)"abc", 3)),
           std::string("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                       "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
  CHECK_EQ(to_hex(Sha512::hash((const void*)"", 0)),
           std::string("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                       "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
}

TEST_CASE(crc32_vector) {
  CHECK_EQ(Crc32::compute("123456789", 9), 0xCBF43926u);
}

TEST_CASE(ed25519_rfc8032) {
  Ed25519SecretKey sk{};
  const char* hexsk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  for (int i = 0; i < 32; ++i) {
    unsigned v = 0;
    std::sscanf(hexsk + 2 * i, "%2x", &v);
    sk[i] = static_cast<uint8_t>(v);
  }
  Ed25519PublicKey pk = ed25519_public_key(&sk);
  CHECK_EQ(to_hex(pk),
           std::string("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
  Signature sig;
  ed25519_sign(sk, nullptr, 0, &sig);
  CHECK(ed25519_verify(pk, nullptr, 0, sig));
  // 改动任意一位都不得通过。
  Signature bad = sig;
  bad[0] ^= 1;
  CHECK(!ed25519_verify(pk, nullptr, 0, bad));
  std::array<uint8_t, 1> msg = {0x42};
  CHECK(!ed25519_verify(pk, msg.data(), 1, sig));
}

TEST_CASE(package_roundtrip) {
  Fixture fx;
  Bytes image = testutil::make_image(9000, 11);
  Bytes pkg = fx.full_package(image, 5, "1.2.3");
  CHECK_EQ(pkg.size(), kHeaderSize + pkg_manifest_hint(pkg) + image.size() + kSignatureSize);
  VerifiedPackage vp = verify_package(pkg, fx.pk, fx.key_id);
  CHECK_EQ(vp.header.seq, 5u);
  CHECK_EQ(vp.manifest.image_version, std::string("1.2.3"));
  CHECK_EQ(vp.header.payload_hash, Sha256::hash(image));
}

TEST_CASE(package_rejects_tamper) {
  Fixture fx;
  Bytes image = testutil::make_image(4000, 3);
  Bytes pkg = fx.full_package(image, 2, "1.0.0");

  // 载荷任意一字节翻转。
  Bytes t = pkg;
  t[kHeaderSize + 200 + 100] ^= 0x01;
  CHECK_THROWS_CODE(verify_package(t, fx.pk, fx.key_id), OtaError::kBadSignature);

  // 包头 seq 被抬高（攻击者尝试伪造更高版本）。
  Bytes t2 = pkg;
  t2[hdr::kSeq] ^= 0x01;
  CHECK_THROWS_CODE(verify_package(t2, fx.pk, fx.key_id), OtaError::kBadSignature);

  // 签名本身被改。
  Bytes t3 = pkg;
  t3[t3.size() - 1] ^= 0x80;
  CHECK_THROWS_CODE(verify_package(t3, fx.pk, fx.key_id), OtaError::kBadSignature);

  // 截断。
  Bytes t4 = testutil::take(pkg, pkg.size() - 10);
  CHECK_THROWS_CODE(verify_package(t4, fx.pk, fx.key_id), OtaError::kBadFormat);

  // 追加垃圾。
  Bytes t5 = pkg;
  t5.push_back(0x00);
  CHECK_THROWS_CODE(verify_package(t5, fx.pk, fx.key_id), OtaError::kBadFormat);
}

TEST_CASE(package_rejects_wrong_key_and_keyid) {
  Fixture fx;
  Bytes image = testutil::make_image(2000, 4);
  Bytes pkg = fx.full_package(image, 1, "1.0.0");

  std::array<uint8_t, 32> other_seed{};
  other_seed.fill(0x99);
  Ed25519SecretKey other = ed25519_keypair_from_seed(other_seed);
  Ed25519PublicKey other_pk{};
  std::memcpy(other_pk.data(), other.data() + 32, 32);

  CHECK_THROWS_CODE(verify_package(pkg, other_pk, fx.key_id), OtaError::kBadSignature);

  KeyId wrong_id = fx.key_id;
  wrong_id[0] ^= 0xFF;
  CHECK_THROWS_CODE(verify_package(pkg, fx.pk, wrong_id), OtaError::kBadSignature);
}

TEST_CASE(streaming_verification_matches_one_shot) {
  Fixture fx;
  Bytes image = testutil::make_image(20000, 21);
  Bytes pkg = fx.full_package(image, 7, "3.0.0");

  for (size_t chunk : {size_t{1}, size_t{17}, size_t{4096}, size_t{100000}}) {
    VerifiedPackage vp = verify_package_streaming(pkg, fx.pk, fx.key_id, chunk);
    CHECK_EQ(vp.header.seq, 7u);
    CHECK_EQ(vp.manifest.image_version, std::string("3.0.0"));
  }

  // 篡改包在任意分块下都必须被拒。
  Bytes bad = pkg;
  bad[kHeaderSize + 500] ^= 0x10;
  for (size_t chunk : {size_t{1}, size_t{4096}}) {
    CHECK_THROWS_CODE(verify_package_streaming(bad, fx.pk, fx.key_id, chunk),
                      OtaError::kBadSignature);
  }
}

TEST_CASE(package_rejects_manifest_corruption) {
  Fixture fx;
  Bytes image = testutil::make_image(2000, 5);
  Bytes pkg = fx.full_package(image, 1, "1.0.0");
  // 破坏清单区首字节：CRC 先生效，报格式错误。
  Bytes t = pkg;
  t[kHeaderSize] ^= 0xFF;
  CHECK_THROWS_CODE(verify_package(t, fx.pk, fx.key_id), OtaError::kBadFormat);
}
