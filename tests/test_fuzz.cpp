// SPDX-License-Identifier: MIT
// 确定性变异测试：对解析器喂入大量畸形输入，要求
//   * 绝不崩溃 / 越界（配合 ASan 运行）；
//   * 绝不把被篡改的合法包当成有效包接受。
// 这是轻量版的 fuzz：种子固定，结果可复现，适合放进 CI。
#include <random>

#include "bootctl.h"
#include "delta.h"
#include "package.h"
#include "sha256.h"
#include "test_framework.h"
#include "test_util.h"

using namespace ota;
using testutil::Fixture;

namespace {

struct Rng {
  std::mt19937 engine{0x0AF00D};
  uint8_t byte() { return static_cast<uint8_t>(engine() & 0xFF); }
  size_t below(size_t n) { return n == 0 ? 0 : static_cast<size_t>(engine() % n); }
};

}  // namespace

TEST_CASE(fuzz_mutated_packages_never_verify) {
  Fixture fx;
  Bytes payload = testutil::make_image(700, 0x11);
  Bytes good = fx.full_package(payload, 3, "1.0.0");

  Rng rng;
  int rejected = 0;
  for (int iter = 0; iter < 1500; ++iter) {
    Bytes m = good;
    switch (iter % 4) {
      case 0:
        m.assign(rng.below(900), 0);
        for (auto& c : m) c = rng.byte();
        break;
      case 1: {
        size_t pos = rng.below(m.size());
        m[pos] = static_cast<uint8_t>(m[pos] ^ (1u << (rng.below(8))));
        break;
      }
      case 2:
        m.resize(rng.below(m.size()));
        break;
      default: {
        const size_t fields[] = {hdr::kFormat, hdr::kType, hdr::kFlags, hdr::kManifestLen,
                                 hdr::kPayloadLen, hdr::kSeq};
        size_t pos = fields[rng.below(6)];
        uint8_t v = rng.byte();
        if (v == m[pos]) v = static_cast<uint8_t>(v ^ 0xFF);
        m[pos] = v;
        break;
      }
    }
    bool accepted = false;
    try {
      verify_package(m, fx.pk, fx.key_id);
      accepted = true;
    } catch (const OtaError&) {
    }
    CHECK(!accepted);
    ++rejected;
  }
  CHECK_EQ(rejected, 1500);
}

TEST_CASE(fuzz_garbage_manifest_never_parses_silently) {
  Rng rng;
  for (int iter = 0; iter < 2000; ++iter) {
    Bytes m(rng.below(200));
    for (auto& c : m) c = rng.byte();
    if (m.size() >= 16 && iter % 3 == 0) {
      m[0] = 'M';
      m[1] = 'A';
      m[2] = 'N';
      m[3] = '1';
      put_u16(m.data() + 4, kFormatVersion);
    }
    try {
      Manifest::parse(m.data(), m.size());
    } catch (const OtaError&) {
      // 预期路径：拒绝。
    }
  }
}

TEST_CASE(fuzz_garbage_patch_is_rejected_or_bounded) {
  Rng rng;
  Bytes base = testutil::make_image(4000, 0x22);
  for (int iter = 0; iter < 2000; ++iter) {
    Bytes p(rng.below(300));
    for (auto& c : p) c = rng.byte();
    if (p.size() >= kDeltaHeaderSize && iter % 4 == 0) {
      std::memcpy(p.data(), kDeltaMagic, 4);
      put_u16(p.data() + 4, kFormatVersion);
      put_u64(p.data() + 8, base.size());
      put_u64(p.data() + 16, 4000);
    }
    try {
      Bytes out = delta_apply(base, p, 4000, {});
      // 极少数随机流可能恰好构成合法补丁；此时输出大小必须精确等于声明值。
      CHECK_EQ(out.size(), 4000u);
    } catch (const OtaError&) {
    }
  }
}

TEST_CASE(fuzz_garbage_boot_record_is_ignored) {
  testutil::TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  SimFlash flash(dir.file("f.bin"), Fixture::kFlashSize);
  Bytes v1 = testutil::make_image(3000, 1);
  write_good_image(&flash, cfg, 0, v1, 4, "1.0.0");

  Rng rng;
  // 在空记录槽里塞入随机字节；load() 必须仍返回正确状态。
  for (int iter = 0; iter < 300; ++iter) {
    uint64_t off = cfg.layout.boot_meta_offset + (1 + rng.below(63)) * kBootRecordSize;
    Bytes junk(kBootRecordSize);
    for (auto& c : junk) c = rng.byte();
    if (!flash.is_erased(off, kBootRecordSize)) continue;  // 只写空槽
    flash.program(off, junk.data(), junk.size());

    BootState s = read_boot_state(&flash, cfg);
    CHECK_EQ(s.active_slot, 0u);
    CHECK_EQ(s.counter, 4u);
  }
}
