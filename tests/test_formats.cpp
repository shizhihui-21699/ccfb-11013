// SPDX-License-Identifier: MIT
// 差分格式、闪存模拟与清单解析的边界测试。
#include "bootctl.h"
#include "crc32.h"
#include "delta.h"
#include "flash.h"
#include "package.h"
#include "test_framework.h"
#include "test_util.h"

using namespace ota;
using testutil::Fixture;
using testutil::TempDir;

TEST_CASE(delta_roundtrip_various_sizes) {
  for (size_t size : {size_t{1}, size_t{13}, size_t{4096}, size_t{70000}, size_t{200000}}) {
    Bytes base = testutil::make_image(size, static_cast<uint32_t>(size));
    Bytes target = testutil::mutate_slightly(base, 3);
    Bytes patch = delta_create(base, target);
    Bytes out = delta_apply(base, patch, target.size(), to_bytes(Sha256::hash(target)));
    CHECK(out == target);
  }
}

TEST_CASE(delta_identical_images_is_tiny) {
  Bytes base = testutil::make_image(50000, 1);
  Bytes patch = delta_create(base, base);
  CHECK(patch.size() < 200);  // 基本只有几条 COPY + 头
  Bytes out = delta_apply(base, patch, base.size(), {});
  CHECK(out == base);
}

TEST_CASE(delta_detects_corrupt_patch) {
  Bytes base = testutil::make_image(30000, 1);
  Bytes target = testutil::mutate_slightly(base, 9);
  Bytes patch = delta_create(base, target);
  Bytes bad = patch;
  bad[kDeltaHeaderSize + 2] ^= 0xFF;
  CHECK_THROWS_CODE(delta_apply(base, bad, target.size(), {}), OtaError::kBadDelta);
}

TEST_CASE(delta_detects_wrong_base) {
  Bytes base = testutil::make_image(30000, 1);
  Bytes target = testutil::mutate_slightly(base, 9);
  Bytes patch = delta_create(base, target);
  Bytes other_base = testutil::make_image(30000, 2);  // 同样大小，内容不同
  // 应用端不校验 base 内容，只有最终目标哈希能发现；这里显式给出期望哈希。
  CHECK_THROWS_CODE(delta_apply(other_base, patch, target.size(), to_bytes(Sha256::hash(target))),
                    OtaError::kBadHash);
}

TEST_CASE(delta_rejects_truncated_or_oversized_patch) {
  Bytes base = testutil::make_image(10000, 1);
  Bytes target = testutil::mutate_slightly(base, 4);
  Bytes patch = delta_create(base, target);

  Bytes truncated = testutil::take(patch, patch.size() - 5);
  CHECK_THROWS_CODE(delta_apply(base, truncated, target.size(), {}), OtaError::kBadDelta);

  Bytes tiny = testutil::take(patch, 10);
  CHECK_THROWS_CODE(delta_apply(base, tiny, target.size(), {}), OtaError::kBadDelta);

  // 伪造头部声称更大的 target。
  Bytes fake = patch;
  put_u64(fake.data() + 16, target.size() + 1);
  CHECK_THROWS_CODE(delta_apply(base, fake, target.size() + 1, {}), OtaError::kBadDelta);
}

TEST_CASE(manifest_rejects_duplicate_and_unknown_tags) {
  Manifest m;
  m.image_version = "1.0.0";
  Bytes ser = m.serialize();
  Manifest parsed = Manifest::parse(ser.data(), ser.size());
  CHECK_EQ(parsed.image_version, std::string("1.0.0"));

  // 追加一个未知 tag（伪造条目数 +1）。
  uint16_t count = get_u16(ser.data() + 6);
  put_u16(ser.data() + 6, static_cast<uint16_t>(count + 1));
  ser.push_back(0x7F);
  ser.push_back(0);
  ser.push_back(0);
  CHECK_THROWS_CODE(Manifest::parse(ser.data(), ser.size()), OtaError::kBadFormat);

  // 重复标签。
  Bytes dup = Manifest{}.serialize();
  put_u16(dup.data() + 6, 2);
  // 现有 0 个条目；手工加两个 0x04 build_id。
  Bytes item = {0x04, 1, 0, 'a'};
  dup.insert(dup.end(), item.begin(), item.end());
  dup.insert(dup.end(), item.begin(), item.end());
  CHECK_THROWS_CODE(Manifest::parse(dup.data(), dup.size()), OtaError::kBadFormat);
}

TEST_CASE(flash_enforces_erase_before_program) {
  TempDir dir;
  SimFlash flash(dir.file("f.bin"), 8192);
  Bytes data = {1, 2, 3, 4};
  flash.program(0, data.data(), data.size());
  // 同一位置再写不同值：试图 0->1。
  Bytes other = {1, 2, 3, 9};
  CHECK_THROWS_CODE(flash.program(0, other.data(), other.size()),
                    OtaError::kFlashBitViolation);
  // 1->0 允许（NOR 特性）。
  Bytes subset = {0, 2, 3, 0};
  flash.program(0, subset.data(), subset.size());
  CHECK_EQ(flash.read(0, 4), subset);

  flash.erase_sector(0);
  CHECK(flash.is_erased(0, 8192));
  CHECK_THROWS_CODE(flash.erase_sector(1), OtaError::kFlashRange);
  CHECK_THROWS_CODE(flash.read(8192, 1), OtaError::kFlashRange);
}

TEST_CASE(flash_persists_across_reopen) {
  TempDir dir;
  std::string f = dir.file("f.bin");
  {
    SimFlash flash(f, 8192);
    Bytes d = {0xDE, 0xAD, 0xBE, 0xEF};
    flash.program(100, d.data(), d.size());
  }
  SimFlash flash(f, 8192);
  CHECK_EQ(flash.read(100, 4), (Bytes{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST_CASE(boot_ring_wrap_keeps_latest_state_and_resists_cut) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  uint32_t capacity = cfg.layout.boot_meta_sectors * (4096 / kBootRecordSize);

  // 正常情况：写满两圈（2*capacity + 5 次），最新计数器必须可读。
  {
    SimFlash flash(dir.file("a.bin"), Fixture::kFlashSize);
    BootControl bc(&flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
    BootState s;
    for (uint32_t i = 0; i < capacity * 2 + 5; ++i) {
      s.counter = i + 1;
      s = bc.commit(s);
    }
    CHECK_EQ(bc.load().counter, static_cast<uint64_t>(capacity * 2 + 5));
  }

  // 环满后的回收过程中断电：最新状态不得丢失。
  {
    std::string f = dir.file("b.bin");
    SimFlash probe(f, Fixture::kFlashSize);
    BootControl pbc(&probe, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
    BootState s;
    for (uint32_t i = 0; i < capacity; ++i) {
      s.counter = i + 1;
      s = pbc.commit(s);
    }
    uint64_t counter_before = s.counter;
    uint64_t ops_before = probe.op_count();
    {
      BootControl bc(&probe, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
      s.counter = 9999;
      bc.commit(s);  // 这一次会触发环满回收
    }
    uint64_t recovery_ops = probe.op_count() - ops_before;
    CHECK(recovery_ops > 2);

    for (uint64_t cut = 0; cut < recovery_ops; ++cut) {
      std::string g = dir.file("c.bin");
      std::remove(g.c_str());
      {
        SimFlash flash(g, Fixture::kFlashSize);
        BootControl bc(&flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
        BootState st;
        for (uint32_t i = 0; i < capacity; ++i) {
          st.counter = i + 1;
          st = bc.commit(st);
        }
        uint64_t base_ops = flash.op_count();
        flash.arm_power_cut(base_ops + cut, 0);
        BootState big = st;
        big.counter = 9999;
        try {
          bc.commit(big);
        } catch (const OtaError&) {
        }
      }
      SimFlash flash(g, Fixture::kFlashSize);
      BootControl bc(&flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
      BootState loaded = bc.load();
      // 要么还是回收前的最新状态，要么新状态已写入；绝不允许倒退成 0/旧值。
      CHECK(loaded.counter == counter_before || loaded.counter == 9999);
    }
  }
}

TEST_CASE(boot_records_survive_many_commits) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  SimFlash flash(dir.file("f.bin"), Fixture::kFlashSize);
  BootControl bc(&flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);

  BootState s;
  for (int i = 0; i < 200; ++i) {
    s.counter = static_cast<uint64_t>(i + 1);
    s = bc.commit(s);
  }
  BootState loaded = bc.load();
  CHECK_EQ(loaded.counter, 200u);
  CHECK_EQ(loaded.record_seq, s.record_seq);
}
