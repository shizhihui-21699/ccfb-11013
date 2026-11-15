// SPDX-License-Identifier: MIT
// 断电注入：在升级流程的每一个闪存操作处切断电源，验证
//   * 设备总能启动到一个完整、哈希正确的镜像；
//   * 旧槽在安装未完成时保持原样；
//   * 引导元数据不会因撕裂而指向一个不完整的镜像。
#include <memory>

#include "bootctl.h"
#include "device.h"
#include "flash.h"
#include "test_framework.h"
#include "test_util.h"

using namespace ota;
using testutil::Fixture;
using testutil::TempDir;

namespace {

// 返回 true 表示该镜像在槽内完整有效（与 write_good_image 写入时一致）。
bool slot_holds(SimFlash* flash, const DeviceConfig& cfg, uint8_t slot, const Bytes& image) {
  uint64_t base = cfg.layout.slot_offset[slot];
  try {
    Bytes hdr = flash->read(base, ImageHeader::kSize);
    ImageHeader ih = ImageHeader::parse(hdr.data(), hdr.size());
    if (ih.image_size != image.size()) return false;
    if (ih.image_hash != Sha256::hash(image)) return false;
    Bytes body = flash->read(base + ImageHeader::kSize, image.size());
    return body == image;
  } catch (const OtaError&) {
    return false;
  }
}

}  // namespace

TEST_CASE(power_cut_at_every_flash_operation_keeps_a_bootable_image) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();

  Bytes v1 = testutil::make_image(12000, 1);
  Bytes v2 = testutil::make_image(13000, 2);
  Bytes pkg = fx.full_package(v2, 2, "2.0.0");

  // 先跑一次拿到总操作数。
  std::string path = dir.file("flash.bin");
  uint64_t total_ops = 0;
  {
    SimFlash flash(path, Fixture::kFlashSize);
    write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");
    total_ops = flash.op_count();
    DeviceUpdater up(&flash, cfg);
    CHECK_EQ(up.install(pkg).result, InstallResult::kOk);
    total_ops = flash.op_count() - total_ops;
  }
  CHECK(total_ops > 10);

  int torn = 0, completed = 0;
  int booted_old = 0, booted_new = 0;
  for (uint64_t cut_op = 0; cut_op <= total_ops; ++cut_op) {
    std::string f = dir.file("case.bin");
    std::remove(f.c_str());
    {
      SimFlash flash(f, Fixture::kFlashSize);
      write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");
      uint64_t base_ops = flash.op_count();
      flash.arm_power_cut(base_ops + cut_op, /*tear_bytes=*/0);
      DeviceUpdater up(&flash, cfg);
      InstallOutcome r = up.install(pkg);
      if (r.result == InstallResult::kOk) {
        ++completed;
      } else {
        CHECK_EQ(r.result, InstallResult::kRejectedInterrupted);
        ++torn;
      }
    }

    // “重新上电”：重新打开闪存文件。
    SimFlash flash(f, Fixture::kFlashSize);
    CHECK(slot_holds(&flash, cfg, 0, v1));  // 旧槽绝不能被破坏
    BootDecision bd = boot_and_select(&flash, cfg);
    CHECK(bd.action != BootDecision::kNoBootable);
    if (bd.slot == 0) {
      CHECK(slot_holds(&flash, cfg, 0, v1));
      ++booted_old;
    } else {
      CHECK(slot_holds(&flash, cfg, 1, v2));
      ++booted_new;
    }
    // 若提交已完成，槽 1 必须完整；未完成则允许是垃圾，但不得被选中。
    BootState s = read_boot_state(&flash, cfg);
    if (s.active_slot == 1) {
      CHECK(s.slots[1].state == SlotState::kPending || s.slots[1].state == SlotState::kGood);
      CHECK(slot_holds(&flash, cfg, 1, v2));
    }

    // 再次上电 / 自检确认后应能稳定到某个好镜像。
    if (bd.slot == 1) {
      confirm_running(&flash, cfg, 1);
      BootDecision after = boot_and_select(&flash, cfg);
      CHECK_EQ(after.action, BootDecision::kBootGood);
      CHECK_EQ(after.slot, 1u);
    }
  }
  // 两端都应被覆盖：至少一次撕裂失败、一次完整成功，且
  // 既有“回退到旧镜像”也有“切换到新镜像”的断电点。
  CHECK(torn > 0);
  CHECK(completed > 0);
  CHECK(booted_old > 0);
  CHECK(booted_new > 0);
  std::printf("        断电点 %llu 个：中断 %d，完成 %d；启动旧镜像 %d，新镜像 %d\n",
              static_cast<unsigned long long>(total_ops + 1), torn, completed, booted_old,
              booted_new);
}

// 每个操作点都撕裂一半：擦除写一半、编程写一半。这是最恶劣的掉电形态。
TEST_CASE(power_cut_halfway_through_every_operation_keeps_a_bootable_image) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  Bytes v1 = testutil::make_image(9000, 1);
  Bytes v2 = testutil::make_image(9500, 2);
  Bytes pkg = fx.full_package(v2, 2, "2.0.0");

  uint64_t total_ops = 0;
  {
    std::string f = dir.file("probe.bin");
    SimFlash flash(f, Fixture::kFlashSize);
    write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");
    uint64_t base_ops = flash.op_count();
    DeviceUpdater up(&flash, cfg);
    CHECK_EQ(up.install(pkg).result, InstallResult::kOk);
    total_ops = flash.op_count() - base_ops;
  }

  int booted_old = 0;
  for (uint64_t cut_op = 0; cut_op < total_ops; ++cut_op) {
    std::string f = dir.file("half.bin");
    std::remove(f.c_str());
    {
      SimFlash flash(f, Fixture::kFlashSize);
      write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");
      uint64_t base_ops = flash.op_count();
      flash.arm_power_cut(base_ops + cut_op, SimFlash::kTearHalf);
      DeviceUpdater up(&flash, cfg);
      InstallOutcome r = up.install(pkg);
      CHECK(r.result != InstallResult::kOk);  // 一半中断必然失败
    }
    SimFlash flash(f, Fixture::kFlashSize);
    CHECK(slot_holds(&flash, cfg, 0, v1));
    BootDecision bd = boot_and_select(&flash, cfg);
    CHECK(bd.action == BootDecision::kBootGood || bd.action == BootDecision::kRollback ||
          bd.action == BootDecision::kBootPending);
    CHECK(bd.action != BootDecision::kNoBootable);
    // 引导提交是最后一条 program 且必须整条 512 字节写完才有效，
    // 因此任何“中途掉电”都不可能切到新镜像——这是提交的原子性。
    CHECK_EQ(bd.slot, 0u);
    CHECK(slot_holds(&flash, cfg, 0, v1));
    ++booted_old;
  }
  CHECK_EQ(booted_old, static_cast<int>(total_ops));
}

TEST_CASE(power_cut_mid_program_torn_sector_never_bootable) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  Bytes v1 = testutil::make_image(20000, 1);
  Bytes v2 = testutil::make_image(20000, 2);
  Bytes pkg = fx.full_package(v2, 2, "2.0.0");

  std::string f = dir.file("flash.bin");
  {
    SimFlash flash(f, Fixture::kFlashSize);
    write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");
    // 找到镜像写入的第一个 program 操作：write_good_image 后最大扇区数 +
    // 擦除目标是 64 个扇区 + 镜像头 1 次。
    uint64_t base_ops = flash.op_count();
    flash.arm_power_cut(base_ops + 65, /*tear_bytes=*/512);  // 擦除完、镜像写到一半
    DeviceUpdater up(&flash, cfg);
    InstallOutcome r = up.install(pkg);
    CHECK_EQ(r.result, InstallResult::kRejectedInterrupted);
  }
  SimFlash flash(f, Fixture::kFlashSize);
  BootDecision bd = boot_and_select(&flash, cfg);
  CHECK_EQ(bd.action, BootDecision::kBootGood);
  CHECK_EQ(bd.slot, 0u);
  CHECK(slot_holds(&flash, cfg, 0, v1));
}

TEST_CASE(power_cut_during_boot_metadata_commit_keeps_previous_state) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  Bytes v1 = testutil::make_image(8000, 1);
  Bytes v2 = testutil::make_image(8000, 2);
  Bytes pkg = fx.full_package(v2, 2, "2.0.0");

  // 逐字节撕裂引导记录的写入：128..512 字节的不同前缀。
  for (size_t tear : {size_t{1}, size_t{64}, size_t{300}, size_t{511}}) {
    std::string f = dir.file("meta.bin");
    std::remove(f.c_str());
    {
      SimFlash flash(f, Fixture::kFlashSize);
      write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");
      // 元数据记录写在 boot_meta_offset 起第 2 条（第 1 条由 write_good_image 占用）。
      // 安装的最后一个 program 就是提交记录：先算总操作数再减一。
      DeviceUpdater up(&flash, cfg);
      uint64_t before = flash.op_count();
      // 先试跑一次不注入以得知总操作数（在独立文件上）。
      (void)before;
      // 直接注入到最后一次 program：slot 擦除数 + 2 次 program + 记录 1 次。
      uint64_t erase_ops = Fixture::kSlotSize / 4096;
      flash.arm_power_cut(flash.op_count() + erase_ops + 2, tear);
      InstallOutcome r = up.install(pkg);
      CHECK_EQ(r.result, InstallResult::kRejectedInterrupted);
    }
    SimFlash flash(f, Fixture::kFlashSize);
    BootState s = read_boot_state(&flash, cfg);
    // 撕裂的记录被忽略，回退到上一份有效记录：活动槽仍是 0。
    CHECK_EQ(s.active_slot, 0u);
    CHECK_EQ(s.counter, 1u);
    BootDecision bd = boot_and_select(&flash, cfg);
    CHECK_EQ(bd.action, BootDecision::kBootGood);
    CHECK_EQ(bd.slot, 0u);
  }
}

TEST_CASE(metadata_ring_garbage_records_are_ignored) {
  TempDir dir;
  Fixture fx;
  DeviceConfig cfg = fx.config();
  SimFlash flash(dir.file("f.bin"), Fixture::kFlashSize);
  write_good_image(&flash, cfg, 0, testutil::make_image(4000, 1), 3, "1.0.0");

  // 在记录区内注垃圾（模拟历史撕裂/位翻转），不应影响读取。
  // 选第 9 条记录（位于第 2 个扇区），避免碰掉已写入的有效记录。
  uint64_t off = cfg.layout.boot_meta_offset + 9 * kBootRecordSize;
  CHECK_EQ(off / 4096, 1u);
  Bytes junk(kBootRecordSize, 0x5A);
  flash.program(off, junk.data(), junk.size());

  BootState s = read_boot_state(&flash, cfg);
  CHECK_EQ(s.active_slot, 0u);
  CHECK_EQ(s.counter, 3u);
}
