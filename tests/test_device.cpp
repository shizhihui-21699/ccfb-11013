// SPDX-License-Identifier: MIT
// 设备端升级流程：A/B 选择、防回滚、产品绑定、差分应用。
#include "bootctl.h"
#include "device.h"
#include "flash.h"
#include "test_framework.h"
#include "test_util.h"

using namespace ota;
using testutil::Fixture;
using testutil::TempDir;

namespace {

struct Device {
  TempDir dir;
  Fixture fx;
  SimFlash flash;

  explicit Device(const std::string& name = "flash.bin")
      : flash(dir.file(name), Fixture::kFlashSize) {}
};

}  // namespace

TEST_CASE(full_upgrade_writes_inactive_slot_and_pends) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(6000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");

  DeviceUpdater up(&d.flash, cfg);
  Bytes v2 = testutil::make_image(7000, 2);
  InstallOutcome r = up.install(d.fx.full_package(v2, 2, "1.1.0"));
  CHECK_EQ(r.result, InstallResult::kOk);
  CHECK_EQ(r.target_slot, 1u);

  BootState s = read_boot_state(&d.flash, cfg);
  CHECK_EQ(s.active_slot, 1u);
  CHECK_EQ(static_cast<int>(s.slots[1].state), static_cast<int>(SlotState::kPending));
  CHECK_EQ(s.slots[1].seq, 2u);
  CHECK_EQ(s.counter, 1u);  // 尚未确认，计数器不抬升

  // 槽 0 的旧镜像必须原样保留。
  Bytes old = d.flash.read(cfg.layout.slot_offset[0] + ImageHeader::kSize, v1.size());
  CHECK(old == v1);
}

TEST_CASE(first_install_targets_slot_zero) {
  Device d;  // 全新设备：两槽皆空
  DeviceConfig cfg = d.fx.config();
  DeviceUpdater up(&d.flash, cfg);
  InstallOutcome r = up.install(d.fx.full_package(testutil::make_image(3000, 1), 1, "1.0.0"));
  CHECK_EQ(r.result, InstallResult::kOk);
  CHECK_EQ(r.target_slot, 0u);

  // 确认后再装一次，此时应写到槽 1。
  confirm_running(&d.flash, cfg, 0);
  InstallOutcome r2 = up.install(d.fx.full_package(testutil::make_image(3000, 2), 2, "1.1.0"));
  CHECK_EQ(r2.result, InstallResult::kOk);
  CHECK_EQ(r2.target_slot, 1u);
}

TEST_CASE(install_never_overwrites_the_only_good_slot) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(3000, 1);
  // 只有槽 0 是 Good；槽 1 是上一次试运行失败留下的 Bad。
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");
  BootControl bc(&d.flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  BootState s = bc.load();
  s.slots[1].state = SlotState::kBad;
  s.active_slot = 0;
  bc.commit(s);

  DeviceUpdater up(&d.flash, cfg);
  InstallOutcome r = up.install(d.fx.full_package(testutil::make_image(3000, 2), 2, "1.1.0"));
  CHECK_EQ(r.result, InstallResult::kOk);
  CHECK_EQ(r.target_slot, 1u);  // 覆盖 Bad 槽，保留 Good 槽

  // 关键不变式：Good 槽 0 的内容一个字节都没动。
  CHECK(d.flash.read(cfg.layout.slot_offset[0] + ImageHeader::kSize, v1.size()) == v1);
}

TEST_CASE(delta_refused_when_only_base_slot_is_available) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(6000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");
  // 把 active 置为 Pending（模拟“刚装好、还没确认”），此时另一槽是空的，
  // 唯一可写的槽就是 base 所在槽：差分不安全，必须拒绝。
  BootControl bc(&d.flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  BootState s = bc.load();
  s.slots[0].state = SlotState::kPending;
  s.active_slot = 0;
  bc.commit(s);

  DeviceUpdater up(&d.flash, cfg);
  InstallOutcome r = up.install(d.fx.delta_package(v1, 1, testutil::mutate_slightly(v1, 3), 2, "2.0"));
  CHECK_EQ(r.result, InstallResult::kRejectedBaseMismatch);
}

TEST_CASE(rejects_rollback_and_equal_version) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  write_good_image(&d.flash, cfg, 0, testutil::make_image(3000, 1), 5, "1.0.0");
  DeviceUpdater up(&d.flash, cfg);

  // seq == counter：拒绝（同一版本重放）。
  InstallOutcome r1 = up.install(d.fx.full_package(testutil::make_image(3000, 9), 5, "0.9"));
  CHECK_EQ(r1.result, InstallResult::kRejectedRollback);

  // seq < counter：拒绝降级。
  InstallOutcome r2 = up.install(d.fx.full_package(testutil::make_image(3000, 9), 4, "0.8"));
  CHECK_EQ(r2.result, InstallResult::kRejectedRollback);

  // 失败不得触碰引导状态。
  BootState s = read_boot_state(&d.flash, cfg);
  CHECK_EQ(s.active_slot, 0u);
  CHECK_EQ(s.counter, 5u);
  CHECK_EQ(s.slots[1].state, SlotState::kEmpty);

  // 更高版本可以。
  InstallOutcome r3 = up.install(d.fx.full_package(testutil::make_image(3000, 9), 6, "1.1"));
  CHECK_EQ(r3.result, InstallResult::kOk);
}

TEST_CASE(rejects_product_and_hardware_mismatch) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  write_good_image(&d.flash, cfg, 0, testutil::make_image(3000, 1), 1, "1.0.0");
  DeviceUpdater up(&d.flash, cfg);

  BuildRequest wrong_product = d.fx.request(testutil::make_image(3000, 2), 2, "1.1.0");
  wrong_product.product = "other-dev";
  CHECK_EQ(up.install(build_package(wrong_product, d.fx.sk)).result,
           InstallResult::kRejectedProduct);

  BuildRequest wrong_hw = d.fx.request(testutil::make_image(3000, 2), 2, "1.1.0");
  wrong_hw.hardware = "hw2";
  CHECK_EQ(up.install(build_package(wrong_hw, d.fx.sk)).result,
           InstallResult::kRejectedHardware);
}

TEST_CASE(rejects_tampered_package_without_touching_flash) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(3000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");

  Bytes pkg = d.fx.full_package(testutil::make_image(3000, 2), 2, "1.1.0");
  pkg[pkg.size() - 100] ^= 0xFF;  // 载荷被篡改
  Bytes slot1_before = d.flash.read(cfg.layout.slot_offset[1], 1024);

  DeviceUpdater up(&d.flash, cfg);
  CHECK_EQ(up.install(pkg).result, InstallResult::kRejectedSignature);
  CHECK(d.flash.read(cfg.layout.slot_offset[1], 1024) == slot1_before);
  CHECK_EQ(read_boot_state(&d.flash, cfg).active_slot, 0u);
}

TEST_CASE(boot_pending_then_confirm_makes_good_and_bumps_counter) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  write_good_image(&d.flash, cfg, 0, testutil::make_image(4000, 1), 1, "1.0.0");
  DeviceUpdater up(&d.flash, cfg);
  Bytes v2 = testutil::make_image(4000, 2);
  CHECK_EQ(up.install(d.fx.full_package(v2, 2, "2.0.0")).result, InstallResult::kOk);

  BootDecision bd = boot_and_select(&d.flash, cfg);
  CHECK_EQ(bd.action, BootDecision::kBootPending);
  CHECK_EQ(bd.slot, 1u);

  BootState s = confirm_running(&d.flash, cfg, 1);
  CHECK_EQ(static_cast<int>(s.slots[1].state), static_cast<int>(SlotState::kGood));
  CHECK_EQ(s.counter, 2u);
  CHECK_EQ(s.boot_attempts, 0u);

  // 再次上电直接启动。
  BootDecision again = boot_and_select(&d.flash, cfg);
  CHECK_EQ(again.action, BootDecision::kBootGood);
  CHECK_EQ(again.slot, 1u);
}

TEST_CASE(unconfirmed_bad_image_rolls_back_after_max_attempts) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(4000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");
  DeviceUpdater up(&d.flash, cfg);
  CHECK_EQ(up.install(d.fx.full_package(testutil::make_image(4000, 2), 2, "2.0.0")).result,
           InstallResult::kOk);

  // 新镜像“启动不起来”：每次上电都进入 pending，但从不 confirm。
  for (int i = 0; i < kMaxBootAttempts; ++i) {
    BootDecision bd = boot_and_select(&d.flash, cfg);
    CHECK_EQ(bd.action, BootDecision::kBootPending);
    CHECK_EQ(bd.slot, 1u);
  }
  BootDecision rollback = boot_and_select(&d.flash, cfg);
  CHECK_EQ(rollback.action, BootDecision::kRollback);
  CHECK_EQ(rollback.slot, 0u);

  BootState s = read_boot_state(&d.flash, cfg);
  CHECK_EQ(static_cast<int>(s.slots[1].state), static_cast<int>(SlotState::kBad));
  CHECK_EQ(s.active_slot, 0u);
  CHECK_EQ(s.counter, 1u);

  // 回退后能稳定启动旧镜像。
  BootDecision after = boot_and_select(&d.flash, cfg);
  CHECK_EQ(after.action, BootDecision::kBootGood);
  CHECK_EQ(after.slot, 0u);

  // 计数器没有被坏镜像污染：它仍可接受 seq=2 的修复包。
  InstallOutcome repair = up.install(d.fx.full_package(testutil::make_image(4000, 3), 2, "2.0.1"));
  CHECK_EQ(repair.result, InstallResult::kOk);
}

TEST_CASE(corrupted_active_slot_rolls_back_immediately) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  write_good_image(&d.flash, cfg, 0, testutil::make_image(4000, 1), 1, "1.0.0");
  write_good_image(&d.flash, cfg, 1, testutil::make_image(4000, 2), 2, "2.0.0");
  // 当前活动槽为 1（write_good_image 会设为活动槽）；破坏其中一字节。
  uint64_t base = cfg.layout.slot_offset[1];
  uint64_t sector = base - base % cfg.layout.sector_size;
  d.flash.erase_sector(sector);
  Bytes patched = d.flash.read(sector, cfg.layout.sector_size);
  patched[ImageHeader::kSize] ^= 0xFF;  // 改坏镜像体首字节，保留头可解析
  d.flash.program(sector, patched.data(), patched.size());

  BootDecision bd = boot_and_select(&d.flash, cfg);
  CHECK_EQ(bd.action, BootDecision::kRollback);
  CHECK_EQ(bd.slot, 0u);
  BootState s = read_boot_state(&d.flash, cfg);
  CHECK_EQ(static_cast<int>(s.slots[1].state), static_cast<int>(SlotState::kBad));
}

TEST_CASE(delta_upgrade_applies_and_verifies_target) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(20000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");
  Bytes v2 = testutil::mutate_slightly(v1, 7);

  Bytes delta = d.fx.delta_package(v1, 1, v2, 2, "2.0.0");
  CHECK(delta.size() < v1.size() / 2);  // 差分应显著更小

  DeviceUpdater up(&d.flash, cfg);
  InstallOutcome r = up.install(delta);
  CHECK_EQ(r.result, InstallResult::kOk);
  CHECK(r.used_delta);

  Bytes written = d.flash.read(cfg.layout.slot_offset[1] + ImageHeader::kSize, v2.size());
  CHECK(written == v2);
}

TEST_CASE(delta_rejected_when_base_seq_differs) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(8000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");
  Bytes v2 = testutil::mutate_slightly(v1, 2);

  Bytes delta = d.fx.delta_package(v1, /*base_seq=*/0, v2, 3, "2.0.0");
  DeviceUpdater up(&d.flash, cfg);
  InstallOutcome r = up.install(delta);
  CHECK_EQ(r.result, InstallResult::kRejectedBaseMismatch);
}

TEST_CASE(delta_rejected_when_base_image_tampered) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  Bytes v1 = testutil::make_image(8000, 1);
  write_good_image(&d.flash, cfg, 0, v1, 1, "1.0.0");
  Bytes v2 = testutil::mutate_slightly(v1, 2);
  Bytes delta = d.fx.delta_package(v1, 1, v2, 2, "2.0.0");

  // 篡改槽内 base 镜像的一个字节（模拟闪存损坏）。
  uint64_t off = cfg.layout.slot_offset[0] + ImageHeader::kSize + 100;
  d.flash.erase_sector(off - off % 4096);
  Bytes sector = d.flash.read(off - off % 4096, 4096);
  sector[off % 4096] ^= 0x01;
  d.flash.program(off - off % 4096, sector.data(), sector.size());

  DeviceUpdater up(&d.flash, cfg);
  CHECK_EQ(up.install(delta).result, InstallResult::kRejectedBaseMismatch);
}

TEST_CASE(install_rejects_image_too_large_for_slot) {
  Device d;
  DeviceConfig cfg = d.fx.config();
  write_good_image(&d.flash, cfg, 0, testutil::make_image(1000, 1), 1, "1.0.0");
  DeviceUpdater up(&d.flash, cfg);
  // 槽大小 256 KiB，镜像 300 KiB。
  Bytes too_big = testutil::make_image(300 * 1024, 3);
  CHECK_EQ(up.install(d.fx.full_package(too_big, 2, "2.0.0")).result,
           InstallResult::kRejectedNoSpace);
}
