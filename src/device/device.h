// SPDX-License-Identifier: MIT
// 设备端升级器：接收一个包字节流，验证并写入非活动槽，然后提交引导状态。
//
// 各阶段写入的先后顺序是断电安全的关键：
//   1) 擦除目标槽并写入槽内镜像头（seq/hash/版本）。
//   2) 流式写入镜像载荷，边写边算 SHA-256。
//   3) 回读校验哈希与大小（防止闪存写坏）。
//   4) 最后才提交“目标槽 = Pending、active_slot = 目标槽”的引导记录。
// 在 1~3 任意点断电：活动槽与引导状态都没变，设备仍从旧槽启动，
// 目标槽只是脏数据，下次安装会重新擦除。
// 在 4 中撕裂：引导记录 CRC 不成立，加载时回退到上一份有效记录。
#pragma once

#include <cstdint>
#include <string>

#include "bootctl.h"
#include "package.h"

namespace ota {

class SimFlash;

enum class InstallResult : uint8_t {
  kOk = 0,
  kRejectedFormat,
  kRejectedSignature,
  kRejectedProduct,
  kRejectedHardware,
  kRejectedRollback,
  kRejectedNoSpace,
  kRejectedBaseMismatch,
  kRejectedInterrupted,
};

const char* install_result_name(InstallResult r);

struct DeviceConfig {
  std::string product;
  std::string hardware;
  Ed25519PublicKey public_key{};
  KeyId key_id{};
  DeviceLayout layout;

  // 差分升级时用于生成 base 的临时缓冲上限（模拟设备的 RAM 限制）。
  uint64_t max_image_bytes = 64ull * 1024ull * 1024ull;
};

struct InstallOutcome {
  InstallResult result = InstallResult::kOk;
  std::string detail;
  uint8_t target_slot = 0;
  uint64_t seq = 0;
  bool used_delta = false;
  uint64_t bytes_written = 0;
};

// 只读当前引导状态（不改变它）。
BootState read_boot_state(SimFlash* flash, const DeviceConfig& cfg);

class DeviceUpdater {
 public:
  DeviceUpdater(SimFlash* flash, DeviceConfig cfg);

  // 安装一个完整包（内存中）。失败时不会改变引导状态。
  InstallOutcome install(const Bytes& package);

  // 模拟“当前运行中的镜像正在使用槽 which”。用于校验 A/B 选择。
  static uint8_t inactive_slot(uint8_t active) { return active == 0 ? 1 : 0; }

  // 选择本次安装要写的槽。核心不变式：**绝不覆盖当前唯一的 Good 槽**
  // （否则未确认的新镜像一旦启动失败，就没有可回退的镜像了）。
  //   active=Good              -> 写另一槽（标准 A/B 交替）
  //   active!=Good, 另一槽Good -> 写 active（覆盖试运行/损坏的那一槽）
  //   两槽都不是 Good          -> 写 active（首次安装即写 0 号槽）
  static uint8_t select_target_slot(const BootState& state);

 private:
  struct Prepared {
    PackageHeader header;
    Manifest manifest;
    Bytes image;  // 最终要写入槽的镜像（完整包=载荷，差分包=应用补丁后）
    bool used_delta = false;
  };

  Prepared prepare(const Bytes& package, const BootState& state);
  InstallOutcome install_prepared(const Prepared& prep, const BootState& state);
  Bytes read_slot_image_bytes(uint8_t slot, const SlotMeta& meta);
  void erase_slot(uint8_t slot);

  SimFlash* flash_;
  DeviceConfig cfg_;
};

// ---------------- 启动与自检 ----------------

struct BootDecision {
  enum Action : uint8_t {
    kBootGood = 0,      // 直接启动 active_slot
    kBootPending = 1,   // 启动 active_slot 并计入尝试次数
    kRollback = 2,      // 当前活动槽不可用，回退到另一槽
    kNoBootable = 3,    // 没有可启动镜像（需要恢复模式）
  };
  Action action = kNoBootable;
  uint8_t slot = 0;
  std::string reason;
};

// 上电时调用：校验镜像头与镜像哈希，更新尝试计数，必要时回退。
// 返回的 BootState 已经写回闪存（若需要变更）。
BootDecision boot_and_select(SimFlash* flash, const DeviceConfig& cfg);

// 自检成功后调用：把当前运行槽标记为 Good 并抬高单调计数器。
BootState confirm_running(SimFlash* flash, const DeviceConfig& cfg, uint8_t slot);

// 用于测试：直接写一个“好”镜像到指定槽（不经过升级器）。
void write_good_image(SimFlash* flash, const DeviceConfig& cfg, uint8_t slot,
                      const Bytes& image, uint64_t seq, const std::string& version);

}  // namespace ota
