// SPDX-License-Identifier: MIT
// 引导控制块：A/B 槽状态 + 单调计数器。
//
// 存储方式：追加式记录环。每条记录是 512 字节的 BootState 快照，带
// crc32。上电时扫描所有记录，忽略 CRC 损坏的（写到一半被断电撕裂的），
// 取 record_seq 最大的有效记录。写入新记录总是落在一条已擦除的记录槽上，
// 因此一次编程即可原子提交；撕裂只会毁掉这一条新记录，旧状态仍完整。
//
// 抗回滚计数器的语义很重要：counter 是“已确认可启动”的最高 seq，只在
// 新镜像成功自检并 confirm 之后才抬高。这样试运行失败回退到旧槽不会
// 被自己的计数器挡住；而向设备安装 seq <= counter 的包会被拒绝。
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "bytes.h"

namespace ota {

class SimFlash;

enum class SlotState : uint8_t {
  kEmpty = 0,      // 从未写入
  kPending = 1,    // 已写入，等待首次启动自检
  kGood = 2,       // 已验证可启动
  kBad = 3,        // 明确损坏/自检失败，禁止启动
};

const char* slot_state_name(SlotState s);

struct SlotMeta {
  SlotState state = SlotState::kEmpty;
  uint64_t seq = 0;            // 该槽镜像的安全版本号
  uint64_t image_size = 0;
  Hash256 image_hash{};
  char version[32] = {0};
};

constexpr uint8_t kBootMagic[4] = {'O', 'T', 'B', 'S'};
constexpr uint16_t kBootFormat = 1;
constexpr size_t kBootRecordSize = 512;
constexpr uint32_t kBootRecordCrcOff = kBootRecordSize - 4;
constexpr uint8_t kMaxBootAttempts = 3;

struct BootState {
  uint64_t record_seq = 0;     // 本记录在环内的序号，用于选出最新
  uint64_t counter = 0;        // 单调计数器：已确认可启动的最高 seq
  uint8_t active_slot = 0;     // 下次启动尝试的槽
  uint8_t boot_attempts = 0;   // 当前 pending 槽已尝试启动次数
  uint8_t reserved[6] = {0};
  SlotMeta slots[2];

  Bytes serialize() const;
  static BootState parse(const uint8_t* data, size_t len);
  uint32_t crc() const;  // 对前 508 字节求 CRC
};

class BootControl {
 public:
  // 元数据区从 flash 的 offset 开始，共 sectors 个扇区。
  BootControl(SimFlash* flash, uint64_t offset, uint32_t sectors);

  // 扫描并返回最新有效状态。没有任何有效记录时返回初始状态
  // （counter=0, active_slot=0, 两槽 Empty）。
  BootState load() const;

  // 追加提交。内部会选择下一个已擦除记录槽；环满时保留最新记录并
  // 回收其余扇区。返回提交后的完整状态（record_seq 已递增）。
  BootState commit(const BootState& state);

  // 统计有效记录数，供测试断言。
  size_t valid_record_count() const;

 private:
  uint64_t record_offset(uint32_t index) const;
  uint32_t record_capacity() const { return sectors_ * (4096 / kBootRecordSize); }

  SimFlash* flash_;
  uint64_t offset_;
  uint32_t sectors_;
};

// 镜像槽内的镜像头（位于槽起始处，128 字节）。
struct ImageHeader {
  static constexpr size_t kSize = 128;  // 与包头分开，独立演进
  uint64_t seq = 0;
  uint64_t image_size = 0;
  Hash256 image_hash{};
  std::array<char, 32> version{};
  std::array<char, 24> product{};
  std::array<char, 16> hardware{};
  uint8_t reserved[16] = {0};

  Bytes serialize() const;
  static ImageHeader parse(const uint8_t* data, size_t len);
};

// 设备分区布局。所有偏移与大小以字节计。
struct DeviceLayout {
  uint64_t boot_meta_offset = 0;
  uint32_t boot_meta_sectors = 8;   // 32 KiB 记录环
  uint64_t slot_offset[2] = {0, 0};
  uint64_t slot_size[2] = {0, 0};
  uint32_t sector_size = 4096;

  static DeviceLayout make(uint64_t flash_size, uint64_t slot_size,
                           uint32_t sector_size = 4096);
  uint64_t total_needed() const;
};

}  // namespace ota
