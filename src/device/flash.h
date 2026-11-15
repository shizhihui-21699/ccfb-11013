// SPDX-License-Identifier: MIT
// 模拟 NOR 闪存：文件承载、按扇区擦除、按位编程（只允许 1->0）、
// 断电注入（在指定操作处撕裂并让设备“死掉”，之后所有操作失败）。
//
// 真实约束在这里被强制：
//   * program 只能把位从 1 写成 0，否则抛 kFlashBitViolation；
//   * 擦除以扇区为单位，且必须先擦后写；
//   * 每次操作完成后立即落盘，因此断电测试可以重新打开文件，
//     看到的是中断那一刻的真实内容。
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

#include "bytes.h"

namespace ota {

class SimFlash {
 public:
  static constexpr uint32_t kDefaultSectorSize = 4096;

  // 打开（不存在则创建并填 0xFF）。size 必须是扇区大小的整数倍。
  SimFlash(const std::string& path, uint64_t size, uint32_t sector_size = kDefaultSectorSize);
  ~SimFlash();
  SimFlash(const SimFlash&) = delete;
  SimFlash& operator=(const SimFlash&) = delete;
  SimFlash(SimFlash&&) = delete;
  SimFlash& operator=(SimFlash&&) = delete;

  uint64_t size() const { return size_; }
  uint32_t sector_size() const { return sector_size_; }
  const std::string& path() const { return path_; }

  uint8_t read_byte(uint64_t offset) const;
  Bytes read(uint64_t offset, size_t len) const;
  bool is_erased(uint64_t offset, size_t len) const;

  void erase_sector(uint64_t offset);

  // 按位与语义编程；跨越未擦除区域会失败（模拟 NOR 只能 1->0）。
  void program(uint64_t offset, const uint8_t* data, size_t len);

  // 断电注入：第 at_op 次擦/写操作（从 0 计数）时制造撕裂并断电。
  // tear_bytes 表示该次操作实际完成了多少字节：
  //   0         -> 操作尚未开始就断电
  //   kTearHalf -> 完成一半后断电（模拟掉电时电压跌落）
  //   >= len    -> 操作完成后、下一次操作前断电
  static constexpr size_t kTearHalf = static_cast<size_t>(-1);
  void arm_power_cut(uint64_t at_op, size_t tear_bytes = 0);
  void disarm_power_cut();

  bool is_dead() const { return dead_; }
  uint64_t op_count() const { return op_count_; }

  // 供测试/工具：把整个闪存导出，便于比对。
  Bytes snapshot() const;

 private:
  void check_alive_and_tick();
  void flush_range(uint64_t offset, size_t len);
  void punch_power_cut(uint64_t offset, size_t len, bool is_erase, size_t tear_bytes);

  std::string path_;
  int fd_ = -1;
  uint64_t size_ = 0;
  uint32_t sector_size_ = kDefaultSectorSize;
  uint64_t op_count_ = 0;
  bool cut_armed_ = false;
  uint64_t cut_at_ = 0;
  size_t cut_tear_ = 0;
  bool dead_ = false;
};

}  // namespace ota
