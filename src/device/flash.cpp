// SPDX-License-Identifier: MIT
#include "flash.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

namespace ota {
namespace {

void io_fail(const std::string& what) {
  fail(OtaError::kIo, what + "：" + std::strerror(errno));
}

}  // namespace

SimFlash::SimFlash(const std::string& path, uint64_t size, uint32_t sector_size)
    : path_(path), size_(size), sector_size_(sector_size) {
  if (sector_size == 0 || size == 0 || size % sector_size != 0) {
    fail(OtaError::kFlashRange, "闪存尺寸必须是扇区大小的正整数倍");
  }
  bool created = false;
  fd_ = ::open(path.c_str(), O_RDWR);
  if (fd_ < 0 && errno == ENOENT) {
    fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
    created = fd_ >= 0;
  }
  if (fd_ < 0) io_fail("无法打开闪存文件 " + path);

  off_t actual = ::lseek(fd_, 0, SEEK_END);
  if (actual < 0) io_fail("无法获取闪存大小");
  if (created || static_cast<uint64_t>(actual) != size) {
    // 新文件或尺寸变化：重建为全 0xFF（擦除态）。
    if (::ftruncate(fd_, static_cast<off_t>(size)) != 0) io_fail("无法设置闪存大小");
    std::vector<uint8_t> chunk(64 * 1024, 0xFF);
    uint64_t off = 0;
    while (off < size) {
      size_t n = static_cast<size_t>(std::min<uint64_t>(chunk.size(), size - off));
      if (::pwrite(fd_, chunk.data(), n, static_cast<off_t>(off)) != static_cast<ssize_t>(n)) {
        io_fail("无法初始化闪存");
      }
      off += n;
    }
  }
}

SimFlash::~SimFlash() {
  if (fd_ >= 0) ::close(fd_);
}

void SimFlash::check_alive_and_tick() {
  if (dead_) fail(OtaError::kIo, "设备已断电，闪存不可访问");
}

void SimFlash::flush_range(uint64_t offset, size_t len) {
  (void)offset;
  (void)len;
  if (::fsync(fd_) != 0) io_fail("落盘失败");
}

uint8_t SimFlash::read_byte(uint64_t offset) const {
  if (dead_) fail(OtaError::kIo, "设备已断电，闪存不可访问");
  if (offset >= size_) fail(OtaError::kFlashRange, "读地址越界");
  uint8_t b = 0;
  if (::pread(fd_, &b, 1, static_cast<off_t>(offset)) != 1) io_fail("读取闪存失败");
  return b;
}

Bytes SimFlash::read(uint64_t offset, size_t len) const {
  if (dead_) fail(OtaError::kIo, "设备已断电，闪存不可访问");
  if (offset > size_ || len > size_ - offset) fail(OtaError::kFlashRange, "读区间越界");
  Bytes out(len);
  size_t done = 0;
  while (done < len) {
    ssize_t n = ::pread(fd_, out.data() + done, len - done, static_cast<off_t>(offset + done));
    if (n <= 0) io_fail("读取闪存失败");
    done += static_cast<size_t>(n);
  }
  return out;
}

bool SimFlash::is_erased(uint64_t offset, size_t len) const {
  Bytes b = read(offset, len);
  for (uint8_t v : b) {
    if (v != 0xFF) return false;
  }
  return true;
}

void SimFlash::punch_power_cut(uint64_t offset, size_t len, bool is_erase, size_t tear_bytes) {
  // 当前操作计数等于注入点：先做撕裂写入，再进入断电状态。
  // 擦除的撕裂建模为“前 tear_bytes 字节已变成 0xFF，其余保持原值”，
  // 这比随机填充更接近 NOR 擦除中途断电的实际表现。
  size_t applied = std::min(tear_bytes, len);
  if (is_erase && applied > 0) {
    std::vector<uint8_t> ones(applied, 0xFF);
    if (::pwrite(fd_, ones.data(), applied, static_cast<off_t>(offset)) !=
        static_cast<ssize_t>(applied)) {
      io_fail("撕裂擦除失败");
    }
  }
  ::fsync(fd_);
  dead_ = true;
  fail(OtaError::kIo, "模拟断电（操作 #" + std::to_string(op_count_) + "）");
}

void SimFlash::erase_sector(uint64_t offset) {
  check_alive_and_tick();
  if (offset % sector_size_ != 0) fail(OtaError::kFlashRange, "擦除地址未按扇区对齐");
  if (offset >= size_ || sector_size_ > size_ - offset) fail(OtaError::kFlashRange, "擦除越界");

  uint64_t op = op_count_++;
  if (cut_armed_ && op == cut_at_) {
    size_t tear = (cut_tear_ == kTearHalf) ? sector_size_ / 2 : cut_tear_;
    punch_power_cut(offset, sector_size_, /*is_erase=*/true, tear);
  }
  std::vector<uint8_t> ones(sector_size_, 0xFF);
  if (::pwrite(fd_, ones.data(), ones.size(), static_cast<off_t>(offset)) !=
      static_cast<ssize_t>(ones.size())) {
    io_fail("擦除失败");
  }
  flush_range(offset, sector_size_);
}

void SimFlash::program(uint64_t offset, const uint8_t* data, size_t len) {
  check_alive_and_tick();
  if (offset > size_ || len > size_ - offset) fail(OtaError::kFlashRange, "写区间越界");
  if (len == 0) return;

  uint64_t op = op_count_++;
  size_t apply_len = len;
  bool cutting = cut_armed_ && op == cut_at_;

  // 先读出原值做 1->0 检查（模拟 NOR 位特性）。
  Bytes old = read(offset, len);
  for (size_t i = 0; i < len; ++i) {
    uint8_t merged = static_cast<uint8_t>(old[i] & data[i]);
    if (merged != data[i]) {
      fail(OtaError::kFlashBitViolation,
           "写入试图把 0 变 1（偏移 " + std::to_string(offset + i) +
               "），说明目标区域未擦除");
    }
  }

  if (cutting) {
    size_t tear = (cut_tear_ == kTearHalf) ? len / 2 : cut_tear_;
    apply_len = std::min(tear, len);
  }

  if (apply_len > 0) {
    if (::pwrite(fd_, data, apply_len, static_cast<off_t>(offset)) !=
        static_cast<ssize_t>(apply_len)) {
      io_fail("写入失败");
    }
    flush_range(offset, apply_len);
  }
  if (cutting) {
    dead_ = true;
    fail(OtaError::kIo, "模拟断电（写入操作 #" + std::to_string(op) + " 撕裂于 " +
                            std::to_string(apply_len) + "/" + std::to_string(len) + " 字节）");
  }
}

void SimFlash::arm_power_cut(uint64_t at_op, size_t tear_bytes) {
  cut_armed_ = true;
  cut_at_ = at_op;
  cut_tear_ = tear_bytes;
}

void SimFlash::disarm_power_cut() { cut_armed_ = false; }

Bytes SimFlash::snapshot() const { return read(0, static_cast<size_t>(size_)); }

}  // namespace ota
