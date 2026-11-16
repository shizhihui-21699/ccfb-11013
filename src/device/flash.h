// Simulated NOR flash with power-loss injection.
//
// Realistic NOR semantics the tests depend on:
//   * erased state is 0xFF;
//   * carving (programming) can only clear bits (0xFF -> 0x00), never set
//     them, so programming over non-erased data fails;
//   * erase works on whole sectors and restores 0xFF;
//   * erase before program is mandatory, and skipping it is an error.
//
// Power-loss model: `arm_power_cut(n_ops)` lets the next n operations complete
// and then makes every following operation fail with PowerLost. A "torn write"
// variant programs only a prefix of the requested bytes before the failure and
// then goes dead; `arm_power_cut(0)` means the very next operation dies.
// Bytes never touched retain their previous value, exactly what a brown-out
// mid-program leaves behind.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "common/status.h"

namespace ota {

class Flash {
 public:
  explicit Flash(size_t size);
  ~Flash();
  Flash(Flash&&) noexcept;
  Flash& operator=(Flash&&) noexcept;
  Flash(const Flash&) = delete;
  Flash& operator=(const Flash&) = delete;

  size_t size() const;
  uint32_t sector_size() const;
  size_t sector_count() const;

  // Raw read. Ranges must be in bounds.
  Result<std::vector<uint8_t>> read(uint64_t offset, size_t length) const;
  Status read_into(uint64_t offset, std::span<uint8_t> out) const;

  // Program without erasing first. Fails with FlashProgram if any bit would
  // have to go 0 -> 1.
  Status program(uint64_t offset, std::span<const uint8_t> data);

  Status erase_sector(size_t sector_index);
  Status erase_range(uint64_t offset, size_t length);

  bool is_erased(uint64_t offset, size_t length) const;

  // ---- power-loss injection -------------------------------------------------
  // Arms a cut: n further operations succeed, the next one tears and the
  // device is then dead until `power_restore`.
  void arm_power_cut(uint64_t ops_until_cut);
  bool dead() const;
  void power_restore();
  // Number of operations that fully completed (useful to prove progress).
  uint64_t completed_ops() const;

  // Persistence: load/save the raw array so a test can simulate a full reboot
  // (process restart) by round-tripping through a file.
  Result<std::vector<uint8_t>> dump() const;
  Status load(std::span<const uint8_t> data);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ota
