// Simulated NOR flash semantics and power-loss injection.
#include <vector>

#include "device/flash.h"
#include "test_harness.h"

using namespace ota;

TEST(flash_starts_erased) {
  Flash f(16 * 1024);
  CHECK_EQ(f.size(), size_t{16 * 1024});
  CHECK_EQ(f.sector_size(), 4096u);
  CHECK_EQ(f.sector_count(), size_t{4});
  CHECK(f.is_erased(0, f.size()));
}

TEST(flash_program_then_read) {
  Flash f(8 * 1024);
  const uint8_t data[] = {1, 2, 3, 4, 5};
  Status s = f.program(100, std::span<const uint8_t>(data, sizeof(data)));
  CHECK_MSG(s.ok(), s.message);
  auto out = f.read(100, sizeof(data));
  CHECK(out.ok());
  CHECK(out.value() == std::vector<uint8_t>(data, data + sizeof(data)));
}

TEST(flash_refuses_program_without_erase) {
  Flash f(8 * 1024);
  uint8_t a[] = {0x0F, 0x0F};
  CHECK(f.program(0, std::span<const uint8_t>(a, 2)).ok());
  uint8_t b[] = {0xF0, 0xF0};  // would need a 0 -> 1 transition
  Status s = f.program(0, std::span<const uint8_t>(b, 2));
  CHECK(!s);
  CHECK_EQ(s.code, Error::FlashProgram);
  // Programming more zeros over existing zeros is fine (NOR AND semantics).
  uint8_t c[] = {0x0E, 0x0E};
  CHECK(f.program(0, std::span<const uint8_t>(c, 2)).ok());
  auto out = f.read(0, 2);
  CHECK(out.value()[0] == 0x0E);
}

TEST(flash_erase_restores_ff) {
  Flash f(8 * 1024);
  std::vector<uint8_t> junk(4096, 0x00);
  CHECK(f.program(4096, junk).ok());
  CHECK(!f.is_erased(4096, 4096));
  CHECK(f.erase_sector(1).ok());
  CHECK(f.is_erased(4096, 4096));
  // Unaligned erase range is refused.
  CHECK(!f.erase_range(1, 4096).ok());
}

TEST(flash_out_of_range) {
  Flash f(8 * 1024);
  uint8_t b[4] = {};
  CHECK(!f.program(8190, std::span<const uint8_t>(b, 4)).ok());
  CHECK(!f.read(8190, 4).ok());
  CHECK(!f.erase_sector(99).ok());
}

TEST(flash_power_cut_immediate) {
  Flash f(8 * 1024);
  f.arm_power_cut(0);
  uint8_t b[4] = {1, 2, 3, 4};
  Status s = f.program(0, std::span<const uint8_t>(b, 4));
  CHECK(!s);
  CHECK_EQ(s.code, Error::PowerLost);
  CHECK(f.dead());
  // Everything after the cut stays dead.
  CHECK(!f.program(8, std::span<const uint8_t>(b, 4)).ok());
  f.power_restore();
  CHECK(f.program(8, std::span<const uint8_t>(b, 4)).ok());
}

TEST(flash_power_cut_after_n_ops) {
  Flash f(8 * 1024);
  f.arm_power_cut(2);
  uint8_t b[1] = {0xAA};
  CHECK(f.program(0, std::span<const uint8_t>(b, 1)).ok());
  CHECK(f.program(1, std::span<const uint8_t>(b, 1)).ok());
  Status s = f.program(2, std::span<const uint8_t>(b, 1));
  CHECK(!s);
  CHECK_EQ(s.code, Error::PowerLost);
  CHECK_EQ(f.completed_ops(), uint64_t{2});
  auto r0 = f.read(0, 1);
  auto r2 = f.read(2, 1);
  CHECK(r0.value()[0] == 0xAA);
  CHECK(r2.value()[0] == 0xFF);  // the torn op left the cell untouched
}

TEST(flash_torn_write_leaves_partial_record) {
  Flash f(8 * 1024);
  f.arm_power_cut(0);
  std::vector<uint8_t> rec(16, 0x01);
  Status s = f.program(0, rec);
  CHECK(!s);
  // Half the record landed, the rest is still erased: exactly the "torn"
  // state that CRC checks must detect.
  auto raw = f.read(0, 16);
  CHECK(raw.ok());
  bool some_written = false, some_erased = false;
  for (uint8_t b : raw.value()) {
    some_written |= (b != 0xFF);
    some_erased |= (b == 0xFF);
  }
  CHECK(some_written);
  CHECK(some_erased);
}

TEST(flash_dump_load_roundtrip) {
  Flash f(8 * 1024);
  const uint8_t data[] = {9, 8, 7};
  CHECK(f.program(1234, std::span<const uint8_t>(data, 3)).ok());
  auto dump = f.dump();
  CHECK(dump.ok());

  Flash g(8 * 1024);
  CHECK(g.load(dump.value()).ok());
  auto out = g.read(1234, 3);
  CHECK(out.value() == std::vector<uint8_t>(data, data + 3));
  CHECK(!g.load(std::span<const uint8_t>(dump.value().data(), 10)).ok());
}
