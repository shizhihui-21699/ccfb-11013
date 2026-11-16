// Two-floor monotonic counter: forward-only, crash-safe, corruption-tolerant.
#include "device/counter.h"
#include "device/flash.h"
#include "test_harness.h"

using namespace ota;

namespace {
constexpr uint64_t kSectorA = 0;
constexpr uint64_t kSectorB = 4096;
}

TEST(counter_starts_at_zero) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  auto v = c.read();
  CHECK(v.ok());
  CHECK_EQ(v.value().installed, uint64_t{0});
  CHECK_EQ(v.value().booted, uint64_t{0});
}

TEST(counter_installed_floor_moves_forward) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK(c.advance_installed(5).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{5});
  CHECK(c.advance_installed(6).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{6});
  CHECK(c.advance_installed(100).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{100});
}

TEST(counter_installed_floor_refuses_rollback) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK(c.advance_installed(10).ok());
  auto s = c.advance_installed(10);
  CHECK(!s);
  CHECK_EQ(s.code, Error::RollbackRejected);
  auto s2 = c.advance_installed(9);
  CHECK(!s2);
  CHECK_EQ(s2.code, Error::RollbackRejected);
  CHECK(!c.advance_installed(0).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{10});
}

TEST(counter_booted_floor_is_independent_and_never_above_installed) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK(c.advance_installed(3).ok());
  // Cannot claim to have confirmed a version that was never installed.
  auto s = c.mark_booted(9);
  CHECK(!s);
  CHECK_EQ(s.code, Error::InvalidArgument);
  CHECK(c.mark_booted(3).ok());
  CHECK_EQ(c.read().value().booted, uint64_t{3});
  CHECK_EQ(c.read().value().installed, uint64_t{3});
  // Boot floor only moves up.
  CHECK(c.mark_booted(2).ok());  // no-op, already at 3
  CHECK_EQ(c.read().value().booted, uint64_t{3});
  // 4 was never installed, so it cannot be confirmed.
  CHECK(!c.mark_booted(4).ok());
  CHECK_EQ(c.read().value().booted, uint64_t{3});
}

TEST(counter_writes_redundant_copies) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK(c.advance_installed(1).ok());
  CHECK(!f.is_erased(kSectorA, 32));
  CHECK(!f.is_erased(kSectorB, 32));
  CHECK(c.advance_installed(2).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{2});

  // Erase sector A only: B still carries the installed floor.
  CHECK(f.erase_range(kSectorA, 32).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{2});

  Flash g(64 * 1024);
  MonotonicCounter cg(g, kSectorA, kSectorB);
  CHECK(cg.advance_installed(2).ok());
  CHECK(g.erase_range(kSectorB, 32).ok());
  CHECK_EQ(cg.read().value().installed, uint64_t{2});
}

TEST(counter_initialize_only_once) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK(c.initialize(7).ok());
  CHECK_EQ(c.read().value().installed, uint64_t{7});
  CHECK(!c.initialize(8).ok());  // already provisioned
}

TEST(counter_blank_or_corrupt_reads_zero) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK_EQ(c.read().value().installed, uint64_t{0});
  uint8_t junk[32];
  for (size_t i = 0; i < 32; ++i) junk[i] = static_cast<uint8_t>(i ^ 0x5A);
  CHECK(f.program(kSectorA, std::span<const uint8_t>(junk, 32)).ok());
  auto v = c.read();
  CHECK(v.ok());
  CHECK_EQ(v.value().installed, uint64_t{0});  // garbage is never trusted
}

TEST(counter_power_loss_during_commit_keeps_floor) {
  for (uint64_t cut = 0; cut < 8; ++cut) {
    Flash f(64 * 1024);
    MonotonicCounter c(f, kSectorA, kSectorB);
    CHECK(c.initialize(5).ok());
    f.arm_power_cut(cut);
    Status s = c.advance_installed(9);
    f.power_restore();
    auto v = c.read();
    CHECK_MSG(v.ok(), "counter unreadable after cut at " + std::to_string(cut));
    CHECK_MSG(v.value().installed == 5 || v.value().installed == 9,
              "installed floor is " + std::to_string(v.value().installed) + " after cut at " +
                  std::to_string(cut));
    if (!s.ok()) {
      CHECK(s.code == Error::PowerLost || s.code == Error::FlashProgram);
    }
  }
}

TEST(counter_never_lowers_after_power_loss) {
  Flash f(64 * 1024);
  MonotonicCounter c(f, kSectorA, kSectorB);
  CHECK(c.initialize(3).ok());
  f.arm_power_cut(1);
  c.advance_installed(4);
  f.power_restore();
  CHECK(c.read().value().installed >= 3);
}
