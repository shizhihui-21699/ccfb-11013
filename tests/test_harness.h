// Tiny test harness: no external framework, deterministic, one binary.
#pragma once

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace otatest {

struct Case {
  std::string name;
  std::function<void()> fn;
};

std::vector<Case>& registry();

struct Reg {
  Reg(const char* name, std::function<void()> fn) {
    registry().push_back(Case{name, std::move(fn)});
  }
};

// Fails the current test. Throws so the runner can report and continue.
[[noreturn]] void fail(const char* file, int line, const std::string& msg);

int run_all(const char* filter);

}  // namespace otatest

#define TEST(name)                                             \
  static void name();                                          \
  static ::otatest::Reg reg_##name(#name, name);               \
  static void name()

#define CHECK(cond)                                            \
  do {                                                         \
    if (!(cond)) ::otatest::fail(__FILE__, __LINE__, "CHECK(" #cond ")"); \
  } while (0)

#define CHECK_MSG(cond, msg)                                   \
  do {                                                         \
    if (!(cond)) ::otatest::fail(__FILE__, __LINE__, std::string("CHECK(" #cond "): ") + (msg)); \
  } while (0)

#define CHECK_EQ(a, b)                                         \
  do {                                                         \
    auto _va = (a);                                            \
    auto _vb = (b);                                            \
    if (!(_va == _vb)) {                                       \
      ::otatest::fail(__FILE__, __LINE__,                      \
                      std::string("CHECK_EQ failed: " #a " == " #b)); \
    }                                                          \
  } while (0)
