// SPDX-License-Identifier: MIT
// 极简测试框架：注册用例、断言、失败时打印位置。
#pragma once

#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace test {

struct Case {
  std::string name;
  std::function<void()> fn;
};

inline std::vector<Case>& registry() {
  static std::vector<Case> r;
  return r;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> fn) {
    registry().push_back({name, std::move(fn)});
  }
};

struct Failure : std::exception {
  explicit Failure(std::string msg) : msg(std::move(msg)) {}
  const char* what() const noexcept override { return msg.c_str(); }
  std::string msg;
};

inline int run_all() {
  int failed = 0;
  int passed = 0;
  for (auto& c : registry()) {
    try {
      c.fn();
      std::printf("  [PASS] %s\n", c.name.c_str());
      ++passed;
    } catch (const Failure& f) {
      std::printf("  [FAIL] %s\n         %s\n", c.name.c_str(), f.msg.c_str());
      ++failed;
    } catch (const std::exception& e) {
      std::printf("  [FAIL] %s\n         未预期异常: %s\n", c.name.c_str(), e.what());
      ++failed;
    }
  }
  std::printf("\n%d 通过, %d 失败\n", passed, failed);
  return failed == 0 ? 0 : 1;
}

}  // namespace test

#define TEST_CASE(name)                                                        \
  static void name##_impl();                                                   \
  static test::Registrar name##_registrar(#name, name##_impl);                 \
  static void name##_impl()

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      throw test::Failure(std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
                          " CHECK 失败: " #cond);                              \
    }                                                                          \
  } while (0)

#define CHECK_EQ(a, b)                                                         \
  do {                                                                         \
    auto va = (a);                                                             \
    auto vb = (b);                                                             \
    if (!(va == vb)) {                                                         \
      throw test::Failure(std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
                          " CHECK_EQ 失败: " #a " != " #b);                    \
    }                                                                          \
  } while (0)

// 注意：宏参数不能叫 code，否则会把 e.code() 一并替换掉。
#define CHECK_THROWS_CODE(expr, expected_code_)                                 \
  do {                                                                          \
    bool threw = false;                                                         \
    try {                                                                       \
      (void)(expr);                                                             \
    } catch (const ota::OtaError& e) {                                          \
      threw = true;                                                             \
      if (e.code() != (expected_code_)) {                                       \
        throw test::Failure(std::string(__FILE__) + ":" +                       \
                            std::to_string(__LINE__) + " 错误码不符: " +        \
                            std::to_string(static_cast<int>(e.code())) +        \
                            " 期望 " +                                          \
                            std::to_string(static_cast<int>(expected_code_)) +  \
                            " (" + e.what() + ")");                             \
      }                                                                         \
    }                                                                           \
    if (!threw) {                                                               \
      throw test::Failure(std::string(__FILE__) + ":" +                         \
                          std::to_string(__LINE__) + " 期望抛出异常: " #expr);  \
    }                                                                           \
  } while (0)
