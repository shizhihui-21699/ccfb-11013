#include <cstring>
#include <stdexcept>

#include "test_harness.h"

namespace otatest {

std::vector<Case>& registry() {
  static std::vector<Case> r;
  return r;
}

void fail(const char* file, int line, const std::string& msg) {
  throw std::runtime_error(std::string(file) + ":" + std::to_string(line) + ": " + msg);
}

int run_all(const char* filter) {
  int passed = 0, failed = 0, skipped = 0;
  for (auto& c : registry()) {
    if (filter && *filter && c.name.find(filter) == std::string::npos) {
      ++skipped;
      continue;
    }
    try {
      c.fn();
      std::printf("  ok    %s\n", c.name.c_str());
      ++passed;
    } catch (const std::exception& e) {
      std::printf("  FAIL  %s\n        %s\n", c.name.c_str(), e.what());
      ++failed;
    }
  }
  std::printf("\n%d passed, %d failed", passed, failed);
  if (skipped) std::printf(", %d skipped", skipped);
  std::printf("\n");
  return failed == 0 ? 0 : 1;
}

}  // namespace otatest

int main(int argc, char** argv) {
  const char* filter = argc > 1 ? argv[1] : "";
  return otatest::run_all(filter);
}
