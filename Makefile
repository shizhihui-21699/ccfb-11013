# SPDX-License-Identifier: MIT
# 纯 Makefile，无需 cmake。`make test` 构建并运行全部测试。
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
            -Wno-sign-conversion -Isrc/common -Isrc/device -Isrc/tools
LDFLAGS  ?=

BUILD := build
COMMON_SRC := $(wildcard src/common/*.cpp)
DEVICE_SRC := $(wildcard src/device/*.cpp)
TOOLS_SRC  := $(wildcard src/tools/*.cpp)
TEST_SRC   := $(wildcard tests/*.cpp)

COMMON_OBJ := $(patsubst %.cpp,$(BUILD)/%.o,$(COMMON_SRC))
DEVICE_OBJ := $(patsubst %.cpp,$(BUILD)/%.o,$(DEVICE_SRC))
TOOLS_LIB_SRC := $(filter-out src/tools/otatool.cpp,$(TOOLS_SRC))
TOOLS_OBJ  := $(patsubst %.cpp,$(BUILD)/%.o,$(TOOLS_LIB_SRC))
OTATOOL_OBJ := $(BUILD)/src/tools/otatool.o

# 测试使用单一测试运行器（自带极简断言框架），避免引入外部依赖。
TEST_BIN := $(BUILD)/ota_tests
TOOL_BIN := $(BUILD)/otatool

.PHONY: all test clean tool

all: tool $(TEST_BIN)

tool: $(TOOL_BIN)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TOOL_BIN): $(OTATOOL_OBJ) $(TOOLS_OBJ) $(DEVICE_OBJ) $(COMMON_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BIN): $(TEST_SRC) $(DEVICE_OBJ) $(TOOLS_OBJ) $(COMMON_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD)
