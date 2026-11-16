SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium)
SODIUM_LIBS := $(shell pkg-config --libs libsodium)

CXX ?= c++
CXXFLAGS ?= -std=c++20 -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
CPPFLAGS += -Isrc $(SODIUM_CFLAGS)
LDLIBS += $(SODIUM_LIBS)

BUILD := build

COMMON_SRC := src/common/status.cpp src/common/crypto.cpp
PKG_SRC := src/package/format.cpp src/package/delta.cpp
DEV_SRC := src/device/flash.cpp src/device/layout.cpp src/device/counter.cpp \
           src/device/meta.cpp src/device/slot.cpp src/device/updater.cpp
LIB_SRC := $(COMMON_SRC) $(PKG_SRC) $(DEV_SRC)

TEST_SRC := tests/test_main.cpp tests/test_package.cpp tests/test_flash.cpp \
            tests/test_counter.cpp tests/test_install.cpp tests/test_powerloss.cpp

HOST_SRC := src/host/otapack.cpp

LIB_OBJ := $(LIB_SRC:%.cpp=$(BUILD)/%.o)
TEST_OBJ := $(TEST_SRC:%.cpp=$(BUILD)/%.o)
HOST_OBJ := $(HOST_SRC:%.cpp=$(BUILD)/%.o)

.PHONY: all test clean fmt demo

all: $(BUILD)/otapack $(BUILD)/ota_tests

$(BUILD)/otapack: $(HOST_OBJ) $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/ota_tests: $(TEST_OBJ) $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

test: $(BUILD)/ota_tests
	./$(BUILD)/ota_tests

demo: all
	./scripts/demo.sh

clean:
	rm -rf $(BUILD)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
