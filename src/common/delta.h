// SPDX-License-Identifier: MIT
// OTAD 差分补丁格式（v1）。
//
// 补丁流由若干条指令组成，作用在 base 镜像上，逐字节产生 target 镜像：
//   COPY  (len)           从 base 当前位置顺序拷贝 len 字节
//   SEEK  (offset)        把 base 读取游标置为 offset
//   LITERAL (len, bytes)  直接输出 len 字节
//   END   ()              结束；之后必须恰好得到 target_size 字节
// 产生算法：在 base 上滑动长度为 W 的块，建立 16 位滚动哈希索引，
// 对 target 每个位置查表，命中则验证并输出 COPY（一次最多 64 KiB），
// 否则累积到 LITERAL。块大小可配置，默认 12 字节。
// 局限：仅支持等长块匹配，不做“复制+增量”的近似匹配——对固件这种
// 大段相同、局部改动的场景已足够，并且生成/应用都简单、无回溯。
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bytes.h"

namespace ota {

struct DeltaOptions {
  size_t block_size = 12;     // 滚动哈希块长度，4..32
  size_t max_copy = 65536;    // 单条 COPY 上限
  size_t min_copy_savings = 4;  // 命中但省不下字节则不生成 COPY
};

constexpr uint8_t kDeltaMagic[4] = {'O', 'T', 'D', '1'};
constexpr size_t kDeltaHeaderSize = 24;

// 生成补丁。base 与 target 均不得超过 kMaxImageSize。
Bytes delta_create(const Bytes& base, const Bytes& target, const DeltaOptions& opt = {});

// 应用补丁。任何格式错误、越界、目标大小/哈希不符都会抛 OtaError。
// expected_target_hash 为空则跳过哈希校验（仍校验大小）。
Bytes delta_apply(const Bytes& base, const Bytes& patch, uint64_t expected_target_size,
                  const Bytes& expected_target_hash);

}  // namespace ota
