#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# 演示脚本：生成密钥 -> 打包（完整 + 差分）-> 模拟设备安装/启动/断电。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${OTATOOL:-$ROOT/build/otatool}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ ! -x "$TOOL" ]]; then
  echo "构建 otatool 中..." >&2
  make -C "$ROOT" tool >/dev/null
fi

cd "$WORK"
echo "== 1. 生成签名密钥 =="
"$TOOL" keygen --secret sk.txt --public pk.txt

echo
echo "== 2. 构造两版固件镜像 =="
python3 - <<'PY'
import os
def make_image(size, seed):
    x = seed
    out = bytearray(size)
    for i in range(size):
        if i % 97 == 0:
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= x >> 17
            x ^= (x << 5) & 0xFFFFFFFF
            x &= 0xFFFFFFFF
        out[i] = (x + i) & 0xFF
    for i in range(0, size - 64, 512):
        out[i:i+64] = b"\xA5" * 64
    return bytes(out)

v1 = make_image(40000, 1)
v2 = bytearray(v1)
for i in range(0, len(v2), 4096):
    v2[i] ^= 0x33
v2[len(v2)//2] ^= 0x5A
open("v1.bin", "wb").write(v1)
open("v2.bin", "wb").write(bytes(v2))
PY
ls -l v1.bin v2.bin

echo
echo "== 3. 打包（完整包 + 差分包）=="
"$TOOL" pack  --key sk.txt --image v2.bin --seq 2 --version 2.0.0 \
  --product dev-x --hardware hw1 --timestamp 1700000000 -o full.otap
"$TOOL" delta --key sk.txt --base v1.bin --base-seq 1 --image v2.bin \
  --seq 2 --version 2.0.0 --product dev-x --hardware hw1 \
  --timestamp 1700000000 -o delta.otap
ls -l full.otap delta.otap

echo
echo "== 4. 校验包 =="
"$TOOL" inspect --package full.otap --public pk.txt

echo
echo "== 5. 篡改后应被拒绝 =="
cp full.otap bad.otap
printf '\xff' | dd of=bad.otap bs=1 seek=800 conv=notrunc 2>/dev/null
if "$TOOL" inspect --package bad.otap --public pk.txt; then
  echo "错误：篡改包竟然通过验证" >&2
  exit 1
fi

echo
echo "== 6. 模拟设备安装/启动/回退 =="
"$TOOL" 2>/dev/null || true
echo "（设备流程见 build/ota_tests 中的集成测试；这里仅演示服务端工具）"

echo
echo "全部演示完成。"
