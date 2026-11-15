# 固件 OTA 升级：服务端打包 + 设备端校验（C++17）

一套可运行的固件 OTA 实现：

- **服务端工具** `otatool`：密钥生成、完整包/差分包打包、包检查。
- **设备端库**：签名校验、A/B 双槽安装、单调计数器防回滚、断电安全的
  引导状态、自动回退。
- **模拟 NOR 闪存**：文件承载，强制“先擦后写 / 只能 1→0”，支持在任意
  闪存操作处注入断电（零字节、半途或指定字节数撕裂）。
- **测试**：44 个用例，覆盖篡改、降级、重放、断电全操作点、坏固件回退、
  差分基准攻击、闪存语义与元数据韧性；整套可在 ASan + UBSan 下通过。

格式规范见 **[docs/format.md](docs/format.md)**，安全模型见
**[docs/security.md](docs/security.md)**。

## 快速开始

```bash
make            # 构建 otatool 与测试
make test       # 运行全部测试

./scripts/demo.sh   # 密钥 -> 两版镜像 -> 完整包/差分包 -> 校验 -> 篡改检测
```

手动打包：

```bash
./build/otatool keygen --secret sk.txt --public pk.txt

./build/otatool pack \
  --key sk.txt --image new.bin --seq 12 --version 2.3.0 \
  --product dev-x --hardware hw1 -o update.otap

./build/otatool delta \
  --key sk.txt --base old.bin --base-seq 11 --image new.bin \
  --seq 12 --version 2.3.0 --product dev-x --hardware hw1 -o delta.otap

./build/otatool inspect --package update.otap --public pk.txt
```

## 目录结构

```
src/common/   格式与密码学（设备端可移植，不依赖 OpenSSL）
  bytes.h         小端读写、定长字符串、溢出安全加法/乘法、OtaError
  sha256|sha512   自包含实现
  crc32           清单/元数据完整性（非安全用途）
  ed25519         TweetNaCl 派生实现 + 流式验签 Ed25519Verifier
  package         包头/清单/验证/构建
  delta           差分补丁生成与应用
src/device/   设备端
  flash           模拟 NOR 闪存 + 断电注入
  bootctl         槽元数据、追加式引导记录环、单调计数器
  device          安装器、目标槽选择、启动决策与回退、自检确认
src/tools/    服务端
  packager        密钥文件、打包请求、包描述
  otatool.cpp     CLI
tests/        44 个用例（自带极简断言框架）
docs/         格式规范与安全分析
scripts/      demo.sh
```

## 设计要点

**包布局**：`[192B 包头][清单 TLV][载荷][64B 签名]`。签名覆盖前三段，
总长必须精确匹配。设备先验签再信任任何字段。

**流式验签**：Ed25519 验签只需一次 `SHA-512(R‖A‖M)`，因此设备可以在
读取几百 KB 载荷的同时增量计算，最后做两次标量乘。设备 RAM 占用与镜像
大小无关。设备路径调用 `verify_package_streaming()`（4 KiB 分块），
`streaming_verification_matches_one_shot` 用 1/17/4096/100000 字节分块
交叉验证它与一次性实现等价。

**防回滚**：包头 `seq` 必须严格大于设备计数器；计数器只在镜像成功自检并
`confirm` 后才抬升。这避免了“坏包回退后旧镜像被自己的计数器挡住”的自锁。

**断电安全**：
- 镜像写入顺序是 `擦槽 → 写头 → 写体 → 回读校验 → 最后提交引导记录`；
- 引导状态用追加记录环，每条 512 字节带 CRC，一次编程原子提交；撕裂的
  记录被忽略，回退到上一条有效记录；
- 环满回收时保留最新记录所在扇区，回收过程自身也可被断电。

**A/B 不变式**：绝不覆盖当前唯一的 Good 槽。若存在未确认的 Pending 镜像，
下一次安装写到 Pending/损坏的那一槽，保证 Good 槽作为回退镜像始终完好。

**差分**：滚动哈希块匹配，`COPY/SEEK/LITERAL/END` 指令流；清单携带
base 哈希/版本与目标哈希/大小，应用后校验最终哈希。20 KB 镜像局部改动
时补丁约 470 字节。

## 局限与后续

- 未实现真正的安全启动链（假设引导 ROM 会校验本引导器）；
- 差分仅做等长块匹配，不含“复制+增量”近似匹配；
- 变异测试使用固定种子（`tests/test_fuzz.cpp`），可替换为 libFuzzer 做长时 fuzz；
- 生产化需要：HSM 签名、密钥轮换流程、遥测与灰度、闪存写保护与看门狗。
