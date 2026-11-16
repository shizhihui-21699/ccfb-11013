# OTA 升级：打包工具 + 设备端校验/回退模块

C++20 实现,无外部依赖（除 libsodium 提供 Ed25519 / SHA-256）。

* **主机端打包工具** `otapack`：密钥生成、完整包/差分包签名打包、验包、查看包信息。
* **设备端模块**：完整包/差分包安装、每次启动重新验签、A/B 试用启动、失败自动回退、双下限单调计数器（安装下限 + 启动下限）防降级与防已签名旧镜像重放。
* **模拟闪存**：NOR 语义（只能 0xFF→0、按扇区擦除）+ 任意操作点的断电撕裂注入。
* 包格式文档：[`docs/package-format.md`](docs/package-format.md)
* 威胁模型：[`docs/threat-model.md`](docs/threat-model.md)

## 构建与测试

```bash
make            # 构建 build/otapack 与 build/ota_tests
make test       # 运行全部测试
make demo       # 端到端演示（打包 → 验包 → 模拟设备升级/回退/断电）
```

依赖：`libsodium`（macOS：`brew install libsodium`；Debian：`apt install libsodium-dev`）、支持 C++20 的编译器。

## 快速上手

```bash
# 1. 生成签名密钥（seed 离线保管，勿入库）
./build/otapack keygen --seed fw.seed --out-pub fw.pub

# 2. 打完整包
./build/otapack pack --image app-v2.bin --version 2 \
    --device my-device --hw-min 1 --hw-max 3 \
    --key fw.seed --pub fw.pub --out v2.otap

# 3. 打差分包（从 v1 到 v2）
./build/otapack pack --image app-v2.bin --version 2 --delta-from app-v1.bin --delta-version 1 \
    --device my-device --key fw.seed --pub fw.pub --out v1-to-v2.otap

# 4. 验证（CI 用）
./build/otapack verify --package v2.otap --pub fw.pub
./build/otapack verify --package v1-to-v2.otap --pub fw.pub --source app-v1.bin
```

## 设备端用法

```cpp
#include "device/flash.h"
#include "device/updater.h"

ota::Flash flash(1 << 20);                    // 1 MiB 模拟闪存
ota::DeviceConfig cfg;
cfg.device_id = "my-device";
cfg.hw_revision = 2;
cfg.trial_boots = 2;                          // 新固件允许 2 次试用启动
cfg.public_key = /* 内置的 Ed25519 公钥 */;

ota::Updater updater(flash, cfg);

// 出厂：装入并激活首个镜像
updater.provision(bootstrap_package_bytes, now);

// 收到升级包（完整或差分均可）
auto r = updater.install(package_bytes, now);
if (!r) { log(r.failure().message); }         // 验签/降级/不匹配都会被拒，闪存无副作用

// 启动器：每次上电调用
auto boot = updater.select_boot();
if (!boot) { enter_recovery(); }
launch_image(boot.value().slot, boot.value().version);

// 应用自检通过后确认；不调用则试用次数耗尽自动回退
updater.confirm_boot();

// 应用发现异常时立即放弃本次升级
updater.mark_unhealthy();
```

## 目录结构

```
src/common/     status/错误类型、字节读写、SHA-256+Ed25519 封装、CRC-32
src/package/    包格式（format.*）与差分格式（delta.*）
src/device/     模拟闪存、布局、单调计数器、启动元数据、槽存储、升级总控
src/host/       otapack CLI
tests/          逐字节篡改、恶意差分、计数器、断电逐操作扫描等
docs/           包格式与威胁模型
scripts/demo.sh 端到端演示
```

## 行为要点（都有测试固定）

| 场景 | 行为 |
|---|---|
| 包内任意一字节被改 | 拒绝（逐字节翻转测试） |
| 用错误私钥签名 | 拒绝 |
| 截断 / 追加 / 拼接 | 拒绝（长度精确匹配 + 签名绑定） |
| 安装旧版本 | 拒绝 `RollbackRejected`，安装下限不动 |
| 保留旧槽、改元数据让它启动旧版 | 启动下限拒绝（旧镜像即使签名有效也不能启动） |
| 重放已签名的旧包 | 拒绝（同上限） |
| 差分包源镜像不符 | 拒绝，不写闪存 |
| 恶意差分指令 | 拒绝（越界/超长/缺 END/未知操作码） |
| 安装中任意时刻断电 | 重启后可启动、可重试；逐操作扫描验证 |
| 新固件启动后未确认 | 试用次数耗尽自动回退旧槽 |
| 槽内镜像被篡改 | 启动时验签失败，自动回退 |
| 元数据损坏 | 从签名槽恢复，不会执行未签名内容 |
| 计数器单扇区丢失 | 两个下限都不倒退（冗余副本） |
| 同版本重装（断电重试） | 幂等允许；更旧版本仍被拒 |
