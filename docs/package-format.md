# OTA 包格式与设备端升级协议（OTAP v1）

本文是 `src/package/format.h` 的人类可读版本。代码与本文如有出入，以代码为准，并且两侧都有测试固定（`tests/test_package.cpp`）。

## 1. 设计目标

| 目标 | 实现手段 |
|---|---|
| 包不可篡改 | Ed25519 签名覆盖 **manifest + 目标镜像**；任一字节改变都验签失败 |
| 不可降级到有漏洞的旧版 | 单调计数器（安装时校验 `target_version > counter`） |
| A/B 分区 | 安装永远写入非活动槽；新槽先试用，失败自动回退 |
| 断电安全 | 所有持久化结构都是"先擦旧副本、后写新副本"，任何时刻断电都至少有一份可用 |
| 差分升级 | DLTA 流式差分格式，源/目标镜像哈希都在签名范围内 |
| 端到端可验证 | 设备端每次启动都从闪存重新计算哈希并验签，不信任任何未签名元数据 |

## 2. 包的整体布局

```
偏移 0      ┌───────────────────────────┐
            │ Header（512 字节）         │  未受信任的快速索引
512         ├───────────────────────────┤
            │ Manifest（可变长，含签名）  │  受签名保护
512+M       ├───────────────────────────┤
            │ Payload（可变长）           │  完整包 = 镜像；差分包 = DLTA 流
            ├───────────────────────────┤
EOF-64      │ Signature（64 字节）        │  Ed25519
            └───────────────────────────┘
```

总长度必须 **精确等于** `512 + M + P + 64`，不接受任何多余或缺失字节（防截断/拼接/尾部注入）。

## 3. Header（512 字节，小端）

Header 是**未受信任**的索引。它存在的唯一理由是让设备/工具在不解码 manifest 的情况下快速拿到大小与版本；凡与 manifest 重叠的字段都会被交叉校验，不一致即拒收。

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | magic | `"OTAP"` |
| 4 | 2 | format_version | 必须为 1 |
| 6 | 2 | header_size | 必须为 512 |
| 8 | 4 | flags | bit0 = 差分包 |
| 12 | 4 | manifest_format | 必须为 1 |
| 16 | 8 | package_id | 与 manifest 一致 |
| 24 | 8 | target_version | 与 manifest 一致 |
| 32 | 8 | source_version | 完整包为 0；差分包为源版本 |
| 40 | 8 | payload_size | 与 manifest entry 一致 |
| 48 | 8 | target_image_size | 与 manifest entry 一致 |
| 56 | 4 | manifest_size | ≤ 2048（设备槽头扇区上限） |
| 60 | 4 | 保留 | 必须为 0 |
| 64 | 8 | build_time | 与 manifest 一致 |
| 72 | 32 | target_image_sha256 | 与 manifest entry 一致 |
| 104 | 32 | source_image_sha256 | 与 manifest 一致 |
| 136 | 8 | key_id | `SHA-256(pubkey)[0..8]` |
| 144 | 368 | 保留 | 必须为 0 |

保留字节必须为零，否则拒绝——这保证同一逻辑内容只有一种字节表示，避免"同一签名多种编码"。

## 4. Manifest（受签名的元数据块）

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 4 | magic `"MFST"` |
| 4 | 4 | manifest_format = 1 |
| 8 | 8 | package_id |
| 16 | 8 | target_version（**必须 > 0**） |
| 24 | 8 | source_version（完整包必须为 0；差分包必须 < target） |
| 32 | 8 | build_time |
| 40 | 4 | flags（bit0 = delta） |
| 44 | 4 | image_flags（厂商自定义，v1 不解释） |
| 48 | 4 | hw_min |
| 52 | 4 | hw_max |
| 56 | 2 | device_id_len（≤ 96，ASCII 可打印） |
| 58 | 2 | builder_len（≤ 128） |
| 60 | 4 | entry_count（v1 必须为 1） |
| 64 | 4 | 保留 = 0 |
| 68 | 32 | source_image_sha256（完整包全零） |
| 100 | N | device_id（空串表示通用包） |
| … | B | builder 字符串 |
| … | 96×E | Image Entry |

Manifest 的总长度必须与各字段推导出的长度**精确相等**（`device_len + builder_len + 96*entry_count == size - 100`），因此不能靠追加字节夹带数据。

### Image Entry（96 字节）

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 2 | type（1 = firmware） |
| 2 | 2 | flags |
| 4 | 4 | 保留 = 0 |
| 8 | 8 | payload_offset（v1 必须为 0） |
| 16 | 8 | payload_size |
| 24 | 8 | image_size |
| 32 | 32 | image_sha256 |
| 64 | 32 | 保留 = 0 |

### 签名消息

```
sig_msg = SHA-256("OTAP-SIG-v1" ‖ 0x00 ‖ manifest ‖ 目标镜像)
signature = Ed25519_sign(设备信任公钥对应的私钥, sig_msg)
```

关键点：签名覆盖的是**重建后的目标镜像**，不是 payload。这样：

* 完整包：payload 就是镜像，设备可当场验签；`payload` 也必须哈希到 `image_sha256`。
* 差分包：设备先用 DLTA 重建镜像，重建结果的哈希必须等于 `image_sha256`，且 Ed25519 验签必须通过——**源镜像哈希、目标镜像哈希、差分指令三者同时被签名绑定**，无法把差分包指向别的源或别的目标。

`"OTAP-SIG-v1"` 前导串做域分离，防止同一密钥在其它协议中的签名被 reinterpret 成 OTA 包。

## 5. 差分格式 DLTA v1

```
magic "DLTA" | u32 version=1 | u64 source_size | u64 target_size
ops（顺序执行，直到 END）:
  0x01 COPY : u64 source_offset | u64 length
  0x02 DATA : u32 length | length 字节
  0xFF END
```

校验规则（任一违反即拒绝，且在写入任何字节前尽可能早地拒绝）：

* `source_size` 必须等于设备当前活动镜像的真实长度；
* 每个 COPY 区间必须完全落在源镜像内（`off + len ≤ source_size`，无整数溢出）；
* 累计输出不得超过 `target_size`，结束时必须**恰好等于** `target_size`；
* 必须以 `END` 结束，不接受截断；
* 未知操作码拒绝。

编码器以 16 字节块做 FNV-1a 索引匹配，输出确定性（同样输入必得同样字节）。

## 6. 设备端闪存布局

以 1 MiB NOR、4 KiB 扇区为例（`src/device/layout.h`）：

| 区域 | 扇区 | 内容 |
|---|---|---|
| 0–1 | 2 | 单调计数器 A/B（32 字节记录，各占一扇区） |
| 2–3 | 2 | 启动元数据 A/B（40 字节记录） |
| 4 … 130 | 127 | **Slot 0**：1 个槽头扇区 + 126 个镜像扇区 |
| 131 … 257 | 127 | **Slot 1**：同构 |

槽头扇区（最后 4 字节为 CRC-32）：

```
0    magic "SLOT" | u32 header_format | u32 record_size | u32 state
16   u64 image_size | u64 generation | u64 installed_at | u32 flags | u32 reserved
48   manifest（record_size - 48 - 64 字节）
…    signature（64 字节，即包里的签名）
末 4  CRC-32(前 sector_size-4 字节)
```

槽头保存的是**签名过的 manifest + 签名本身**，因此设备无需保留原始包就能在每次启动时重新验签。CRC 只用于识别撕裂写，不是信任边界。

镜像区紧跟槽头，长度以 `image_size` 为准，其余保持擦除态（0xFF）。

## 7. 计数器与元数据

### 单调计数器：两个下限

```
记录: magic "CTR1" | u32 seq | u64 installed_floor | u64 booted_floor | 4 保留 | u32 crc32
```

两个下限相互独立，因为"不许装旧包"和"不许跑旧码"是两个不同的问题：

| 下限 | 何时推进 | 作用 |
|---|---|---|
| `installed_floor` | 安装完成、镜像落盘并验签通过后 | 拒绝 `target_version < installed_floor` 的安装 |
| `booted_floor` | `confirm_boot()` 成功后 | 拒绝启动版本号低于它的镜像 |

为什么必须有 `booted_floor`：仅靠"安装下限"挡不住**已签名旧镜像的重放**。攻击者有闪存写权限时，可以把留在另一个槽里的旧版（厂商签过名的）镜像保留不动，只改启动元数据指向它——`verify_slot` 会通过，因为它确实是合法签名。启动时把验签得到的版本号与 `booted_floor` 比对，才能拒绝。

为什么 `booted_floor` 不在安装时推进：A/B 试用期间必须允许回退到"上一个好版本"，而它的版本号更低。只有当新镜像被确认健康后，旧版本才被彻底锁死。

存储：两个扇区各存一份完整记录（同值），所以擦掉任意一个都不会让任一下限倒退。若用"交替写日志"，最新值只在一个扇区里，擦掉它就是一次真实的降级窗口。

`read()` 对两个下限分别取各有效记录的最大值；两扇区都无效视为 0，只在出厂空白件出现。

### 启动元数据

```
记录: magic "META" | u32 seq | u32 active_slot | u32 pending_slot(或 0xFFFFFFFF)
      | u32 trial_remaining | u64 active_version | u64 pending_version | u32 crc32
```

两扇区 ping-pong：更新时擦**较旧**的那份并写入 seq+1，最新的记录在替换完成前永不被擦除。

元数据不做 MAC：它能影响的范围只有"启动哪个槽"，而两个槽在启动前都会各自验签；版本下限由计数器提供，且与签名 manifest 交叉校验。CRC 足以覆盖真正会使它出错的原因——断电撕裂。

## 8. 安装流程与断电语义

```
1  解析包（结构/长度/交叉校验）        ← 失败：闪存零改动
2  策略校验（device_id、hw 范围）      ← 失败：闪存零改动
3  反回滚校验 target > counter          ← 失败：RollbackRejected，零改动
4  擦除非活动槽（头 + 镜像区）
5  写入镜像：完整包直接流式写；差分包边应用边写
6  边写边算 SHA-256，与签名哈希比对     ← 不符：作废该槽，计数器不动
7  写槽头（Ready 状态，含 manifest+签名）
8  从闪存重新验签整个槽（自检）
9  提交单调计数器
10 写 pending 元数据（trial_remaining = N），活动槽不变
```

顺序设计的核心是第 9、10 步：**计数器先于 pending 元数据**。理由：

* 若在 9 之前断电，计数器未动，旧版本仍可启动，重装同一包会被正常接受。
* 若在 9 之后、10 之前断电，计数器已推进到新版。为了让重试仍然可行，安装时允许 `target == counter`，但**仅当某个槽里已有该版本的、能通过验签的镜像**。这既不破坏反回滚（旧版本号依然 < counter 被拒），又让重试幂等。
* 计数器已推进而设备却回退到旧版本启动是允许的——计数器约束的是"安装"，不是"启动已经验签通过的既有镜像"。这样即使新镜像损坏也不会变砖。

第 8 步的自检把"写进去的东西"和"启动时会读的东西"统一起来：安装成功即意味着下次启动必然能验签通过。

## 9. 启动选择与回退

```
select_boot():
  if 无元数据:                  → 扫描两槽，选最高版本且能验签、且 ≥ booted_floor 的槽（断电恢复）
  if 有 pending_slot:
      if trial_remaining == 0 或 pending 验签失败 或 pending 版本 < booted_floor:
          → 清除 pending，回到 active（RevertedPending）
      else:
          → 先消耗一次 trial 并落盘，再启动 pending（BootedTrial）
  if active 不可启动（验签失败或低于 booted_floor）:
      → 尝试另一槽（同样要求 ≥ booted_floor）；都不行才报 NoValidSlot
  → 正常启动 active
```

要点：

* 启动路径报告的版本号来自**验签通过的 manifest**，不来自未签名的元数据。
* "可启动"= 验签通过 **且** 版本 ≥ `booted_floor`。后半句是挡住"重放已签名旧镜像"的关键。
* trial 次数在**启动前**就写盘，所以试用期间崩溃同样计入次数。
* 应用自检/联网成功后调用 `confirm_boot()`：把 pending 提升为 active，并推进 `booted_floor`；不调用则次数耗尽自动回退。应用主动判定不健康时调用 `mark_unhealthy()` 立即放弃本次试用。
* 启动路径只信任"验签通过且不违反启动下限的槽"，绝不因为元数据说某个槽是 active 就直接执行它。

## 10. 每次启动的验签成本

启动时对每个被选中的槽：读 manifest → 重新解析 → 从闪存读回镜像 → SHA-256 → Ed25519 验签。1 MiB 规模下这是毫秒级的工作，换来的是"任何在闪存里被改动过的字节都无法被执行"。

## 11. 工具

```
otapack keygen --seed key.seed --out-pub key.pub
otapack pack   --image app.bin --version 3 --key key.seed --pub key.pub \
               --device dev-1 --hw-min 1 --hw-max 3 --out v3.otap
otapack pack   --image app-v3.bin --version 3 --delta-from app-v2.bin --delta-version 2 \
               --key key.seed --pub key.pub --out v2-to-v3-delta.otap
otapack verify --package v3.otap --pub key.pub
otapack verify --package v2-to-v3-delta.otap --pub key.pub --source app-v2.bin
otapack info   --package v3.otap
```

`pack` 在返回前会用与设备端相同的代码路径自校验（含差分重建），绝不产出自己验不过的包。

## 12. 兼容性与演进

* `format_version` / `manifest_format` / `delta version` 三者独立演进，设备遇到不认识的值一律拒绝（而不是"尽力解析"）。
* Header 的 368 字节保留区 + manifest 的 reserved 字段为后续扩展留位；因为保留区必须为零，新增字段需要提升格式版本。
* 一个包只带一个镜像 entry；多组件 OTA 提升 `entry_count` 即可，v1 设备显式拒绝。

## 13. 已知取舍与后续工作

* **单镜像 entry**：v1 只支持一个 firmware 镜像。多组件需要提升 `entry_count` 语义并定义组件依赖，留待 v2。
* **密钥轮换**：设备只内置一把公钥。轮换需要固件支持"过渡期双公钥"，未实现。
* **磨损与写放大**：每次安装会擦除非活动槽整个镜像区；计数器每次提交擦写两个扇区。对 NOR 寿命而言足够，但未做磨损均衡。
* **加密**：包内容不加密，只保证完整性与来源。若镜像含机密，需在 payload 层加密封装（可放在 entry 层扩展）。
* **主控验证**：`otapack verify --source` 会把重建镜像全部读入内存，因此对声明大小设了 1 GiB 上限；设备端是流式写槽，受槽容量约束，不受此限。
