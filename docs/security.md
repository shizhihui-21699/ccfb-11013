# 安全模型与威胁分析

本文档说明系统**防住什么、不防什么、为什么**，以及每个断言对应哪条测试。
格式细节见 [format.md](format.md)。

## 1. 资产与信任边界

| 资产 | 受什么保护 |
| --- | --- |
| 设备执行的固件 | Ed25519 签名 + 安装后回读 SHA-256 |
| 设备的版本单调性 | `seq` + 单调计数器，设备端落地 |
| 可引导性 | A/B 双槽 + 引导记录环 + 试运行计数 |
| 服务端签名私钥 | 进程外（工具只读密钥文件，不存储） |

信任边界：

- **签名私钥**是唯一能产出可安装包的凭据。设备只信任内置公钥（可按
  `key_id` 选多把）。
- 传输通道**不可信**。所有安全性来自包内签名与设备端状态，不依赖 TLS。
- 闪存内容**可能损坏**（位翻转、写到一半）。因此安装后回读校验，
  每次上电校验镜像哈希。

## 2. 攻击场景与对策

### 2.1 篡改升级包

攻击者改任意字节（载荷、清单、包头、签名）。

- 签名覆盖 `header‖manifest‖payload`，任何改动都使 Ed25519 验签失败。
- 改动包头中的长度字段会被“总长必须精确相等”拦下。
- **测试**：`package_rejects_tamper`、`package_rejects_manifest_corruption`、
  `rejects_tampered_package_without_touching_flash`、CLI 篡改测试。

### 2.2 降级到有漏洞的旧版本

攻击者重放一个旧版本、且签名合法的包。

- 包头 `seq` 必须严格大于设备 `counter`；等于也拒绝（防同版本重放）。
- `counter` 只在 `confirm_running` 中抬升，且只取“已成功自检”的 `seq`。
- `rollback_floor` 让发布方可声明最低可接受版本。
- **测试**：`rejects_rollback_and_equal_version`、CLI 重放测试。

为什么不依赖时间戳：设备时钟不可信，攻击者可以断电让 RTC 归零。
用 `timestamp` 做防回滚等于把安全交给一个可被物理操控的输入。

### 2.3 断电 / 掉电

在任何一条闪存操作处切断电源。

| 断电位置 | 结果 |
| --- | --- |
| 擦除目标槽中途 | 目标槽是垃圾，但 `active_slot` 未变，仍从旧槽启动 |
| 写镜像头中途 | 头部 CRC 不成立，槽不会被选为可启动 |
| 写镜像体中途 | 镜像哈希不匹配，`slot_image_valid` 失败 |
| 回读校验后、提交前 | 设备仍从旧槽启动；下次安装会重擦目标槽 |
| 提交记录编程中途 | 记录 CRC 不成立，加载时忽略，回退到上一条有效记录 |
| 提交完成之后 | 新槽为 Pending，正常进入试运行 |

- **测试**：`power_cut_at_every_flash_operation_keeps_a_bootable_image`
  （遍历全部 68 个操作点，**零字节撕裂**）、
  `power_cut_halfway_through_every_operation_keeps_a_bootable_image`
  （每个操作点**撕裂一半**）、
  `power_cut_during_boot_metadata_commit_keeps_previous_state`
  （1/64/300/511 字节前缀）、`power_cut_mid_program_torn_sector_never_bootable`。

半途撕裂测试刻意断言“无论断在哪，都只能启动旧镜像”：提交记录必须
整条 512 字节写完才有效，这就是提交的原子性。

### 2.4 新固件本身有问题（能装但不能跑）

签名只证明“来自发布方”，不证明“质量好”。若新固件启动即崩溃：

- 安装后状态是 Pending，`boot_attempts` 每次上电递增；
- 达到上限（3 次）仍未 `confirm`，标记为 Bad 并回退到另一槽；
- 回退后 `counter` 未被污染，仍可安装同 `seq` 的修复包。
- **测试**：`unconfirmed_bad_image_rolls_back_after_max_attempts`、
  `corrupted_active_slot_rolls_back_immediately`。

注意 2.4 的边界：如果新固件能启动、能跑自检、调用 `confirm_running`，
之后才崩溃，那么系统会认为它“好”。这是任何 A/B 方案都无法完全消除的
风险，只能靠更长的稳定性观察窗口（产品策略，非本格式职责）。

### 2.5 刷入别的机型的包

- `product` 与 `hardware` 在包头内（被签名），设备逐字节比较；
- 额外的 `hardware` 约束防止“同一产品不同硬件版本”刷错。
- **测试**：`rejects_product_and_hardware_mismatch`。

### 2.6 使用未授权密钥

- 设备按 `key_id` 选公钥；未知 `key_id` 立即拒绝。
- 即使攻击者把自己的密钥的 `key_id` 伪装成合法值，验签仍会失败。
- **测试**：`package_rejects_wrong_key_and_keyid`。

### 2.7 差分包的基准攻击

攻击者构造“针对某个旧 base”的补丁，试图让设备产出非预期镜像。

- 清单包含 `base_hash`、`base_seq`、`target_image_hash`、`target_image_size`；
- 设备校验活动槽的 `seq` 与 base 实际哈希；
- 应用补丁后校验目标哈希与大小。
- 即使补丁流通过了边界检查，**最终哈希不符仍然拒绝**。
- **测试**：`delta_rejected_when_base_seq_differs`、
  `delta_rejected_when_base_image_tampered`、`delta_detects_wrong_base`、
  `delta_detects_corrupt_patch`、`delta_rejects_truncated_or_oversized_patch`。

### 2.8 畸形输入导致崩溃 / 内存问题

解析器要能在任意字节序列上安全返回“拒绝”。

- 所有长度先做上限检查；乘法/加法用溢出安全函数；
- 补丁应用端每条指令都做边界检查；
- 测试用 ASan + UBSan 跑完整套件；另修掉了 TweetNaCl 中
  “负数左移”的 C++ UB。
- `tests/test_fuzz.cpp` 用固定种子喂入 5500+ 个畸形包/补丁/清单/引导记录，
  断言“绝不接受、绝不崩溃”。**测试**：4 个 `fuzz_*` 用例。

## 3. 明确不防的

| 不防 | 原因 / 建议 |
| --- | --- |
| 攻击者拥有签名私钥 | 密钥管理问题。建议 HSM + 双人审批 + 定期轮换 |
| 设备已被物理控制（可改闪存、改引导器） | 需要安全启动链（ROM 验签第一级引导）、调试口关闭、防拆 |
| 侧信道（功耗/时序） | Ed25519 常量时间实现可加固；本模拟器不涉及 |
| 固件的功能正确性 | 签名只绑定来源，不保证质量。需 CI、灰度、看门狗 |
| 同版本重放之外的“回滚到试运行中版本” | Pending 机制下重装同 seq 会被计数器挡住（若已 confirm） |

## 4. 关键设计取舍

**签名覆盖全包，但验证是流式的。**
设备不缓存整包，只在读取载荷时增量算 SHA-512。这要求 Ed25519 的哈希
恰好是一次消息哈希——RFC 8032 的验签正是如此。签名端需要两遍，但那是
服务端。收益是设备 RAM 占用与镜像大小无关。

**防回滚计数器只在 confirm 后抬升。**
直觉上“安装时就抬升”更严格，但那样会让“坏包 -> 回退”把设备锁在
回退态：回退到的旧镜像 `seq` 低于计数器，下次上电会被判为不可启动。
把抬升点放在“已证明能跑”之后，既保证单调性，又避免自锁。

**引导元数据用追加环而非双备份。**
追加环的每次提交都是一次独立扇区内的单次编程，天然原子；双备份需要
“写 B、校验、再写 A”的三步，每步之间都可能断电，状态机更复杂。
代价是 32 KiB 元数据区（默认），对 MB 级闪存可接受。

**`flags` 中的 `delta` 位是冗余的。**
冗余是为了让解析器在读完 192 字节包头后就能快速判定“这不该被当作完整包
处理”，而不必等到解析清单。冗余字段必须一致，否则拒绝。

## 5. 测试映射总表

| 威胁 | 主要测试 |
| --- | --- |
| 篡改 | `package_rejects_tamper`、`rejects_tampered_package_without_touching_flash` |
| 降级/重放 | `rejects_rollback_and_equal_version`、CLI 重放 |
| 断电 | 4 个 `power_cut_*`（全操作点 + 半撕裂 + 元数据撕裂） |
| 坏固件 | `unconfirmed_bad_image_rolls_back_after_max_attempts` |
| 机型不符 | `rejects_product_and_hardware_mismatch` |
| 密钥不符 | `package_rejects_wrong_key_and_keyid` |
| 差分基准攻击 | 4 个 `delta_*` |
| 闪存语义 | `flash_enforces_erase_before_program`、`flash_persists_across_reopen` |
| 元数据韧性 | `boot_records_survive_many_commits`、`metadata_ring_garbage_records_are_ignored` |
| 密码学正确性 | `sha*_vectors`、`crc32_vector`、`ed25519_rfc8032` |
