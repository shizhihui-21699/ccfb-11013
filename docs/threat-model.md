# 威胁模型与安全边界

本文说明"防住了什么、没防住什么"。OTA 的安全强度取决于信任根的边界；把边界写清楚比夸大防护更重要。

## 1. 信任根

设备固件**内置**一个 Ed25519 公钥（`DeviceConfig::public_key`）。这是整个系统的唯一信任根：

* 私钥只存在于离线签名环境；`otapack keygen` 生成的 seed 文件不进入任何仓库（`.gitignore` 已排除 `*.key` / `*.pem` / `secrets.*`）。
* 设备只接受 `key_id == SHA-256(pubkey)[0..8]` 的包，并在验签时使用完整 32 字节公钥。
* 轮换密钥需要同时更新设备固件并接受过渡期双密钥——当前版本未实现密钥轮换，这属于后续工作。

## 2. 明确防住的攻击

| 攻击 | 防护 | 测试 |
|---|---|---|
| 改包内任意一个字节 | 签名覆盖 manifest + 目标镜像 | `package_rejects_every_single_byte_flip`（逐字节） |
| 截断 / 追加 / 拼接两个包 | 精确长度检查 + manifest 长度自洽 + 签名绑定 | `package_rejects_truncation_and_extension`、`package_rejects_spliced_payload` |
| 用别的设备/厂商的包 | device_id + hw 范围 + key_id + 签名 | `install_rejects_wrong_device_and_hw` |
| 用攻击者自己的密钥重签 | key_id 与验签都不通过 | `install_rejects_forged_signature_from_other_key` |
| 降级到有漏洞的旧版 | 单调计数器 `target > counter` | `rollback_to_older_package_is_rejected` |
| 重放一个旧的合法签名包（重新安装） | 安装下限：旧版本号 < installed_floor | `replay_of_old_signed_package_after_upgrade_is_rejected` |
| 保留旧槽、改元数据指向旧的已签名镜像（不重装，直接让它启动） | 启动下限：验签版本 < booted_floor 就拒绝启动 | `offline_downgrade_by_repointing_metadata_is_blocked` |
| 把差分包指向别的源镜像 | 源镜像哈希在签名 manifest 内，设备比对活动镜像真实哈希 | `delta_from_wrong_source_is_rejected` |
| 恶意差分指令（越界读/写、超长输出） | 每个 COPY 边界检查 + 输出尺寸精确匹配 | `delta_rejects_hostile_streams` |
| 改写槽头伪造版本号 | 槽头只是索引；启动时重新哈希镜像并验签 manifest | `tampering_with_image_inside_a_slot_blocks_that_boot` |
| 破坏元数据让设备乱选槽 | 无元数据时扫描两槽选"能验签的最高版本" | `metadata_corruption_does_not_select_garbage` |
| 擦掉计数器让版本下限回退 | 计数器两份冗余副本，单扇区丢失不降低任一上下限 | `counter_sector_corruption_cannot_lower_the_bar` |
| 升级过程中断电（任意时刻） | 所有结构"先写新副本后擦旧副本"；安装顺序保证可重试 | `powerloss_*`（逐操作扫描） |
| 新固件起不来 | trial 次数耗尽自动回退；`mark_unhealthy` 立即回退 | `trial_counts_down_then_reverts`、`explicit_unhealthy_marks_revert` |

## 3. 明确不防（或依赖其他手段）

* **能同时擦除两个计数器扇区 + 保留旧镜像的攻击者**：这等价于物理拆除防回滚熔丝（即"整片闪存回滚"）。生产环境应把单调计数器放在真正的 OTP/eFuse/防拆区，而不是普通 NOR。本仓库用双扇区冗余模拟"单扇区擦除不可降级"，但整片回滚仍超出软件能力，需硬件信任根。
* **签名私钥泄露**：签名基础设施的安全不在固件范围内。建议硬件 HSM / 离线签名机。
* **设备固件本身被完全替换（含信任公钥）**：需要安全启动（ROM 验签）作为第一级信任根，OTA 是第二级。本项目不实现安全启动。
* **拒绝服务（反复擦写闪存磨损）**：未实现磨损均衡与写次数限制。
* **回滚到"同版本但不同构建"**：下限只比较版本号，不区分同版本的不同构建。若需要，可把构建号纳入单调空间。
* **整片闪存回滚（把计数器扇区一起恢复到旧状态）**：软件层无法阻止，因为攻击者同时恢复了"下限"本身。生产环境须把单调计数器放在真正的 OTP/eFuse（不可擦写）中，或由安全芯片维护。本项目用双扇区冗余模拟"单扇区擦除不可降级"，但不掩盖这一边界。
* **差分包的源镜像保密性**：差分本身不加密；如果镜像含机密，需要额外加密层（v1 未提供）。

## 4. 关于元数据不做 MAC 的说明

`BootMeta` 只做 CRC，不做签名/MAC。这是有意的取舍：

* 元数据能让攻击者做的事只有"让设备去启动另一个槽"；
* 两个槽在启动前都会各自独立验签，攻击者无法借此执行未签名代码；
* 版本下限来自单调计数器（独立存储、与签名 manifest 交叉校验），不来自元数据；
* 若给元数据加 MAC，密钥又必须在设备上，安全增益有限，而每次启动多一次运算；CRC 已覆盖真正会让它出错的原因（断电撕裂）。

## 5. 测试如何覆盖这些声明

* 逐字节翻转/逐位翻转：证明"签名覆盖了每一个字节"不是口头承诺。
* 恶意差分流：手工构造越界、超长、缺 END、未知操作码四类，全部必须被拒。
* 断电扫描：先测出一次干净安装的闪存操作总数 N，然后对每个 k ∈ [1,N] 在第 k 次操作撕裂，共 N 次重启验证。不变式：设备始终可启动、启动的镜像始终验签通过、版本只能是旧版或新版、计数器不倒退、重试后可完成升级。
