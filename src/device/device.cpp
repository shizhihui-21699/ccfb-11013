// SPDX-License-Identifier: MIT
#include "device.h"

#include <algorithm>
#include <cstring>

#include "crc32.h"
#include "delta.h"
#include "flash.h"
#include "sha256.h"

namespace ota {
namespace {

// 槽内镜像头固定放在槽起始处，载荷紧随其后。
constexpr uint64_t kSlotHeaderSize = 128;

}  // namespace

const char* install_result_name(InstallResult r) {
  switch (r) {
    case InstallResult::kOk:
      return "ok";
    case InstallResult::kRejectedFormat:
      return "rejected-format";
    case InstallResult::kRejectedSignature:
      return "rejected-signature";
    case InstallResult::kRejectedProduct:
      return "rejected-product";
    case InstallResult::kRejectedHardware:
      return "rejected-hardware";
    case InstallResult::kRejectedRollback:
      return "rejected-rollback";
    case InstallResult::kRejectedNoSpace:
      return "rejected-no-space";
    case InstallResult::kRejectedBaseMismatch:
      return "rejected-base-mismatch";
    case InstallResult::kRejectedInterrupted:
      return "rejected-interrupted";
  }
  return "?";
}

BootState read_boot_state(SimFlash* flash, const DeviceConfig& cfg) {
  BootControl bc(flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  return bc.load();
}

uint8_t DeviceUpdater::select_target_slot(const BootState& state) {
  uint8_t active = state.active_slot;
  uint8_t other = inactive_slot(active);
  if (state.slots[active].state == SlotState::kGood) return other;
  if (state.slots[other].state == SlotState::kGood) return active;
  return active;
}

DeviceUpdater::DeviceUpdater(SimFlash* flash, DeviceConfig cfg)
    : flash_(flash), cfg_(std::move(cfg)) {
  if (cfg_.layout.total_needed() > flash_->size()) {
    fail(OtaError::kNoSpace, "分区表超出闪存容量");
  }
}

void DeviceUpdater::erase_slot(uint8_t slot) {
  uint64_t begin = cfg_.layout.slot_offset[slot];
  uint64_t end = begin + cfg_.layout.slot_size[slot];
  for (uint64_t off = begin; off < end; off += cfg_.layout.sector_size) {
    flash_->erase_sector(off);
  }
}

Bytes DeviceUpdater::read_slot_image_bytes(uint8_t slot, const SlotMeta& meta) {
  if (meta.image_size > cfg_.layout.slot_size[slot] - kSlotHeaderSize) {
    fail(OtaError::kNoSpace, "槽内镜像超出容量");
  }
  return flash_->read(cfg_.layout.slot_offset[slot] + kSlotHeaderSize,
                      static_cast<size_t>(meta.image_size));
}

DeviceUpdater::Prepared DeviceUpdater::prepare(const Bytes& package, const BootState& state) {
  // 设备路径使用分块流式验签：常量内存，不需要第二个整包缓冲。
  VerifiedPackage vp = verify_package_streaming(package, cfg_.public_key, cfg_.key_id, 4096);

  Prepared p;
  p.header = vp.header;
  p.manifest = vp.manifest;

  // 产品/硬件绑定：防止把别的机型的包刷进来。
  if (vp.header.product_str() != cfg_.product) {
    fail(OtaError::kProductMismatch,
         "产品不匹配：包=" + vp.header.product_str() + " 设备=" + cfg_.product);
  }
  if (vp.header.hardware_str() != cfg_.hardware) {
    fail(OtaError::kHardwareMismatch,
         "硬件版本不匹配：包=" + vp.header.hardware_str() + " 设备=" + cfg_.hardware);
  }

  // 防回滚：安全版本号必须严格大于已确认的单调计数器。
  if (vp.header.seq <= state.counter) {
    fail(OtaError::kAntiRollback,
         "降级被拒绝：包 seq=" + std::to_string(vp.header.seq) +
             " 不高于设备计数器=" + std::to_string(state.counter));
  }
  if (vp.manifest.rollback_floor != 0 && vp.header.seq < vp.manifest.rollback_floor) {
    fail(OtaError::kAntiRollback, "包的 seq 低于其清单声明的回滚下限");
  }

  const uint8_t* payload = package.data() + vp.header.payload_offset();
  if (vp.header.type == PackageType::kFull) {
    p.image.assign(payload, payload + vp.header.payload_len);
  } else {
    p.used_delta = true;
    // 差分的 base 是“当前实际运行的镜像”。只有处于 Good 或 Pending 的槽
    // 可能是运行中的镜像；Empty/Bad 都不能当基准。
    uint8_t base_slot = state.active_slot;
    const SlotMeta& base_meta = state.slots[base_slot];
    if (base_meta.state != SlotState::kGood && base_meta.state != SlotState::kPending) {
      fail(OtaError::kBaseMismatch, "差分包需要一个可用的 base 镜像，当前活动槽不可用");
    }
    if (select_target_slot(state) == base_slot) {
      // 目标槽就是 base 所在的槽：应用补丁时会把它擦掉。设备端本可以把
      // 补丁结果先缓存，但那需要额外的 RAM/闪存；这里明确拒绝，要求先
      // 切到另一槽后再做差分。
      fail(OtaError::kBaseMismatch,
           "差分包不能安装到其 base 所在的槽（当前没有安全的备用槽）");
    }
    if (base_meta.seq != vp.manifest.base_seq) {
      fail(OtaError::kBaseMismatch,
           "差分基准版本不符：清单 base_seq=" + std::to_string(vp.manifest.base_seq) +
               " 设备=" + std::to_string(base_meta.seq));
    }
    if (vp.manifest.target_image_size > cfg_.max_image_bytes) {
      fail(OtaError::kNoSpace, "目标镜像超过设备允许的镜像上限");
    }
    Bytes base = read_slot_image_bytes(base_slot, base_meta);
    if (Sha256::hash(base) != base_meta.image_hash) {
      fail(OtaError::kBaseMismatch, "base 镜像与其记录的哈希不符");
    }
    if (vp.manifest.base_hash.size() != 32 ||
        std::memcmp(vp.manifest.base_hash.data(), base_meta.image_hash.data(), 32) != 0) {
      fail(OtaError::kBaseMismatch, "base 哈希与清单不符");
    }
    Bytes patch(payload, payload + vp.header.payload_len);
    p.image = delta_apply(base, patch, vp.manifest.target_image_size,
                          vp.manifest.target_image_hash);
  }

  if (static_cast<uint64_t>(p.image.size()) + kSlotHeaderSize > cfg_.layout.slot_size[0]) {
    fail(OtaError::kNoSpace, "镜像超过槽容量");
  }
  return p;
}

InstallOutcome DeviceUpdater::install(const Bytes& package) {
  InstallOutcome out;

  BootState state = read_boot_state(flash_, cfg_);
  Prepared prep;
  try {
    prep = prepare(package, state);
  } catch (const OtaError& e) {
    out.detail = e.what();
    switch (e.code()) {
      case OtaError::kBadSignature:
        out.result = InstallResult::kRejectedSignature;
        break;
      case OtaError::kProductMismatch:
        out.result = InstallResult::kRejectedProduct;
        break;
      case OtaError::kHardwareMismatch:
        out.result = InstallResult::kRejectedHardware;
        break;
      case OtaError::kAntiRollback:
        out.result = InstallResult::kRejectedRollback;
        break;
      case OtaError::kNoSpace:
        out.result = InstallResult::kRejectedNoSpace;
        break;
      case OtaError::kBaseMismatch:
      case OtaError::kBadDelta:
        out.result = InstallResult::kRejectedBaseMismatch;
        break;
      case OtaError::kIo:
        out.result = InstallResult::kRejectedInterrupted;
        out.detail = "升级中断：" + std::string(e.what());
        break;
      default:
        out.result = InstallResult::kRejectedFormat;
        break;
    }
    return out;
  }

  return install_prepared(prep, state);
}

InstallOutcome DeviceUpdater::install_prepared(const Prepared& prep, const BootState& state) {
  InstallOutcome out;
  out.seq = prep.header.seq;
  out.used_delta = prep.used_delta;
  out.target_slot = select_target_slot(state);

  try {
    uint8_t target = out.target_slot;

    // 步骤 1：擦除目标槽。
    erase_slot(target);

    // 步骤 2：写槽内镜像头与镜像载荷。
    ImageHeader ih;
    ih.seq = prep.header.seq;
    ih.image_size = prep.image.size();
    ih.image_hash = Sha256::hash(prep.image);
    ih.version = fixed_string<32>(prep.manifest.image_version, "image_version");
    ih.product = fixed_string<24>(cfg_.product, "product");
    ih.hardware = fixed_string<16>(cfg_.hardware, "hardware");
    Bytes hdr = ih.serialize();

    uint64_t slot_base = cfg_.layout.slot_offset[target];
    flash_->program(slot_base, hdr.data(), hdr.size());
    out.bytes_written += hdr.size();
    flash_->program(slot_base + kSlotHeaderSize, prep.image.data(), prep.image.size());
    out.bytes_written += prep.image.size();

    // 步骤 3：回读校验（闪存写入可能出错，必须验证落地后的字节）。
    Bytes readback = flash_->read(slot_base + kSlotHeaderSize, prep.image.size());
    if (Sha256::hash(readback) != ih.image_hash) {
      fail(OtaError::kBadHash, "槽内回读哈希不匹配，写入可能损坏");
    }
    Bytes hdr_read = flash_->read(slot_base, ImageHeader::kSize);
    ImageHeader parsed = ImageHeader::parse(hdr_read.data(), hdr_read.size());
    if (parsed.image_hash != ih.image_hash || parsed.image_size != ih.image_size ||
        parsed.seq != ih.seq) {
      fail(OtaError::kBadHash, "槽内镜像头回读不一致");
    }

    // 步骤 4：最后提交引导状态。
    BootState next = state;
    next.slots[target].state = SlotState::kPending;
    next.slots[target].seq = prep.header.seq;
    next.slots[target].image_size = prep.image.size();
    next.slots[target].image_hash = ih.image_hash;
    std::memcpy(next.slots[target].version, ih.version.data(), ih.version.size());
    next.active_slot = target;
    next.boot_attempts = 0;
    BootControl bc(flash_, cfg_.layout.boot_meta_offset, cfg_.layout.boot_meta_sectors);
    bc.commit(next);

    out.result = InstallResult::kOk;
    return out;
  } catch (const OtaError& e) {
    if (e.code() == OtaError::kIo) {
      out.result = InstallResult::kRejectedInterrupted;
      out.detail = "升级中断（断电模拟）：" + std::string(e.what());
    } else {
      out.result = InstallResult::kRejectedFormat;
      out.detail = e.what();
    }
    return out;
  }
}

// ---------------- 启动与自检 ----------------

namespace {

bool slot_image_valid(SimFlash* flash, const DeviceConfig& cfg, uint8_t slot,
                      const SlotMeta& meta, std::string* reason) {
  if (meta.state == SlotState::kEmpty) {
    *reason = "槽为空";
    return false;
  }
  if (meta.state == SlotState::kBad) {
    *reason = "槽被标记为坏";
    return false;
  }
  uint64_t base = cfg.layout.slot_offset[slot];
  Bytes hdr_bytes;
  try {
    hdr_bytes = flash->read(base, ImageHeader::kSize);
  } catch (const OtaError& e) {
    *reason = std::string("读镜像头失败：") + e.what();
    return false;
  }
  ImageHeader ih;
  try {
    ih = ImageHeader::parse(hdr_bytes.data(), hdr_bytes.size());
  } catch (const OtaError& e) {
    *reason = e.what();
    return false;
  }
  if (ih.seq != meta.seq || ih.image_size != meta.image_size ||
      ih.image_hash != meta.image_hash) {
    *reason = "镜像头与引导元数据不一致";
    return false;
  }
  if (ih.image_size > cfg.layout.slot_size[slot] - ImageHeader::kSize) {
    *reason = "镜像大小超出槽容量";
    return false;
  }
  Bytes image = flash->read(base + ImageHeader::kSize, static_cast<size_t>(ih.image_size));
  if (Sha256::hash(image) != ih.image_hash) {
    *reason = "镜像哈希不匹配";
    return false;
  }
  return true;
}

BootState commit_state(SimFlash* flash, const DeviceConfig& cfg, const BootState& s) {
  BootControl bc(flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  return bc.commit(s);
}

}  // namespace

BootDecision boot_and_select(SimFlash* flash, const DeviceConfig& cfg) {
  BootControl bc(flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  BootState state = bc.load();
  BootDecision d;

  uint8_t active = state.active_slot;
  uint8_t other = DeviceUpdater::inactive_slot(active);
  std::string reason;

  if (slot_image_valid(flash, cfg, active, state.slots[active], &reason)) {
    if (state.slots[active].state == SlotState::kPending) {
      if (state.boot_attempts >= kMaxBootAttempts) {
        // 多次试运行均未确认：判定新镜像不可用，回退。
        BootState next = state;
        next.slots[active].state = SlotState::kBad;
        next.boot_attempts = 0;
        std::string other_reason;
        if (slot_image_valid(flash, cfg, other, state.slots[other], &other_reason)) {
          next.active_slot = other;
          commit_state(flash, cfg, next);
          d.action = BootDecision::kRollback;
          d.slot = other;
          d.reason = "pending 槽连续 " + std::to_string(state.boot_attempts) +
                     " 次未确认，回退到另一槽";
          return d;
        }
        commit_state(flash, cfg, next);
        d.action = BootDecision::kNoBootable;
        d.reason = "pending 槽自检失败且无可回退镜像";
        return d;
      }
      BootState next = state;
      next.boot_attempts = static_cast<uint8_t>(state.boot_attempts + 1);
      commit_state(flash, cfg, next);
      d.action = BootDecision::kBootPending;
      d.slot = active;
      d.reason = "试运行 pending 镜像（第 " + std::to_string(next.boot_attempts) + " 次尝试）";
      return d;
    }
    d.action = BootDecision::kBootGood;
    d.slot = active;
    d.reason = "启动已验证镜像";
    return d;
  }

  // 活动槽不可用：尝试回退。
  std::string other_reason;
  if (slot_image_valid(flash, cfg, other, state.slots[other], &other_reason)) {
    BootState next = state;
    next.slots[active].state = SlotState::kBad;
    next.active_slot = other;
    next.boot_attempts = 0;
    commit_state(flash, cfg, next);
    d.action = BootDecision::kRollback;
    d.slot = other;
    d.reason = "活动槽不可用（" + reason + "），回退到另一槽";
    return d;
  }

  d.action = BootDecision::kNoBootable;
  d.reason = "两个槽都不可启动（活动槽：" + reason + "；另一槽：" + other_reason + "）";
  return d;
}

BootState confirm_running(SimFlash* flash, const DeviceConfig& cfg, uint8_t slot) {
  BootControl bc(flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  BootState state = bc.load();
  if (state.active_slot != slot) {
    fail(OtaError::kMetadata, "确认的槽不是当前活动槽");
  }
  SlotMeta& m = state.slots[slot];
  if (m.state == SlotState::kEmpty) fail(OtaError::kMetadata, "确认了一个空槽");
  m.state = SlotState::kGood;
  state.boot_attempts = 0;
  if (m.seq > state.counter) state.counter = m.seq;
  return bc.commit(state);
}

void write_good_image(SimFlash* flash, const DeviceConfig& cfg, uint8_t slot,
                      const Bytes& image, uint64_t seq, const std::string& version) {
  if (image.size() + ImageHeader::kSize > cfg.layout.slot_size[slot]) {
    fail(OtaError::kNoSpace, "镜像放不进槽");
  }
  uint64_t base = cfg.layout.slot_offset[slot];
  for (uint64_t off = base; off < base + cfg.layout.slot_size[slot];
       off += cfg.layout.sector_size) {
    flash->erase_sector(off);
  }
  Hash256 h = Sha256::hash(image);
  ImageHeader ih;
  ih.seq = seq;
  ih.image_size = image.size();
  ih.image_hash = h;
  ih.version = fixed_string<32>(version, "version");
  ih.product = fixed_string<24>(cfg.product, "product");
  ih.hardware = fixed_string<16>(cfg.hardware, "hardware");
  Bytes hdr = ih.serialize();
  flash->program(base, hdr.data(), hdr.size());
  flash->program(base + ImageHeader::kSize, image.data(), image.size());

  BootControl bc(flash, cfg.layout.boot_meta_offset, cfg.layout.boot_meta_sectors);
  BootState s = bc.load();
  s.slots[slot].state = SlotState::kGood;
  s.slots[slot].seq = seq;
  s.slots[slot].image_size = image.size();
  s.slots[slot].image_hash = h;
  std::memcpy(s.slots[slot].version, ih.version.data(), ih.version.size());
  s.active_slot = slot;
  s.boot_attempts = 0;
  if (seq > s.counter) s.counter = seq;
  bc.commit(s);
}

}  // namespace ota
