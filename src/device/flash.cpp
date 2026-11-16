#include "device/flash.h"

#include <algorithm>
#include <cstring>

namespace ota {
namespace {
constexpr uint32_t kSectorSize = 4096;
}

struct Flash::Impl {
  std::vector<uint8_t> bytes;
  uint64_t ops_until_cut = UINT64_MAX;
  bool cut_armed = false;
  bool dead = false;
  uint64_t completed = 0;

  enum class OpState { Proceed, Tear, Dead };

  // Dead: nothing happens at all. Tear: the operation lands partially and the
  // device then powers off. Proceed: normal operation.
  OpState begin_op() {
    if (dead) return OpState::Dead;
    if (cut_armed && ops_until_cut == 0) {
      dead = true;
      return OpState::Tear;
    }
    return OpState::Proceed;
  }
  void end_op() {
    ++completed;
    if (cut_armed && ops_until_cut > 0) --ops_until_cut;
  }
};

Flash::Flash(size_t size) : impl_(new Impl()) {
  impl_->bytes.assign(size, 0xFF);
}

Flash::~Flash() = default;
Flash::Flash(Flash&&) noexcept = default;
Flash& Flash::operator=(Flash&&) noexcept = default;

size_t Flash::size() const { return impl_->bytes.size(); }
uint32_t Flash::sector_size() const { return kSectorSize; }
size_t Flash::sector_count() const { return impl_->bytes.size() / kSectorSize; }

Result<std::vector<uint8_t>> Flash::read(uint64_t offset, size_t length) const {
  if (offset > impl_->bytes.size() || length > impl_->bytes.size() - offset)
    return fail(Error::FlashRange, "read out of range");
  std::vector<uint8_t> out(length);
  std::memcpy(out.data(), impl_->bytes.data() + offset, length);
  return out;
}

Status Flash::read_into(uint64_t offset, std::span<uint8_t> out) const {
  if (offset > impl_->bytes.size() || out.size() > impl_->bytes.size() - offset)
    return fail(Error::FlashRange, "read out of range");
  std::memcpy(out.data(), impl_->bytes.data() + offset, out.size());
  return Status{};
}

Status Flash::program(uint64_t offset, std::span<const uint8_t> data) {
  if (offset > impl_->bytes.size() || data.size() > impl_->bytes.size() - offset)
    return fail(Error::FlashRange, "program out of range");
  switch (impl_->begin_op()) {
    case Impl::OpState::Dead:
      return fail(Error::PowerLost, "device is powered off");
    case Impl::OpState::Tear:
      // Tear mid-program: a prefix of the bytes lands, the rest never gets
      // written. A non-erased cell still refuses the write, same as hardware.
      break;
    case Impl::OpState::Proceed:
      for (size_t i = 0; i < data.size(); ++i) {
        if ((impl_->bytes[offset + i] & data[i]) != data[i])
          return fail(Error::FlashProgram, "program requires erase (0 -> 1 transition)");
      }
      std::memcpy(impl_->bytes.data() + offset, data.data(), data.size());
      impl_->end_op();
      return Status{};
  }
  for (size_t i = 0; i < data.size(); ++i) {
    if ((impl_->bytes[offset + i] & data[i]) != data[i])
      return fail(Error::FlashProgram, "program requires erase (0 -> 1 transition)");
  }
  // Deterministic tear point: at least one byte is always lost so tests see a
  // genuinely partial record, not an all-or-nothing abort.
  size_t torn = data.size() / 2;
  for (size_t i = 0; i < torn; ++i) impl_->bytes[offset + i] &= data[i];
  return fail(Error::PowerLost, "power lost during program (torn write)");
}

Status Flash::erase_sector(size_t sector_index) {
  uint64_t offset = static_cast<uint64_t>(sector_index) * kSectorSize;
  if (offset + kSectorSize > impl_->bytes.size())
    return fail(Error::FlashRange, "sector out of range");
  switch (impl_->begin_op()) {
    case Impl::OpState::Dead:
      return fail(Error::PowerLost, "device is powered off");
    case Impl::OpState::Tear: {
      // A torn erase leaves a partially erased sector.
      auto first = impl_->bytes.begin() + static_cast<std::ptrdiff_t>(offset);
      std::fill(first, first + static_cast<std::ptrdiff_t>(kSectorSize / 2), 0xFF);
      return fail(Error::PowerLost, "power lost during erase");
    }
    case Impl::OpState::Proceed: {
      auto first = impl_->bytes.begin() + static_cast<std::ptrdiff_t>(offset);
      std::fill(first, first + static_cast<std::ptrdiff_t>(kSectorSize), 0xFF);
      impl_->end_op();
      return Status{};
    }
  }
  return fail(Error::PowerLost, "power lost during erase");
}

Status Flash::erase_range(uint64_t offset, size_t length) {
  uint64_t end = offset + length;
  if (offset % kSectorSize != 0 || end > impl_->bytes.size())
    return fail(Error::FlashRange, "erase range must be sector aligned and in bounds");
  for (uint64_t s = offset; s < end; s += kSectorSize) {
    Status st = erase_sector(static_cast<size_t>(s / kSectorSize));
    if (!st) return st;
  }
  return Status{};
}

bool Flash::is_erased(uint64_t offset, size_t length) const {
  if (offset > impl_->bytes.size() || length > impl_->bytes.size() - offset) return false;
  for (size_t i = 0; i < length; ++i)
    if (impl_->bytes[offset + i] != 0xFF) return false;
  return true;
}

void Flash::arm_power_cut(uint64_t ops_until_cut) {
  impl_->cut_armed = true;
  impl_->ops_until_cut = ops_until_cut;
  impl_->dead = false;
}

bool Flash::dead() const { return impl_->dead; }

void Flash::power_restore() {
  impl_->cut_armed = false;
  impl_->ops_until_cut = UINT64_MAX;
  impl_->dead = false;
}

uint64_t Flash::completed_ops() const { return impl_->completed; }

Result<std::vector<uint8_t>> Flash::dump() const { return impl_->bytes; }

Status Flash::load(std::span<const uint8_t> data) {
  if (data.size() != impl_->bytes.size())
    return fail(Error::InvalidArgument, "flash image size does not match device");
  std::memcpy(impl_->bytes.data(), data.data(), data.size());
  return Status{};
}

}  // namespace ota
