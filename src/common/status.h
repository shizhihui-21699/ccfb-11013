// Error/result plumbing shared by the packaging tool and the device module.
#pragma once

#include <optional>
#include <string>
#include <utility>

namespace ota {

enum class Error {
  Ok = 0,
  // Generic
  InvalidArgument,
  IoError,
  NotFound,
  AlreadyInitialized,
  Busy,
  // Package structure
  BadMagic,
  UnsupportedVersion,
  Malformed,
  SizeMismatch,
  SignatureInvalid,
  ManifestInvalid,
  Incompatible,
  // Update policy
  RollbackRejected,
  DeltaInvalid,
  DeltaSourceMismatch,
  ImageHashMismatch,
  SlotTooSmall,
  // Flash / persistence
  FlashRange,
  FlashProgram,
  PowerLost,
  MetaCorrupt,
  CounterCorrupt,
  NoValidSlot,
};

const char* to_string(Error e);

struct Failure {
  Error code = Error::Ok;
  std::string message;
};

inline Failure fail(Error code, std::string message) {
  return Failure{code, std::move(message)};
}

// Status is used for operations that produce no value.
struct Status {
  Error code = Error::Ok;
  std::string message;

  Status() = default;
  Status(Failure f) : code(f.code), message(std::move(f.message)) {}

  bool ok() const { return code == Error::Ok; }
  explicit operator bool() const { return ok(); }

  // Lets a failed Status be propagated through Result<T> returns.
  Failure failure() const { return Failure{code, message}; }
};

template <typename T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}
  Result(Failure f) : failure_(std::move(f)) {}
  Result(Status s) : failure_(s.failure()) {}

  bool ok() const { return value_.has_value(); }
  explicit operator bool() const { return ok(); }

  T& value() { return *value_; }
  const T& value() const { return *value_; }
  T take() { return std::move(*value_); }

  T value_or(T fallback) const { return value_.has_value() ? *value_ : std::move(fallback); }

  const Failure& failure() const { return failure_; }

 private:
  std::optional<T> value_;
  Failure failure_{};
};

}  // namespace ota
