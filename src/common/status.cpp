#include "common/status.h"

namespace ota {

const char* to_string(Error e) {
  switch (e) {
    case Error::Ok: return "ok";
    case Error::InvalidArgument: return "invalid argument";
    case Error::IoError: return "i/o error";
    case Error::NotFound: return "not found";
    case Error::AlreadyInitialized: return "already initialized";
    case Error::Busy: return "busy";
    case Error::BadMagic: return "bad magic";
    case Error::UnsupportedVersion: return "unsupported format version";
    case Error::Malformed: return "malformed structure";
    case Error::SizeMismatch: return "size mismatch";
    case Error::SignatureInvalid: return "signature invalid";
    case Error::ManifestInvalid: return "manifest invalid";
    case Error::Incompatible: return "incompatible device/package";
    case Error::RollbackRejected: return "rollback rejected";
    case Error::DeltaInvalid: return "delta stream invalid";
    case Error::DeltaSourceMismatch: return "delta source image mismatch";
    case Error::ImageHashMismatch: return "image hash mismatch";
    case Error::SlotTooSmall: return "slot too small";
    case Error::FlashRange: return "flash access out of range";
    case Error::FlashProgram: return "flash program failed (not erased)";
    case Error::PowerLost: return "simulated power loss";
    case Error::MetaCorrupt: return "metadata corrupt";
    case Error::CounterCorrupt: return "counter corrupt";
    case Error::NoValidSlot: return "no valid slot";
  }
  return "unknown error";
}

}  // namespace ota
