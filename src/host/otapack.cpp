// otapack — host-side packaging tool.
//
//   otapack keygen  --seed <file> --out-pub <file> [--out-key-id]
//   otapack pack    --image <file> --version <n> --key <seed-file>
//                   --pub <pub-file> [--device <id>] [--hw-min n] [--hw-max n]
//                   [--out <file>] [--delta-from <old-image> --delta-version <n>]
//                   [--package-id n] [--build-time n] [--builder <str>]
//   otapack verify  --package <file> --pub <pub-file> [--source <image>]
//   otapack info    --package <file>
//
// Exit codes: 0 ok, 1 usage error, 2 verification/policy failure.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "common/crypto.h"
#include "common/status.h"
#include "package/delta.h"
#include "package/format.h"

namespace {

using ota::Error;
using ota::Result;
using ota::Status;

int fail(int code, const std::string& msg) {
  std::cerr << "otapack: " << msg << "\n";
  return code;
}

void usage() {
  std::cout <<
      "usage:\n"
      "  otapack keygen --seed <file> --out-pub <file> [--out-key-id <file>]\n"
      "  otapack pack   --image <file> --version <n> --key <seed> --pub <pub>\n"
      "                 [--device <id>] [--hw-min <n>] [--hw-max <n>]\n"
      "                 [--delta-from <image> --delta-version <n>]\n"
      "                 [--package-id <n>] [--build-time <n>] [--builder <s>]\n"
      "                 [--out <file>]\n"
      "  otapack verify --package <file> --pub <file> [--source <image>]\n"
      "  otapack info   --package <file>\n";
}

struct Args {
  std::vector<std::string> positional;
  std::vector<std::pair<std::string, std::string>> flags;

  bool has(const std::string& k) const {
    for (const auto& f : flags)
      if (f.first == k) return true;
    return false;
  }
  std::string get(const std::string& k, const std::string& def = "") const {
    for (const auto& f : flags)
      if (f.first == k) return f.second;
    return def;
  }
};

Args parse_args(int argc, char** argv, int start, std::string& err) {
  Args a;
  for (int i = start; i < argc; ++i) {
    std::string s = argv[i];
    if (s.rfind("--", 0) == 0) {
      std::string key = s.substr(2);
      if (i + 1 >= argc) {
        err = "flag --" + key + " needs a value";
        return a;
      }
      a.flags.emplace_back(key, argv[++i]);
    } else {
      a.positional.push_back(s);
    }
  }
  return a;
}

uint64_t parse_u64(const std::string& s, bool& ok) {
  ok = false;
  if (s.empty()) return 0;
  char* end = nullptr;
  unsigned long long v = std::strtoull(s.c_str(), &end, 10);
  if (end && *end == '\0') ok = true;
  return static_cast<uint64_t>(v);
}

Result<std::string> read_text(const std::string& path) {
  auto d = ota::pkg::read_file(path);
  if (!d) return d.failure();
  return std::string(reinterpret_cast<const char*>(d.value().data()), d.value().size());
}

Status write_text(const std::string& path, const std::string& text) {
  return ota::pkg::write_file(
      path, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

int cmd_keygen(const Args& a) {
  std::string seed_path = a.get("seed");
  std::string pub_path = a.get("out-pub");
  if (seed_path.empty() || pub_path.empty()) {
    usage();
    return 1;
  }
  ota::crypto::init();
  ota::crypto::Seed seed{};
  // Random seed: the tool never prints or reuses it.
  if (ota::crypto::random_bytes(seed) != 0)
    return fail(2, "cannot read system randomness");
  ota::crypto::PublicKey pk{};
  ota::crypto::SecretKey sk{};
  ota::crypto::keypair_from_seed(seed, pk, sk);
  Status s = write_text(seed_path, ota::crypto::to_hex(seed));
  if (!s) return fail(2, s.message);
  s = write_text(pub_path, ota::crypto::to_hex(pk));
  if (!s) return fail(2, s.message);
  if (a.has("out-key-id")) {
    auto id = ota::crypto::key_id(pk);
    s = write_text(a.get("out-key-id"), ota::crypto::to_hex(id));
    if (!s) return fail(2, s.message);
  }
  std::cout << "public key: " << ota::crypto::to_hex(pk) << "\n"
            << "key id:     " << ota::crypto::to_hex(ota::crypto::key_id(pk)) << "\n"
            << "seed file:  " << seed_path << " (keep offline, never ship)\n";
  return 0;
}

Result<ota::crypto::SecretKey> load_seed(const std::string& path) {
  auto text = read_text(path);
  if (!text) return text.failure();
  std::string hex = text.value();
  while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r' || hex.back() == ' '))
    hex.pop_back();
  std::vector<uint8_t> raw;
  if (!ota::crypto::from_hex(hex, raw) || raw.size() != 32)
    return ota::fail(Error::InvalidArgument, "seed file must contain 64 hex characters");
  ota::crypto::Seed seed{};
  std::memcpy(seed.data(), raw.data(), 32);
  ota::crypto::PublicKey pk{};
  ota::crypto::SecretKey sk{};
  ota::crypto::keypair_from_seed(seed, pk, sk);
  return sk;
}

Result<ota::crypto::PublicKey> load_pub(const std::string& path) {
  auto text = read_text(path);
  if (!text) return text.failure();
  std::string hex = text.value();
  while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r' || hex.back() == ' '))
    hex.pop_back();
  std::vector<uint8_t> raw;
  if (!ota::crypto::from_hex(hex, raw) || raw.size() != 32)
    return ota::fail(Error::InvalidArgument, "public key file must contain 64 hex characters");
  ota::crypto::PublicKey pk{};
  std::memcpy(pk.data(), raw.data(), 32);
  return pk;
}

int cmd_pack(const Args& a) {
  bool ok = false;
  std::string image_path = a.get("image");
  std::string key_path = a.get("key");
  std::string pub_path = a.get("pub");
  if (image_path.empty() || key_path.empty() || pub_path.empty() || !a.has("version")) {
    usage();
    return 1;
  }
  ota::pkg::PackRequest req;
  req.target_version = parse_u64(a.get("version"), ok);
  if (!ok) return fail(1, "--version must be a decimal number");
  auto image = ota::pkg::read_file(image_path);
  if (!image) return fail(2, image.failure().message);
  req.image = image.take();
  req.device_id = a.get("device", "");
  req.builder = a.get("builder", "otapack/1");

  if (a.has("hw-min")) {
    req.hw_min = static_cast<uint32_t>(parse_u64(a.get("hw-min"), ok));
    if (!ok) return fail(1, "--hw-min must be a number");
  }
  if (a.has("hw-max")) {
    req.hw_max = static_cast<uint32_t>(parse_u64(a.get("hw-max"), ok));
    if (!ok) return fail(1, "--hw-max must be a number");
  }
  if (a.has("package-id")) {
    req.package_id = parse_u64(a.get("package-id"), ok);
    if (!ok) return fail(1, "--package-id must be a number");
  }
  if (a.has("build-time")) {
    req.build_time = parse_u64(a.get("build-time"), ok);
    if (!ok) return fail(1, "--build-time must be a number (unix seconds)");
  }

  if (a.has("delta-from")) {
    if (!a.has("delta-version")) return fail(1, "--delta-from requires --delta-version");
    auto src = ota::pkg::read_file(a.get("delta-from"));
    if (!src) return fail(2, "source image: " + src.failure().message);
    req.delta = true;
    req.source_image = src.take();
    req.source_version = parse_u64(a.get("delta-version"), ok);
    if (!ok) return fail(1, "--delta-version must be a number");
  }

  auto sk = load_seed(key_path);
  if (!sk) return fail(2, sk.failure().message);
  auto pk = load_pub(pub_path);
  if (!pk) return fail(2, pk.failure().message);

  auto built = ota::pkg::build_package(req, sk.value(), pk.value());
  if (!built) return fail(2, built.failure().message);

  std::string out = a.get("out");
  if (out.empty()) out = "update-v" + std::to_string(req.target_version) + ".otap";
  Status s = ota::pkg::write_file(out, built.value());
  if (!s) return fail(2, s.message);
  std::cout << "wrote " << out << " (" << built.value().size() << " bytes, "
            << (req.delta ? "delta" : "full") << ", version " << req.target_version << ")\n";
  return 0;
}

int cmd_verify(const Args& a) {
  std::string path = a.get("package");
  std::string pub_path = a.get("pub");
  if (path.empty() || pub_path.empty()) {
    usage();
    return 1;
  }
  auto blob = ota::pkg::read_file(path);
  if (!blob) return fail(2, blob.failure().message);
  auto pk = load_pub(pub_path);
  if (!pk) return fail(2, pk.failure().message);

  auto parsed = ota::pkg::parse_package(blob.value());
  if (!parsed) return fail(2, parsed.failure().message);

  if (!parsed.value().header.is_delta()) {
    Status s = ota::pkg::verify_signature(parsed.value(), parsed.value().payload, pk.value());
    if (!s) return fail(2, s.message);
    std::cout << "OK: full package, version " << parsed.value().manifest.target_version
              << ", signature valid\n";
    return 0;
  }
  if (!a.has("source")) {
    return fail(2, "delta package: pass --source <image> to verify and apply");
  }
  auto src = ota::pkg::read_file(a.get("source"));
  if (!src) return fail(2, src.failure().message);
  if (ota::crypto::sha256(src.value()) != parsed.value().manifest.source_image_sha256)
    return fail(2, "source image does not match the package's signed source hash");
  auto rebuilt = ota::delta::apply_to_buffer(parsed.value().payload, src.value(),
                                             parsed.value().manifest.entries.at(0).image_size);
  if (!rebuilt) return fail(2, rebuilt.failure().message);
  Status s = ota::pkg::verify_signature(parsed.value(), rebuilt.value(), pk.value());
  if (!s) return fail(2, s.message);
  std::cout << "OK: delta package, version " << parsed.value().manifest.target_version
            << ", reconstructed image verified\n";
  return 0;
}

int cmd_info(const Args& a) {
  std::string path = a.get("package");
  if (path.empty()) {
    usage();
    return 1;
  }
  auto blob = ota::pkg::read_file(path);
  if (!blob) return fail(2, blob.failure().message);
  auto parsed = ota::pkg::parse_package(blob.value());
  if (!parsed) return fail(2, parsed.failure().message);
  const auto& p = parsed.value();
  std::cout << "format:         OTAP v" << p.header.format_version << "\n"
            << "kind:           " << (p.header.is_delta() ? "delta" : "full") << "\n"
            << "package id:     " << p.manifest.package_id << "\n"
            << "target version: " << p.manifest.target_version << "\n"
            << "source version: " << p.manifest.source_version << "\n"
            << "device id:      '" << p.manifest.device_id << "'\n"
            << "hw range:       " << p.manifest.hw_min << ".." << p.manifest.hw_max << "\n"
            << "build time:     " << p.manifest.build_time << "\n"
            << "builder:        " << p.manifest.builder << "\n"
            << "manifest bytes: " << p.manifest_bytes.size() << "\n"
            << "payload bytes:  " << p.payload.size() << "\n"
            << "image bytes:    " << p.manifest.entries.at(0).image_size << "\n"
            << "image sha256:   " << ota::crypto::to_hex(p.manifest.entries.at(0).image_sha256)
            << "\n"
            << "key id:         " << ota::crypto::to_hex(p.header.key_id) << "\n"
            << "signature:      " << ota::crypto::to_hex(p.signature) << "\n";
  if (p.header.is_delta()) {
    std::cout << "source sha256:  " << ota::crypto::to_hex(p.manifest.source_image_sha256) << "\n";
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 1;
  }
  std::string cmd = argv[1];
  std::string err;
  Args a = parse_args(argc, argv, 2, err);
  if (!err.empty()) return fail(1, err);
  try {
    if (cmd == "keygen") return cmd_keygen(a);
    if (cmd == "pack") return cmd_pack(a);
    if (cmd == "verify") return cmd_verify(a);
    if (cmd == "info") return cmd_info(a);
    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
      usage();
      return 0;
    }
    return fail(1, "unknown command '" + cmd + "'");
  } catch (const std::exception& e) {
    return fail(2, std::string("error: ") + e.what());
  }
}
