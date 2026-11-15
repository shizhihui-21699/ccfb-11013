// SPDX-License-Identifier: MIT
// otatool —— 服务端打包与检查工具（命令行）。
//
//   otatool keygen  --secret sk.txt --public pk.txt
//   otatool pack    --key sk.txt --image new.bin --seq 12 --version 2.3.0
//                   --product dev-x --hardware hw1 -o update.otap
//   otatool delta   --key sk.txt --base old.bin --base-seq 11 --image new.bin
//                   --seq 12 --version 2.3.0 --product dev-x --hardware hw1 -o d.otap
//   otatool inspect --package update.otap [--public pk.txt]
//
// 所有命令失败时返回非 0 并打印原因。
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include "packager.h"
#include "package.h"

using namespace ota;

// 解析 16 字节 key_id（32 个十六进制字符）。
static Bytes parse_hex_key_id(const std::string& hex) {
  if (hex.size() != 32) fail(OtaError::kBadFormat, "--key-id 必须是 32 个十六进制字符");
  Bytes out(16);
  for (size_t i = 0; i < 16; ++i) {
    auto nib = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) fail(OtaError::kBadFormat, "--key-id 含非十六进制字符");
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

namespace {

void usage() {
  std::fprintf(stderr,
               "用法:\n"
               "  otatool keygen  --secret sk.txt --public pk.txt\n"
               "  otatool pack    --key sk.txt --image new.bin --seq N --version V\n"
               "                  --product P --hardware H [-o out.otap] [--timestamp T]\n"
               "                  [--build-id B] [--rollback-floor F] [--notes S]\n"
               "  otatool delta   --key sk.txt --base old.bin --base-seq N --image new.bin\n"
               "                  --seq N --version V --product P --hardware H [-o out.otap]\n"
               "  otatool inspect --package p.otap [--public pk.txt] [--key-id HEX]\n");
}

struct Args {  std::string command;
  std::vector<std::string> raw;

  bool has(const std::string& k) const {
    for (size_t i = 1; i < raw.size(); ++i) {
      if (raw[i] == k) return true;
    }
    return false;
  }
  std::string get(const std::string& k, const std::string& def = "") const {
    for (size_t i = 1; i + 1 < raw.size(); ++i) {
      if (raw[i] == k) return raw[i + 1];
    }
    return def;
  }
  uint64_t get_u64(const std::string& k, uint64_t def = 0) const {
    std::string v = get(k);
    if (v.empty()) return def;
    return std::stoull(v, nullptr, 0);
  }
};

int do_keygen(const Args& a) {
  std::string sk = a.get("--secret"), pk = a.get("--public");
  if (sk.empty() || pk.empty()) {
    usage();
    return 2;
  }
  Ed25519SecretKey secret = generate_keypair(sk, pk);
  Ed25519PublicKey public_key{};
  std::memcpy(public_key.data(), secret.data() + 32, 32);
  std::printf("公钥: %s\nkey_id: %s\n", to_hex(public_key).c_str(),
              to_hex(key_id_for(public_key)).c_str());
  std::printf("私钥已写入 %s（权限请自行收紧为 0600）\n", sk.c_str());
  return 0;
}

int do_pack(const Args& a, bool delta_mode) {
  std::string key_path = a.get("--key");
  std::string image_path = a.get("--image");
  std::string product = a.get("--product");
  std::string hardware = a.get("--hardware");
  if (key_path.empty() || image_path.empty() || product.empty() || hardware.empty() ||
      a.get("--seq").empty() || a.get("--version").empty()) {
    usage();
    return 2;
  }

  Ed25519SecretKey sk = load_secret_key(key_path);
  Ed25519PublicKey pk{};
  std::memcpy(pk.data(), sk.data() + 32, 32);

  BuildRequest req;
  req.mode = delta_mode ? SigningMode::kDelta : SigningMode::kFull;
  req.image = read_binary_file(image_path);
  req.product = product;
  req.hardware = hardware;
  req.seq = a.get_u64("--seq");
  req.version = a.get("--version");
  req.build_id = a.get("--build-id",
                       "build-" + std::to_string(req.seq));
  req.rollback_floor = a.get_u64("--rollback-floor");
  req.notes = a.get("--notes");
  req.timestamp = a.get_u64("--timestamp",
                            static_cast<uint64_t>(std::time(nullptr)));
  req.key_id = key_id_for(pk);
  if (delta_mode) {
    req.base_image = read_binary_file(a.get("--base"));
    req.base_seq = a.get_u64("--base-seq");
    if (req.base_image.empty()) {
      std::fprintf(stderr, "错误: 差分包需要 --base\n");
      return 2;
    }
  }

  Bytes pkg = build_package(req, sk);
  std::string out = a.get("-o", delta_mode ? "update-delta.otap" : "update.otap");
  write_binary_file(out, pkg);
  std::printf("已生成 %s（%zu 字节，%s，seq=%llu）\n", out.c_str(), pkg.size(),
              package_type_name(req.mode == SigningMode::kDelta ? PackageType::kDelta
                                                               : PackageType::kFull),
              static_cast<unsigned long long>(req.seq));
  return 0;
}

int do_inspect(const Args& a) {
  std::string p = a.get("--package");
  if (p.empty()) {
    usage();
    return 2;
  }
  Bytes pkg = read_binary_file(p);
  std::cout << describe_package(pkg);
  std::string pk_path = a.get("--public");
  std::string key_id_hex = a.get("--key-id");
  if (!pk_path.empty()) {
    Ed25519PublicKey pk = load_public_key(pk_path);
    KeyId id = key_id_for(pk);
    if (!key_id_hex.empty()) {
      // 允许显式指定 key_id（16 字节十六进制），用于测试不一致的情形。
      Bytes raw = parse_hex_key_id(key_id_hex);
      std::memcpy(id.data(), raw.data(), 16);
    }
    try {
      VerifiedPackage vp = verify_package(pkg, pk, id);
      std::printf("签名验证: 通过（seq=%llu，%s）\n",
                  static_cast<unsigned long long>(vp.header.seq),
                  package_type_name(vp.header.type));
    } catch (const OtaError& e) {
      std::printf("签名验证: 失败 —— %s\n", e.what());
      return 1;
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  Args a;
  a.command = argv[1];
  for (int i = 1; i < argc; ++i) a.raw.push_back(argv[i]);

  try {
    if (a.command == "keygen") return do_keygen(a);
    if (a.command == "pack") return do_pack(a, false);
    if (a.command == "delta") return do_pack(a, true);
    if (a.command == "inspect") return do_inspect(a);
    usage();
    return 2;
  } catch (const OtaError& e) {
    std::fprintf(stderr, "错误: %s\n", e.what());
    return 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "异常: %s\n", e.what());
    return 1;
  }
}
