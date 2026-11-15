// SPDX-License-Identifier: MIT
// 端到端：用 otatool 命令行产出包，再交给设备端安装/启动。
// 这条路径覆盖真实的运维工作流（密钥文件 -> 打包 -> 刷写）。
#include <cstdio>
#include <cstdlib>

#include "bootctl.h"
#include "device.h"
#include "flash.h"
#include "packager.h"
#include "test_framework.h"
#include "test_util.h"

using namespace ota;
using testutil::TempDir;

namespace {

std::string tool_path() {
  // 测试从仓库根运行；允许用环境变量覆盖。
  if (const char* env = std::getenv("OTATOOL")) return env;
  return "./build/otatool";
}

int run(const std::string& cmd) {
  int rc = std::system(cmd.c_str());
  if (rc == -1) return -1;
  if (WIFEXITED(rc)) return WEXITSTATUS(rc);
  return -2;
}

}  // namespace

TEST_CASE(cli_keygen_pack_delta_inspect_roundtrip) {
  TempDir dir;
  std::string tool = tool_path();
  std::string sk = dir.file("sk.txt"), pk = dir.file("pk.txt");
  std::string old_img = dir.file("old.bin"), new_img = dir.file("new.bin");
  std::string full = dir.file("full.otap"), delta = dir.file("delta.otap");

  CHECK_EQ(run(tool + " keygen --secret " + sk + " --public " + pk), 0);

  Bytes v1 = testutil::make_image(30000, 1);
  Bytes v2 = testutil::mutate_slightly(v1, 5);
  write_binary_file(old_img, v1);
  write_binary_file(new_img, v2);

  CHECK_EQ(run(tool + " pack --key " + sk + " --image " + new_img + " --seq 2 --version 2.0.0" +
               " --product dev-x --hardware hw1 --timestamp 1700000000 -o " + full),
           0);
  CHECK_EQ(run(tool + " delta --key " + sk + " --base " + old_img + " --base-seq 1 --image " +
               new_img + " --seq 2 --version 2.0.0 --product dev-x --hardware hw1" +
               " --timestamp 1700000000 -o " + delta),
           0);

  Bytes full_pkg = read_binary_file(full);
  Bytes delta_pkg = read_binary_file(delta);
  CHECK(delta_pkg.size() * 3 < full_pkg.size());

  // inspect 能用公钥验签成功。
  CHECK_EQ(run(tool + " inspect --package " + full + " --public " + pk), 0);
  CHECK_EQ(run(tool + " inspect --package " + delta + " --public " + pk), 0);

  // 篡改后 inspect 必须失败。
  std::string bad = dir.file("bad.otap");
  Bytes tampered = full_pkg;
  tampered[tampered.size() - 40] ^= 0x01;
  write_binary_file(bad, tampered);
  CHECK_EQ(run(tool + " inspect --package " + bad + " --public " + pk), 1);

  // 设备端直接安装 CLI 产出的两个包。
  Ed25519PublicKey pub = load_public_key(pk);
  DeviceConfig cfg;
  cfg.product = "dev-x";
  cfg.hardware = "hw1";
  cfg.public_key = pub;
  cfg.key_id = key_id_for(pub);
  cfg.layout = DeviceLayout::make(1024 * 1024, 256 * 1024);

  SimFlash flash(dir.file("flash.bin"), 1024 * 1024);
  write_good_image(&flash, cfg, 0, v1, 1, "1.0.0");

  DeviceUpdater up(&flash, cfg);
  InstallOutcome r = up.install(delta_pkg);
  CHECK_EQ(r.result, InstallResult::kOk);
  CHECK(r.used_delta);
  Bytes installed = flash.read(cfg.layout.slot_offset[1] + ImageHeader::kSize, v2.size());
  CHECK(installed == v2);

  BootDecision bd = boot_and_select(&flash, cfg);
  CHECK_EQ(bd.action, BootDecision::kBootPending);
  confirm_running(&flash, cfg, 1);
  CHECK_EQ(read_boot_state(&flash, cfg).counter, 2u);

  // 新固件再装一次同样的包（重放）应被防回滚拒绝。
  InstallOutcome replay = up.install(delta_pkg);
  CHECK_EQ(replay.result, InstallResult::kRejectedRollback);
}

TEST_CASE(cli_keygen_writes_usable_key_files) {
  TempDir dir;
  std::string tool = tool_path();
  std::string sk = dir.file("sk.txt"), pk = dir.file("pk.txt");
  CHECK_EQ(run(tool + " keygen --secret " + sk + " --public " + pk), 0);

  Ed25519SecretKey secret = load_secret_key(sk);
  Ed25519PublicKey pub = load_public_key(pk);
  Ed25519PublicKey derived{};
  std::memcpy(derived.data(), secret.data() + 32, 32);
  CHECK(derived == pub);

  // 用这把密钥签一个包，公钥能验过。
  BuildRequest req;
  req.image = testutil::make_image(1000, 1);
  req.seq = 1;
  req.product = "p";
  req.hardware = "h";
  req.version = "1.0";
  req.key_id = key_id_for(pub);
  Bytes pkg = build_package(req, secret);
  CHECK_EQ(verify_package(pkg, pub, key_id_for(pub)).header.seq, 1u);
}
