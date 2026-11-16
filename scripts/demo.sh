#!/usr/bin/env bash
# End-to-end demo: generate keys, sign v1/v2, produce a delta, then drive the
# simulated device through install -> trial -> confirm, a downgrade attempt,
# a tampered package, and a power cut.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=./build/otapack
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "1. Generate a signing key (seed stays offline)"
$BIN keygen --seed "$WORK/fw.seed" --out-pub "$WORK/fw.pub" --out-key-id "$WORK/fw.id"

say "2. Build two firmware images and sign version 1 and 2"
python3 - "$WORK" <<'PY'
import os, sys
w = sys.argv[1]
v1 = bytes((i * 37 + 11) & 0xFF for i in range(48 * 1024))
v2 = bytearray(v1)
v2[8000:12000] = bytes((i * 91 + 3) & 0xFF for i in range(4000))
v2 += b"-- new in v2 --"
open(os.path.join(w, "app-v1.bin"), "wb").write(v1)
open(os.path.join(w, "app-v2.bin"), "wb").write(v2)
PY

$BIN pack --image "$WORK/app-v1.bin" --version 1 --device demo-dev --hw-min 1 --hw-max 2 \
      --key "$WORK/fw.seed" --pub "$WORK/fw.pub" --out "$WORK/v1.otap" --build-time 1700000001
$BIN pack --image "$WORK/app-v2.bin" --version 2 --device demo-dev --hw-min 1 --hw-max 2 \
      --key "$WORK/fw.seed" --pub "$WORK/fw.pub" --out "$WORK/v2.otap" --build-time 1700000002
$BIN pack --image "$WORK/app-v2.bin" --version 2 --device demo-dev --hw-min 1 --hw-max 2 \
      --delta-from "$WORK/app-v1.bin" --delta-version 1 \
      --key "$WORK/fw.seed" --pub "$WORK/fw.pub" --out "$WORK/v1-to-v2.otap" --build-time 1700000002

say "3. Verify the packages the way CI would"
$BIN verify --package "$WORK/v1.otap" --pub "$WORK/fw.pub"
$BIN verify --package "$WORK/v1-to-v2.otap" --pub "$WORK/fw.pub" --source "$WORK/app-v1.bin"

say "4. Package metadata"
$BIN info --package "$WORK/v1-to-v2.otap"

say "5. A single flipped byte must be rejected"
python3 - "$WORK" <<'PY'
import sys
w = sys.argv[1]
data = bytearray(open(w + "/v2.otap", "rb").read())
data[len(data) // 2] ^= 0xFF
open(w + "/v2-tampered.otap", "wb").write(data)
PY
if $BIN verify --package "$WORK/v2-tampered.otap" --pub "$WORK/fw.pub"; then
  echo "ERROR: tampered package was accepted"; exit 1
else
  echo "rejected as expected"
fi

say "6. Simulated device: install v2, trial boot, confirm"
cat > "$WORK/sim.cpp" <<'CPP'
#include <cstdio>
#include <vector>
#include "device/flash.h"
#include "device/updater.h"
#include "common/crypto.h"
#include "package/format.h"
using namespace ota;
static std::vector<uint8_t> slurp(const char* p) {
  auto r = pkg::read_file(p); if (!r) { std::fprintf(stderr, "%s\n", r.failure().message.c_str()); std::exit(1);} return r.take();
}
static crypto::PublicKey pub(const char* p) {
  auto r = pkg::read_file(p); std::string h((const char*)r.value().data(), r.value().size());
  while (!h.empty() && (h.back()=='\n'||h.back()=='\r')) h.pop_back();
  std::vector<uint8_t> raw; crypto::from_hex(h, raw);
  crypto::PublicKey k{}; std::memcpy(k.data(), raw.data(), 32); return k;
}
int main(int argc, char** argv) {
  DeviceConfig cfg; cfg.device_id = "demo-dev"; cfg.hw_revision = 1; cfg.trial_boots = 2;
  cfg.public_key = pub(argv[1]);
  Flash flash(1u << 20);
  {
    Updater u(flash, cfg);
    auto s = u.provision(slurp(argv[2]), 1700000001);
    if (!s) { std::fprintf(stderr, "provision: %s\n", s.message.c_str()); return 1; }
    auto b = u.select_boot(); u.confirm_boot();
    std::printf("booted v%llu from slot %u\n", (unsigned long long)b.value().version, b.value().slot);
  }
  auto reboot = [&](Updater& u) {
    auto b = u.select_boot();
    if (!b) { std::printf("BOOT FAILED: %s\n", b.failure().message.c_str()); return; }
    std::printf("boot -> v%llu slot %u (%s)\n", (unsigned long long)b.value().version, b.value().slot,
                b.value().outcome == BootOutcome::BootedTrial ? "trial" :
                b.value().outcome == BootOutcome::RevertedPending ? "reverted" : "active");
    if (b.value().outcome != BootOutcome::RevertedPending) u.confirm_boot();
  };

  std::printf("\n-- tampered v2 must be rejected --\n");
  { Updater u(flash, cfg); auto r = u.install(slurp(argv[4]), 1700000011);
    if (!r) std::printf("rejected: %s\n", r.failure().message.c_str()); else std::printf("ACCEPTED (bug)\n"); }

  std::printf("\n-- install v2: trial boot, then crash loop, then revert --\n");
  { Updater u(flash, cfg); auto r = u.install(slurp(argv[3]), 1700000012);
    if (!r) { std::printf("FAILED: %s\n", r.failure().message.c_str()); return 1; }
    std::printf("installed v%llu into slot %u\n", (unsigned long long)r.value().version, r.value().slot);
    auto b = u.select_boot();
    std::printf("boot -> v%llu slot %u (trial, not confirmed)\n",
                (unsigned long long)b.value().version, b.value().slot); }
  { Updater u(flash, cfg); auto b = u.select_boot();
    std::printf("boot -> v%llu slot %u (trial, not confirmed)\n",
                (unsigned long long)b.value().version, b.value().slot); }
  { Updater u(flash, cfg); reboot(u); }   // trials exhausted -> automatic revert

  std::printf("\n-- install v2 again, confirm this time --\n");
  { Updater u(flash, cfg); auto r = u.install(slurp(argv[3]), 1700000013);
    if (!r) { std::printf("FAILED: %s\n", r.failure().message.c_str()); return 1; }
    reboot(u); }

  std::printf("\n-- real downgrade attempt: replay the old signed v1 --\n");
  { Updater u(flash, cfg); auto r = u.install(slurp(argv[2]), 1700000014);
    if (!r) std::printf("rejected: %s\n", r.failure().message.c_str()); else std::printf("ACCEPTED (bug)\n"); }

  std::printf("\n-- same-version retry of the installed package is allowed (idempotent) --\n");
  { Updater u(flash, cfg); auto r = u.install(slurp(argv[3]), 1700000015);
    std::printf("retry: %s\n", r.ok() ? "ok" : r.failure().message.c_str()); }

  std::printf("\n-- offline attack: repoint boot metadata at the other slot --\n");
  { Updater u(flash, cfg);
    auto before = u.status();
    std::printf("before: active slot %u, booted floor %llu, slot0 verifies=%d (v%llu)\n",
                before.value().active_slot.value_or(99), (unsigned long long)before.value().booted_floor,
                (int)before.value().slot_verifies[0], (unsigned long long)before.value().slot_version[0].value_or(0));
    Layout layout = Layout::make(flash.size(), flash.sector_size());
    MetaLog meta(flash, layout.meta_sector[0] * 4096, layout.meta_sector[1] * 4096);
    BootMeta forged; forged.active_slot = 0; forged.active_version = 1;
    forged.pending_slot = std::nullopt; forged.trial_remaining = 0;
    meta.write(forged);
    std::printf("attacker rewrote metadata -> active_slot 0 (both slots hold genuinely signed images)\n");
  }
  { Updater u(flash, cfg); reboot(u);
    auto st = u.status();
    std::printf("booted floor still %llu, so v1 cannot boot\n",
                (unsigned long long)st.value().booted_floor); }

  std::printf("\n-- power cut during install, then retry --\n");
  { Updater u(flash, cfg); flash.arm_power_cut(0); auto r = u.install(slurp(argv[3]), 1700000020);
    std::printf("torn install: %s\n", r.ok() ? "completed before cut" : r.failure().message.c_str());
    flash.power_restore(); }
  { Updater u(flash, cfg); auto r = u.install(slurp(argv[3]), 1700000021);
    std::printf("retry: %s\n", r.ok() ? "ok" : r.failure().message.c_str()); }
  { Updater u(flash, cfg); reboot(u); }
  return 0;
}
CPP
c++ -std=c++20 -O1 -Isrc $(pkg-config --cflags libsodium) \
    "$WORK/sim.cpp" build/src/common/*.o build/src/package/*.o build/src/device/*.o \
    -o "$WORK/sim" $(pkg-config --libs libsodium)
"$WORK/sim" "$WORK/fw.pub" "$WORK/v1.otap" "$WORK/v2.otap" "$WORK/v2-tampered.otap"

say "done"
