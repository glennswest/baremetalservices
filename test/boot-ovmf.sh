#!/bin/bash
# Boot a built baremetalservices image under QEMU and check the agent answers
# (#2). Needs qemu-system-x86_64 and OVMF (edk2-ovmf); KVM if /dev/kvm is
# writable, TCG otherwise.
#
#   test/boot-ovmf.sh disk IMAGE   # the -maint golden: 4096-byte virtio disk, UEFI
#   test/boot-ovmf.sh iso  IMAGE   # the ISO golden: CD-ROM, UEFI
#   test/boot-ovmf.sh bios IMAGE   # the ISO golden: CD-ROM, legacy BIOS (SeaBIOS)
#
# PASS means: the firmware started the image, the kernel ran our init, and
# the agent answered GET /health, /system and /boot/order (UEFI only) over the
# guest's DHCP'd network.
set -uo pipefail

MODE="${1:?usage: boot-ovmf.sh disk|iso|bios IMAGE}"
IMAGE="${2:?usage: boot-ovmf.sh disk|iso|bios IMAGE}"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.fd}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"

say() { printf '[boot-%s] %s\n' "$MODE" "$*"; }
W="$(mktemp -d "${TMPDIR:-/tmp}/bms-boot.XXXXXX")"
QPID=""
cleanup() { [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

ACCEL=tcg; [[ -w /dev/kvm ]] && ACCEL=kvm
PORT=$(( 20000 + RANDOM % 20000 ))
cp "$IMAGE" "$W/image"     # the guest may write to its disk; never to the golden

FW=()
case "$MODE" in
disk)
    cp "$OVMF_VARS" "$W/vars.fd"
    FW=(-drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" -drive if=pflash,format=raw,file="$W/vars.fd")
    DISK=(-drive if=none,id=d4k,format=raw,file="$W/image"
          -device virtio-blk-pci,drive=d4k,logical_block_size=4096,physical_block_size=4096,bootindex=0) ;;
iso)
    cp "$OVMF_VARS" "$W/vars.fd"
    FW=(-drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" -drive if=pflash,format=raw,file="$W/vars.fd")
    DISK=(-drive if=none,id=cd,format=raw,media=cdrom,readonly=on,file="$W/image"
          -device ide-cd,drive=cd,bootindex=0) ;;
bios)
    DISK=(-drive if=none,id=cd,format=raw,media=cdrom,readonly=on,file="$W/image"
          -device ide-cd,drive=cd,bootindex=0) ;;
*) say "unknown mode $MODE"; exit 2 ;;
esac

say "booting $(basename "$IMAGE") ($(du -h "$IMAGE" | cut -f1), $ACCEL), API on :$PORT"
qemu-system-x86_64 -machine q35,accel=$ACCEL -cpu max -smp 2 -m 4096 -display none -no-reboot \
    "${FW[@]}" "${DISK[@]}" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:8080 -device e1000e,netdev=n0 \
    -serial file:"$W/serial.log" -serial file:"$W/console.log" &
QPID=$!

ok=no
for ((i = 0; i < BOOT_TIMEOUT; i += 5)); do
    sleep 5
    kill -0 "$QPID" 2>/dev/null || { say "qemu exited"; break; }
    if curl -sf --max-time 3 "http://127.0.0.1:$PORT/health" >"$W/health.json" 2>/dev/null; then
        ok=yes; say "agent answered /health after ~${i}s"; break
    fi
done

# ttyS0 has the firmware and the kernel; init writes to /dev/console, the
# last console= on the command line (ttyS1).
console() { sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\r//g' "$W/serial.log" "$W/console.log" | grep -av '^\s*$'; }
fail() { say "FAIL: $*"; say "--- serial console (last 60 lines) ---"; console | tail -60; exit 1; }

[ "$ok" = yes ] || fail "the agent never answered /health within ${BOOT_TIMEOUT}s"
for ((i = 0; i < 30; i++)); do
    console | grep -aq '=== Bare Metal Services Booting ===' && break
    sleep 1
done
console | grep -aq '=== Bare Metal Services Booting ===' || { ls -l "$W"; fail "init banner not on the serial console"; }
say "console: $(console | grep -ac .) lines; $(console | grep -am1 'Linux version' | cut -c1-80)"
curl -sf --max-time 30 "http://127.0.0.1:$PORT/system" | grep -q '"status":"ok"' || fail "/system"
say "/system ok: $(curl -sf --max-time 30 "http://127.0.0.1:$PORT/system" | grep -o '"kernel":"[^"]*"')"
if [ "$MODE" != bios ]; then
    bo=$(curl -s --max-time 30 "http://127.0.0.1:$PORT/boot/order")
    echo "$bo" | grep -q '"status":"ok"' && echo "$bo" | grep -q '"entries":\[{' || fail "/boot/order: $bo"
    say "/boot/order ok: $(echo "$bo" | grep -o '"boot_current":"[^"]*"')"
fi
say "PASS"
