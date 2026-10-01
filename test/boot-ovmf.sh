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
# the getty banner init writes is on a serial console, and the agent answered GET /health, /system and /boot/order (UEFI only) over the
# guest's DHCP'd network. The guest has an emulated BMC (ipmi-bmc-sim on a
# KCS interface), and GET /bios/config must show that sum ran on the image's
# glibc (#14): QEMU's board is not a Supermicro one, so sum itself refuses,
# but never with a loader error.
# Two scratch AHCI disks, an HDD (rotation_rate 7200) and an SSD (rotation_rate
# 1, discard on), are partitioned and formatted through the API and then
# wiped with POST /disks/wipe/{dev} (#15): the wipe must say it verified, the
# partitions must be gone, and on the host both images must read zero at the
# head and the tail.
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

for d in hdd ssd; do truncate -s 4G "$W/$d.img"; done
SCRATCH=(-drive if=none,id=hdd,format=raw,file="$W/hdd.img"
         -device ide-hd,drive=hdd,serial=WIPEHDD,rotation_rate=7200
         -drive if=none,id=ssd,format=raw,discard=unmap,file="$W/ssd.img"
         -device ide-hd,drive=ssd,serial=WIPESSD,rotation_rate=1)

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
    "${FW[@]}" "${DISK[@]}" "${SCRATCH[@]}" \
    -device ipmi-bmc-sim,id=bmc0 -device isa-ipmi-kcs,bmc=bmc0 \
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
    console | grep -aq '   Bare Metal Services$' && break
    sleep 1
done
console | grep -aq '   Bare Metal Services$' || { ls -l "$W"; fail "the getty banner (/etc/issue from init) is not on the serial console"; }
say "console: $(console | grep -ac .) lines; $(console | grep -am1 'Linux version' | cut -c1-80)"
curl -sf --max-time 30 "http://127.0.0.1:$PORT/system" | grep -q '"status":"ok"' || fail "/system"
say "/system ok: $(curl -sf --max-time 30 "http://127.0.0.1:$PORT/system" | grep -o '"kernel":"[^"]*"')"
if [ "$MODE" != bios ]; then
    bo=$(curl -s --max-time 30 "http://127.0.0.1:$PORT/boot/order")
    echo "$bo" | grep -q '"status":"ok"' && echo "$bo" | grep -q '"entries":\[{' || fail "/boot/order: $bo"
    say "/boot/order ok: $(echo "$bo" | grep -o '"boot_current":"[^"]*"')"
fi
bc=$(curl -s --max-time 180 "http://127.0.0.1:$PORT/bios/config")
if grep -Eq 'Error relocating|symbol not found|error while loading shared libraries|not available' <<<"$bc" \
    || ! grep -q 'Supermicro Update Manager' <<<"$bc"; then
    fail "/bios/config: sum did not run: $bc"
fi
say "/bios/config: sum ran: $(grep -o 'Supermicro Update Manager[^\]*' <<<"$bc" | head -1); $(grep -o 'Error message:[^"]*' <<<"$bc" | sed 's/\\[nt]/ /g' | tr -s ' ' | cut -c1-120)"

# Disk wipe (#15).
api() { curl -s --max-time 600 "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
disks=$(api "http://127.0.0.1:$PORT/disks")
for kind in hdd ssd; do
    serial=WIPE${kind^^}
    name=$(json "next((x['name'] for x in d['data'] if x.get('serial')=='$serial'), '')" <<<"$disks")
    [ -n "$name" ] || fail "wipe: no disk with serial $serial in /disks: $disks"
    out=$(api -X POST "http://127.0.0.1:$PORT/disks/partition/$name")
    grep -q '"status":"ok"' <<<"$out" || fail "wipe: partition $name: $out"
    out=$(api -X POST -d fstype=ext4 "http://127.0.0.1:$PORT/disks/format/${name}1")
    grep -q '"status":"ok"' <<<"$out" || fail "wipe: format ${name}1: $out"
    n=$(api "http://127.0.0.1:$PORT/disks/detail/$name" | json "len(d['data'].get('partitions') or [])")
    [ "$n" -ge 1 ] || fail "wipe: $name has no partition to wipe"
    out=$(api -X POST "http://127.0.0.1:$PORT/disks/wipe/$name")
    v=$(json "d['status']+' '+str(d['data']['/dev/$name']['verified'])+' '+str(d['data']['/dev/$name']['rotational'])+' '+','.join(s['step'].replace(' ','_') for s in d['data']['/dev/$name']['steps'])" <<<"$out") \
        || fail "wipe: $name: $out"
    case "$kind:$v" in
        hdd:"ok True True "*) grep -q blkdiscard <<<"$v" && fail "wipe: blkdiscard ran on the HDD: $v" ;;
        ssd:"ok True False "*) grep -q blkdiscard <<<"$v" || fail "wipe: no blkdiscard on the SSD: $v" ;;
        *) fail "wipe: $name ($kind): $v: $out" ;;
    esac
    n=$(api "http://127.0.0.1:$PORT/disks/detail/$name" | json "len(d['data'].get('partitions') or [])")
    [ "$n" -eq 0 ] || fail "wipe: $name still has $n partition(s)"
    python3 - "$W/$kind.img" <<'PY' || fail "wipe: $kind.img on the host is not zero at the head/tail"
import os, sys
f = open(sys.argv[1], 'rb'); size = os.path.getsize(sys.argv[1]); M = 64 << 20
for off in (0, size - M):
    f.seek(off)
    if f.read(M).count(0) != M: sys.exit(1)
PY
    say "wipe $kind ($name): verified; steps ${v##* }; host image zero at head and tail"
done
out=$(api -X POST "http://127.0.0.1:$PORT/disks/wipe/nosuchdisk")
grep -q '"status":"error"' <<<"$out" || fail "wipe: a missing disk did not fail: $out"
say "PASS"
