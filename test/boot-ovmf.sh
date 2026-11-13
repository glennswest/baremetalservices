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
# NIC drivers (#12): a second NIC, vmxnet3, is in no list init names, so only
# init's PCI modalias coldplug can bring it up: /network must show an
# interface driven by vmxnet3. i40e and ice (no QEMU model) must have loaded:
# their banners are in the kernel log on the serial console.
# Image write (#36): POST /disks/image/{dev} must refuse a disk with a
# stormblock slab and a wrong sha256 (leaving the stick as it was), then write
# a new stick image (made by test/mkstick.py, served from the host) onto an
# old stick on a USB disk (xhci + usb-storage, so init must load USB) with
# keep_local_conf=true. On the host the stick must hold the new ESP, the old
# local.conf plus the name/tag the new stormboot.conf drops, and a backup GPT
# at the end of the disk.
set -uo pipefail

MODE="${1:?usage: boot-ovmf.sh disk|iso|bios IMAGE}"
IMAGE="${2:?usage: boot-ovmf.sh disk|iso|bios IMAGE}"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.fd}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"

say() { printf '[boot-%s] %s\n' "$MODE" "$*"; }
W="$(mktemp -d "${TMPDIR:-/tmp}/bms-boot.XXXXXX")"
QPID=""
HPID=""
cleanup() { [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; [ -n "$HPID" ] && kill "$HPID" 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

ACCEL=tcg; [[ -w /dev/kvm ]] && ACCEL=kvm
PORT=$(( 20000 + RANDOM % 20000 ))
cp "$IMAGE" "$W/image"     # the guest may write to its disk; never to the golden

for d in hdd ssd; do truncate -s 4G "$W/$d.img"; done
SCRATCH=(-drive if=none,id=hdd,format=raw,file="$W/hdd.img"
         -device ide-hd,bus=ide.4,drive=hdd,serial=WIPEHDD,rotation_rate=7200
         -drive if=none,id=ssd,format=raw,discard=unmap,file="$W/ssd.img"
         -device ide-hd,bus=ide.5,drive=ssd,serial=WIPESSD,rotation_rate=1)

# Image write (#36): an old boot stick (0.37.0-like: name/tag in
# stormboot.conf, a local.conf) at the start of a 1 GiB USB disk on xhci, a
# new image (0.39.0-like: no name/tag) served from the host, and a 64 MiB disk
# with a stormblock slab header that must be refused.
mkdir -p "$W/srv" "$W/old" "$W/new"
head -c 300000 /dev/urandom >"$W/old/BOOTX64.EFI"
head -c 400000 /dev/urandom >"$W/new/BOOTX64.EFI"
printf 'version = 0.37.0\nname = forge1\ntag = forge\n' >"$W/old/stormboot.conf"
printf 'portal = 10.0.0.1\n' >"$W/old/local.conf"
printf 'version = 0.39.0\n' >"$W/new/stormboot.conf"
printf '# defaults\n' >"$W/new/local.conf"
for v in old new; do
    python3 "$(dirname "$0")/mkstick.py" "$W/$v.img" 32 EFI/BOOT/BOOTX64.EFI="$W/$v/BOOTX64.EFI" \
        stormboot/stormboot.conf="$W/$v/stormboot.conf" stormboot/local.conf="$W/$v/local.conf" \
        || { say "FAIL: mkstick $v"; exit 1; }
done
mv "$W/new.img" "$W/srv/new.img"
truncate -s 1G "$W/stick.img"; dd if="$W/old.img" of="$W/stick.img" conv=notrunc status=none
truncate -s 64M "$W/slab.img"; printf STRMSLAB | dd of="$W/slab.img" conv=notrunc status=none
SCRATCH+=(-drive if=none,id=slab,format=raw,file="$W/slab.img"
          -device ide-hd,bus=ide.2,drive=slab,serial=SLABDISK
          -device qemu-xhci,id=xhci
          -drive if=none,id=stick,format=raw,file="$W/stick.img"
          -device usb-storage,bus=xhci.0,drive=stick,serial=IMGSTICK)
SPORT=$(( 40000 + RANDOM % 20000 ))
python3 -m http.server -b 127.0.0.1 -d "$W/srv" "$SPORT" >"$W/http.log" 2>&1 &
HPID=$!

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
          -device ide-cd,bus=ide.0,drive=cd,bootindex=0) ;;
bios)
    DISK=(-drive if=none,id=cd,format=raw,media=cdrom,readonly=on,file="$W/image"
          -device ide-cd,bus=ide.0,drive=cd,bootindex=0) ;;
*) say "unknown mode $MODE"; exit 2 ;;
esac

say "booting $(basename "$IMAGE") ($(du -h "$IMAGE" | cut -f1), $ACCEL), API on :$PORT"
qemu-system-x86_64 -machine q35,accel=$ACCEL -cpu max -smp 2 -m 4096 -display none -no-reboot \
    "${FW[@]}" "${DISK[@]}" "${SCRATCH[@]}" \
    -device ipmi-bmc-sim,id=bmc0 -device isa-ipmi-kcs,bmc=bmc0 \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:8080 -device e1000e,netdev=n0 \
    -netdev user,id=n1,net=10.0.3.0/24 -device vmxnet3,netdev=n1 \
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
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
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

# NIC drivers (#12).
for m in 'i40e: Intel(R) Ethernet Connection XL710' 'ice: Intel(R) Ethernet Connection E800'; do
    console | grep -aqF "$m" || fail "NIC drivers: ${m%%:*} not loaded (no '$m' in the kernel log)"
done
net=$(curl -s --max-time 30 "http://127.0.0.1:$PORT/network")
drv=$(json "' '.join(sorted(x['name']+'='+x['driver'] for x in d['data'] if x.get('driver')))" <<<"$net") || fail "/network: $net"
grep -q '=vmxnet3' <<<"$drv" || fail "NIC drivers: no vmxnet3 interface (coldplug): $drv"
grep -q 'eth0=e1000e' <<<"$drv" || fail "NIC drivers: eth0 is not the named-first e1000e: $drv"
say "NIC drivers ok: i40e and ice loaded; interfaces $drv"

fw=$(curl -s --max-time 30 "http://127.0.0.1:$PORT/firmware")
grep -q 'fw-ConnectX3-rel-2_42_5000-MCX311A-XCA_Ax-FlexBoot-3.4.752.bin' <<<"$fw" || fail "/firmware: no ConnectX-3 firmware (#13): $fw"
say "/firmware ok: ConnectX-3 2.42.5000 bundled"

# Disk wipe (#15).
api() { curl -s --max-time 600 "$@"; }
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

# Image write (#36).
disks=$(api "http://127.0.0.1:$PORT/disks")
stick=$(json "next((x['name'] for x in d['data'] if x.get('serial')=='IMGSTICK' or x.get('size')=='1G'), '')" <<<"$disks")
slab=$(json "next((x['name'] for x in d['data'] if x.get('serial')=='SLABDISK' or x.get('size')=='64M'), '')" <<<"$disks")
[ -n "$stick" ] && [ -n "$slab" ] || fail "image: no USB stick (1G) or slab disk (64M) in /disks: $disks"
url="http://10.0.2.2:$SPORT/new.img"
sum=$(sha256sum "$W/srv/new.img" | cut -d' ' -f1)
out=$(api -X POST -d "url=$url" -d "sha256=$sum" "http://127.0.0.1:$PORT/disks/image/$slab")
grep -q '"status":"error"' <<<"$out" && grep -q STRMSLAB <<<"$out" || fail "image: the slab disk $slab was not refused: $out"
say "image: slab disk $slab refused: $(json "d['error']" <<<"$out")"
out=$(api -X POST -d "url=$url" -d "sha256=$(printf '0%.0s' {1..64})" "http://127.0.0.1:$PORT/disks/image/$stick")
grep -q '"status":"error"' <<<"$out" && grep -q 'sha256' <<<"$out" || fail "image: a wrong sha256 was not refused: $out"
cmp -s -n 1048576 "$W/old.img" "$W/stick.img" || fail "image: a refused image changed the stick"
say "image: wrong sha256 refused, stick untouched: $(json "d['error']" <<<"$out")"
out=$(api -X POST -d "url=$url" -d "sha256=$sum" -d keep_local_conf=true "http://127.0.0.1:$PORT/disks/image/$stick")
v=$(json "d['status']+' '+str(d['data']['verified'])+' '+d['data']['gpt']+' | '+', '.join(d['data'].get('local_conf_kept') or [])" <<<"$out") \
    || fail "image: $stick: $out"
case "$v" in
    "ok True 512-byte blocks | local.conf (18 bytes), name = forge1, tag = forge") ;;
    *) fail "image: $stick: $v: $out" ;;
esac
say "image: $stick written: $v; steps $(json "','.join(s['step'].replace(' ','_') for s in d['data']['steps'])" <<<"$out")"
# On the host: the new image's ESP, the old local.conf plus the identity the
# new stormboot.conf drops, the backup GPT at the end of the 1 GiB disk.
E="$W/stick.img@@1048576"
mtype -i "$E" ::/EFI/BOOT/BOOTX64.EFI | cmp -s - "$W/new/BOOTX64.EFI" || fail "image: BOOTX64.EFI on the stick is not the new one"
mtype -i "$E" ::/stormboot/stormboot.conf | cmp -s - "$W/new/stormboot.conf" || fail "image: stormboot.conf is not the new one"
lc=$(mtype -i "$E" ::/stormboot/local.conf)
[ "$lc" = "$(printf 'portal = 10.0.0.1\nname = forge1\ntag = forge')" ] || fail "image: local.conf on the stick: $lc"
[ "$(tail -c 512 "$W/stick.img" | head -c 8)" = "EFI PART" ] || fail "image: no backup GPT at the end of the stick"
say "image: on the host the stick has the new image, local.conf kept ($(tr '\n' ';' <<<"$lc")), backup GPT at its end"
say "PASS"
