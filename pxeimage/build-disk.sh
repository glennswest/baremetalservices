#!/bin/bash
# The network-boot image (#2): a GPT disk at 4096-byte blocks whose EFI System
# Partition holds one file, \EFI\BOOT\BOOTX64.EFI, a unified kernel image
# (systemd-stub + vmlinuz + initramfs + command line).
#
# This is the shape stormbootx boots from a claimed volume: stormblock volumes
# are 4096-byte, and stormbootx reads the GPT at the disk's block size, finds
# the ESP, reads BOOTX64.EFI off a FAT (12/16/32, 512..4096-byte sectors) and
# LoadImage()s it (stormbootx src/esp.rs, #37). A UKI needs nothing after
# that: its initramfs is inside it, so the kernel owning the NIC (and so
# dropping the NVMe/TCP session) costs nothing.
#
#   build-disk.sh VMLINUZ INITRAMFS OUTPUT
set -euo pipefail

VMLINUZ="${1:?usage: build-disk.sh VMLINUZ INITRAMFS OUTPUT}"
INITRAMFS="${2:?usage: build-disk.sh VMLINUZ INITRAMFS OUTPUT}"
OUTPUT="${3:?usage: build-disk.sh VMLINUZ INITRAMFS OUTPUT}"
STUB="${UKI_STUB:-/usr/lib/systemd/boot/efi/linuxx64.efi.stub}"
CMDLINE="${CMDLINE:-console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8 iomem=relaxed}"

for cmd in objcopy objdump mkfs.fat mmd mcopy python3; do
    command -v "$cmd" >/dev/null || { echo "build-disk: $cmd not found" >&2; exit 1; }
done
[ -r "$STUB" ] || { echo "build-disk: no EFI stub at $STUB (systemd-boot / systemd-ukify)" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bms-disk.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "=== Building the network-boot disk (4K GPT + ESP + UKI) ==="

# --- The UKI: the stub with .osrel/.cmdline/.linux/.initrd appended, each at
# the stub's section alignment past the end of its last section.
printf 'NAME="baremetalservices"\nID=baremetalservices\nPRETTY_NAME="Bare Metal Services"\n' > "$WORK/os-release"
printf '%s' "$CMDLINE" > "$WORK/cmdline"
align=$((16#$(objdump -p "$STUB" | awk '$1 == "SectionAlignment" {print $2}')))
next=$(objdump -h "$STUB" | awk 'NF == 7 && $1 ~ /^[0-9]+$/ {e = strtonum("0x" $3) + strtonum("0x" $4); if (e > m) m = e} END {print m}')
up() { echo $(( ($1 + align - 1) / align * align )); }
args=()
for s in osrel:"$WORK/os-release" cmdline:"$WORK/cmdline" linux:"$VMLINUZ" initrd:"$INITRAMFS"; do
    name="${s%%:*}" file="${s#*:}"
    at=$(up "$next")
    args+=(--add-section ".$name=$file" --change-section-vma ".$name=$(printf 0x%x "$at")")
    next=$(( at + $(stat -Lc%s "$file") ))
done
objcopy "${args[@]}" "$STUB" "$WORK/BOOTX64.EFI"
uki=$(stat -c%s "$WORK/BOOTX64.EFI")
echo "  UKI: $((uki / 1048576)) MiB (cmdline: $CMDLINE)"

# --- The ESP: FAT at 4096-byte sectors (a 4K disk will not mount a smaller
# one), 4 KiB clusters. FAT16 holds up to ~250 MiB that way; FAT32 beyond.
esp_mib=$(( uki / 1048576 + 16 ))
if [ "$esp_mib" -le 240 ]; then fat=16; else fat=32; [ "$esp_mib" -ge 300 ] || esp_mib=300; fi
mkfs.fat -C -S 4096 -s 1 -F "$fat" -n BMSMAINT "$WORK/esp.fat" $(( esp_mib * 1024 )) >/dev/null
mmd -i "$WORK/esp.fat" ::/EFI ::/EFI/BOOT
mcopy -i "$WORK/esp.fat" "$WORK/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
echo "  ESP: ${esp_mib} MiB FAT${fat} at 4096-byte sectors"

# --- The disk: protective MBR, GPT at 4096-byte LBAs, the ESP at 1 MiB, and
# the backup table at the end (as stormbootx tests/esp-ovmf.sh lays one).
python3 - "$WORK/esp.fat" "$OUTPUT" <<'PY'
import os, struct, sys, uuid, zlib
esp, out = sys.argv[1], sys.argv[2]
bs = 4096
esp_len = os.path.getsize(esp)
first = (1 << 20) // bs
last = first + -(-esp_len // bs) - 1
total = last + 1 + 4 + 1                  # backup entries (16 KiB) + header
entries = bytearray(128 * 128)
entries[0:128] = (uuid.UUID('C12A7328-F81F-11D2-BA4B-00A0C93EC93B').bytes_le
                  + uuid.uuid4().bytes_le + struct.pack('<QQQ', first, last, 0)
                  + 'EFI system partition'.encode('utf-16-le').ljust(72, b'\0'))
ecrc = zlib.crc32(entries)
disk_guid = uuid.uuid4().bytes_le
def header(me, alt, table):
    h = struct.pack('<8sIIIIQQQQ16sQIII', b'EFI PART', 0x10000, 92, 0, 0,
                    me, alt, 6, total - 6, disk_guid, table, 128, 128, ecrc)
    return h[:16] + struct.pack('<I', zlib.crc32(h)) + h[20:]
with open(out, 'wb') as f:
    f.truncate(total * bs)
    mbr = bytearray(512)
    mbr[446:462] = struct.pack('<BBBBBBBBII', 0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF, 1,
                               min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b'\x55\xaa'
    f.seek(0); f.write(mbr)
    f.seek(bs); f.write(header(1, total - 1, 2))
    f.seek(2 * bs); f.write(entries)
    f.seek(first * bs)
    with open(esp, 'rb') as e:
        while chunk := e.read(1 << 22):
            f.write(chunk)
    f.seek((total - 5) * bs); f.write(entries)
    f.seek((total - 1) * bs); f.write(header(total - 1, 1, total - 5))
PY
echo "=== Disk image complete ==="
ls -lh "$OUTPUT"
