#!/bin/bash
# Build a baremetalservices golden (#2). stormcentral runs this on the build
# box (dev.g8.lo) for a `media` component, from the root of a clean checkout:
#
#   deploy/build-golden.sh baremetalservices       OUT   # hybrid BIOS+UEFI ISO
#   deploy/build-golden.sh baremetalservices-maint OUT   # network-boot disk
#
# and keeps OUT/boot/<component>.iso as the golden's bytes (the name is
# stormcentral's convention for every media golden; for -maint the bytes are
# a GPT disk image, not ISO9660). Both goldens come from one image build:
#
#   baremetalservices        ISOLINUX (BIOS) + GRUB (UEFI), hybrid MBR/GPT:
#                            BMC virtual CD, USB sticks.
#   baremetalservices-maint  4096-byte-block GPT disk, ESP with a UKI as
#                            \EFI\BOOT\BOOTX64.EFI: what stormbootx claims over
#                            NVMe/TCP and chain-loads (boothost/<host> ->
#                            this golden), so a blade boots it at 10G instead
#                            of over the BMC's SMB1 virtual CD.
#
# OUT also gets vmlinuz, initramfs, BUILD and SHA256SUMS (logged by the build).
# Unprivileged; everything outside OUT is in a mktemp dir under $TMPDIR.
set -euo pipefail

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

GOLDEN="${1:-}"; OUT="${2:-}"
[[ -n "$GOLDEN" && -n "$OUT" ]] || die "usage: $0 baremetalservices|baremetalservices-maint OUT"
shift 2
[[ $# -eq 0 ]] || die "unknown argument: $1"
case "$GOLDEN" in
    baremetalservices|baremetalservices-maint) ;;
    *) die "unknown golden: $GOLDEN" ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
[[ -z "$(ls -A "$OUT")" ]] || die "$OUT is not empty; a golden is written into an empty tree"

COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
git -C "$ROOT" diff --quiet || die "the checkout has uncommitted changes; a golden is built from a commit"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bms-golden.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export TMPDIR="$WORK"

say "agent binary (commit ${COMMIT:0:7})"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o "$WORK/baremetalservices-linux" .)
cp "$WORK/baremetalservices-linux" "$ROOT/baremetalservices-linux"   # gitignored; build.sh takes it

say "kernel + initramfs"
mkdir -p "$OUT/boot"
BUILD_DIR="$WORK/rootfs" OUTPUT_DIR="$WORK/boot" bash "$ROOT/pxeimage/build.sh" 2>&1 | tail -25
[[ -s "$WORK/boot/vmlinuz" && -s "$WORK/boot/initramfs" ]] || die "no vmlinuz/initramfs"
cp "$WORK/boot/vmlinuz" "$WORK/boot/initramfs" "$OUT/"

case "$GOLDEN" in
baremetalservices)
    say "ISO (BIOS + UEFI)"
    BOOT_DIR="$WORK/boot" ISO_OUTPUT="$OUT/boot/$GOLDEN.iso" SYSLINUX_CACHE="$WORK/syslinux" \
        bash "$ROOT/pxeimage/build-iso.sh"
    ;;
baremetalservices-maint)
    say "network-boot disk (4K GPT, UKI)"
    bash "$ROOT/pxeimage/build-disk.sh" "$WORK/boot/vmlinuz" "$WORK/boot/initramfs" "$OUT/boot/$GOLDEN.iso"
    ;;
esac
[[ -s "$OUT/boot/$GOLDEN.iso" ]] || die "no boot/$GOLDEN.iso"

( cd "$OUT" && find . -type f ! -name SHA256SUMS ! -name BUILD | sed 's|^\./||' | sort \
    | xargs -r sha256sum ) > "$WORK/SHA256SUMS"
mv "$WORK/SHA256SUMS" "$OUT/SHA256SUMS"
{
    echo "golden   = $GOLDEN"
    echo "repo     = glennswest/baremetalservices"
    echo "commit   = $COMMIT"
    echo "kernel   = $(file -b "$OUT/vmlinuz" 2>/dev/null | grep -o 'version [^ ]*' || echo unknown)"
} > "$OUT/BUILD"
say "golden $GOLDEN: $(du -sh "$OUT/boot/$GOLDEN.iso" | cut -f1)"
cat "$OUT/BUILD" "$OUT/SHA256SUMS"
