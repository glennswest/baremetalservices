#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BOOT_DIR="$SCRIPT_DIR/boot"
ISO_BUILD="/tmp/baremetalservices-iso"
ISO_OUTPUT="$PROJECT_DIR/baremetalservices.iso"
SYSLINUX_CACHE="$SCRIPT_DIR/.syslinux-cache"

echo "=== Building Bare Metal Services ISO (BIOS + EFI) ==="

# Check prerequisites
if [ ! -f "$BOOT_DIR/vmlinuz" ] || [ ! -f "$BOOT_DIR/initramfs" ]; then
    echo "Error: vmlinuz or initramfs not found in $BOOT_DIR"
    echo "Run 'make pxeimage' first to build the PXE image."
    exit 1
fi

if ! command -v xorriso >/dev/null 2>&1; then
    echo "Error: xorriso not found. Install it:"
    echo "  macOS:  brew install xorriso"
    echo "  Linux:  apt install xorriso  (or  apk add xorriso)"
    exit 1
fi

if ! command -v grub-mkstandalone >/dev/null 2>&1; then
    echo "Error: grub-mkstandalone not found. Install it:"
    echo "  macOS:  brew install grub"
    echo "  Linux:  apt install grub-common grub-efi-amd64-bin"
    exit 1
fi

if ! command -v mformat >/dev/null 2>&1; then
    echo "Error: mtools (mformat/mcopy/mmd) not found. Install it:"
    echo "  macOS:  brew install mtools"
    echo "  Linux:  apt install mtools"
    exit 1
fi

# Download syslinux for isolinux.bin and isohdpfx.bin if not cached
SYSLINUX_VER="6.04_pre1-r15"
SYSLINUX_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/syslinux-${SYSLINUX_VER}.apk"
if [ ! -f "$SYSLINUX_CACHE/isolinux.bin" ] || [ ! -f "$SYSLINUX_CACHE/isohdpfx.bin" ]; then
    echo "Downloading syslinux for ISOLINUX bootloader..."
    mkdir -p "$SYSLINUX_CACHE"
    TMPAPK="/tmp/syslinux.apk"
    curl -sL "$SYSLINUX_URL" -o "$TMPAPK"
    tar xzf "$TMPAPK" -C "$SYSLINUX_CACHE" 'usr/share/syslinux/isolinux.bin' 2>/dev/null || true
    tar xzf "$TMPAPK" -C "$SYSLINUX_CACHE" 'usr/share/syslinux/isohdpfx.bin' 2>/dev/null || true
    tar xzf "$TMPAPK" -C "$SYSLINUX_CACHE" 'usr/share/syslinux/ldlinux.c32' 2>/dev/null || true
    # Flatten extracted files
    if [ -d "$SYSLINUX_CACHE/usr/share/syslinux" ]; then
        mv "$SYSLINUX_CACHE/usr/share/syslinux/isolinux.bin" "$SYSLINUX_CACHE/" 2>/dev/null || true
        mv "$SYSLINUX_CACHE/usr/share/syslinux/isohdpfx.bin" "$SYSLINUX_CACHE/" 2>/dev/null || true
        mv "$SYSLINUX_CACHE/usr/share/syslinux/ldlinux.c32" "$SYSLINUX_CACHE/" 2>/dev/null || true
        rm -rf "$SYSLINUX_CACHE/usr"
    fi
    rm -f "$TMPAPK"

    if [ ! -f "$SYSLINUX_CACHE/isolinux.bin" ]; then
        echo "Error: Failed to extract isolinux.bin from syslinux package"
        exit 1
    fi
    echo "  isolinux.bin cached"
fi

# Clean and create ISO build directory
rm -rf "$ISO_BUILD"
mkdir -p "$ISO_BUILD/isolinux"
mkdir -p "$ISO_BUILD/boot/grub"

# Copy ISOLINUX bootloader files
echo "Preparing ISO directory structure..."
cp "$SYSLINUX_CACHE/isolinux.bin" "$ISO_BUILD/isolinux/"
cp "$SYSLINUX_CACHE/ldlinux.c32"  "$ISO_BUILD/isolinux/"

# Copy kernel and initramfs
cp "$BOOT_DIR/vmlinuz"   "$ISO_BUILD/vmlinuz"
cp "$BOOT_DIR/initramfs" "$ISO_BUILD/initramfs"

# Create ISOLINUX config (BIOS boot)
cat > "$ISO_BUILD/isolinux/isolinux.cfg" <<'ISOLINUXCFG'
DEFAULT baremetalservices
TIMEOUT 0
PROMPT 0

LABEL baremetalservices
    MENU LABEL Bare Metal Services
    KERNEL /vmlinuz
    INITRD /initramfs
    APPEND console=tty0 console=ttyS1,115200n8 ip=dhcp iomem=relaxed
ISOLINUXCFG

# Create GRUB config (EFI boot) — same kernel params as ISOLINUX
cat > "$ISO_BUILD/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=0
set default=0
insmod all_video
insmod search
insmod search_label
menuentry "Bare Metal Services" {
    search --set=root --label BAREMETALSERVICES --no-floppy
    linux /vmlinuz console=tty0 console=ttyS1,115200n8 ip=dhcp iomem=relaxed
    initrd /initramfs
}
GRUBCFG

# Build standalone EFI binary with embedded grub.cfg
echo "Building GRUB EFI bootloader..."
TMPGRUB="/tmp/baremetalservices-grub"
mkdir -p "$TMPGRUB"
grub-mkstandalone \
    --format=x86_64-efi \
    --output="$TMPGRUB/bootx64.efi" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=$ISO_BUILD/boot/grub/grub.cfg"
echo "  bootx64.efi built"

# Create FAT EFI boot image using mtools
echo "Creating EFI boot image..."
dd if=/dev/zero of="$ISO_BUILD/efiboot.img" bs=1M count=4 2>/dev/null
mformat -i "$ISO_BUILD/efiboot.img" -F ::
mmd -i "$ISO_BUILD/efiboot.img" ::/EFI
mmd -i "$ISO_BUILD/efiboot.img" ::/EFI/BOOT
mcopy -i "$ISO_BUILD/efiboot.img" "$TMPGRUB/bootx64.efi" ::/EFI/BOOT/BOOTX64.EFI
rm -rf "$TMPGRUB"
echo "  efiboot.img created (4MB FAT)"

# Build the ISO with dual BIOS + EFI boot
echo "Building ISO image..."
XORRISO_ARGS=(
    -as mkisofs
    -o "$ISO_OUTPUT"
    -R -J                           # Rock Ridge + Joliet extensions
    -V "BAREMETALSERVICES"          # Volume label
    # BIOS boot (ISOLINUX)
    -c isolinux/boot.cat            # Boot catalog
    -b isolinux/isolinux.bin        # Boot image
    -no-emul-boot                   # No disk emulation
    -boot-load-size 4               # Load 4 sectors
    -boot-info-table                # Patch boot info table
    # EFI boot (GRUB)
    -eltorito-alt-boot              # Second boot entry
    -e efiboot.img                  # EFI boot image
    -no-emul-boot                   # No disk emulation for EFI
)

# Add hybrid MBR for USB boot if isohdpfx.bin is available
if [ -f "$SYSLINUX_CACHE/isohdpfx.bin" ]; then
    XORRISO_ARGS+=(
        -isohybrid-mbr "$SYSLINUX_CACHE/isohdpfx.bin"
        -isohybrid-gpt-basdat          # GPT entry for EFI partition
    )
    echo "  Hybrid MBR+GPT enabled (USB bootable, BIOS+EFI)"
fi

XORRISO_ARGS+=("$ISO_BUILD")

xorriso "${XORRISO_ARGS[@]}" 2>/dev/null

# Clean up
rm -rf "$ISO_BUILD"

echo ""
echo "=== ISO build complete (BIOS + EFI) ==="
ls -lh "$ISO_OUTPUT"
echo ""
echo "Boot from ISO:"
echo "  USB:  dd if=$ISO_OUTPUT of=/dev/sdX bs=1M status=progress"
echo "  IPMI: Upload via virtual media / remote console"
echo "  VM:   Attach as CD-ROM"
echo "  Supports both BIOS (ISOLINUX) and EFI (GRUB) boot modes"
