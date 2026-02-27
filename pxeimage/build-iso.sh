#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BOOT_DIR="$SCRIPT_DIR/boot"
ISO_BUILD="/tmp/baremetalservices-iso"
ISO_OUTPUT="$PROJECT_DIR/baremetalservices.iso"
SYSLINUX_CACHE="$SCRIPT_DIR/.syslinux-cache"

echo "=== Building Bare Metal Services ISO ==="

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

# Copy ISOLINUX bootloader files
echo "Preparing ISO directory structure..."
cp "$SYSLINUX_CACHE/isolinux.bin" "$ISO_BUILD/isolinux/"
cp "$SYSLINUX_CACHE/ldlinux.c32"  "$ISO_BUILD/isolinux/"

# Copy kernel and initramfs
cp "$BOOT_DIR/vmlinuz"   "$ISO_BUILD/vmlinuz"
cp "$BOOT_DIR/initramfs" "$ISO_BUILD/initramfs"

# Create ISOLINUX config
cat > "$ISO_BUILD/isolinux/isolinux.cfg" <<'ISOLINUXCFG'
DEFAULT baremetalservices
TIMEOUT 50
PROMPT 1

SAY
SAY =============================================
SAY   Bare Metal Services - Boot ISO
SAY =============================================
SAY

LABEL baremetalservices
    MENU LABEL Bare Metal Services
    KERNEL /vmlinuz
    INITRD /initramfs
    APPEND console=tty0 console=ttyS1,115200n8 ip=dhcp iomem=relaxed
ISOLINUXCFG

# Build the ISO
echo "Building ISO image..."
XORRISO_ARGS=(
    -as mkisofs
    -o "$ISO_OUTPUT"
    -R -J                           # Rock Ridge + Joliet extensions
    -V "BAREMETALSERVICES"          # Volume label
    -c isolinux/boot.cat            # Boot catalog
    -b isolinux/isolinux.bin        # Boot image
    -no-emul-boot                   # No disk emulation
    -boot-load-size 4               # Load 4 sectors
    -boot-info-table                # Patch boot info table
)

# Add hybrid MBR for USB boot if isohdpfx.bin is available
if [ -f "$SYSLINUX_CACHE/isohdpfx.bin" ]; then
    XORRISO_ARGS+=(-isohybrid-mbr "$SYSLINUX_CACHE/isohdpfx.bin")
    echo "  Hybrid MBR enabled (USB bootable)"
fi

XORRISO_ARGS+=("$ISO_BUILD")

xorriso "${XORRISO_ARGS[@]}" 2>/dev/null

# Clean up
rm -rf "$ISO_BUILD"

echo ""
echo "=== ISO build complete ==="
ls -lh "$ISO_OUTPUT"
echo ""
echo "Boot from ISO:"
echo "  USB:  dd if=$ISO_OUTPUT of=/dev/sdX bs=1M status=progress"
echo "  IPMI: Upload via virtual media / remote console"
echo "  VM:   Attach as CD-ROM"
