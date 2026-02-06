#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="/tmp/baremetalservices-build"
OUTPUT_DIR="$SCRIPT_DIR/boot"

echo "=== Building Bare Metal Services PXE Image ==="

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Extract base rootfs
echo "Extracting base rootfs..."
tar xzf "$SCRIPT_DIR/rootfs/rootfs-base.tar.gz" -C "$BUILD_DIR"

# Copy init script
echo "Installing init script..."
cp "$SCRIPT_DIR/init" "$BUILD_DIR/init"
chmod +x "$BUILD_DIR/init"

# Build the Go binary if not already built
if [ ! -f "$PROJECT_DIR/baremetalservices-linux" ]; then
    echo "Building baremetalservices binary..."
    cd "$PROJECT_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o baremetalservices-linux .
fi

# Copy the binary
echo "Installing baremetalservices binary..."
cp "$PROJECT_DIR/baremetalservices-linux" "$BUILD_DIR/usr/bin/baremetalservices"
chmod +x "$BUILD_DIR/usr/bin/baremetalservices"

# Install mstflint, dmidecode, smartmontools and dependencies
echo "Installing tools (mstflint, dmidecode, smartmontools)..."
MSTFLINT_URL="https://dl-cdn.alpinelinux.org/alpine/edge/testing/x86_64"
MAIN_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64"
COMMUNITY_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/community/x86_64"
mkdir -p "$BUILD_DIR/tmp/apk"
cd "$BUILD_DIR/tmp/apk"
# Download packages
curl -sLO "$MSTFLINT_URL/mstflint-4.26.0.1-r0.apk" || true
curl -sLO "$MAIN_URL/libgcc-13.2.1_git20240309-r1.apk" || true
curl -sLO "$MAIN_URL/libstdc++-13.2.1_git20240309-r1.apk" || true
curl -sLO "$MAIN_URL/dmidecode-3.6-r0.apk" || true
curl -sLO "$COMMUNITY_URL/smartmontools-7.4-r0.apk" || true
curl -sLO "$COMMUNITY_URL/flashrom-1.3.0-r2.apk" || true
curl -sLO "$MAIN_URL/ethtool-6.7-r0.apk" || true
curl -sLO "$MAIN_URL/libmnl-1.0.5-r2.apk" || true
curl -sLO "$MAIN_URL/pciutils-libs-3.12.0-r1.apk" || true
curl -sLO "$MAIN_URL/libusb-1.0.27-r0.apk" || true
curl -sLO "$COMMUNITY_URL/libftdi1-1.5-r3.apk" || true
curl -sLO "$MAIN_URL/confuse-3.3-r4.apk" || true
curl -sLO "$COMMUNITY_URL/ipmitool-1.8.19-r1.apk" || true
curl -sLO "$MAIN_URL/libcrypto3-3.3.6-r0.apk" || true
curl -sLO "$MAIN_URL/readline-8.2.10-r0.apk" || true
curl -sLO "$MAIN_URL/libncursesw-6.4_p20240420-r2.apk" || true
curl -sLO "$MAIN_URL/linux-lts-6.6.121-r0.apk" || true
# Disk management tools
curl -sLO "$MAIN_URL/hdparm-9.65-r2.apk" || true
curl -sLO "$MAIN_URL/parted-3.6-r2.apk" || true
curl -sLO "$MAIN_URL/e2fsprogs-1.47.0-r5.apk" || true
curl -sLO "$MAIN_URL/e2fsprogs-libs-1.47.0-r5.apk" || true
curl -sLO "$MAIN_URL/xfsprogs-6.8.0-r0.apk" || true
curl -sLO "$MAIN_URL/dosfstools-4.2-r2.apk" || true
curl -sLO "$MAIN_URL/nvme-cli-2.9.1-r0.apk" || true
curl -sLO "$MAIN_URL/libnvme-1.9-r0.apk" || true
curl -sLO "$MAIN_URL/libuuid-2.40.1-r1.apk" || true
curl -sLO "$MAIN_URL/libblkid-2.40.1-r1.apk" || true
curl -sLO "$MAIN_URL/libeconf-0.6.3-r0.apk" || true
curl -sLO "$MAIN_URL/libsmartcols-2.40.1-r1.apk" || true
curl -sLO "$MAIN_URL/libmount-2.40.1-r1.apk" || true
curl -sLO "$MAIN_URL/libfdisk-2.40.1-r1.apk" || true
curl -sLO "$MAIN_URL/lvm2-libs-2.03.23-r3.apk" || true
curl -sLO "$MAIN_URL/json-c-0.17-r0.apk" || true
# PCI and block device tools
curl -sLO "$MAIN_URL/pciutils-3.12.0-r1.apk" || true
curl -sLO "$MAIN_URL/lsblk-2.40.1-r1.apk" || true
# Extract packages (except linux-lts which is handled specially)
for pkg in *.apk; do
    [ -f "$pkg" ] && [ "$pkg" != "linux-lts-6.6.121-r0.apk" ] && tar xzf "$pkg" -C "$BUILD_DIR" 2>/dev/null || true
done
# Extract IPMI, AHCI, and SATA modules from linux-lts
if [ -f "linux-lts-6.6.121-r0.apk" ]; then
    tar xzf linux-lts-6.6.121-r0.apk -C "$BUILD_DIR" 'lib/modules/*/kernel/drivers/char/ipmi/*' 2>/dev/null || true
    tar xzf linux-lts-6.6.121-r0.apk -C "$BUILD_DIR" 'lib/modules/*/kernel/drivers/ata/*' 2>/dev/null || true
    tar xzf linux-lts-6.6.121-r0.apk -C "$BUILD_DIR" 'lib/modules/*/kernel/drivers/scsi/*' 2>/dev/null || true
    tar xzf linux-lts-6.6.121-r0.apk -C "$BUILD_DIR" 'lib/modules/*/kernel/block/*' 2>/dev/null || true
    tar xzf linux-lts-6.6.121-r0.apk -C "$BUILD_DIR" 'lib/modules/*/kernel/lib/*' 2>/dev/null || true
    tar xzf linux-lts-6.6.121-r0.apk -C "$BUILD_DIR" 'lib/modules/*/kernel/drivers/cdrom/*' 2>/dev/null || true
    # Run depmod to update module dependencies
    depmod -b "$BUILD_DIR" 6.6.121-0-lts 2>/dev/null || true
fi
cd "$PROJECT_DIR"
rm -rf "$BUILD_DIR/tmp/apk" "$BUILD_DIR/.PKGINFO" "$BUILD_DIR/.SIGN."* 2>/dev/null || true

# Download Mellanox firmware files
echo "Downloading Mellanox firmware..."
mkdir -p "$BUILD_DIR/usr/share/firmware/mellanox"
FIRMWARE_DIR="$BUILD_DIR/usr/share/firmware/mellanox"
# ConnectX-3 firmware (MCX311A-XCAT, PSID MT_1170110023)
curl -sL "http://www.mellanox.com/downloads/firmware/fw-ConnectX3-rel-2_42_5000-MCX311A-XCA_Ax-FlexBoot-3.4.752.bin.zip" -o /tmp/cx3-fw.zip 2>/dev/null && \
    unzip -q -o /tmp/cx3-fw.zip -d "$FIRMWARE_DIR" 2>/dev/null && \
    rm /tmp/cx3-fw.zip || echo "Warning: Could not download ConnectX-3 firmware"
# List downloaded firmware
ls -la "$FIRMWARE_DIR" 2>/dev/null || true

# Copy BIOS files if available
echo "Installing BIOS files..."
mkdir -p "$BUILD_DIR/usr/share/firmware/bios"
BIOS_DIR="$BUILD_DIR/usr/share/firmware/bios"
# Supermicro X9SRD-F BIOS 3.2b
if [ -f ~/Downloads/X9SRD6.bin ]; then
    cp ~/Downloads/X9SRD6.bin "$BIOS_DIR/X9SRD-F_3.2b.bin"
    echo "  Installed X9SRD-F BIOS 3.2b"
elif [ -f "$SCRIPT_DIR/firmware/X9SRD-F_3.2b.bin" ]; then
    cp "$SCRIPT_DIR/firmware/X9SRD-F_3.2b.bin" "$BIOS_DIR/"
    echo "  Installed X9SRD-F BIOS 3.2b from firmware dir"
fi
ls -la "$BIOS_DIR" 2>/dev/null || true

# Install SSH authorized keys from user's home directory
if ls ~/.ssh/id_*.pub >/dev/null 2>&1; then
    echo "Installing SSH authorized keys..."
    mkdir -p "$BUILD_DIR/root/.ssh"
    cat ~/.ssh/id_*.pub > "$BUILD_DIR/root/.ssh/authorized_keys"
    chmod 700 "$BUILD_DIR/root/.ssh"
    chmod 600 "$BUILD_DIR/root/.ssh/authorized_keys"
    # Fix ownership (will be root:root in the cpio archive)
    chown -R 0:0 "$BUILD_DIR/root/.ssh" 2>/dev/null || true
fi

# Create initramfs
echo "Creating initramfs..."
cd "$BUILD_DIR"
find . | cpio -H newc -o 2>/dev/null | gzip > "$OUTPUT_DIR/initramfs"

echo "=== Build complete ==="
echo "Output files in: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR/initramfs" "$OUTPUT_DIR/vmlinuz"
echo ""
echo "To deploy to PXE server:"
echo "  make deploy"
echo "Or manually:"
echo "  scp -o ProxyJump=admin@192.168.1.88 $OUTPUT_DIR/{vmlinuz,initramfs,pxelinux.0,ldlinux.c32} root@192.168.10.200:/tftpboot/"
echo "  scp -o ProxyJump=admin@192.168.1.88 $OUTPUT_DIR/pxelinux.cfg/default root@192.168.10.200:/tftpboot/pxelinux.cfg/"
