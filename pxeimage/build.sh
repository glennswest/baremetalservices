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
echo "  scp $OUTPUT_DIR/{vmlinuz,initramfs,pxelinux.0,ldlinux.c32} root@pxe11.gw.lo:/tftpboot/"
echo "  scp $OUTPUT_DIR/pxelinux.cfg/default root@pxe11.gw.lo:/tftpboot/pxelinux.cfg/"
