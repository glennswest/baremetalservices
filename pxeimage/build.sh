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

# Fetch an APK by NAME without pinning its version.
#
# Alpine's CDN rotates package versions, so a pinned filename 404s the moment
# the index moves — and with `|| true` that failure is silent. That is how the
# image shipped nvme-cli without libnvme: `nvme` then dies at startup with
# "Error loading shared library libnvme-mi.so.1" (issue #1). Discover the
# current filename from the repo index instead, and make a miss LOUD.
#
#   fetch_apk <repo-url> <package-name> [required]
fetch_apk() {
    local repo="$1" name="$2" required="${3:-optional}" file
    file=$(curl -sL "$repo/" | grep -o "${name}-[0-9][^\"]*\.apk" | grep -v -- '-doc-\|-dev-' | sort -V | tail -1)
    if [ -z "$file" ]; then
        if [ "$required" = "required" ]; then
            echo "ERROR: package '$name' not found in $repo — refusing to build a broken image"
            exit 1
        fi
        echo "WARNING: package '$name' not found in $repo (skipping)"
        return 0
    fi
    if curl -sfLO "$repo/$file"; then
        echo "  fetched $file"
    elif [ "$required" = "required" ]; then
        echo "ERROR: download of $file failed"; exit 1
    else
        echo "WARNING: download of $file failed (skipping)"
    fi
}

# Download packages
curl -sLO "$MSTFLINT_URL/mstflint-4.26.0.1-r0.apk" || true
curl -sLO "$MAIN_URL/libgcc-13.2.1_git20240309-r1.apk" || true
curl -sLO "$MAIN_URL/libstdc++-13.2.1_git20240309-r1.apk" || true
curl -sLO "$MAIN_URL/dmidecode-3.6-r0.apk" || true
curl -sLO "$MAIN_URL/smartmontools-7.4-r1.apk" || true
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
# Discover latest linux-lts package version dynamically (CDN rotates versions)
LINUX_LTS_APK=$(curl -sL "$MAIN_URL/" | grep -o 'linux-lts-[0-9][^"]*\.apk' | sort -V | tail -1)
if [ -z "$LINUX_LTS_APK" ]; then
    echo "ERROR: Could not discover linux-lts package version from Alpine CDN"
    exit 1
fi
echo "Using kernel package: $LINUX_LTS_APK"
LINUX_LTS_KVER=$(echo "$LINUX_LTS_APK" | sed 's/linux-lts-//;s/-r[0-9]*\.apk//' | sed 's/$/-0-lts/')
echo "Kernel module version: $LINUX_LTS_KVER"
curl -sLO "$MAIN_URL/$LINUX_LTS_APK" || true
# Disk management tools
curl -sLO "$MAIN_URL/hdparm-9.65-r2.apk" || true
curl -sLO "$MAIN_URL/parted-3.6-r2.apk" || true
curl -sLO "$MAIN_URL/e2fsprogs-1.47.0-r5.apk" || true
curl -sLO "$MAIN_URL/e2fsprogs-libs-1.47.0-r5.apk" || true
curl -sLO "$MAIN_URL/xfsprogs-6.8.0-r0.apk" || true
curl -sLO "$MAIN_URL/dosfstools-4.2-r2.apk" || true
# NVMe: nvme-cli is useless without libnvme + libnvme-mi, and both must match
# the CDN's current version — pin nothing, and fail the build if either is
# missing rather than shipping a binary that cannot start (issue #1).
fetch_apk "$MAIN_URL" libnvme required
fetch_apk "$MAIN_URL" nvme-cli required
# Storage benchmarking — dd alone is queue-depth 1 and cannot produce an
# IOPS/latency curve (issue #1).
fetch_apk "$MAIN_URL" fio required
fetch_apk "$MAIN_URL" libaio
# iSCSI initiator, so the agent can consume iSCSI targets as well as NVMe-oF.
fetch_apk "$MAIN_URL" open-iscsi
fetch_apk "$MAIN_URL" libopeniscsiusr
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
curl -sLO "$MAIN_URL/hwdata-pci-0.382-r0.apk" || true
# EFI boot manager (for BIOS/PXE configuration)
curl -sLO "$MAIN_URL/efibootmgr-18-r2.apk" || true
curl -sLO "$MAIN_URL/efivar-libs-38-r0.apk" || true
curl -sLO "$MAIN_URL/popt-1.19-r3.apk" || true
# Extract packages (except linux-lts which is handled specially)
for pkg in *.apk; do
    [ -f "$pkg" ] && [ "$pkg" != "$LINUX_LTS_APK" ] && tar xzf "$pkg" -C "$BUILD_DIR" 2>/dev/null || true
done
# Extract ALL modules and vmlinuz from linux-lts APK
# Kernel and modules must come from the same APK to ensure version match
if [ -f "$LINUX_LTS_APK" ]; then
    # Remove any old kernel modules from rootfs-base (different version)
    rm -rf "$BUILD_DIR/lib/modules"
    # Extract all modules and kernel
    tar xzf "$LINUX_LTS_APK" -C "$BUILD_DIR" 'lib/modules/' 2>/dev/null || true
    tar xzf "$LINUX_LTS_APK" -C "$BUILD_DIR" 'boot/vmlinuz-lts' 2>/dev/null || true
    if [ -f "$BUILD_DIR/boot/vmlinuz-lts" ]; then
        cp "$BUILD_DIR/boot/vmlinuz-lts" "$OUTPUT_DIR/vmlinuz"
        echo "Updated vmlinuz from $LINUX_LTS_APK (kernel $LINUX_LTS_KVER)"
    fi
    # Run depmod to update module dependencies
    depmod -b "$BUILD_DIR" "$LINUX_LTS_KVER" 2>/dev/null || true
else
    echo "ERROR: linux-lts APK not found: $LINUX_LTS_APK"
    exit 1
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

# Install Supermicro Update Manager (SUM)
echo "Installing Supermicro Update Manager (SUM)..."
if [ -d "$SCRIPT_DIR/tools/sum" ]; then
    cp "$SCRIPT_DIR/tools/sum/sum" "$BUILD_DIR/usr/bin/sum"
    chmod +x "$BUILD_DIR/usr/bin/sum"
    mkdir -p "$BUILD_DIR/usr/share/sum"
    cp -r "$SCRIPT_DIR/tools/sum/ExternalData" "$BUILD_DIR/usr/share/sum/"
    echo "  Installed SUM binary and ExternalData"
fi

# Install mlxup (Mellanox firmware update tool)
echo "Installing mlxup..."
if [ -f "$SCRIPT_DIR/tools/mlxup" ]; then
    cp "$SCRIPT_DIR/tools/mlxup" "$BUILD_DIR/usr/bin/mlxup"
    chmod +x "$BUILD_DIR/usr/bin/mlxup"
    echo "  Installed mlxup"
fi

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
