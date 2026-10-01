#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# Scratch and output are overridable so the golden build (deploy/build-golden.sh)
# keeps everything on its own job drive: nothing in /tmp or ~ (#2).
BUILD_DIR="${BUILD_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bms-rootfs.XXXXXX")}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/boot}"
mkdir -p "$OUTPUT_DIR"

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
rm -f "$BUILD_DIR/usr/bin/baremetalservices"
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

# Download packages. Every one is found by name in the repo index (#1): a
# pinned revision 404s silently as the CDN moves on, which is how the image
# shipped an efibootmgr without libefivar (#2). The tools the image exists for
# are required, so a miss fails the build instead of shipping a broken tool.
fetch_apk "$MSTFLINT_URL" mstflint
fetch_apk "$MAIN_URL" libgcc required
fetch_apk "$MAIN_URL" libstdc++ required
fetch_apk "$MAIN_URL" dmidecode required
fetch_apk "$MAIN_URL" smartmontools required
fetch_apk "$COMMUNITY_URL" flashrom
fetch_apk "$MAIN_URL" ethtool required
fetch_apk "$MAIN_URL" libmnl required
fetch_apk "$MAIN_URL" pciutils-libs required
fetch_apk "$MAIN_URL" libusb required
fetch_apk "$COMMUNITY_URL" libftdi1
fetch_apk "$MAIN_URL" confuse required
fetch_apk "$COMMUNITY_URL" ipmitool required
fetch_apk "$MAIN_URL" libcrypto3 required
fetch_apk "$MAIN_URL" readline required
fetch_apk "$MAIN_URL" libncursesw required
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
fetch_apk "$MAIN_URL" hdparm required
fetch_apk "$MAIN_URL" parted required
fetch_apk "$MAIN_URL" e2fsprogs required
fetch_apk "$MAIN_URL" e2fsprogs-libs required
fetch_apk "$MAIN_URL" xfsprogs required
fetch_apk "$MAIN_URL" dosfstools required
# A disk wipe needs wipefs and sgdisk (#15): without wipefs the old wipe
# "succeeded" and left every partition in place.
fetch_apk "$MAIN_URL" wipefs required
fetch_apk "$MAIN_URL" sgdisk required
# NVMe: nvme-cli is useless without libnvme + libnvme-mi, and both must match
# the CDN's current version — pin nothing, and fail the build if either is
# missing rather than shipping a binary that cannot start (issue #1).
fetch_apk "$MAIN_URL" libnvme required
# libnvme-mi.so.1 ships in a separate package, libnvmemi — without it nvme
# still dies at startup exactly as in issue #1.
fetch_apk "$MAIN_URL" libnvmemi required
fetch_apk "$MAIN_URL" nvme-cli required
# Storage benchmarking — dd alone is queue-depth 1 and cannot produce an
# IOPS/latency curve (issue #1). fio lives in the community repo, not main.
fetch_apk "$COMMUNITY_URL" fio required
fetch_apk "$MAIN_URL" libaio
# iSCSI initiator, so the agent can consume iSCSI targets as well as NVMe-oF.
# The runtime libs package is open-iscsi-libs (libopeniscsiusr does not exist
# in v3.20 — it silently skipped as optional).
fetch_apk "$MAIN_URL" open-iscsi
fetch_apk "$MAIN_URL" open-iscsi-libs
fetch_apk "$MAIN_URL" libuuid required
fetch_apk "$MAIN_URL" libblkid required
fetch_apk "$MAIN_URL" libeconf required
fetch_apk "$MAIN_URL" libsmartcols required
fetch_apk "$MAIN_URL" libmount required
fetch_apk "$MAIN_URL" libfdisk required
fetch_apk "$MAIN_URL" lvm2-libs required
# libparted links libdevmapper; without it `parted` (POST /disks/partition)
# dies at startup (found by the #15 boot test).
fetch_apk "$MAIN_URL" device-mapper-libs required
# Found missing by the shared-library check below (#15): mkfs.ext4/e2fsck
# (libcom_err), mkfs.xfs/xfs_repair (inih, userspace-rcu), fio (numactl),
# iscsiadm/iscsid (kmod-libs, open-isns-lib), efibootdump (libintl), lvm2
# (device-mapper-event-libs).
fetch_apk "$MAIN_URL" libcom_err required
fetch_apk "$MAIN_URL" inih required
fetch_apk "$MAIN_URL" userspace-rcu required
fetch_apk "$MAIN_URL" numactl required
fetch_apk "$MAIN_URL" kmod-libs required
fetch_apk "$MAIN_URL" open-isns-lib required
fetch_apk "$MAIN_URL" libintl required
fetch_apk "$MAIN_URL" device-mapper-event-libs required
fetch_apk "$MAIN_URL" json-c required
# PCI and block device tools
fetch_apk "$MAIN_URL" pciutils required
fetch_apk "$MAIN_URL" lsblk required
fetch_apk "$MAIN_URL" hwdata-pci required
# EFI boot manager (for BIOS/PXE configuration)
fetch_apk "$MAIN_URL" efibootmgr required
fetch_apk "$MAIN_URL" efivar-libs required
fetch_apk "$MAIN_URL" popt required
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
# Built unprivileged (dev), read-only dirs and files from the packages stay
# read-only to us too: make the tree writable by its owner so the installs
# below can land. The image's ownership is set at cpio time (-R 0:0).
chmod -R u+w "$BUILD_DIR"

# Download Mellanox firmware files
echo "Downloading Mellanox firmware..."
mkdir -p "$BUILD_DIR/usr/share/firmware/mellanox"
FIRMWARE_DIR="$BUILD_DIR/usr/share/firmware/mellanox"
# ConnectX-3 firmware (MCX311A-XCAT, PSID MT_1170110023)
CX3_ZIP="$BUILD_DIR/tmp/cx3-fw.zip"
curl -sL "http://www.mellanox.com/downloads/firmware/fw-ConnectX3-rel-2_42_5000-MCX311A-XCA_Ax-FlexBoot-3.4.752.bin.zip" -o "$CX3_ZIP" 2>/dev/null && \
    unzip -q -o "$CX3_ZIP" -d "$FIRMWARE_DIR" 2>/dev/null || echo "Warning: Could not download ConnectX-3 firmware"
rm -f "$CX3_ZIP"
# List downloaded firmware
ls -la "$FIRMWARE_DIR" 2>/dev/null || true

# glibc runtime for the vendor binaries (sum, mlxup), issue #14.
#
# Both are glibc programs (PT_INTERP /lib64/ld-linux-x86-64.so.2). The base
# rootfs points that path at Alpine's gcompat shim, which lacks symbols sum
# needs: `Error relocating /usr/bin/sum: mallopt / posix_fallocate64: symbol
# not found`. Ship a real glibc instead: Debian's libc6, libgcc-s1, zlib1g and
# libstdc++6, unpacked into /usr/lib/x86_64-linux-gnu (the multiarch dir
# Debian's ld.so searches before /lib, so it never picks up a musl lib, and
# musl's loader never looks there), and repoint /lib64/ld-linux-x86-64.so.2 at
# Debian's loader. The binaries run unmodified; nothing else uses /lib64.
echo "Installing glibc runtime for sum/mlxup..."
DEBIAN_URL="https://deb.debian.org/debian"
DEBIAN_SUITE="trixie"
GLIBC_DIR="usr/lib/x86_64-linux-gnu"
GLIBC_WORK="$(mktemp -d "${TMPDIR:-/tmp}/bms-glibc.XXXXXX")"
curl -sfL "$DEBIAN_URL/dists/$DEBIAN_SUITE/main/binary-amd64/Packages.xz" -o "$GLIBC_WORK/Packages.xz" \
    || { echo "ERROR: cannot fetch the Debian $DEBIAN_SUITE package index"; exit 1; }
for deb in libc6 libgcc-s1 zlib1g libstdc++6; do
    # Found by name in the index, like fetch_apk: nothing pinned (#1).
    file=$(xz -dc "$GLIBC_WORK/Packages.xz" | awk -v p="$deb" '
        /^Package: / { hit = ($2 == p) }
        hit && /^Filename: / { print $2; exit }')
    [ -n "$file" ] || { echo "ERROR: $deb not in the Debian $DEBIAN_SUITE index"; exit 1; }
    curl -sfL "$DEBIAN_URL/$file" -o "$GLIBC_WORK/$deb.deb" || { echo "ERROR: download of $file failed"; exit 1; }
    data=$(cd "$GLIBC_WORK" && ar t "$deb.deb" | grep '^data\.tar')
    (cd "$GLIBC_WORK" && ar x "$deb.deb" "$data")
    tar xf "$GLIBC_WORK/$data" -C "$BUILD_DIR" "./$GLIBC_DIR" \
        || { echo "ERROR: $deb has no $GLIBC_DIR"; exit 1; }
    rm -f "$GLIBC_WORK/$data"
    echo "  $(basename "$file")"
done
rm -rf "$GLIBC_WORK"
chmod -R u+w "$BUILD_DIR/$GLIBC_DIR"
mkdir -p "$BUILD_DIR/lib64"
ln -sfn "/$GLIBC_DIR/ld-linux-x86-64.so.2" "$BUILD_DIR/lib64/ld-linux-x86-64.so.2"
GLIBC_LD="$BUILD_DIR/$GLIBC_DIR/ld-linux-x86-64.so.2"
[ -x "$GLIBC_LD" ] || { echo "ERROR: no glibc loader at /$GLIBC_DIR"; exit 1; }

# Run a vendor binary on the image's glibc, from the build host: every symbol
# bound up front (LD_BIND_NOW), libraries only from the image.
image_glibc_run() { LD_BIND_NOW=1 "$GLIBC_LD" --inhibit-cache --library-path "$BUILD_DIR/$GLIBC_DIR" "$@"; }

# Install Supermicro Update Manager (SUM), with its ExternalData beside it as
# in Supermicro's package; /usr/bin/sum links to it.
echo "Installing Supermicro Update Manager (SUM)..."
# usr/bin/sum is busybox's `sum` applet, an absolute symlink: remove it rather
# than let cp follow it onto the build host's /bin/busybox.
rm -f "$BUILD_DIR/usr/bin/sum"
mkdir -p "$BUILD_DIR/opt/sum"
cp "$SCRIPT_DIR/tools/sum/sum" "$BUILD_DIR/opt/sum/sum"
chmod +x "$BUILD_DIR/opt/sum/sum"
cp -r "$SCRIPT_DIR/tools/sum/ExternalData" "$BUILD_DIR/opt/sum/"
ln -s /opt/sum/sum "$BUILD_DIR/usr/bin/sum"
# sum -v exits 5 ("no command") once it has run; a loader failure is 127.
# It writes sum.log to its working directory: run it in the image's /tmp.
(cd "$BUILD_DIR/tmp" && image_glibc_run "$BUILD_DIR/opt/sum/sum" -v >sum-v.log 2>&1) || true
rm -f "$BUILD_DIR/tmp/sum.log"
grep -q 'Supermicro Update Manager' "$BUILD_DIR/tmp/sum-v.log" \
    || { echo "ERROR: sum does not run on the image's glibc:"; cat "$BUILD_DIR/tmp/sum-v.log"; exit 1; }
echo "  $(head -1 "$BUILD_DIR/tmp/sum-v.log") — runs on the image's glibc"
rm -f "$BUILD_DIR/tmp/sum-v.log"

# Install mlxup (Mellanox firmware update tool)
echo "Installing mlxup..."
if [ -f "$SCRIPT_DIR/tools/mlxup" ]; then
    rm -f "$BUILD_DIR/usr/bin/mlxup"
    cp "$SCRIPT_DIR/tools/mlxup" "$BUILD_DIR/usr/bin/mlxup"
    chmod +x "$BUILD_DIR/usr/bin/mlxup"
    # mlxup is a self-extractor that reads /proc/self/exe, so it cannot be
    # started through the loader; resolve and relocate it instead (ldd -r).
    out=$(LD_WARN=yes image_glibc_run --list "$BUILD_DIR/usr/bin/mlxup" 2>&1) && ! grep -q 'undefined symbol' <<<"$out" \
        || { echo "ERROR: mlxup does not link against the image's glibc:"; echo "$out"; exit 1; }
    echo "  Installed mlxup (links against the image's glibc)"
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

# Every musl program and library must find its shared libraries (#15): a
# missing one only shows when the tool is run (libnvme-mi #1, libefivar #2,
# libdevmapper #15). The vendor glibc binaries were checked above.
echo "Checking shared libraries..."
command -v readelf >/dev/null || { echo "ERROR: readelf (binutils) is needed to check the image"; exit 1; }
missing=$(cd "$BUILD_DIR" && find bin sbin usr/bin usr/sbin lib usr/lib usr/libexec -type f \
        -not -path 'lib/modules/*' -not -path "$GLIBC_DIR/*" -not -path 'opt/*' -not -path 'usr/bin/mlxup' 2>/dev/null |
    while read -r f; do
        [ "$(head -c4 "$f" | od -An -c | tr -d ' ')" = '177ELF' ] || continue
        readelf -d "$f" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | while read -r lib; do
            [ -e "lib/$lib" ] || [ -e "usr/lib/$lib" ] || [ -e "usr/local/lib/$lib" ] || echo "  /$f needs $lib"
        done
    done)
if [ -n "$missing" ]; then
    echo "ERROR: shared libraries missing from the image:"; echo "$missing"; exit 1
fi
echo "  every ELF in the image finds its shared libraries"

# Create initramfs
echo "Creating initramfs..."
cd "$BUILD_DIR"
# -R 0:0: every file is root's in the image, whoever ran the build (dev builds
# as an unprivileged user).
find . | cpio -H newc -R 0:0 -o 2>/dev/null | gzip > "$OUTPUT_DIR/initramfs"
cd "$PROJECT_DIR"
[ -n "${KEEP_BUILD_DIR:-}" ] || rm -rf "$BUILD_DIR"

echo "=== Build complete ==="
echo "Output files in: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR/initramfs" "$OUTPUT_DIR/vmlinuz"
echo ""
echo "To deploy to PXE server:"
echo "  make deploy"
echo "Or manually:"
echo "  scp -o ProxyJump=admin@192.168.1.88 $OUTPUT_DIR/{vmlinuz,initramfs,pxelinux.0,ldlinux.c32} root@192.168.10.200:/tftpboot/"
echo "  scp -o ProxyJump=admin@192.168.1.88 $OUTPUT_DIR/pxelinux.cfg/default root@192.168.10.200:/tftpboot/pxelinux.cfg/"
