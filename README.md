# Bare Metal Services

A bare metal server management and provisioning system that runs as a boot image (network boot through stormbootx, BMC virtual CD, USB). Provides a REST API, web dashboard, and CLI tools for hardware discovery, disk management, firmware updates, and IPMI configuration.

## Architecture

- **Go binary** serving two HTTP servers simultaneously:
  - **Port 80** - Web UI dashboard with auto-refresh
  - **Port 8080** - JSON REST API
- **Boot image** based on Alpine Linux with a custom init script, built as two goldens: a 4K GPT disk for network boot through stormbootx, and a hybrid BIOS+UEFI ISO for BMC virtual CD and USB
- Boots, discovers hardware, and exposes management interfaces over the network

## Quick Start

Built on the build box (dev.g8.lo) as two stormcentral **media goldens** from
one image build — never on server1, never with podman, no `make deploy`:

| Golden | Bytes | Used for |
|--------|-------|----------|
| `baremetalservices` | Hybrid ISO: ISOLINUX (BIOS) + GRUB (UEFI), MBR+GPT | BMC virtual CD, USB sticks; boot helper `iso` |
| `baremetalservices-maint` | GPT disk at **4096-byte blocks**, one ESP holding a unified kernel image as `\EFI\BOOT\BOOTX64.EFI` | Network boot through stormbootx at NIC speed; boot helper `img` |

```bash
# Build and boot-test both images on dev (from your checkout, after git push)
sc-build test/run.sh

# Request the goldens (stormcentral runs deploy/build-golden.sh on dev)
stormcentral component build baremetalservices      --url http://stormcentral.g8.lo
stormcentral component build baremetalservices-maint --url http://stormcentral.g8.lo

# Run the agent locally for development
make run
```

Both are boot helpers that ride with the BMC/IPMI role (`boothelper_with =
["stormipmi"]`, stormcentral#227): a release whose image carries stormipmi
lists them as optional rows, and minismbd shares them for BMC virtual media.

## REST API

All API responses use the format:
```json
{
  "status": "ok",
  "message": "...",
  "data": { ... }
}
```

### System Information

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API documentation (lists all endpoints) |
| GET | `/health` | Health check |
| GET | `/system` | System info (hostname, CPU, cores, memory, network, uptime, kernel) |
| GET | `/asset` | Asset info (system manufacturer, serial, UUID, BIOS, chassis, baseboard) |
| GET | `/network` | Network interfaces with MAC, IP, speed, driver, firmware, model |
| GET | `/macs` | MAC addresses for eth0, eth1, and IPMI |
| GET | `/memory` | Memory DIMM details (locator, size, type, speed, manufacturer, part number, serial) |

### IPMI

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ipmi` | IPMI info (IP, MAC, IP source, subnet, gateway, users) |
| POST | `/ipmi/reset` | Reset IPMI to ADMIN/ADMIN credentials with full access and DHCP |

### Disk Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/disks` | List all disks with details (serial, firmware, SMART health, media type, temperature, power-on hours) |
| GET | `/disks/detail/{dev}` | Detailed info for a specific disk (e.g., `/disks/detail/sda`) |
| POST | `/disks/partition/{dev}` | Create partition table. Parameters: `label=gpt\|msdos` (default: gpt) |
| POST | `/disks/format/{dev}` | Format a partition. Parameters: `fstype=ext4\|xfs\|vfat` (default: ext4) |
| POST | `/disks/wipe` | Wipe ALL disks (blkdiscard/dd + wipefs) |
| POST | `/disks/wipe/{dev}` | Wipe a specific disk |
| POST | `/disks/secure-erase/{dev}` | ATA Secure Erase (hdparm) for SATA, nvme format for NVMe |

### Firmware & BIOS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/firmware` | List bundled Mellanox firmware files |
| POST | `/firmware/update` | Update Mellanox NIC firmware. Parameters: `device=<pci_addr>`, optional `url=<firmware_url>` |
| GET | `/bios` | BIOS version and update availability |
| POST | `/bios/update` | Update BIOS via flashrom (checks board compatibility, requires `force=true`) |
| POST | `/bios/configure` | Configure BIOS settings (quick_boot, quiet_boot, disable PXE on specified NICs) |
| GET | `/bios/config` | The whole BIOS configuration file (`sum -c GetCurrentBiosCfg`), returned as-is (text, or XML on newer boards) |
| POST | `/bios/config` | Apply a file from `GET /bios/config` as the request body (`sum -c ChangeBiosCfg`); takes effect on the next reboot |

### Boot Order (UEFI)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/boot/order` | EFI boot entries (`num`, `name`, `active`, `path`), `order`, `boot_current`, `boot_next`, `timeout` (`efibootmgr -v`) |
| POST | `/boot/order` | JSON `{"order": ["0003","0001"], "next": "0003"}` — either or both; every number must be an existing `BootXXXX` entry |

Both need the agent to have been booted in UEFI mode (efivarfs); in legacy BIOS mode they answer 503.

### API Examples

```bash
# System info
curl http://server1:8080/system

# List all disks with firmware and SMART data
curl http://server1:8080/disks

# Detailed info for a single disk
curl http://server1:8080/disks/detail/sda

# Create GPT partition table
curl -X POST http://server1:8080/disks/partition/sda

# Format as ext4
curl -X POST http://server1:8080/disks/format/sda1?fstype=ext4

# Secure erase a disk
curl -X POST http://server1:8080/disks/secure-erase/sda

# Wipe a specific disk
curl -X POST http://server1:8080/disks/wipe/sda

# Reset IPMI credentials
curl -X POST http://server1:8080/ipmi/reset

# Update Mellanox NIC firmware
curl -X POST http://server1:8080/firmware/update -d "device=05:00.0"

# Copy one blade's BIOS setup to another (reboot the target to apply)
curl -s http://server1:8080/bios/config -o bios.cfg
curl -X POST --data-binary @bios.cfg http://server2:8080/bios/config

# Boot order: show it, then put Boot0003 first and boot Boot0001 once
curl http://server1:8080/boot/order
curl -X POST http://server1:8080/boot/order \
  -H 'Content-Type: application/json' -d '{"order": ["0003","0001","0000"], "next": "0001"}'

# Configure BIOS — disable PXE on Mellanox NICs, enable quick boot
curl -X POST http://server1:8080/bios/configure \
  -H 'Content-Type: application/json' \
  -d '{"quick_boot": true, "quiet_boot": true, "disable_pxe_nics": ["mellanox"]}'
```

## Web UI

The web dashboard on port 80 provides:

- **System info** - hostname, kernel, CPU, cores
- **Memory** - total, used, free
- **Asset info** - manufacturer, product, serial, BIOS version, board
- **Network interfaces** - MAC, IP, state, speed, driver, firmware, model
- **Disks** - device, size, type (SSD/HDD/NVMe badges), model, serial, firmware, SMART health, temperature, power-on hours, with wipe and secure erase action buttons
- **lspci** - raw PCI device listing
- **lsblk** - raw block device listing

Auto-refreshes every 30 seconds.

## CLI Tools Available

When SSH'd into a booted server (`ssh root@<ip>`), the following tools are available:

| Tool | Purpose |
|------|---------|
| `lsblk` | List block devices |
| `lspci` | List PCI devices |
| `smartctl` | SMART disk diagnostics |
| `hdparm` | ATA drive parameters and secure erase |
| `parted` | Disk partitioning |
| `mkfs.ext4` | Format ext4 filesystem |
| `mkfs.xfs` | Format XFS filesystem |
| `mkfs.vfat` | Format FAT32 filesystem |
| `nvme` | NVMe drive management |
| `ipmitool` | IPMI/BMC management |
| `ethtool` | Network interface configuration |
| `dmidecode` | DMI/SMBIOS hardware info |
| `mstflint` | Mellanox NIC firmware tools |
| `flashrom` | BIOS flash programming |
| `efibootmgr` | EFI boot entry management |

## Boot Image

The image includes:

- Alpine Linux minimal rootfs
- Custom init script with automatic hardware detection
- Kernel modules: AHCI, SATA, SCSI, IPMI, network drivers (Intel, Mellanox, Realtek, Virtio)
- Dropbear SSH server (passwordless root)
- NTP time synchronization
- Automatic DHCP with retry logic and gateway validation
- Bundled Mellanox ConnectX-3 firmware

### Supported Network Drivers

- Intel: e1000, e1000e, igb, ixgbe, i40e, ice
- Mellanox: mlx4_core, mlx4_en, mlx5_core
- Realtek: r8169
- Virtual: virtio_net

### Build

`deploy/build-golden.sh <golden> OUT` is the recipe stormcentral runs. It is
unprivileged and keeps everything under `$TMPDIR` and `OUT`:

1. `go build` the agent (static, linux/amd64).
2. `pxeimage/build.sh`: Alpine 3.20 rootfs + `linux-lts` kernel and all its
   modules + tools, every package found by name in the Alpine index (a missing
   required package fails the build), packed as a root-owned gzip cpio.
3. `baremetalservices`: `pxeimage/build-iso.sh` → `OUT/boot/baremetalservices.iso`.
   `baremetalservices-maint`: `pxeimage/build-disk.sh` → `OUT/boot/baremetalservices-maint.iso`
   (stormcentral's file name for every media golden; the bytes are a GPT disk image).

OUT also holds `vmlinuz`, `initramfs`, `BUILD` and `SHA256SUMS`.

Build host needs: Go 1.24+, curl, cpio, gzip, unzip, depmod, xorriso,
grub(2)-mkstandalone with x86_64-efi modules, mtools, dosfstools, objcopy and
the systemd-boot EFI stub (`/usr/lib/systemd/boot/efi/linuxx64.efi.stub`),
python3. dev.g8.lo (Fedora 43) has them all.

### Test

`test/run.sh` (run it with `sc-build test/run.sh`) runs `go vet`/`go test`,
builds both goldens, and boots each under QEMU the way it is used:

| Mode | Boots | Firmware |
|------|-------|----------|
| `disk` | the -maint image as a virtio disk with 4096-byte logical blocks | OVMF (UEFI) |
| `iso` | the ISO as a CD-ROM | OVMF (UEFI) |
| `bios` | the ISO as a CD-ROM | SeaBIOS (legacy) |

Each passes when the getty banner is on the serial console and the agent
answers `/health`, `/system` and (UEFI) `/boot/order` over the guest's DHCP'd
network. `test/boot-ovmf.sh <mode> <image>` runs one.

## Network Boot (stormbootx)

Booting the ISO from an X9 BMC's virtual CD is very slow (the BMC reads it over
SMB1 in small reads; ISOLINUX sits at `Loading /initramfs...` for minutes).
Instead the blade boots **stormbootx** (small, quick from virtual CD or the
NIC), and stormbootx claims `boothost/<host>` from the storage engine: when that
points at the `baremetalservices-maint` golden, stormbootx attaches a
copy-on-write clone over NVMe/TCP, reads `\EFI\BOOT\BOOTX64.EFI` off the ESP
itself (its `esp.rs`: GPT at the disk's block size, FAT at 4096-byte sectors)
and starts it — the same path a release boots by.

The `-maint` image is built for that path:

- **4096-byte blocks**, like every stormblock volume: GPT header at byte 4096,
  the ESP at 1 MiB, FAT16 (FAT32 past ~240 MiB) at 4096-byte sectors.
- **A unified kernel image** (systemd-stub + kernel + initramfs + command line
  `console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8 iomem=relaxed`).
  Once loaded nothing else is read from the volume, so the kernel taking the
  NIC over (and the NVMe/TCP session with it) costs nothing.

Pointing a machine's boothost at the -maint golden (and back to its release)
is stormcentral's: see the work plan in `CLAUDE.md`.

## Hardware Support

Tested on Supermicro MicroCloud SYS-5037MR-H8TRF (8-node, X9SRD-F motherboards).
