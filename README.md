# Bare Metal Services

A bare metal server management and provisioning system that runs as a PXE boot image. Provides a REST API, web dashboard, and CLI tools for hardware discovery, disk management, firmware updates, and IPMI configuration.

## Architecture

- **Go binary** serving two HTTP servers simultaneously:
  - **Port 80** - Web UI dashboard with auto-refresh
  - **Port 8080** - JSON REST API
- **PXE boot image** based on Alpine Linux with custom init script
- Boots via PXE, discovers hardware, and exposes management interfaces over the network

## Quick Start

```bash
# Build and deploy to PXE server
make deploy

# Build only (no deploy)
make pxeimage

# Run locally for development
make run
```

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

## PXE Boot Image

The PXE image includes:

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

### Build Requirements

- Go 1.24+
- curl, cpio, gzip (for PXE image build)
- Access to Alpine Linux package repositories

### Build Targets

```bash
make build          # Compile Go binary (local OS)
make build-linux    # Cross-compile for Linux x86_64
make clean          # Remove binaries and initramfs
make run            # Run locally
make pxeimage       # Build PXE image (vmlinuz + initramfs)
make deploy         # Build + deploy to PXE server
```

## Hardware Support

Tested on Supermicro MicroCloud SYS-5037MR-H8TRF (8-node, X9SRD-F motherboards).
