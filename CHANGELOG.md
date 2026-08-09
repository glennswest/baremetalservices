# Changelog

## [Unreleased]

### 2026-08-09
- **fix:** PXE image no longer ships a broken `nvme-cli`. Pinned APK filenames 404 silently as Alpine's CDN rotates versions (`|| true` hid it), which is why `nvme` died with `Error loading shared library libnvme-mi.so.1` (#1). New `fetch_apk` helper discovers the current filename from the repo index and **fails the build** for packages marked required, instead of producing an image whose tools cannot start.
- **feat:** Added `fio` (+`libaio`) so storage measurement is not limited to queue-depth-1 `dd`, and `open-iscsi` (+`libopeniscsiusr`) so the agent can consume iSCSI targets as well as NVMe-oF (#1).
- **fix:** `init` now loads the fabric transports at boot — `nvme`, `nvme_core`, `nvme_fabrics`, `nvme_tcp`, plus `iscsi_tcp`/`libiscsi`/`scsi_transport_iscsi`. Previously `nvme_tcp` had to be modprobed by hand before any NVMe-oF target could be reached (#1).

### 2026-04-02
- **feat:** Add Supermicro Update Manager (SUM) v2.15.0 to ISO — binary + ExternalData installed to /usr/bin/sum and /usr/share/sum/
- **feat:** Add mlxup (Mellanox firmware update tool) installation to build script

### 2026-03-09
- **fix:** Dynamic linux-lts kernel version discovery from Alpine CDN (old 6.6.121-r0 was removed)
- **fix:** Extract ALL kernel modules + vmlinuz from linux-lts APK so kernel and modules always match
- **refactor:** Rename ISO to baremetalservicev2 for parallel testing alongside production baremetalservices
- **chore:** Separate iSCSI CDROM deployment (baremetalservicev2) to avoid disrupting production
- **fix:** Multi-stage Containerfile.iso — build Go natively (cross-compile), then x86_64 for syslinux/grub-efi/ISO tools
- **fix:** IPMI LAN info parsing — parse output even if ipmitool returns non-zero exit code (some BMCs do this)
- **fix:** Add BMC cold reset (`mc reset cold`) after IPMI credential/network reset so changes take effect immediately

### 2026-03-04
- **fix:** Add announce banner and getty login prompts on all consoles (ttyS0, ttyS1, console)
- **fix:** Output init messages to /dev/console instead of hardcoded ttyS1
- **fix:** Add GRUB serial terminal output (unit 0+1) and kernel console on both ttyS0+ttyS1
- **fix:** Fix GRUB EFI boot — search for ISO9660 volume by label so GRUB finds kernel/initramfs
- **feat:** Add EFI boot support to ISO — dual BIOS (ISOLINUX) + EFI (GRUB) boot modes
- **feat:** Build standalone GRUB x86_64-EFI binary with grub-mkstandalone
- **feat:** Create FAT EFI boot image using mtools for El Torito alt-boot
- **feat:** Hybrid MBR+GPT ISO for USB boot on both BIOS and EFI systems
- **fix:** Add SAS controller drivers (mpt3sas, mpt2sas, megaraid_sas, hpsa) to init for SATA drives behind SAS HBAs
- **fix:** Extract SCSI subdirectory modules (mpt3sas/, megaraid/) and fusion drivers in build
- **fix:** Load libahci, ata_generic, sr_mod, scsi_transport_sas modules at boot
- **feat:** Add `POST /bios/configure` endpoint — configure quick_boot, quiet_boot (via SUM), and disable PXE on specified NICs (via efibootmgr)
- **feat:** Smart PXE disable — skips if all NICs match the disable list to preserve PXE capability
- **feat:** Add efibootmgr, efivar-libs to PXE image build
- **feat:** Mount efivarfs in init for EFI variable access
- **perf:** Set boot timeout to 0 and disable prompt for faster PXE/ISO boot

### 2026-02-27
- **feat:** Add bootable ISO generation (`make iso`) with ISOLINUX + hybrid MBR for USB boot
