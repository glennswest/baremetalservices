# Changelog

## [Unreleased]

### 2026-03-04
- **fix:** Suppress kernel log spam on serial console (loglevel=1 quiet)
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
