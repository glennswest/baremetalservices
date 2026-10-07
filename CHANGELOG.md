# Changelog

## [Unreleased]

### 2026-10-06
- **fix:** `init` never loaded `i40e` or `ice`, so a blade with an Intel 40G/100G NIC came up with no interface. Both are now in the named NIC list, and `init` then coldplugs every PCI mass-storage and network device by its modalias (blacklists honoured), so a NIC or controller missing from the list still gets its driver. (#12).
- **test:** The boot test adds a vmxnet3 NIC, which only coldplug can bring up, and checks `/network` shows it, that `eth0` is still the named-first e1000e, and that `i40e` and `ice` loaded (their banners in the kernel log) (#12).
- **docs:** Work plan: #12 verified, `sc-build test/run.sh` all PASS at 0d5ffbd.
- **fix:** The ConnectX-3 firmware (2.42.5000, MCX311A-XCAT) is fetched from a pinned content.mellanox.com URL and checked against its sha256; the build fails if it is missing or changed (was best effort, only a warning). The boot test checks `GET /firmware` lists it (#13).
- **fix:** `build.sh` no longer reads the builder's home: no `~/.ssh/id_*.pub` copied into the image (open by design, #23) and no `~/Downloads/X9SRD6.bin`; it warns loudly when no BIOS file is bundled (#13).
- **chore:** `build.sh` no longer prints the retired `make deploy` / scp-to-pxe.g10.lo hint (#13).
- **docs:** Work plan: #24 (wipe on server1's real HDD) waits on stormcentral#236; a session has no way to boot server1 into the image until then.
- **docs:** README states access is open by design (owner's decision, #23/#25): no token or key on any API call, no SSH keys in goldens.

### 2026-10-01
- **docs:** In-band `sum` (`/bios/config`, `/bios/configure`) is unproven on X9 blades: without the BIOS's "virtual driver" it needs `sum_bios.ko`, which the image does not carry. Noted in README; #14 stays open at P3 (out-of-band `sum` covers the X9s today).
- **fix:** `POST /disks/wipe[/{dev}]` reported `ok` on a spinning disk and wiped nothing: `blkdiscard` is a no-op on an HDD and `wipefs` was not in the image. A wipe is now: refuse a mounted/swap/held disk; `wipefs -a` every partition and the disk; `sgdisk --zap-all`; `blkdiscard` only when non-rotational; zero the first and last 64 MiB and the first 1 GiB of every old partition; re-read the partition table; verify (no partitions, no signatures, head and tail read zero). Any failed step or unverified disk returns HTTP 500 with the per-step results (`wipe.go`, #15).
- **fix:** The image now carries `wipefs` and `sgdisk` (required packages) (#15).
- **fix:** Several tools in the image could not start because a shared library was missing: `parted` (libdevmapper, so `POST /disks/partition` always failed), `mkfs.ext4`/`e2fsck` (libcom_err, so `POST /disks/format` ext4 failed), `mkfs.xfs`/`xfs_repair` (inih, userspace-rcu), `fio` (libnuma), `iscsiadm`/`iscsid` (libkmod with zstd/xz, libisns), `efibootdump` (libintl). The packages are now in the image (#15).
- **fix:** The build now fails if any musl program or library in the image needs a shared library the image does not have (`readelf` over every ELF), so this class of bug (#1, #2, #15) stops at build time (#15).
- **fix:** `fetch_apk` matched package names as substrings (`libintl` matched `musl-libintl-…`); it now matches the whole name in the index's link text (#15).
- **test:** The boot test pins the CD and the scratch disks to their own AHCI ports (#15).
- **test:** Unit tests for the wipe's zero regions and sysfs partition/holder reading; the QEMU boot test partitions, formats and wipes a scratch HDD and SSD through the API and checks the images on the host (#15).
- **fix:** `sum` (Supermicro Update Manager) did not run on the image: it is a glibc binary, and the musl image's `/lib64/ld-linux-x86-64.so.2` was Alpine's `gcompat` shim (`Error relocating /usr/bin/sum: mallopt: symbol not found`). The image now carries Debian trixie's glibc runtime (`libc6`, `libgcc-s1`, `zlib1g`, `libstdc++6`, found by name in the Debian index) in `/usr/lib/x86_64-linux-gnu` with `/lib64/ld-linux-x86-64.so.2` pointing at its loader, so `sum` and `mlxup` run unmodified; musl programs never look there. `sum` moves to `/opt/sum` with its `ExternalData` beside it (`/usr/bin/sum` links to it). The build fails if `sum -v` does not run, or `mlxup` does not link, against the image's glibc (#14).
- **test:** The QEMU boot test gives the guest an emulated BMC (`ipmi-bmc-sim` + KCS) and checks `GET /bios/config` shows `sum` ran (#14).

### 2026-09-30
- **docs:** Refreshed README and CLAUDE.md from the code: `PORT` override for the API (web UI fixed on :80, no auth), what `/ipmi/reset`, `/bios`, `/bios/configure` and `/firmware` actually do, the kernel modules `init` loads (SAS, NVMe/TCP, iSCSI), boot behaviour (reverse-DNS hostname, bounded NTP, gettys), the full tool list (`fio`, `iscsiadm`, `sum`, `mlxup`; `flashrom`/`mstflint` best effort), the boot command line, and what the Make targets still do. Filed #12 (i40e/ice listed as supported but never loaded) and #13 (goldens carry no SSH keys or BIOS image).
- **feat:** `deploy/build-golden.sh baremetalservices|baremetalservices-maint OUT` — the stormcentral media-golden recipe, run unprivileged on dev.g8.lo. `baremetalservices` is the hybrid BIOS+UEFI ISO (BMC virtual CD, USB); `baremetalservices-maint` is a 4096-byte-block GPT disk whose ESP holds a unified kernel image as `\EFI\BOOT\BOOTX64.EFI`, the shape stormbootx claims over NVMe/TCP and chain-loads (#2).
- **feat:** `pxeimage/build-disk.sh` builds that disk (systemd-stub UKI via objcopy, FAT at 4096-byte sectors, 4K GPT) (#2).
- **fix:** Image builds use no `/tmp` or `~` paths (mktemp under `$TMPDIR`, output dirs overridable), use `grub2-mkstandalone` where `grub-mkstandalone` is absent (Fedora), find syslinux by name in the Alpine index instead of a pinned revision, and pack the initramfs with every file owned by root (`cpio -R 0:0`) whoever builds it (#2).
- **fix:** The image shipped busybox's `sum` checksum applet as `/usr/bin/sum`, not Supermicro Update Manager: `cp` followed the applet's absolute symlink (as root in the old podman build it overwrote the build container's busybox; unprivileged on dev it failed, #3). The link is removed before SUM, mlxup and the agent are installed (#2, #3).
- **fix:** `init` bounds the boot-time NTP sync to 20 s; with no NTP server reachable `ntpd -q` never returned and the API never started (#2).
- **fix:** Every Alpine package in the image is now fetched by name from the repo index (`fetch_apk`), not by a pinned filename that 404s silently once the CDN moves on; the tools the image exists for (efibootmgr, smartmontools, ipmitool, dmidecode, hdparm, parted, mkfs.*, lsblk, lspci, …) are required, so a miss fails the build. The boot test found `efibootmgr` dead in the image (`libefivar.so.1` missing) (#2).
- **fix:** The ISO's El Torito EFI image is sized from the GRUB loader (Fedora's standalone GRUB is past the old fixed 4 MiB) and formatted FAT12/16 with `mkfs.fat`; `mformat -F` forced a FAT32 too small to be valid, and OVMF found no `BOOTX64.EFI` on it (#2).
- **chore:** Retired the podman `Containerfile.iso` (built on server1) and the `make deploy`/`pxeimage-deploy` targets (scp to pxe.g10.lo); images are built on dev.g8.lo as goldens (#2).
- **docs:** README: the two goldens, the dev build and its requirements, the QEMU boot test, network boot through stormbootx, and the new BIOS-config and boot-order API (#2).
- **test:** `test/run.sh` builds both goldens and boots them under QEMU (4K virtio disk under OVMF; ISO under OVMF and SeaBIOS), checking the agent answers `/health`, `/system` and `/boot/order` (#2).
- **feat:** `GET /bios/config` returns the whole `sum -c GetCurrentBiosCfg` file and `POST /bios/config` applies such a file with `sum -c ChangeBiosCfg`, so one blade's BIOS setup can be copied to the rest without ssh (#2).
- **feat:** `GET /boot/order` returns the EFI boot entries, order, current and next boot (`efibootmgr -v`); `POST /boot/order` sets `{"order": [...], "next": "..."}`, validated against the entries that exist (#2).

### 2026-08-09
- **fix:** Fetch `libnvmemi` — `libnvme-mi.so.1` ships in its own Alpine package, not in `libnvme`, so `nvme` still failed to start with the exact issue #1 error even after the libnvme fix. Verified against a clean Alpine 3.20 container (#1).
- **fix:** Fetch `fio` from Alpine's community repo (it is not in main — the required-package check correctly failed the build), and fetch `open-iscsi-libs` instead of the nonexistent `libopeniscsiusr` (which was silently skipped as optional) (#1).
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
