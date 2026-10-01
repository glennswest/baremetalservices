# CLAUDE.md — baremetalservices

Maintenance image for bare-metal blades (Supermicro X9 microcloud): an Alpine
initramfs + Go agent (`main.go`) exposing hardware, disk, SMART, IPMI, BIOS
(`sum`) and boot-order management over HTTP (API :8080, web UI :80).

- Version: `VERSION` in `Makefile` (1.0.0). No tags yet.
- Build: on dev.g8.lo through `sc-build` only (cross-project rules). No podman,
  no builds on server1; `make deploy` to pxe.g10.lo is retired.
- Tests: `go test ./...` (pure parsers); `sc-build test/run.sh` builds both
  goldens and boots them under QEMU.
- Ships as two stormcentral media goldens (`baremetalservices` ISO,
  `baremetalservices-maint` 4K network-boot disk), boot helpers with stormipmi.
- API port: `PORT` env (default 8080); web UI fixed on :80. No auth.

## Work plan

### Issue #2 — golden on dev + network boot via stormbootx (P1)
1. [x] API: `GET/POST /bios/config` (sum) and `GET/POST /boot/order`
       (efibootmgr), unit tests (bootconfig.go / bootconfig_test.go).
2. [x] Build scripts unprivileged on dev; `deploy/build-golden.sh
       baremetalservices|baremetalservices-maint OUT`.
3. [x] Goldens (registered live by stormcentral#227, boothelper iso/img with
       stormipmi): golden-baremetalservices-923ab8556f57393e and
       golden-baremetalservices-maint-546af68a04a19632 at 610c397.
4. [x] `sc-build test/run.sh`: both images boot under QEMU (4K disk/OVMF,
       ISO/OVMF, ISO/SeaBIOS) and the agent answers.
5. [ ] Pointing boothost/<host> at -maint and back: stormcentral#236
       (stormbootx needs no change). Then verify on server1 (server3 also
       waits on stormbootx#56) and close #2.
6. [x] README.

### Issue #14 — sum is glibc, the image is musl (P1)
1. [x] build.sh ships Debian trixie's glibc runtime (libc6, libgcc-s1, zlib1g,
       libstdc++6) in /usr/lib/x86_64-linux-gnu, /lib64/ld-linux-x86-64.so.2
       -> its loader (was gcompat's shim). sum in /opt/sum + ExternalData.
       Build fails if sum -v doesn't run / mlxup doesn't link. (2315d6d)
2. [x] init already loads ipmi_msghandler/ipmi_devintf/ipmi_si.
3. [x] sc-build test/run.sh: all three boots PASS; with an emulated BMC,
       sum runs, finds IPMI, then: "BIOS does not support virtual driver and
       Driver sum_bios.ko does not exist."
4. [ ] In-band GetCurrentBiosCfg/ChangeBiosCfg on an X9. If the X9 BIOS has
       no "virtual driver", sum needs sum_bios.ko (built from driver/Source in
       Supermicro's SUM tarball, which the repo doesn't have) — asked the
       owner on #14 (needs-owner).

### Issue #15 — POST /disks/wipe says ok on an HDD and wipes nothing (in progress 2026-10-01)
1. [ ] Image: wipefs and sgdisk (Alpine v3.20 main, required).
2. [ ] wipe.go: per disk — refuse if mounted; wipefs -a each partition and the
       disk; sgdisk --zap-all; blkdiscard only when rotational=0; zero the
       first 1 GiB of each old partition and the first/last 64 MiB of the
       disk; BLKRRPART; verify (no partitions, wipefs finds nothing, head and
       tail read back zero). Any failure -> HTTP 500, status error.
3. [ ] Unit tests for the zero-region plan; boot test: AHCI HDD
       (rotation_rate 7200) + SSD (rotation_rate 1, discard), partition +
       format via the API, wipe, check.

### Issue #1 — nvme-cli / fio in the image (fixes pushed 2026-08-09)

### Open from the docs refresh (2026-09-30)
- #12: `init` never loads i40e/ice (README listed them as supported).
- #13: goldens carry no SSH keys or BIOS file, and the CX3 firmware download is
  best effort (`build.sh` reads them from the builder's `$HOME`).
