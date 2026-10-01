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

### Issue #1 — nvme-cli / fio in the image (fixes pushed 2026-08-09)

### Open from the docs refresh (2026-09-30)
- #12: `init` never loads i40e/ice (README listed them as supported).
- #13: goldens carry no SSH keys or BIOS file, and the CX3 firmware download is
  best effort (`build.sh` reads them from the builder's `$HOME`).
