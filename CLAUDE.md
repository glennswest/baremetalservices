# CLAUDE.md — baremetalservices

Maintenance image for bare-metal blades (Supermicro X9 microcloud): an Alpine
initramfs + Go agent (`main.go`) exposing hardware, disk, SMART, IPMI, BIOS
(`sum`) and boot-order management over HTTP (API :8080, web UI :80).

- Version: `VERSION` in `Makefile` (1.0.0). No tags yet.
- Build: on dev.g8.lo through `sc-build` only (cross-project rules). No podman,
  no builds on server1; `make deploy` to pxe.g10.lo is retired.
- Tests: `go test ./...` (pure parsers); `sc-build` runs the image build.

## Work plan

### Issue #2 — golden on dev + network boot via stormbootx (P1, in progress)
1. [ ] API: `GET/POST /bios/config` (sum GetCurrentBiosCfg / ChangeBiosCfg,
       whole file) and `GET/POST /boot/order` (efibootmgr), with unit tests.
2. [ ] Build scripts runnable unprivileged on dev: no `/tmp` or `~` use,
       Fedora `grub2-mkstandalone`, no build-host SSH keys baked in;
       one entry point `deploy/build.sh` producing the ISO + kernel + initramfs
       + UEFI loader.
3. [ ] Register as a stormcentral media/boothelper component and build the
       golden (`stormcentral component build baremetalservices`).
4. [ ] stormbootx side: claim a `maint` image (boothost synonym/intent) over
       NVMe/TCP and chain-load its UEFI loader — filed on stormbootx, this work
       proposed after it.
5. [ ] README for all of the above.

### Issue #1 — nvme-cli / fio in the image (fixes pushed 2026-08-09)
