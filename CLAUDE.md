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
- API port: `PORT` env (default 8080); web UI fixed on :80. No auth, by
  owner's decision (#23/#25): no token or key on any call. Do not raise auth again.

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

### Issue #14 — sum is glibc, the image is musl (P3, glibc part done)
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
       Supermicro's SUM tarball, which the repo doesn't have). Owner's answer
       (2026-10-01): don't wait on the tarball; out-of-band sum from
       stormcentral's VM already covers the X9s with the OOB key, so in-band
       sum is a nice-to-have: P3, issue stays open. Next: try in-band on an X9
       once one boots this image (needs #2 / stormcentral#236).

### Issue #15 — POST /disks/wipe said ok on an HDD and wiped nothing (done 2026-10-01)
- wipe.go: refuse in-use disks; wipefs parts + disk; sgdisk --zap-all;
  blkdiscard only if rotational=0; zero edges + partition heads; BLKRRPART;
  verify. Any failure -> HTTP 500. wipefs, sgdisk in the image.
- Boot test wipes an AHCI HDD and SSD in all three modes: PASS at e0f1f6d.
- Found on the way: parted, mkfs.ext4, mkfs.xfs, fio, iscsiadm missing shared
  libs; build.sh now fails on any missing NEEDED lib (readelf).
- Not tested on a real blade (server1's ST2000DM008) yet.

### Issue #24 — verify POST /disks/wipe on server1's real HDD (P3, blocked)
- Checked 2026-10-06: server1 isn't running the image (:8080 closed), and it is
  a shared test machine (in a `test` lease). A session can't boot it into the
  image: no maint path yet (stormcentral#236) and no BMC/virtual-CD access.
  Proposed --after stormcentral#236. When it lands: lease server1,
  `testhost maint server1`, then run the four checks in #24 together with #2 step 5.

### Issue #1 — nvme-cli / fio in the image (fixes pushed 2026-08-09)

### Open from the docs refresh (2026-09-30)
- #12: `init` never loads i40e/ice (README listed them as supported).
- #13 (in progress 2026-10-06): `build.sh` read inputs from the builder's `$HOME`.
  1. [ ] SSH keys: drop the `~/.ssh/id_*.pub` copy (no keys by design, #23).
  2. [ ] CX3 firmware: pinned content.mellanox.com URL + sha256, build fails
         if missing or mismatched.
  3. [ ] Drop the stale `make deploy` / scp hint.
  4. [ ] BIOS X9SRD-F 3.2b: supermicro.com refuses scripted downloads (Akamai
         403), so no pinned vendor URL; the repo is public. Source is an owner
         decision (asked on #13). Until then `~/Downloads` is dropped and the build
         says loudly that no BIOS file is bundled.
