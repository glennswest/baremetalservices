# CLAUDE.md — baremetalservices

Maintenance image for bare-metal blades (Supermicro X9 microcloud): an Alpine
initramfs + Go agent (`main.go`) exposing hardware, disk, SMART, IPMI, BIOS
(`sum`) and boot-order management over HTTP (API :8080, web UI :80).

- Version: `VERSION` in `Makefile` (1.0.0). No tags yet.
- Build: through `sc-build` only (fresh build VM; dev.g8.lo is retired). No podman,
  no builds on server1; `make deploy` to pxe.g10.lo is retired.
- Tests: `go test ./...` (pure parsers); `sc-build test/run.sh` builds both
  goldens and boots them under QEMU.
- Ships as two stormcentral media goldens (`baremetalservices` ISO,
  `baremetalservices-maint` 4K network-boot disk), boot helpers with stormipmi.
- API port: `PORT` env (default 8080); web UI fixed on :80. No auth, by
  owner's decision (#23/#25): no token or key on any call. Do not raise auth again.

## Work plan

### Issue #47 — all-disks wipe took the boot sticks (P0, master, 2026-11-26)
C2NR0Q2 (Dell R230) and server8 (X9): `POST /disks/wipe` from the -maint
golden wiped their stormbootx USB sticks; both need the stick re-flashed by
hand (master/owner; this repo cannot do it).
1. [ ] protect.go: all-disks wipe skips the boot device (BootCurrent's device
       path), USB/removable, stormbootx ESP (or uninspectable); `skipped` in
       the answer; UEFI with unreadable BootCurrent wipes nothing.
2. [ ] GET /disks: boot_device, usb, removable, stormbootx, wipe_all_skips.
3. [ ] README wipe row + section; unit tests; boot test (stick, stormbootx
       HDD, 4K boot disk skipped and unchanged); sc-build test/run.sh all
       PASS; images requested; close #47.

### Issue #46 — wipe's failing step not in the answer (master, done 2026-11-26)
Seen on C2NR0Q2 (WD20EFAX) and server8 (ST2000DM008) from
golden-baremetalservices-maint-91c6bbfefbe6224c: `status: error` within ~1
minute, first 600 bytes all ok steps. The cause was in the string `error`
after all of `data` (likely another disk of the all-disks wipe); still unknown:
the next wipe there names it in `error`/`verdicts`.
1. [x] 46f5678: answer leads with `error: {device, step, message}`,
       `verdicts`, `failures`, then `data`; pre-checks are steps; size-0
       disk fails at `check disk`. 109ff7d: a failed step's message keeps
       its error (zero step said only "N MiB in K region(s)").
2. [x] README: what a wipe does on a rotational disk (not a full overwrite).
3. [x] Unit tests; boot test (read-only disk: error.step + write error in
       first 600 bytes); sc-build test/run.sh all PASS at 109ff7d; images
       requested; #46 closed.

### Issue #2 — golden on dev + network boot via stormbootx (P1, closed 2026-11-25)
1. [x] API: `GET/POST /bios/config` (sum) and `GET/POST /boot/order`
       (efibootmgr), unit tests (bootconfig.go / bootconfig_test.go).
2. [x] Build scripts unprivileged on dev; `deploy/build-golden.sh
       baremetalservices|baremetalservices-maint OUT`.
3. [x] Goldens (registered live by stormcentral#227, boothelper iso/img with
       stormipmi): golden-baremetalservices-923ab8556f57393e and
       golden-baremetalservices-maint-546af68a04a19632 at 610c397.
4. [x] `sc-build test/run.sh`: both images boot under QEMU (4K disk/OVMF,
       ISO/OVMF, ISO/SeaBIOS) and the agent answers.
5. [x] Pointing boothost/<host> at -maint and back: stormcentral#236
       landed (`testhost maint`); server1 verified 2026-10-10 (#24):
       boots the -maint golden, /health and /boot/order answer, `--off`
       restores 11.61. Left: server3 (stormbootx#56 closed), then close #2.
       2026-11-07: a session token can no longer run `testhost maint`
       (master/owner only, #829), so server3's boot is handed to the
       master with `wait-hardware` (media baremetalservices-maint). Pass:
       /health, /system, /boot/order answer on server3, then `--off`.
       2026-11-24: that wait was released by stormcentral#1703's stale
       sweep on "forge1 passed 12.97" (not this boot; no server3 result
       was ever posted). Re-filed `wait-hardware` (server3,
       baremetalservices-maint). 2026-11-25, master: hardware time is
       the owner's to schedule; that wait is cancelled and none is to be
       filed. Issue stays open; the master re-proposes it when the owner
       names the machine and the day. Master decided (2026-11-25): server1
       is the proof; #2 closed, server3 not booted.
6. [x] README.

### Issue #41 — review: 1 minor finding (web UI, done 2026-11-21)
1. [x] 0b8aa8e: cd8c1351e130: the UI on :80 fetched :8080 (cross-origin, no CORS),
       so a wipe/secure-erase that worked showed "Error". The web port now
       also serves the API under `/api/` (same handlers, StripPrefix); the
       UI posts to `/api/disks/...` and shows the HTTP status and body,
       "outcome unknown" only when no answer came. No CORS headers.
2. [x] Unit test (webui_test.go); boot test: GET / on :80 has the relative
       fetch, POST /api/disks/wipe/nosuchdisk on :80 answers the JSON error.
3. [x] CHANGELOG, README; sc-build test/run.sh all PASS at 0b8aa8e
       (disk, iso, bios: web UI check ok in each); #41 closed.

### Issue #40 — review: 3 major findings in imagewrite.go (done 2026-11-21)
1. [x] 0430c4ac66c0: one disk-operation lock (diskOpMu, diskop.go) for image,
       wipe, partition, format and secure-erase, taken before their device
       checks and held to the end; a second request gets 409.
2. [x] 71a7c42c8aec: download budget MemAvailable - 256 MiB; refused (507)
       when <= 0 or unknown, never the disk size; re-checked every 16 MiB
       while streaming.
3. [x] f2990cf34046: readStick inspects every FAT-signed or GPT ESP-typed
       partition; one that cannot be mounted/read fails before any change.
4. [x] Unit tests (diskop_test.go, imagewrite_test.go); sc-build test/run.sh
       all PASS at 12f6b2e (after #42: init coldplugs the virtio bus, so the
       #39 virtio erase disks show up). Image requested; #40 closed.

### Issue #39 — review: 4 major findings in main.go (P1, 2026-11-20)
1. [ ] 516e4f885acb: secure-erase fallback (no ATA security) zeroes the whole
       device in Go (no dd), reads back head/tail/samples past the cache, and
       answers 500 unless the write and the read-back both succeed.
2. [ ] 8fe507b0417b: disable_pxe_nics resolves filters to physical NICs, maps
       EFI PXE entries to NICs by MAC only (no description matching), and
       refuses when no PXE entry of a kept NIC would remain.
3. [ ] be3bdc3dcdf0: NVMe smart_health from critical_warning (0 PASSED,
       else FAILED, unreadable -> unknown).
4. [ ] c2bfa5d76292: mstflintCache behind a mutex, published once filled.
5. [x] Unit tests per finding; boot test: NVMe health PASSED then FAILED
       (QMP qom-set smart_critical_warning), virtio disk secure-erase
       fallback verified zero / read-only disk refused. sc-build test/run.sh
       all PASS at 12f6b2e (needed #42's virtio coldplug).

### Issue #38 — review finding d20f640fc5ce: HTTP parameters in root shell commands (P0, 2026-11-20)
1. [x] No request value reaches `sh -c`: every `runShell(fmt.Sprintf…)` becomes
       `runCommand`/`runStdout` with an argv (no shell) and Go-side filtering;
       sysfs reads via os.ReadFile/Readlink.
2. [x] Validate before anything runs: block device names (charset + exists
       under /sys/class/block) on detail/partition/format/secure-erase;
       PCI address + http(s) URL on /firmware/update; label gpt|msdos.
3. [x] Tests: AST test that `runShell` only ever takes a string literal;
       handler tests that injection payloads get 400 before any exec.
4. [x] CHANGELOG, README; sc-build test/run.sh all PASS at e12f0fc and
       0c1df13 (smartctl -A exit status fix); image requested; #38 closed.
       Findings' majors for this project follow as P1 (stormcentral findings list).

### Issue #36 — POST /disks/image/{dev}: write a boot image to a disk (P0, 2026-11-13)
For forge1's stormbootx USB stick (owner: "dont serve it, upgrade the image on usb").
1. [x] imagewrite.go: `url=`, `sha256=` (required), `keep_local_conf=true`.
       Refuse mounted/swap/held/STRMSLAB (as stormbootx-stick); download to
       RAM + sha256; GPT block size must match the device's; zero the old
       tail; write + fsync; read back past the cache and compare sha256;
       `sgdisk -e` + `sgdisk -v`; BLKRRPART; carry `stormboot/local.conf`
       (and a name/tag the new stormboot.conf drops, as stormbootx-stick).
2. [x] init: USB host controllers (PCI class 0c03 coldplug) + usb_storage/uas,
       or the maint image never sees a USB stick.
3. [x] Unit tests; QEMU boot test writes an image onto an emulated USB stick
       (xhci + usb-storage) served from the host, checks refusals (slab disk,
       bad sha256) and, on the host, the backup GPT and carried local.conf.
4. [x] README, CHANGELOG; sc-build test/run.sh all PASS at d507433 (disk,
       iso, bios: slab and wrong-sha256 refused, stick written over xhci,
       verified, local.conf + name/tag carried, backup GPT at the end).
5. [-] Withdrawn by the master 2026-11-13 (owner: a stick upgrade is a file
       update on its ESP, not a raw image write); issue closed, item rejected.
       The endpoint and the USB init fix stay on main (images requested at
       5f9c650); never run on a real node. Remove the endpoint if the owner asks.

### Open issues not yet worked (docs refresh 2026-11-14; code changed since 2026-11-07 only by #36)
- #32 (P1): `handleIPMIReset` (main.go) writes ADMIN/ADMIN itself; keep the configured login instead.
- #33 (P2): `pxeimage/build.sh` pulls Alpine v3.20 (EOL 2026-04-01); move to 3.22/3.23.
- #30 (P2): `/disks` full SMART set as numbers (`smartctl -x -j`).
- #31: maint UKI ignores the ACPI power button (needs acpid or an input reader running poweroff).
- #27 (P3): init's boot messages do not reach the serial consoles.
- #28 (P3): decision on where the X9SRD-F BIOS 3.2b file comes from.
- #45 (P3, needs-owner): in-band sum BIOS config on a real X9 (split from #14);
  waits for the owner to name an X9 and a day; sum_bios.ko source is an owner decision.
- #29 (P3): this file's #2 notes are stale once stormcentral#236/stormbootx#56 closed (done above).

### Issue #14 — sum is glibc, the image is musl (closed 2026-11-25; in-band split to #45)
1. [x] build.sh ships Debian trixie's glibc runtime (libc6, libgcc-s1, zlib1g,
       libstdc++6) in /usr/lib/x86_64-linux-gnu, /lib64/ld-linux-x86-64.so.2
       -> its loader (was gcompat's shim). sum in /opt/sum + ExternalData.
       Build fails if sum -v doesn't run / mlxup doesn't link. (2315d6d)
2. [x] init already loads ipmi_msghandler/ipmi_devintf/ipmi_si.
3. [x] sc-build test/run.sh: all three boots PASS; with an emulated BMC,
       sum runs, finds IPMI, then: "BIOS does not support virtual driver and
       Driver sum_bios.ko does not exist."
4. [-] Split to #45 (P3, needs-owner) by the master 2026-11-25; #14 closed
       on the verified glibc fix. Was: in-band GetCurrentBiosCfg/ChangeBiosCfg on an X9. If the X9 BIOS has
       no "virtual driver", sum needs sum_bios.ko (built from driver/Source in
       Supermicro's SUM tarball, which the repo doesn't have). Owner's answer
       (2026-10-01): don't wait on the tarball; out-of-band sum from
       stormcentral's VM already covers the X9s with the OOB key, so in-band
       sum is a nice-to-have: P3, now tracked on #45. Next: try in-band on an X9
       once one boots this image. That is owner-scheduled hardware (master,
       2026-11-25): no wait is filed; needs the owner to name an X9 and a day.

### Issue #15 — POST /disks/wipe said ok on an HDD and wiped nothing (done 2026-10-01)
- wipe.go: refuse in-use disks; wipefs parts + disk; sgdisk --zap-all;
  blkdiscard only if rotational=0; zero edges + partition heads; BLKRRPART;
  verify. Any failure -> HTTP 500. wipefs, sgdisk in the image.
- Boot test wipes an AHCI HDD and SSD in all three modes: PASS at e0f1f6d.
- Found on the way: parted, mkfs.ext4, mkfs.xfs, fio, iscsiadm missing shared
  libs; build.sh now fails on any missing NEEDED lib (readelf).
- Not tested on a real blade (server1's ST2000DM008) yet.

### Issue #24 — wipe on server1's real HDD (done 2026-10-10)
- server1 leased, `testhost maint server1 --power-cycle` →
  golden-baremetalservices-maint-b2654a0eb18517c8 (7a091f0); agent answered
  /health, /system, /boot/order (#2 step 5 on server1 done too).
- POST /disks/wipe/sda (ST2000DM008, sda1-4): ok, verified, rotational, no
  blkdiscard; /disks/detail/sda no partitions. `--off`, lease released.
- Not on hardware: in-use refusal (the image runs from RAM, nothing mounts
  sda; no API mounts) -> unit test now covers mount/swap/holder. SSD/NVMe
  blkdiscard: server1 has none; QEMU boot test covers it.

### Issue #1 — nvme-cli / fio in the image (fixes pushed 2026-08-09)

### Open from the docs refresh (2026-09-30)
- #12 (done 2026-10-06 at 0d5ffbd, closed): `init` never loaded i40e/ice.
  1. [x] init: i40e/ice in the named NIC list; PCI class 01/02 modalias
         coldplug (`modprobe -q -b`). (A `NIC drivers loaded:` echo was
         dropped: init's echoes never reach the QEMU serial logs; the test
         reads the kernel's driver banners instead.)
  2. [x] sc-build test/run.sh all PASS at 0d5ffbd: vmxnet3 up by coldplug
         (eth1), i40e/ice loaded, eth0 still e1000e, in all three boots.
         Not tried on a real XL710/E810 card (none known in the fleet).
- #13 (closed 2026-11-07; 1-3 done at db7cfa6, sc-build test/run.sh all PASS; 4 moved to #28): `build.sh` read inputs from the builder's `$HOME`.
  1. [x] SSH keys: drop the `~/.ssh/id_*.pub` copy (no keys by design, #23).
  2. [x] CX3 firmware: pinned content.mellanox.com URL + sha256, build fails
         if missing or mismatched.
  3. [x] Drop the stale `make deploy` / scp hint.
  4. [ ] BIOS X9SRD-F 3.2b: supermicro.com refuses scripted downloads (Akamai
         403), so no pinned vendor URL; the repo is public. Source is an owner
         decision, tracked on #28 (not #13). Until then `~/Downloads` is
         dropped and the build says loudly that no BIOS file is bundled.
