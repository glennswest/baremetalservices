package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const mib = int64(1) << 20

func TestZeroRegions(t *testing.T) {
	disk := 2000 * 1024 * mib // ST2000DM008-sized
	parts := []partRange{
		{Name: "sda1", Start: 1 * mib, Size: 512 * mib},          // inside the head edge, shorter than 1 GiB
		{Name: "sda2", Start: 513 * mib, Size: 116 * 1024 * mib}, // 1 GiB from 513 MiB
		{Name: "sda3", Start: disk - 10*mib, Size: 10 * mib},     // inside the tail edge
	}
	got := zeroRegions(disk, parts)
	want := []byteRange{
		{0, 513*mib + 1024*mib},   // head edge + sda1 + sda2's head, merged
		{disk - 64*mib, 64 * mib}, // tail edge, sda3 inside it
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zeroRegions = %v, want %v", got, want)
	}
}

func TestZeroRegionsSmallDisk(t *testing.T) {
	// Smaller than the two edges: one region, the whole disk.
	got := zeroRegions(100*mib, nil)
	if want := []byteRange{{0, 100 * mib}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zeroRegions = %v, want %v", got, want)
	}
}

func TestDiskPartitionsAndInUse(t *testing.T) {
	root := t.TempDir()
	old := sysBlockDir
	sysBlockDir = root
	defer func() { sysBlockDir = old }()

	write := func(rel, s string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte(s+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("sdz/size", "4096000")
	write("sdz/queue/rotational", "1")
	write("sdz/sdz2/partition", "2")
	write("sdz/sdz2/start", "2048000")
	write("sdz/sdz2/size", "1024")
	write("sdz/sdz1/partition", "1")
	write("sdz/sdz1/start", "2048")
	write("sdz/sdz1/size", "4096")
	os.MkdirAll(filepath.Join(root, "sdz/holders"), 0755)
	os.MkdirAll(filepath.Join(root, "sdz/sdz1/holders"), 0755)
	os.MkdirAll(filepath.Join(root, "sdz/sdz2/holders/dm-0"), 0755)

	parts, err := diskPartitions("sdz")
	if err != nil {
		t.Fatal(err)
	}
	want := []partRange{{"sdz1", 2048 * 512, 4096 * 512}, {"sdz2", 2048000 * 512, 1024 * 512}}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("diskPartitions = %v, want %v", parts, want)
	}
	if why := diskInUse("sdz", parts); why != "/dev/sdz2 is held by dm-0" {
		t.Fatalf("diskInUse = %q", why)
	}

	// #24: a mounted partition and an active swap disk are refused too.
	oldM, oldS := procMounts, procSwaps
	procMounts, procSwaps = filepath.Join(root, "mounts"), filepath.Join(root, "swaps")
	defer func() { procMounts, procSwaps = oldM, oldS }()
	write("mounts", "/dev/sdy1 / ext4 rw 0 0\n/dev/sdz1 /mnt ext4 rw 0 0")
	write("swaps", "Filename Type Size Used Priority\n/dev/sdz partition 1024 0 -2")
	want2 := "/dev/sdz1 is mounted on /mnt; /dev/sdz is active swap; /dev/sdz2 is held by dm-0"
	if why := diskInUse("sdz", parts); why != want2 {
		t.Fatalf("diskInUse = %q, want %q", why, want2)
	}
	if res := wipeDisk("nosuch"); res.Verified || res.Error == "" {
		t.Fatalf("wipeDisk(nosuch) = %+v, want an error", res)
	}
}

// #46: a failed wipe names the failing disk and step first, before the long
// per-step data, and every disk gets a one-line verdict.
func TestWipeAnswerLeadsWithTheFailure(t *testing.T) {
	long := strings.Repeat("x", 2000)
	ok := diskWipeResult{Device: "/dev/sda", Verified: true, Steps: []wipeStep{{Step: "wipefs /dev/sda", OK: true, Output: long}}}
	ok.Verdict = ok.verdict()
	bad := diskWipeResult{Device: "/dev/sdb", FailedStep: "zero", Error: "write at 0: no medium found",
		Steps: []wipeStep{{Step: "wipefs /dev/sdb", OK: true, Output: long}, {Step: "zero", Output: "write at 0: no medium found"}}}
	bad.Verdict = bad.verdict()

	code, resp := wipeAnswer([]diskWipeResult{ok, bad})
	if code != http.StatusInternalServerError || resp.Status != "error" {
		t.Fatalf("code %d status %q, want 500 error", code, resp.Status)
	}
	if want := (wipeError{"/dev/sdb", "zero", "write at 0: no medium found"}); resp.Error == nil || *resp.Error != want {
		t.Fatalf("error = %+v, want %+v", resp.Error, want)
	}
	if resp.Verdicts["/dev/sda"] != "wiped and verified" || resp.Verdicts["/dev/sdb"] != "failed at zero: write at 0: no medium found" {
		t.Fatalf("verdicts = %v", resp.Verdicts)
	}
	b, _ := json.Marshal(resp)
	head := string(b[:600])
	for _, s := range []string{`"error":{"device":"/dev/sdb","step":"zero"`, `"/dev/sdb":"failed at zero`} {
		if !strings.Contains(head, s) {
			t.Errorf("first 600 bytes lack %s: %s", s, head)
		}
	}

	code, resp = wipeAnswer([]diskWipeResult{ok})
	if code != http.StatusOK || resp.Status != "ok" || resp.Error != nil || resp.Failures != nil {
		t.Fatalf("all verified: %d %+v", code, resp)
	}
}

// #46: checks before the first command are steps too, so failed_step is set.
func TestWipeDiskPrecheckSteps(t *testing.T) {
	root := t.TempDir()
	old := sysBlockDir
	sysBlockDir = root
	defer func() { sysBlockDir = old }()
	os.MkdirAll(filepath.Join(root, "sdv"), 0755)
	os.WriteFile(filepath.Join(root, "sdv", "size"), []byte("0\n"), 0644)

	for disk, want := range map[string]string{"nosuch": "is not a whole disk", "sdv": "size 0"} {
		res := wipeDisk(disk)
		if res.Verified || res.FailedStep != "check disk" || !strings.Contains(res.Error, want) ||
			!strings.HasPrefix(res.Verdict, "failed at check disk: ") || len(res.Steps) != 1 || res.Steps[0].OK {
			t.Errorf("wipeDisk(%s) = %+v", disk, res)
		}
	}
}
