// Disk wipe (#15): POST /disks/wipe and POST /disks/wipe/{dev}.
//
// A wipe is only reported ok once it is verified. Per disk:
//
//	refuse if the disk or a partition is mounted, swap, or held (LVM, md)
//	wipefs -a on every partition, then on the disk
//	sgdisk --zap-all (GPT primary + backup, protective MBR)
//	blkdiscard, only on a non-rotational disk (it is a no-op on an HDD)
//	zero the first 1 GiB of every old partition, the first and last 64 MiB
//	re-read the partition table (BLKRRPART)
//	verify: no partitions, wipefs finds no signature, head and tail read zero
//
// Any failed step fails the disk, and any failed disk fails the request.
// A wipe does not overwrite the whole disk (that is secure-erase): on a 2 TB
// HDD it writes about 1-5 GiB and takes seconds to a minute or two.
//
// The answer leads with what failed (#46): "error" is {device, step,
// message} of the first failed disk, "verdicts" one line per disk, then
// "failures" (every failed disk) and the full per-step "data".
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	wipeDiskEdge      = 64 << 20 // zeroed at each end of the disk
	wipePartitionHead = 1 << 30  // zeroed at the start of each old partition
	wipeVerifyBytes   = 1 << 20  // read back at each end of the disk
	blkrrpart         = 0x125f   // BLKRRPART: re-read partition table
	blkflsbuf         = 0x1261   // BLKFLSBUF: drop the device's page cache
)

// sysBlockDir is /sys/block, procMounts and procSwaps the kernel's mount and
// swap tables; tests point them at fakes.
var (
	sysBlockDir = "/sys/block"
	procMounts  = "/proc/mounts"
	procSwaps   = "/proc/swaps"
)

type partRange struct {
	Name  string
	Start int64 // bytes
	Size  int64 // bytes
}

type byteRange struct {
	Off, Len int64
}

type wipeStep struct {
	Step   string `json:"step"`
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
}

type diskWipeResult struct {
	Device     string     `json:"device"`
	Verdict    string     `json:"verdict"`
	Verified   bool       `json:"verified"`
	FailedStep string     `json:"failed_step,omitempty"`
	Error      string     `json:"error,omitempty"`
	Seconds    float64    `json:"seconds"`
	Rotational bool       `json:"rotational"`
	Partitions []string   `json:"partitions_before"`
	Steps      []wipeStep `json:"steps"`
}

// wipeError names what failed: the device, the step and its message.
type wipeError struct {
	Device  string `json:"device,omitempty"`
	Step    string `json:"step"`
	Message string `json:"message"`
}

// wipeResponse is the answer of POST /disks/wipe[/{dev}]. Field order is the
// JSON order: the failure and the verdicts come before the long step lists.
type wipeResponse struct {
	Status   string                    `json:"status"`
	Error    *wipeError                `json:"error,omitempty"`
	Message  string                    `json:"message,omitempty"`
	Verdicts map[string]string         `json:"verdicts,omitempty"`
	Skipped  map[string]string         `json:"skipped,omitempty"`
	Failures []wipeError               `json:"failures,omitempty"`
	Data     map[string]diskWipeResult `json:"data,omitempty"`
}

// verdict is the one-line summary of a disk's wipe.
func (r diskWipeResult) verdict() string {
	if r.Verified {
		return "wiped and verified"
	}
	return "failed at " + r.FailedStep + ": " + r.Error
}

// readSysInt reads a decimal integer sysfs attribute.
func readSysInt(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

// diskPartitions lists the kernel's partitions of disk from sysfs (start and
// size are in 512-byte sectors there, whatever the logical block size).
func diskPartitions(disk string) ([]partRange, error) {
	entries, err := os.ReadDir(filepath.Join(sysBlockDir, disk))
	if err != nil {
		return nil, err
	}
	var parts []partRange
	for _, e := range entries {
		dir := filepath.Join(sysBlockDir, disk, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "partition")); err != nil {
			continue
		}
		start, err := readSysInt(filepath.Join(dir, "start"))
		if err != nil {
			return nil, err
		}
		size, err := readSysInt(filepath.Join(dir, "size"))
		if err != nil {
			return nil, err
		}
		parts = append(parts, partRange{Name: e.Name(), Start: start * 512, Size: size * 512})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Start < parts[j].Start })
	return parts, nil
}

// zeroRegions is what a wipe zeroes on a disk of diskSize bytes: the first
// and last wipeDiskEdge bytes, and the first wipePartitionHead bytes of every
// partition, clipped to the disk, sorted and merged.
func zeroRegions(diskSize int64, parts []partRange) []byteRange {
	var rs []byteRange
	add := func(off, n int64) {
		if off < 0 {
			n += off
			off = 0
		}
		if off+n > diskSize {
			n = diskSize - off
		}
		if n > 0 {
			rs = append(rs, byteRange{off, n})
		}
	}
	add(0, wipeDiskEdge)
	add(diskSize-wipeDiskEdge, wipeDiskEdge)
	for _, p := range parts {
		n := p.Size
		if n > wipePartitionHead {
			n = wipePartitionHead
		}
		add(p.Start, n)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Off < rs[j].Off })
	var merged []byteRange
	for _, r := range rs {
		if k := len(merged) - 1; k >= 0 && r.Off <= merged[k].Off+merged[k].Len {
			if end := r.Off + r.Len; end > merged[k].Off+merged[k].Len {
				merged[k].Len = end - merged[k].Off
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// diskInUse says why disk (or one of its partitions) must not be wiped:
// mounted, active swap, or held by device-mapper/md. "" if it is free.
func diskInUse(disk string, parts []partRange) string {
	names := []string{disk}
	for _, p := range parts {
		names = append(names, p.Name)
	}
	var why []string
	for _, src := range []string{procMounts, procSwaps} {
		b, _ := os.ReadFile(src)
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			for _, n := range names {
				if f[0] == "/dev/"+n {
					if src == procSwaps {
						why = append(why, "/dev/"+n+" is active swap")
					} else {
						why = append(why, "/dev/"+n+" is mounted on "+f[1])
					}
				}
			}
		}
	}
	for _, n := range names {
		dir := filepath.Join(sysBlockDir, disk, "holders")
		if n != disk {
			dir = filepath.Join(sysBlockDir, disk, n, "holders")
		}
		if hs, _ := os.ReadDir(dir); len(hs) > 0 {
			why = append(why, fmt.Sprintf("/dev/%s is held by %s", n, hs[0].Name()))
		}
	}
	return strings.Join(why, "; ")
}

func blockIoctl(f *os.File, req uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, 0); errno != 0 {
		return errno
	}
	return nil
}

// zeroDisk writes zeros over regions of dev and syncs.
func zeroDisk(dev string, regions []byteRange) error {
	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 4<<20)
	for _, r := range regions {
		for off := r.Off; off < r.Off+r.Len; {
			n := int64(len(buf))
			if rest := r.Off + r.Len - off; rest < n {
				n = rest
			}
			if _, err := f.WriteAt(buf[:n], off); err != nil {
				return fmt.Errorf("write at %d: %w", off, err)
			}
			off += n
		}
	}
	return f.Sync()
}

// readsZero reads n bytes at off from dev, past the page cache, and says
// whether they are all zero.
func readsZero(dev string, off, n int64) (bool, error) {
	f, err := os.Open(dev)
	if err != nil {
		return false, err
	}
	defer f.Close()
	blockIoctl(f, blkflsbuf)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return false, err
	}
	return bytes.Count(buf, []byte{0}) == len(buf), nil
}

// stepOutput is a step's output and, when it failed, its error too: the
// output alone can be a plan ("80 MiB in 1 region(s)") that hides the cause.
func stepOutput(out string, err error) string {
	out = strings.TrimSpace(out)
	switch {
	case err == nil:
		return out
	case out == "":
		return err.Error()
	default:
		return out + ": " + err.Error()
	}
}

// wipeDisk wipes and verifies one whole disk, named as in /sys/block.
func wipeDisk(disk string) (res diskWipeResult) {
	dev := "/dev/" + disk
	start := time.Now()
	res = diskWipeResult{Device: dev, Partitions: []string{}, Steps: []wipeStep{}}
	defer func() {
		res.Seconds = float64(time.Since(start).Milliseconds()) / 1000
		res.Verdict = res.verdict()
	}()
	// step records a step; a failed one is the disk's failed_step and error.
	step := func(name string, out string, err error) bool {
		s := wipeStep{Step: name, OK: err == nil, Output: stepOutput(out, err)}
		res.Steps = append(res.Steps, s)
		if err != nil {
			res.FailedStep = name
			res.Error = s.Output
		}
		return err == nil
	}

	sectors, err := readSysInt(filepath.Join(sysBlockDir, disk, "size"))
	if err != nil {
		err = fmt.Errorf("%s is not a whole disk (no %s)", dev, filepath.Join(sysBlockDir, disk, "size"))
	} else if sectors == 0 {
		err = fmt.Errorf("%s has size 0 (no medium?)", dev)
	}
	if !step("check disk", "", err) {
		return res
	}
	size := sectors * 512
	rot, _ := readSysInt(filepath.Join(sysBlockDir, disk, "queue", "rotational"))
	res.Rotational = rot != 0
	parts, err := diskPartitions(disk)
	if !step("read partitions", "", err) {
		return res
	}
	for _, p := range parts {
		res.Partitions = append(res.Partitions, p.Name)
	}
	if why := diskInUse(disk, parts); why != "" {
		step("in-use check", "", fmt.Errorf("in use: %s", why))
		return res
	}

	for _, p := range parts {
		out, err := runCommand("wipefs", "-a", "/dev/"+p.Name)
		if !step("wipefs /dev/"+p.Name, out, err) {
			return res
		}
	}
	if out, err := runCommand("wipefs", "-a", dev); !step("wipefs "+dev, out, err) {
		return res
	}
	if out, err := runCommand("sgdisk", "--zap-all", dev); !step("sgdisk --zap-all", out, err) {
		return res
	}
	if !res.Rotational {
		out, err := runCommand("blkdiscard", dev)
		if err != nil && strings.Contains(strings.ToLower(out), "not supported") {
			// Discard is a speed-up, not the wipe: the zeroing below is.
			res.Steps = append(res.Steps, wipeStep{Step: "blkdiscard", OK: true, Output: "not supported by the device: " + strings.TrimSpace(out)})
		} else if !step("blkdiscard", out, err) {
			return res
		}
	}
	regions := zeroRegions(size, parts)
	var zeroed int64
	for _, r := range regions {
		zeroed += r.Len
	}
	if err := zeroDisk(dev, regions); !step("zero", fmt.Sprintf("%d MiB in %d region(s)", zeroed>>20, len(regions)), err) {
		return res
	}
	f, err := os.Open(dev)
	if err == nil {
		err = blockIoctl(f, blkrrpart)
		f.Close()
	}
	if !step("re-read partition table", "", err) {
		return res
	}

	// Verify.
	left, err := diskPartitions(disk)
	if err == nil && len(left) > 0 {
		var names []string
		for _, p := range left {
			names = append(names, p.Name)
		}
		err = fmt.Errorf("partitions remain: %s", strings.Join(names, " "))
	}
	if !step("verify: no partitions", "", err) {
		return res
	}
	out, err := runCommand("wipefs", dev)
	if err == nil && strings.TrimSpace(out) != "" {
		err = fmt.Errorf("signatures remain")
	}
	if !step("verify: no signatures", out, err) {
		return res
	}
	n := int64(wipeVerifyBytes)
	if n > size {
		n = size
	}
	for _, at := range []struct {
		name string
		off  int64
	}{{"head", 0}, {"tail", size - n}} {
		zero, err := readsZero(dev, at.off, n)
		if err == nil && !zero {
			err = fmt.Errorf("%s of the disk is not zero", at.name)
		}
		if !step("verify: "+at.name+" reads zero", "", err) {
			return res
		}
	}
	res.Verified = true
	return res
}

// wipeRequestError answers a request refused before any disk was touched.
func wipeRequestError(w http.ResponseWriter, code int, device, step, msg string) {
	sendJSON(w, code, wipeResponse{Status: "error", Error: &wipeError{Device: device, Step: step, Message: msg}, Message: msg})
}

// wipeAnswer builds the answer for the wiped disks, in the order wiped.
func wipeAnswer(results []diskWipeResult) (int, wipeResponse) {
	resp := wipeResponse{Verdicts: map[string]string{}, Data: map[string]diskWipeResult{}}
	for _, r := range results {
		resp.Verdicts[r.Device] = r.Verdict
		resp.Data[r.Device] = r
		if !r.Verified {
			resp.Failures = append(resp.Failures, wipeError{Device: r.Device, Step: r.FailedStep, Message: r.Error})
		}
	}
	if len(resp.Failures) > 0 {
		resp.Status = "error"
		resp.Error = &resp.Failures[0]
		var lines []string
		for _, f := range resp.Failures {
			lines = append(lines, f.Device+" failed at "+f.Step+": "+f.Message)
		}
		resp.Message = fmt.Sprintf("Wipe failed on %d of %d disk(s): %s", len(resp.Failures), len(results), strings.Join(lines, "; "))
		return http.StatusInternalServerError, resp
	}
	resp.Status = "ok"
	resp.Message = fmt.Sprintf("Wiped and verified %d disk(s)", len(results))
	return http.StatusOK, resp
}

func handleDiskWipe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		wipeRequestError(w, http.StatusMethodNotAllowed, "", "request", "Method not allowed")
		return
	}

	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/disks/wipe"), "/")
	name = strings.TrimPrefix(name, "dev/")
	var disks []string
	if name != "" && (strings.Contains(name, "/") || name == "." || name == "..") {
		wipeRequestError(w, http.StatusBadRequest, "", "request", "Invalid device name: "+name)
		return
	}
	if !diskOpMu.TryLock() {
		wipeRequestError(w, http.StatusConflict, "", "lock", "another disk operation (image, wipe, partition, format or secure-erase) is running")
		return
	}
	defer diskOpMu.Unlock()
	if name != "" {
		if _, err := os.Stat(filepath.Join(sysBlockDir, name, "size")); err != nil {
			wipeRequestError(w, http.StatusNotFound, "/dev/"+name, "check disk", "/dev/"+name+" is not a whole disk")
			return
		}
		disks = []string{name}
	} else {
		out, err := runShell("lsblk -d -n -o NAME,TYPE | grep disk | awk '{print $1}'")
		if err == nil {
			for _, n := range strings.Fields(out) {
				disks = append(disks, n)
			}
		}
		if len(disks) == 0 {
			wipeRequestError(w, http.StatusNotFound, "", "list disks", "No disks found")
			return
		}
	}

	// All disks (#47): leave the boot device, USB/removable media and
	// stormbootx disks alone; only a named disk is wiped whatever it is.
	var skipped map[string]string
	if name == "" {
		var err error
		disks, skipped, err = wipeAllTargets(disks)
		if err != nil {
			wipeRequestError(w, http.StatusInternalServerError, "", "boot device",
				"cannot tell which disk this image booted from, so no disk was wiped: "+err.Error()+"; name each disk with POST /disks/wipe/{dev}")
			return
		}
		if len(disks) == 0 {
			msg := "no disk to wipe: every disk is skipped (name one with POST /disks/wipe/{dev} to wipe it anyway)"
			sendJSON(w, http.StatusNotFound, wipeResponse{Status: "error", Error: &wipeError{Step: "list disks", Message: msg},
				Message: msg, Verdicts: skipVerdicts(nil, skipped), Skipped: skipped})
			return
		}
	}

	var results []diskWipeResult
	for _, d := range disks {
		results = append(results, wipeDisk(d))
	}
	code, resp := wipeAnswer(results)
	if len(skipped) > 0 {
		resp.Skipped = skipped
		resp.Verdicts = skipVerdicts(resp.Verdicts, skipped)
		resp.Message += fmt.Sprintf("; skipped %d disk(s) (boot device, USB/removable or stormbootx; see skipped)", len(skipped))
	}
	sendJSON(w, code, resp)
}

// wipeAllTargets splits the disks of an all-disks wipe into those to wipe
// and those skipped (/dev/<disk> -> why). An unknown boot device under UEFI
// is an error: then nothing is wiped.
func wipeAllTargets(disks []string) (targets []string, skipped map[string]string, err error) {
	boot, bootWhy, err := bootDiskSet(disks)
	if err != nil {
		return nil, nil, err
	}
	skipped = map[string]string{}
	for _, d := range disks {
		if p := protectDisk(d, boot, bootWhy, true); len(p.Reasons) > 0 {
			skipped["/dev/"+d] = strings.Join(p.Reasons, "; ")
		} else {
			targets = append(targets, d)
		}
	}
	return targets, skipped, nil
}

// skipVerdicts adds a "skipped: <why>" verdict for every skipped disk.
func skipVerdicts(v, skipped map[string]string) map[string]string {
	if v == nil {
		v = map[string]string{}
	}
	for dev, why := range skipped {
		v[dev] = "skipped: " + why
	}
	return v
}
