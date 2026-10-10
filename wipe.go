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
	Rotational bool       `json:"rotational"`
	Partitions []string   `json:"partitions_before"`
	Steps      []wipeStep `json:"steps"`
	Verified   bool       `json:"verified"`
	Error      string     `json:"error,omitempty"`
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

// wipeDisk wipes and verifies one whole disk, named as in /sys/block.
func wipeDisk(disk string) diskWipeResult {
	dev := "/dev/" + disk
	res := diskWipeResult{Device: dev, Partitions: []string{}, Steps: []wipeStep{}}
	step := func(name string, out string, err error) bool {
		s := wipeStep{Step: name, OK: err == nil, Output: strings.TrimSpace(out)}
		if err != nil && s.Output == "" {
			s.Output = err.Error()
		}
		res.Steps = append(res.Steps, s)
		if err != nil {
			res.Error = name + " failed: " + s.Output
		}
		return err == nil
	}

	sectors, err := readSysInt(filepath.Join(sysBlockDir, disk, "size"))
	if err != nil {
		res.Error = dev + " is not a whole disk (no " + filepath.Join(sysBlockDir, disk) + ")"
		return res
	}
	size := sectors * 512
	rot, _ := readSysInt(filepath.Join(sysBlockDir, disk, "queue", "rotational"))
	res.Rotational = rot != 0
	parts, err := diskPartitions(disk)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	for _, p := range parts {
		res.Partitions = append(res.Partitions, p.Name)
	}
	if why := diskInUse(disk, parts); why != "" {
		res.Error = "in use: " + why
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

func handleDiskWipe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/disks/wipe"), "/")
	name = strings.TrimPrefix(name, "dev/")
	var disks []string
	if name != "" {
		if strings.Contains(name, "/") || name == "." || name == ".." {
			sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Invalid device name: " + name})
			return
		}
		if _, err := os.Stat(filepath.Join(sysBlockDir, name, "size")); err != nil {
			sendJSON(w, http.StatusNotFound, APIResponse{Status: "error", Error: "/dev/" + name + " is not a whole disk"})
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
			sendJSON(w, http.StatusNotFound, APIResponse{Status: "error", Error: "No disks found"})
			return
		}
	}

	results := make(map[string]diskWipeResult)
	var failed []string
	for _, d := range disks {
		res := wipeDisk(d)
		results[res.Device] = res
		if !res.Verified {
			failed = append(failed, res.Device+": "+res.Error)
		}
	}
	if len(failed) > 0 {
		sendJSON(w, http.StatusInternalServerError, APIResponse{
			Status: "error",
			Error:  fmt.Sprintf("Wipe failed on %d of %d disk(s): %s", len(failed), len(disks), strings.Join(failed, "; ")),
			Data:   results,
		})
		return
	}
	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: fmt.Sprintf("Wiped and verified %d disk(s)", len(disks)),
		Data:    results,
	})
}
