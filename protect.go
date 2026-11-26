// Disks the all-disks wipe leaves alone (#47).
//
// POST /disks/wipe (no device) took the stormbootx boot sticks of C2NR0Q2 and
// server8 with the data drives, and both lost their boot device. A disk is
// now skipped by the all-disks wipe when it is:
//
//	the boot device: the disk the firmware's BootCurrent entry points at
//	  (its HD() partition GUID/MBR signature, else its PCI path narrowed by
//	  Sata() port or NVMe() namespace; every disk under it when ambiguous)
//	a USB device (its sysfs path runs through a USB bus) or removable
//	  (/sys/block/<disk>/removable = 1)
//	a stormbootx disk: a FAT/ESP partition holding stormboot/, or one that
//	  cannot be inspected (never taken as "no stormboot/")
//
// Naming the disk (POST /disks/wipe/{dev}) still wipes it. GET /disks shows
// the same facts per disk and why the all-disks wipe would skip it.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// efiDir exists when the kernel booted by UEFI; ataPortDir holds the ata
// ports' local port numbers. Tests point them at fakes.
var (
	efiDir     = "/sys/firmware/efi"
	ataPortDir = "/sys/class/ata_port"
)

// readEfibootmgrV runs `efibootmgr -v` (tests replace it).
var readEfibootmgrV = func() (string, error) { return runStdout("efibootmgr", "-v") }

// diskPartUUIDs lists the PARTUUIDs of disk's partitions, lowercase (GPT:
// the partition GUID; MBR: <signature>-<nn>). Tests replace it.
var diskPartUUIDs = func(disk string) []string {
	out, _ := runStdout("lsblk", "-n", "-r", "-o", "PARTUUID", "/dev/"+disk)
	var ids []string
	for _, f := range strings.Fields(out) {
		ids = append(ids, strings.ToLower(f))
	}
	return ids
}

// stickPartition says which partition of disk holds stormboot/ ("" none);
// it mounts FAT partitions read-only, so it runs only under diskOpMu.
var stickPartition = func(disk string) (string, error) {
	lbs, err := readSysInt(filepath.Join(sysBlockDir, disk, "queue", "logical_block_size"))
	if err != nil || lbs <= 0 {
		lbs = 512
	}
	part, _, err := readStick(disk, lbs)
	return part, err
}

// devicePath is what of a UEFI device path names a disk.
type devicePath struct {
	PCI      [][2]int64 // Pci(dev,fn) nodes, in order
	Sata     int64      // Sata(HBAPort,…), -1 if none
	NVMeNS   int64      // NVMe(nsid,…), -1 if none
	PartUUID string     // HD(n,GPT,<guid>,…) or HD(n,MBR,0x<sig>,…) as a PARTUUID
	USB      bool
}

var (
	dpPciRe  = regexp.MustCompile(`Pci\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)`)
	dpSataRe = regexp.MustCompile(`Sata\(\s*(0x[0-9A-Fa-f]+|\d+)`)
	dpNVMeRe = regexp.MustCompile(`NVMe\(\s*(0x[0-9A-Fa-f]+|\d+)`)
	dpHDRe   = regexp.MustCompile(`HD\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(GPT|MBR)\s*,\s*([0-9A-Fa-fx-]+)`)
	pciDirRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:([0-9a-f]{2})\.([0-7])$`)
	ataDirRe = regexp.MustCompile(`^ata\d+$`)
)

func parseNum(s string) int64 {
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return -1
	}
	return v
}

// parseDevicePath reads the disk-naming nodes of an efibootmgr -v path.
func parseDevicePath(p string) devicePath {
	dp := devicePath{Sata: -1, NVMeNS: -1, USB: strings.Contains(p, "USB(") || strings.Contains(p, "UsbClass(") || strings.Contains(p, "UsbWwid(")}
	for _, m := range dpPciRe.FindAllStringSubmatch(p, -1) {
		dp.PCI = append(dp.PCI, [2]int64{parseNum(m[1]), parseNum(m[2])})
	}
	if m := dpSataRe.FindStringSubmatch(p); m != nil {
		dp.Sata = parseNum(m[1])
	}
	if m := dpNVMeRe.FindStringSubmatch(p); m != nil {
		dp.NVMeNS = parseNum(m[1])
	}
	if m := dpHDRe.FindStringSubmatch(p); m != nil {
		if m[2] == "GPT" {
			dp.PartUUID = strings.ToLower(m[3])
		} else if sig := parseNum(m[3]); sig >= 0 {
			dp.PartUUID = fmt.Sprintf("%08x-%02d", sig, parseNum(m[1]))
		}
	}
	return dp
}

// diskSysPath is the resolved sysfs device path of a disk.
func diskSysPath(disk string) string {
	p, err := filepath.EvalSymlinks(filepath.Join(sysBlockDir, disk))
	if err != nil {
		return ""
	}
	return p
}

// pciChain is the Pci(dev,fn) chain of a sysfs path, bus numbers dropped
// (a device path does not carry them).
func pciChain(sys string) [][2]int64 {
	var chain [][2]int64
	for _, c := range strings.Split(sys, "/") {
		if m := pciDirRe.FindStringSubmatch(c); m != nil {
			d, _ := strconv.ParseInt(m[1], 16, 64)
			f, _ := strconv.ParseInt(m[2], 10, 64)
			chain = append(chain, [2]int64{d, f})
		}
	}
	return chain
}

func sameChain(a, b [][2]int64) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ataPortNo is the controller-local (1-based) ata port of a sysfs path, -1
// if it is not on one.
func ataPortNo(sys string) int64 {
	for _, c := range strings.Split(sys, "/") {
		if ataDirRe.MatchString(c) {
			if n, err := readSysInt(filepath.Join(ataPortDir, c, "port_no")); err == nil {
				return n
			}
		}
	}
	return -1
}

// bootDiskSet resolves BootCurrent to the disks it boots from. why says how
// (or why none); err only when the firmware is UEFI and its boot entries
// cannot be read, so the boot device is unknown.
func bootDiskSet(disks []string) (set map[string]bool, why string, err error) {
	set = map[string]bool{}
	if _, err := os.Stat(efiDir); err != nil {
		return set, "legacy BIOS boot: no BootCurrent", nil
	}
	out, err := readEfibootmgrV()
	if err != nil {
		return set, "", fmt.Errorf("efibootmgr -v: %v", err)
	}
	bo := parseEfibootmgr(out)
	if bo.BootCurrent == "" {
		return set, "", fmt.Errorf("efibootmgr -v shows no BootCurrent")
	}
	var path, name string
	for _, e := range bo.Entries {
		if strings.EqualFold(e.Num, bo.BootCurrent) {
			path, name = e.Path, e.Name
		}
	}
	label := fmt.Sprintf("BootCurrent %s (%s)", bo.BootCurrent, name)
	if path == "" {
		return set, "", fmt.Errorf("%s: no device path in efibootmgr -v", label)
	}
	dp := parseDevicePath(path)
	if dp.PartUUID != "" {
		for _, d := range disks {
			for _, id := range diskPartUUIDs(d) {
				if id == dp.PartUUID {
					set[d] = true
				}
			}
		}
		if len(set) > 0 {
			return set, label + ": partition " + dp.PartUUID, nil
		}
	}
	if len(dp.PCI) == 0 {
		return set, label + ": " + path + " names no disk here", nil
	}
	for _, d := range disks {
		sys := diskSysPath(d)
		if !sameChain(pciChain(sys), dp.PCI) {
			continue
		}
		if dp.Sata >= 0 {
			if n := ataPortNo(sys); n >= 0 && n != dp.Sata+1 {
				continue
			}
		}
		if dp.NVMeNS >= 0 {
			if n, err := readSysInt(filepath.Join(sysBlockDir, d, "nsid")); err == nil && n != dp.NVMeNS {
				continue
			}
		}
		set[d] = true
	}
	if len(set) == 0 {
		return set, label + ": " + path + " names no disk here", nil
	}
	return set, label + ": " + path, nil
}

// diskIsUSB says whether a disk sits on a USB bus.
func diskIsUSB(disk string) bool {
	return strings.Contains(diskSysPath(disk), "/usb")
}

// diskIsRemovable is /sys/block/<disk>/removable.
func diskIsRemovable(disk string) bool {
	n, err := readSysInt(filepath.Join(sysBlockDir, disk, "removable"))
	return err == nil && n != 0
}

// diskProtection is why the all-disks wipe leaves a disk alone.
type diskProtection struct {
	BootDevice bool
	USB        bool
	Removable  bool
	Stormbootx string // partition holding stormboot/, or "unknown: …"
	Reasons    []string
}

// protectDisk works out a disk's protection. checkStick is false when the
// stormbootx check cannot run (a disk operation holds the lock).
func protectDisk(disk string, boot map[string]bool, bootWhy string, checkStick bool) diskProtection {
	var p diskProtection
	if boot[disk] {
		p.BootDevice = true
		p.Reasons = append(p.Reasons, "boot device ("+bootWhy+")")
	}
	if diskIsUSB(disk) {
		p.USB = true
		p.Reasons = append(p.Reasons, "USB device")
	}
	if diskIsRemovable(disk) {
		p.Removable = true
		p.Reasons = append(p.Reasons, "removable")
	}
	if !checkStick {
		p.Stormbootx = "unknown: a disk operation is running"
		return p
	}
	part, err := stickPartition(disk)
	switch {
	case err != nil:
		p.Stormbootx = "unknown: " + err.Error()
		p.Reasons = append(p.Reasons, "could not check for a stormbootx ESP: "+err.Error())
	case part != "":
		p.Stormbootx = "/dev/" + part
		p.Reasons = append(p.Reasons, "stormbootx disk (stormboot/ on /dev/"+part+")")
	}
	return p
}
