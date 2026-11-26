package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDevicePath(t *testing.T) {
	for _, c := range []struct {
		path string
		want devicePath
	}{
		// A stormbootx stick on an X9's EHCI (as efibootmgr 18 prints it).
		{"PciRoot(0x0)/Pci(0x1d,0x0)/USB(1,0)/USB(2,0)/HD(1,GPT,6F2A1C3E-0B9D-4E57-9A43-21C3B5E1D0AA,0x800,0x10000)/File(\\EFI\\BOOT\\BOOTX64.EFI)",
			devicePath{PCI: [][2]int64{{0x1d, 0}}, Sata: -1, NVMeNS: -1, PartUUID: "6f2a1c3e-0b9d-4e57-9a43-21c3b5e1d0aa", USB: true}},
		// OVMF's auto entry for a virtio disk: no partition, PCI only.
		{"PciRoot(0x0)/Pci(0x3,0x0){auto_created_boot_option}",
			devicePath{PCI: [][2]int64{{3, 0}}, Sata: -1, NVMeNS: -1}},
		{"PciRoot(0x0)/Pci(0x1f,0x2)/Sata(2,65535,0)/HD(1,MBR,0x1a2b3c4d,0x800,0x100000)",
			devicePath{PCI: [][2]int64{{0x1f, 2}}, Sata: 2, NVMeNS: -1, PartUUID: "1a2b3c4d-01"}},
		{"PciRoot(0x0)/Pci(0x1,0x1)/Pci(0x0,0x0)/NVMe(0x1,00-00-00-00-00-00-00-00)",
			devicePath{PCI: [][2]int64{{1, 1}, {0, 0}}, Sata: -1, NVMeNS: 1}},
		{"MAC(0cc47a000001,0)/IPv4(0.0.0.0,0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)", devicePath{Sata: -1, NVMeNS: -1}},
	} {
		if got := parseDevicePath(c.path); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseDevicePath(%s) = %+v, want %+v", c.path, got, c.want)
		}
	}
}

// fakeDisks builds /sys/block with each disk a symlink into a fake devices
// tree, as the kernel lays it out.
func fakeDisks(t *testing.T, disks map[string]string) string {
	t.Helper()
	root := t.TempDir()
	block := filepath.Join(root, "block")
	os.MkdirAll(block, 0755)
	for name, dev := range disks {
		dir := filepath.Join(root, "devices", dev, "block", name)
		os.MkdirAll(filepath.Join(dir, "queue"), 0755)
		os.WriteFile(filepath.Join(dir, "size"), []byte("8388608\n"), 0644)
		os.WriteFile(filepath.Join(dir, "removable"), []byte("0\n"), 0644)
		if err := os.Symlink(dir, filepath.Join(block, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// #47: the all-disks wipe takes the data disks only.
func TestWipeAllTargets(t *testing.T) {
	root := fakeDisks(t, map[string]string{
		"sda":     "pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0",                  // data HDD, ata port 1
		"sdb":     "pci0000:00/0000:00:1f.2/ata2/host1/target1:0:0/1:0:0:0",                  // data HDD, ata port 2
		"sdc":     "pci0000:00/0000:00:1d.0/usb2/2-1/2-1.1/2-1.1:1.0/host6/target6:0:0/6:0:0:0", // stormbootx stick
		"sdd":     "pci0000:00/0000:00:1f.2/ata3/host2/target2:0:0/2:0:0:0",                  // SATADOM with stormboot/
		"sde":     "pci0000:00/0000:00:1c.0/0000:02:00.0/host7/target7:0:0/7:0:0:0",          // card reader
		"nvme0n1": "pci0000:00/0000:00:01.1/0000:03:00.0/nvme/nvme0",                          // data NVMe
	})
	os.WriteFile(filepath.Join(root, "block", "sde", "removable"), []byte("1\n"), 0644)
	for i := 1; i <= 3; i++ {
		d := filepath.Join(root, "ata_port", "ata"+string(rune('0'+i)))
		os.MkdirAll(d, 0755)
		os.WriteFile(filepath.Join(d, "port_no"), []byte(string(rune('0'+i))+"\n"), 0644)
	}
	oldB, oldE, oldA, oldV, oldU, oldS := sysBlockDir, efiDir, ataPortDir, efibootmgrV, diskPartUUIDs, stickPartition
	defer func() {
		sysBlockDir, efiDir, ataPortDir, efibootmgrV, diskPartUUIDs, stickPartition = oldB, oldE, oldA, oldV, oldU, oldS
	}()
	sysBlockDir, efiDir, ataPortDir = filepath.Join(root, "block"), root, filepath.Join(root, "ata_port")
	diskPartUUIDs = func(d string) []string {
		if d == "sdc" {
			return []string{"6f2a1c3e-0b9d-4e57-9a43-21c3b5e1d0aa"}
		}
		return []string{"part-of-" + d}
	}
	stickPartition = func(d string) (string, error) {
		switch d {
		case "sdc":
			return "sdc1", nil
		case "sdd":
			return "sdd1", nil
		}
		return "", nil
	}
	all := []string{"nvme0n1", "sda", "sdb", "sdc", "sdd", "sde"}
	stick := "BootCurrent: 0002\nBootOrder: 0002,0001\n" +
		"Boot0001* UEFI: PXE IP4 Intel(R) I350\tMAC(0cc47a000001,0)/IPv4(0.0.0.0,0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)\n" +
		"Boot0002* UEFI: SanDisk\tPciRoot(0x0)/Pci(0x1d,0x0)/USB(1,0)/USB(1,0)/HD(1,GPT,6F2A1C3E-0B9D-4E57-9A43-21C3B5E1D0AA,0x800,0x10000)\n"
	efibootmgrV = func() (string, error) { return stick, nil }

	targets, skipped, err := wipeAllTargets(all)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nvme0n1", "sda", "sdb"}; !reflect.DeepEqual(targets, want) {
		t.Errorf("targets = %v, want %v (skipped %v)", targets, want, skipped)
	}
	for dev, want := range map[string]string{
		"/dev/sdc": "boot device (BootCurrent 0002 (UEFI: SanDisk): partition 6f2a1c3e-0b9d-4e57-9a43-21c3b5e1d0aa); USB device; stormbootx disk (stormboot/ on /dev/sdc1)",
		"/dev/sdd": "stormbootx disk (stormboot/ on /dev/sdd1)",
		"/dev/sde": "removable",
	} {
		if skipped[dev] != want {
			t.Errorf("skipped[%s] = %q, want %q", dev, skipped[dev], want)
		}
	}
	if len(skipped) != 3 {
		t.Errorf("skipped = %v", skipped)
	}

	// Booted off SATA port 2 (Sata() is 0-based, ata port_no 1-based): sdb.
	efibootmgrV = func() (string, error) {
		return "BootCurrent: 0003\nBoot0003* SATA HDD\tPciRoot(0x0)/Pci(0x1f,0x2)/Sata(1,65535,0)\n", nil
	}
	if targets, skipped, _ = wipeAllTargets(all); !reflect.DeepEqual(targets, []string{"nvme0n1", "sda"}) || !strings.HasPrefix(skipped["/dev/sdb"], "boot device") {
		t.Errorf("SATA boot: targets %v skipped %v", targets, skipped)
	}
	// A PCI path with no port: every disk under that controller is kept.
	efibootmgrV = func() (string, error) { return "BootCurrent: 0003\nBoot0003* AHCI\tPciRoot(0x0)/Pci(0x1f,0x2)\n", nil }
	if targets, _, _ = wipeAllTargets(all); !reflect.DeepEqual(targets, []string{"nvme0n1"}) {
		t.Errorf("ambiguous AHCI boot: targets %v, want nvme0n1 only", targets)
	}
	// A stick that cannot be inspected is skipped, not wiped.
	stickPartition = func(d string) (string, error) {
		if d == "sda" {
			return "", errors.New("mount /dev/sda1: I/O error")
		}
		return "", nil
	}
	efibootmgrV = func() (string, error) { return stick, nil }
	if targets, skipped, _ = wipeAllTargets(all); !reflect.DeepEqual(targets, []string{"nvme0n1", "sdb", "sdd"}) || !strings.Contains(skipped["/dev/sda"], "I/O error") {
		t.Errorf("uninspectable ESP: targets %v skipped %v", targets, skipped)
	}
	// UEFI with unreadable boot entries: nothing is wiped.
	efibootmgrV = func() (string, error) { return "", errors.New("EFI variables are not supported") }
	if targets, _, err = wipeAllTargets(all); err == nil || targets != nil {
		t.Errorf("unreadable BootCurrent: targets %v err %v, want an error", targets, err)
	}
	// Legacy BIOS: no BootCurrent to resolve; USB/removable/stormbootx still hold.
	efiDir = filepath.Join(root, "nosuch")
	stickPartition = func(string) (string, error) { return "", nil }
	if targets, skipped, err = wipeAllTargets(all); err != nil || !reflect.DeepEqual(targets, []string{"nvme0n1", "sda", "sdb", "sdd"}) || skipped["/dev/sdc"] != "USB device" {
		t.Errorf("BIOS boot: targets %v skipped %v err %v", targets, skipped, err)
	}
}
