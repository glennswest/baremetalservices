package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const mib = int64(1) << 20

func TestZeroRegions(t *testing.T) {
	disk := 2000 * 1024 * mib // ST2000DM008-sized
	parts := []partRange{
		{Name: "sda1", Start: 1 * mib, Size: 512 * mib},        // inside the head edge, shorter than 1 GiB
		{Name: "sda2", Start: 513 * mib, Size: 116 * 1024 * mib}, // 1 GiB from 513 MiB
		{Name: "sda3", Start: disk - 10*mib, Size: 10 * mib},  // inside the tail edge
	}
	got := zeroRegions(disk, parts)
	want := []byteRange{
		{0, 513*mib + 1024*mib},            // head edge + sda1 + sda2's head, merged
		{disk - 64*mib, 64 * mib},          // tail edge, sda3 inside it
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
	if res := wipeDisk("nosuch"); res.Verified || res.Error == "" {
		t.Fatalf("wipeDisk(nosuch) = %+v, want an error", res)
	}
}
