package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestConfField(t *testing.T) {
	text := "# tag = commented\nname=\nname = \"forge1\"\n  tag=prod  \nportal = 1.2.3.4\n"
	for key, want := range map[string]string{"name": "forge1", "tag": "prod", "portal": "1.2.3.4", "update": ""} {
		if got := confField(text, key); got != want {
			t.Errorf("confField(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestMergeLocalConf(t *testing.T) {
	for _, c := range []struct {
		name      string
		old, cur  stickFiles
		text      string
		kept      []string
		wantWrite bool
	}{
		{
			name: "old local.conf replaces the new one, tag carried",
			old:  stickFiles{Local: []byte("portal = 10.0.0.1"), Conf: []byte("version = 0.37.0\ntag = forge\n")},
			cur:  stickFiles{Local: []byte("portal = 9.9.9.9\n"), Conf: []byte("version = 0.39.0\n")},
			text: "portal = 10.0.0.1\ntag = forge\n",
			kept: []string{"local.conf (17 bytes)", "tag = forge"}, wantWrite: true,
		},
		{
			name: "name already in the new stormboot.conf, tag already in local.conf",
			old:  stickFiles{Local: []byte("tag = a\n"), Conf: []byte("name = n1\ntag = b\n")},
			cur:  stickFiles{Conf: []byte("name = n2\n")},
			text: "tag = a\n",
			kept: []string{"local.conf (8 bytes)"}, wantWrite: true,
		},
		{
			name: "no old local.conf, nothing to carry",
			old:  stickFiles{Conf: []byte("version = 0.37.0\n")},
			cur:  stickFiles{Local: []byte("x = 1\n"), Conf: []byte("version = 0.39.0\n")},
			text: "x = 1\n", wantWrite: false,
		},
		{
			name: "no old local.conf, name carried onto the new one",
			old:  stickFiles{Conf: []byte("name = forge1\n")},
			cur:  stickFiles{Local: []byte("x = 1"), Conf: []byte("version = 0.39.0\n")},
			text: "x = 1\nname = forge1\n",
			kept: []string{"name = forge1"}, wantWrite: true,
		},
	} {
		text, kept, write := mergeLocalConf(c.old, c.cur)
		if text != c.text || !reflect.DeepEqual(kept, c.kept) || write != c.wantWrite {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)", c.name, text, kept, write, c.text, c.kept, c.wantWrite)
		}
	}
}

func TestSlabAt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk")
	b := make([]byte, 2<<20)
	copy(b[1<<20:], slabMagic)
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatal(err)
	}
	if at, ok, err := slabAt(p, []int64{0, 1 << 20}); err != nil || !ok || at != 1<<20 {
		t.Fatalf("slabAt = %d %v %v, want 1048576 true", at, ok, err)
	}
	if _, ok, err := slabAt(p, []int64{0, 4096, 4 << 20}); err != nil || ok {
		t.Fatalf("slabAt found a slab that is not there (%v)", err)
	}
}

func TestGPTBlockSize(t *testing.T) {
	dir := t.TempDir()
	for want, img := range map[int][]byte{
		512:  append(make([]byte, 512), []byte("EFI PART")...),
		4096: append(make([]byte, 4096), []byte("EFI PART")...),
		0:    make([]byte, 8192),
	} {
		p := filepath.Join(dir, "img")
		if err := os.WriteFile(p, img, 0644); err != nil {
			t.Fatal(err)
		}
		if got, err := gptBlockSize(p); err != nil || got != want {
			t.Errorf("gptBlockSize = %d %v, want %d", got, err, want)
		}
	}
}

func TestAlignedBuf(t *testing.T) {
	for i := 0; i < 8; i++ {
		b := alignedBuf(8192+i, 4096)
		if len(b) != 8192+i || uintptr(unsafe.Pointer(&b[0]))%4096 != 0 {
			t.Fatalf("alignedBuf: len %d, address %p", len(b), &b[0])
		}
	}
}

// The download, the sha256 and size refusals, the write and the read-back,
// with a regular file standing in for the disk.
func TestFetchWriteVerify(t *testing.T) {
	img := make([]byte, 3<<20+1234) // not a whole number of blocks or chunks
	for i := range img {
		img[i] = byte(i * 7)
	}
	sum := sha256.Sum256(img)
	want := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/img" {
			http.NotFound(w, r)
			return
		}
		w.Write(img)
	}))
	defer srv.Close()
	dir := t.TempDir()

	if _, _, err := fetchImage(srv.URL+"/img", "00"+want[2:], dir, 1<<30); !errors.Is(err, errImage) {
		t.Fatalf("a wrong sha256 was not refused as the image's fault: %v", err)
	}
	if _, _, err := fetchImage(srv.URL+"/img", want, dir, 1<<20); !errors.Is(err, errImage) {
		t.Fatalf("an image larger than the disk was not refused: %v", err)
	}
	if _, _, err := fetchImage(srv.URL+"/nope", want, dir, 1<<30); err == nil || errors.Is(err, errImage) {
		t.Fatalf("a 404 was not a download failure: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "bms-image-*")); len(left) != 0 {
		t.Fatalf("refused downloads left files: %v", left)
	}
	path, n, err := fetchImage(srv.URL+"/img", want, dir, 1<<30)
	if err != nil || n != int64(len(img)) {
		t.Fatalf("fetchImage = %d %v", n, err)
	}

	disk := filepath.Join(dir, "disk")
	old := bytes.Repeat([]byte{0xff}, 8<<20)
	if err := os.WriteFile(disk, old, 0644); err != nil {
		t.Fatal(err)
	}
	if w, err := writeImage(path, disk); err != nil || w != n {
		t.Fatalf("writeImage = %d %v", w, err)
	}
	got, err := readBackSHA256(disk, n, 512)
	if err != nil || got != want {
		t.Fatalf("readBackSHA256 = %s %v, want %s", got, err, want)
	}
	b, _ := os.ReadFile(disk)
	if len(b) != len(old) || !bytes.Equal(b[:n], img) || !bytes.Equal(b[n:], old[n:]) {
		t.Fatal("the disk does not hold the image followed by what was there")
	}
	if _, err := readBackSHA256(disk, int64(len(old))+1, 512); err == nil {
		t.Fatal("reading back past the end of the disk did not fail")
	}
}

// Finding 71a7c42c8aec: no RAM above the reserve is a refusal, never a
// fallback to the disk's size.
func TestImageDownloadLimit(t *testing.T) {
	const disk = 8 << 30
	for _, c := range []struct {
		avail, want int64
		refused     bool
	}{
		{0, 0, true},                       // MemAvailable unknown
		{imageRAMReserve - 1, 0, true},     // under the reserve
		{imageRAMReserve, 0, true},         // exactly the reserve: nothing left
		{imageRAMReserve + 1, 1, false},    // one byte to spare
		{imageRAMReserve + 1<<30, 1 << 30, false}, // a GiB to spare
		{imageRAMReserve + 64<<30, disk, false},   // more RAM than disk
	} {
		got, err := imageDownloadLimit(disk, c.avail)
		if c.refused != (err != nil) || got != c.want || (err != nil && !errors.Is(err, errNoMemory)) {
			t.Errorf("imageDownloadLimit(%d) = %d %v, want %d refused=%v", c.avail, got, err, c.want, c.refused)
		}
	}
}

// The budget holds while streaming too: MemAvailable falling under the
// reserve mid-download stops it, and nothing is left behind.
func TestFetchImageStopsWhenMemoryRunsOut(t *testing.T) {
	img := make([]byte, imageMemCheckEvery+1<<20)
	sum := sha256.Sum256(img)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(img) }))
	defer srv.Close()
	old := memAvailableFn
	defer func() { memAvailableFn = old }()
	memAvailableFn = func() int64 { return imageRAMReserve - 1 }
	dir := t.TempDir()
	if _, _, err := fetchImage(srv.URL, hex.EncodeToString(sum[:]), dir, 1<<30); !errors.Is(err, errNoMemory) {
		t.Fatalf("fetchImage with MemAvailable under the reserve = %v, want errNoMemory", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "bms-image-*")); len(left) != 0 {
		t.Fatalf("a refused download left files: %v", left)
	}
	memAvailableFn = func() int64 { return imageRAMReserve + 1<<30 }
	if _, n, err := fetchImage(srv.URL, hex.EncodeToString(sum[:]), dir, 1<<30); err != nil || n != int64(len(img)) {
		t.Fatalf("fetchImage with RAM to spare = %d %v", n, err)
	}
}

// fakeStick is a 20 MiB disk sdz with partitions sdz1 (at 1 MiB, 4 MiB) and
// sdz2 (at 6 MiB, 4 MiB) in a fake sysfs, their device nodes regular files
// in a fake /dev. It restores the globals when the test ends.
func fakeStick(t *testing.T) string {
	t.Helper()
	root, dev := t.TempDir(), t.TempDir()
	oldSys, oldDev, oldM, oldS, oldMount, oldMem := sysBlockDir, devDir, procMounts, procSwaps, vfatMount, memAvailableFn
	t.Cleanup(func() {
		sysBlockDir, devDir, procMounts, procSwaps, vfatMount, memAvailableFn = oldSys, oldDev, oldM, oldS, oldMount, oldMem
	})
	sysBlockDir, devDir = root, dev
	procMounts, procSwaps = filepath.Join(root, "mounts"), filepath.Join(root, "swaps")
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(procMounts, "")
	write(procSwaps, "")
	write(filepath.Join(root, "sdz/size"), "40960\n")
	write(filepath.Join(root, "sdz/queue/logical_block_size"), "512\n")
	for name, start := range map[string]string{"sdz1": "2048", "sdz2": "12288"} {
		write(filepath.Join(root, "sdz", name, "partition"), name[3:]+"\n")
		write(filepath.Join(root, "sdz", name, "start"), start+"\n")
		write(filepath.Join(root, "sdz", name, "size"), "8192\n")
		write(filepath.Join(dev, name), string(make([]byte, 4<<20)))
	}
	write(filepath.Join(dev, "sdz"), string(make([]byte, 20<<20)))
	return dev
}

// fatBoot makes dev's first sector a FAT32 boot sector.
func fatBoot(t *testing.T, dev string) {
	t.Helper()
	b := make([]byte, 512)
	copy(b[82:], "FAT32   ")
	b[510], b[511] = 0x55, 0xaa
	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(b, 0); err != nil {
		t.Fatal(err)
	}
}

// espGPT gives disk a GPT (512-byte blocks) with one EFI System partition
// starting at block first.
func espGPT(t *testing.T, disk string, first uint64) {
	t.Helper()
	hdr := make([]byte, 92)
	copy(hdr, "EFI PART")
	put := func(b []byte, v uint64) {
		for i := range b {
			b[i] = byte(v >> (8 * i))
		}
	}
	put(hdr[72:80], 2)   // entries at LBA 2
	put(hdr[80:84], 128) // 128 entries
	put(hdr[84:88], 128) // of 128 bytes
	e := make([]byte, 128)
	copy(e, espTypeGUID)
	put(e[32:40], first)
	f, err := os.OpenFile(disk, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteAt(hdr, 512)
	f.WriteAt(e, 1024)
}

// Finding f2990cf34046: an ESP that cannot be inspected is an error; only
// an inspected ESP without stormboot/ (or without a file) is "nothing there".
func TestReadStick(t *testing.T) {
	dev := fakeStick(t)
	mnt := t.TempDir()
	var mountErr error
	mounted := map[string]bool{}
	vfatMount = func(d string, ro bool, fn func(string) error) error {
		mounted[filepath.Base(d)] = true
		if mountErr != nil {
			return mountErr
		}
		return fn(mnt)
	}

	// No FAT and no GPT: nothing is mounted, nothing found.
	if part, _, err := readStick("sdz", 512); err != nil || part != "" || len(mounted) != 0 {
		t.Fatalf("no ESP: part %q err %v, mounted %v", part, err, mounted)
	}

	fatBoot(t, filepath.Join(dev, "sdz2"))
	if part, _, err := readStick("sdz", 512); err != nil || part != "" || !mounted["sdz2"] || mounted["sdz1"] {
		t.Fatalf("FAT without stormboot/: part %q err %v, mounted %v", part, err, mounted)
	}

	mountErr = errors.New("mount /dev/sdz2: invalid argument")
	if _, _, err := readStick("sdz", 512); err == nil || !strings.Contains(err.Error(), "could not be inspected") {
		t.Fatalf("a FAT partition that does not mount was not an error: %v", err)
	}
	mountErr = nil

	os.MkdirAll(filepath.Join(mnt, stickDir), 0755)
	os.WriteFile(filepath.Join(mnt, stickConf), []byte("name = forge1\n"), 0644)
	part, files, err := readStick("sdz", 512)
	if err != nil || part != "sdz2" || files.Local != nil || string(files.Conf) != "name = forge1\n" {
		t.Fatalf("stormboot/ without local.conf: %q %+v %v", part, files, err)
	}

	// local.conf there but unreadable (a directory): an error, not absent.
	os.Mkdir(filepath.Join(mnt, stickLocalConf), 0755)
	if _, _, err := readStick("sdz", 512); err == nil {
		t.Fatal("an unreadable local.conf was taken as absent")
	}
	os.Remove(filepath.Join(mnt, stickLocalConf))
	os.WriteFile(filepath.Join(mnt, stickLocalConf), []byte("portal = 10.0.0.1\n"), 0644)
	if part, files, err := readStick("sdz", 512); err != nil || part != "sdz2" || string(files.Local) != "portal = 10.0.0.1\n" {
		t.Fatalf("stormboot/local.conf: %q %+v %v", part, files, err)
	}

	// A GPT ESP whose boot sector is gone (sdz1, zeros) is still inspected,
	// and failing to mount it is an error.
	espGPT(t, filepath.Join(dev, "sdz"), 2048)
	mountErr = errors.New("mount /dev/sdz1: invalid argument")
	if _, _, err := readStick("sdz", 512); err == nil || !strings.Contains(err.Error(), "sdz1") {
		t.Fatalf("a GPT ESP with no FAT boot sector that does not mount was not an error: %v", err)
	}
}

// writeDiskImage refuses before downloading or touching the disk when the
// old ESP cannot be read (keep_local_conf) or there is no RAM for the image.
func TestWriteDiskImageRefusesBeforeAnyChange(t *testing.T) {
	dev := fakeStick(t)
	fatBoot(t, filepath.Join(dev, "sdz1"))
	before, _ := os.ReadFile(filepath.Join(dev, "sdz"))
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		w.Write([]byte("image"))
	}))
	defer srv.Close()
	sha := strings.Repeat("ab", 32)

	vfatMount = func(string, bool, func(string) error) error { return errors.New("mount: I/O error") }
	memAvailableFn = func() int64 { return 8 << 30 }
	res, status := writeDiskImage("sdz", srv.URL, sha, true)
	if status != http.StatusInternalServerError || !strings.Contains(res.Error, "could not be inspected") {
		t.Fatalf("unreadable old ESP with keep_local_conf: %d %+v", status, res)
	}

	memAvailableFn = func() int64 { return imageRAMReserve }
	res, status = writeDiskImage("sdz", srv.URL, sha, false)
	if status != http.StatusInsufficientStorage || !strings.Contains(res.Error, "memory failed") {
		t.Fatalf("no RAM above the reserve: %d %+v", status, res)
	}

	if n := gets.Load(); n != 0 {
		t.Fatalf("the image was downloaded %d times after a refusal", n)
	}
	if after, _ := os.ReadFile(filepath.Join(dev, "sdz")); !bytes.Equal(before, after) {
		t.Fatal("the disk changed after a refusal")
	}
}
