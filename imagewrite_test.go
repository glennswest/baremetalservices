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
