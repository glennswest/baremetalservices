package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEraseSampleOffsets(t *testing.T) {
	size := int64(100<<20 + 12345)
	offs := eraseSampleOffsets(size)
	if len(offs) != eraseSamples || offs[0] != 0 || offs[len(offs)-1] != size-eraseSampleBytes {
		t.Fatalf("offsets %v: want %d from 0 to the last MiB", offs, eraseSamples)
	}
	if o := eraseSampleOffsets(4096); len(o) != 1 || o[0] != 0 {
		t.Errorf("small device: %v", o)
	}
}

func TestZeroAndVerify(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "disk")
	size := int64(9<<20 + 513)
	data := make([]byte, size)
	rand.Read(data)
	if err := os.WriteFile(dev, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := zeroAndVerify(dev, size); err != nil {
		t.Fatalf("zeroAndVerify: %v", err)
	}
	got, _ := os.ReadFile(dev)
	if int64(len(got)) != size || !bytes.Equal(got, make([]byte, size)) {
		t.Errorf("device not all zero after the erase")
	}
}

// A device that cannot be written is an error, never "wiped".
func TestZeroAndVerifyWriteFails(t *testing.T) {
	if err := zeroAndVerify(filepath.Join(t.TempDir(), "missing", "disk"), 1<<20); err == nil {
		t.Errorf("no error for a device that cannot be opened")
	}
	if err := zeroAndVerify(filepath.Join(t.TempDir(), "disk"), 0); err == nil {
		t.Errorf("no error for an unknown size")
	}
}

// Data left at a sample point fails the verification.
func TestVerifyZeroedFindsData(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "disk")
	size := int64(8 << 20)
	data := make([]byte, size)
	data[size-10] = 0xff // in the tail sample
	os.WriteFile(dev, data, 0o600)
	if err := verifyZeroed(dev, size); err == nil {
		t.Errorf("data at the tail passed verification")
	}
}
