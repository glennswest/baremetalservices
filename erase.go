package main

import (
	"fmt"
	"path/filepath"
)

// Secure-erase fallback for a disk with no ATA security feature (finding
// 516e4f885acb): the whole device is overwritten with zeros from Go (every
// write checked, then fsync), and read back past the page cache at the head,
// the tail and evenly spaced points between. The erase is reported only when
// both succeed; dd's exit status (always non-zero at the end of a device)
// is no longer in the way.

const (
	eraseSampleBytes = 1 << 20 // read back at each sample point
	eraseSamples     = 16      // sample points, head and tail included
)

// eraseSampleOffsets are where verifyZeroed reads on a device of size bytes.
func eraseSampleOffsets(size int64) []int64 {
	n := int64(eraseSampleBytes)
	if size <= n {
		return []int64{0}
	}
	var offs []int64
	last := size - n
	for i := int64(0); i < eraseSamples; i++ {
		offs = append(offs, last*i/(eraseSamples-1))
	}
	return offs
}

// verifyZeroed reads the sample points of dev and fails on any non-zero byte.
func verifyZeroed(dev string, size int64) error {
	for _, off := range eraseSampleOffsets(size) {
		n := int64(eraseSampleBytes)
		if off+n > size {
			n = size - off
		}
		zero, err := readsZero(dev, off, n)
		if err != nil {
			return fmt.Errorf("read back at %d: %w", off, err)
		}
		if !zero {
			return fmt.Errorf("read back at %d: not zero", off)
		}
	}
	return nil
}

// zeroAndVerify overwrites all size bytes of dev with zeros and verifies.
func zeroAndVerify(dev string, size int64) error {
	if size <= 0 {
		return fmt.Errorf("%s: size unknown", dev)
	}
	if err := zeroDisk(dev, []byteRange{{0, size}}); err != nil {
		return fmt.Errorf("zero %s: %w", dev, err)
	}
	return verifyZeroed(dev, size)
}

// blockDeviceSize is a disk or partition's size in bytes, from sysfs
// (always 512-byte units there).
func blockDeviceSize(name string) (int64, error) {
	n, err := readSysInt(filepath.Join(sysClassBlockDir, name, "size"))
	return n * 512, err
}
