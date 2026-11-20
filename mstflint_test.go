package main

import (
	"fmt"
	"sync"
	"testing"
)

// Concurrent cache misses must not write the map unsynchronized (finding
// c2bfa5d76292): without the mutex this dies with "concurrent map writes".
// mstflint is not on the test host, so every probe fails fast and caches an
// empty entry.
func TestMellanoxFirmwareInfoConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				getMellanoxFirmwareInfo(fmt.Sprintf("00:%02x.%d", (i+j)%32, j%8))
			}
		}(i)
	}
	wg.Wait()
	a := getMellanoxFirmwareInfo("00:01.0")
	b := getMellanoxFirmwareInfo("00:01.0")
	if fmt.Sprintf("%p", a) != fmt.Sprintf("%p", b) {
		t.Errorf("a cached entry was not reused")
	}
}
