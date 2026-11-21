package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Finding 0430c4ac66c0: while one disk operation runs, every other mutating
// disk route answers 409 before it checks or touches a device, and each
// handler gives the lock back when it answers.
func TestDiskOpLockShared(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	routes := []struct {
		path string
		h    http.HandlerFunc
	}{
		{"/disks/image/sdz?url=http://127.0.0.1:1/img&sha256=" + sha, handleDiskImage},
		{"/disks/wipe/sdz", handleDiskWipe},
		{"/disks/wipe", handleDiskWipe},
		{"/disks/partition/sdz?label=gpt", handleDiskPartition},
		{"/disks/format/sdz1?fstype=ext4", handleDiskFormat},
		{"/disks/secure-erase/sdz", handleDiskSecureErase},
	}
	call := func(path string, h http.HandlerFunc) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, path, nil))
		return rec
	}

	diskOpMu.Lock()
	for _, r := range routes {
		if rec := call(r.path, r.h); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "another disk operation") {
			t.Errorf("%s while a disk operation runs: %d %s, want 409", r.path, rec.Code, rec.Body.String())
		}
	}
	diskOpMu.Unlock()

	// Unlocked, a disk that does not exist gets past the lock (404) and the
	// lock is free again afterwards.
	for _, r := range []string{"/disks/image/nosuchdisk0?url=http://127.0.0.1:1/img&sha256=" + sha, "/disks/wipe/nosuchdisk0"} {
		h := handleDiskWipe
		if strings.HasPrefix(r, "/disks/image/") {
			h = handleDiskImage
		}
		if rec := call(r, h); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s, want 404", r, rec.Code, rec.Body.String())
		}
		if !diskOpMu.TryLock() {
			t.Fatalf("%s left the disk-operation lock held", r)
		}
		diskOpMu.Unlock()
	}
}
