package main

import (
	"net/http"
	"sync"
)

// diskOpMu lets one mutating disk operation run at a time (finding
// 0430c4ac66c0): POST /disks/image, /disks/wipe, /disks/partition,
// /disks/format and /disks/secure-erase. Each handler takes it before its
// device checks and holds it until its answer, so no other request can
// change a disk between one operation's refusal checks and its verify.
var diskOpMu sync.Mutex

// lockDiskOp takes diskOpMu, or answers 409 and returns false when another
// disk operation holds it. The caller defers diskOpMu.Unlock().
func lockDiskOp(w http.ResponseWriter) bool {
	if diskOpMu.TryLock() {
		return true
	}
	sendJSON(w, http.StatusConflict, APIResponse{Status: "error", Error: "another disk operation (image, wipe, partition, format or secure-erase) is running"})
	return false
}
