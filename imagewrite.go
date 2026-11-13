// Image write (#36): POST /disks/image/{dev}?url=…&sha256=…[&keep_local_conf=true]
//
// Writes a raw boot image (a stormbootx golden's boot/<golden>-usb.img, say)
// onto a whole disk, so a node's boot stick can be brought up to date from
// the maintenance image without a served manifest. Per request:
//
//	refuse a disk that is mounted, active swap, held (dm, md) or carries a
//	  stormblock slab (STRMSLAB at its start or at a partition's start), the
//	  refusals stormbootx-stick makes
//	keep_local_conf: read stormboot/local.conf and stormboot.conf off the
//	  old ESP (mounted read-only)
//	download the image into RAM; refuse it unless its sha256 is the one given
//	  and it fits the disk
//	a GPT image must have its GPT at the disk's logical block size
//	refuse again (nothing may have claimed the disk meanwhile)
//	zero the old disk's last MiB (an old backup GPT), write the image, fsync
//	read the written range back past the page cache, compare its sha256
//	GPT: sgdisk -e (backup GPT to the end of the disk, stormbootx#179),
//	  then sgdisk -v must find no problems
//	re-read the partition table (BLKRRPART)
//	keep_local_conf: write the old local.conf onto the new ESP, plus a
//	  name =/tag = the new stormboot.conf drops (as stormbootx-stick does)
//
// Any failed step fails the request, with the steps so far in the answer.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	slabMagic        = "STRMSLAB"     // stormblock's slab header (stormblock drive/slab.rs)
	imageTailZero    = 1 << 20        // zeroed at the old disk's end before a write
	imageReadChunk   = 4 << 20        // read-back chunk
	imageRAMReserve  = 256 << 20      // left free when the image is held in RAM
	imageHTTPTimeout = 60 * time.Minute
	stickDir         = "stormboot"
	stickLocalConf   = "stormboot/local.conf"
	stickConf        = "stormboot/stormboot.conf"
)

// imageMu lets one image write run at a time.
var imageMu sync.Mutex

type imageWriteResult struct {
	Device    string     `json:"device"`
	URL       string     `json:"url"`
	Written   int64      `json:"written"`
	SHA256    string     `json:"sha256"`
	Verified  bool       `json:"verified"`
	GPT       string     `json:"gpt"`
	LocalConf []string   `json:"local_conf_kept,omitempty"`
	Steps     []wipeStep `json:"steps"`
	Error     string     `json:"error,omitempty"`
}

// slabAt says where dev carries a stormblock slab header, if at any of offs.
func slabAt(dev string, offs []int64) (int64, bool, error) {
	f, err := os.Open(dev)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	m := make([]byte, len(slabMagic))
	for _, off := range offs {
		if n, _ := f.ReadAt(m, off); n == len(m) && string(m) == slabMagic {
			return off, true, nil
		}
	}
	return 0, false, nil
}

// imageRefusal says why disk must not be written, "" if it may be.
func imageRefusal(disk string) string {
	parts, err := diskPartitions(disk)
	if err != nil {
		return err.Error()
	}
	if why := diskInUse(disk, parts); why != "" {
		return "in use: " + why
	}
	offs := []int64{0}
	for _, p := range parts {
		offs = append(offs, p.Start)
	}
	at, slab, err := slabAt("/dev/"+disk, offs)
	if err != nil {
		return "cannot be read to check for a slab: " + err.Error()
	}
	if slab {
		return fmt.Sprintf("it holds a stormblock slab (STRMSLAB at byte %d)", at)
	}
	return ""
}

// memAvailable is MemAvailable from /proc/meminfo in bytes, 0 if unknown.
func memAvailable() int64 {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemAvailable:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb << 10
		}
	}
	return 0
}

// errImage marks a refusal of the image itself (not a failure of the disk).
var errImage = errors.New("image refused")

// fetchImage downloads url into a new file in dir, at most limit bytes, and
// checks its sha256 against want (lower-case hex).
func fetchImage(url, want, dir string, limit int64) (string, int64, error) {
	resp, err := (&http.Client{Timeout: imageHTTPTimeout}).Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	if resp.ContentLength > limit {
		return "", 0, fmt.Errorf("%w: %d bytes, more than %d", errImage, resp.ContentLength, limit)
	}
	f, err := os.CreateTemp(dir, "bms-image-*")
	if err != nil {
		return "", 0, err
	}
	path := f.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
	case n == 0:
		err = fmt.Errorf("%w: empty", errImage)
	case n > limit:
		err = fmt.Errorf("%w: more than %d bytes", errImage, limit)
	case hex.EncodeToString(h.Sum(nil)) != want:
		err = fmt.Errorf("%w: sha256 %s, want %s", errImage, hex.EncodeToString(h.Sum(nil)), want)
	}
	if err != nil {
		os.Remove(path)
		return "", 0, err
	}
	return path, n, nil
}

// gptBlockSize is the block size an image's GPT is laid out at (512 or
// 4096), 0 if the image has no GPT header at either.
func gptBlockSize(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b := make([]byte, 4096+8)
	n, _ := f.ReadAt(b, 0)
	for _, bs := range []int{512, 4096} {
		if n >= bs+8 && string(b[bs:bs+8]) == "EFI PART" {
			return bs, nil
		}
	}
	return 0, nil
}

// alignedBuf is a size-byte buffer at an align-byte boundary (O_DIRECT).
func alignedBuf(size, align int) []byte {
	b := make([]byte, size+align)
	off := int(uintptr(unsafe.Pointer(&b[0])) & uintptr(align-1))
	if off != 0 {
		off = align - off
	}
	return b[off : off+size]
}

// writeImage copies src onto dev from byte 0 and syncs.
func writeImage(src, dev string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.CopyBuffer(out, in, make([]byte, imageReadChunk))
	if err != nil {
		return n, err
	}
	return n, out.Sync()
}

// readBackSHA256 hashes the first n bytes of dev as the device has them:
// the page cache is dropped (BLKFLSBUF) and the read is O_DIRECT where the
// device takes it (a regular file on tmpfs, in tests, does not).
func readBackSHA256(dev string, n int64, lbs int) (string, error) {
	f, err := os.OpenFile(dev, os.O_RDONLY|syscall.O_DIRECT, 0)
	if err != nil {
		if f, err = os.Open(dev); err != nil {
			return "", err
		}
	}
	defer f.Close()
	blockIoctl(f, blkflsbuf)
	if lbs <= 0 {
		lbs = 512
	}
	buf := alignedBuf(imageReadChunk, 4096)
	h := sha256.New()
	for off := int64(0); off < n; {
		need := n - off
		if need > imageReadChunk {
			need = imageReadChunk
		}
		want := (need + int64(lbs) - 1) / int64(lbs) * int64(lbs) // whole blocks for O_DIRECT
		got, err := f.ReadAt(buf[:want], off)
		if int64(got) < need {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return "", fmt.Errorf("read at %d: %w", off, err)
		}
		h.Write(buf[:need])
		off += need
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// confField is stormbootx's manifest::conf_field: the first non-empty
// `key = value` of a stormboot.conf/local.conf text, quotes trimmed.
func confField(text, key string) string {
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == key {
			if v = strings.Trim(strings.TrimSpace(v), `"`); v != "" {
				return v
			}
		}
	}
	return ""
}

// stickFiles is what keep_local_conf reads off an ESP: nil for a file that
// is not there.
type stickFiles struct {
	Local, Conf []byte
}

// mergeLocalConf is the local.conf the new stick gets: the old stick's (the
// new image's when the old had none), plus each name =/tag = the old
// stormboot.conf had that neither the new stormboot.conf nor local.conf
// states (stormbootx-stick's carry_identity). write is false when there is
// nothing to write.
func mergeLocalConf(old, cur stickFiles) (text string, kept []string, write bool) {
	text = string(cur.Local)
	if old.Local != nil {
		text = string(old.Local)
		write = true
		kept = append(kept, fmt.Sprintf("local.conf (%d bytes)", len(old.Local)))
	}
	for _, key := range []string{"name", "tag"} {
		v := confField(string(old.Conf), key)
		if v == "" || confField(string(cur.Conf), key) != "" || confField(text, key) != "" {
			continue
		}
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += key + " = " + v + "\n"
		kept = append(kept, key+" = "+v)
		write = true
	}
	return text, kept, write
}

// withVfat mounts dev (FAT) at a new directory, runs fn, and unmounts.
func withVfat(dev string, readonly bool, fn func(mnt string) error) error {
	for _, m := range []string{"vfat", "nls_cp437", "nls_iso8859_1", "nls_utf8"} {
		runCommand("modprobe", "-q", m)
	}
	mnt, err := os.MkdirTemp("", "bms-esp-*")
	if err != nil {
		return err
	}
	defer os.Remove(mnt)
	flags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	if readonly {
		flags |= syscall.MS_RDONLY
	}
	if err := syscall.Mount(dev, mnt, "vfat", flags, ""); err != nil {
		return fmt.Errorf("mount %s: %w", dev, err)
	}
	ferr := fn(mnt)
	if err := syscall.Unmount(mnt, 0); err != nil && ferr == nil {
		ferr = fmt.Errorf("umount %s: %w", dev, err)
	}
	return ferr
}

// readStick finds the partition of disk whose FAT holds stormboot/ and reads
// its local.conf and stormboot.conf. part is "" when no partition has one.
func readStick(disk string) (part string, files stickFiles, err error) {
	parts, err := diskPartitions(disk)
	if err != nil {
		return "", files, err
	}
	for _, p := range parts {
		found := false
		merr := withVfat("/dev/"+p.Name, true, func(mnt string) error {
			if st, err := os.Stat(filepath.Join(mnt, stickDir)); err != nil || !st.IsDir() {
				return nil
			}
			found = true
			if b, err := os.ReadFile(filepath.Join(mnt, stickLocalConf)); err == nil {
				files.Local = b
			}
			if b, err := os.ReadFile(filepath.Join(mnt, stickConf)); err == nil {
				files.Conf = b
			}
			return nil
		})
		if merr == nil && found {
			return p.Name, files, nil
		}
	}
	return "", files, nil
}

// waitPartitions waits up to 10s for disk to show partitions with /dev nodes.
func waitPartitions(disk string) []partRange {
	for i := 0; i < 20; i++ {
		parts, _ := diskPartitions(disk)
		ok := len(parts) > 0
		for _, p := range parts {
			if _, err := os.Stat("/dev/" + p.Name); err != nil {
				ok = false
			}
		}
		if ok {
			return parts
		}
		time.Sleep(500 * time.Millisecond)
	}
	parts, _ := diskPartitions(disk)
	return parts
}

// carryLocalConf writes the merged local.conf onto the new stick's ESP.
func carryLocalConf(disk string, old stickFiles) (string, []string, error) {
	waitPartitions(disk)
	part, cur, err := readStick(disk)
	if err != nil {
		return "", nil, err
	}
	if part == "" {
		return "", nil, fmt.Errorf("the new image has no FAT partition with %s/", stickDir)
	}
	text, kept, write := mergeLocalConf(old, cur)
	if !write {
		return part, nil, nil
	}
	err = withVfat("/dev/"+part, false, func(mnt string) error {
		f, err := os.OpenFile(filepath.Join(mnt, stickLocalConf), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(text); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(mnt, stickLocalConf))
		if err == nil && !bytes.Equal(b, []byte(text)) {
			err = fmt.Errorf("%s reads back different", stickLocalConf)
		}
		return err
	})
	return part, kept, err
}

// writeDiskImage does the whole write; the int is the HTTP status.
func writeDiskImage(disk, url, want string, keepLocal bool) (imageWriteResult, int) {
	dev := "/dev/" + disk
	res := imageWriteResult{Device: dev, URL: url, Steps: []wipeStep{}}
	step := func(name, out string, err error) bool {
		s := wipeStep{Step: name, OK: err == nil, Output: strings.TrimSpace(out)}
		if err != nil {
			if s.Output != "" {
				s.Output += ": "
			}
			s.Output += err.Error()
			res.Error = name + " failed: " + s.Output
		}
		res.Steps = append(res.Steps, s)
		log.Printf("disks/image %s: %s: ok=%v %s", dev, name, s.OK, s.Output)
		return err == nil
	}

	sectors, err := readSysInt(filepath.Join(sysBlockDir, disk, "size"))
	if err != nil {
		res.Error = dev + " is not a whole disk"
		return res, http.StatusNotFound
	}
	size := sectors * 512
	lbs, err := readSysInt(filepath.Join(sysBlockDir, disk, "queue", "logical_block_size"))
	if err != nil || lbs <= 0 {
		lbs = 512
	}
	if why := imageRefusal(disk); why != "" {
		step("refusals", "", errors.New(why))
		return res, http.StatusConflict
	}
	step("refusals", "not mounted, not held, no stormblock slab", nil)

	var old stickFiles
	if keepLocal {
		part, files, err := readStick(disk)
		out := "no partition with " + stickDir + "/ on the old disk: nothing to carry"
		if part != "" {
			old = files
			out = fmt.Sprintf("/dev/%s: local.conf %s, stormboot.conf %s", part, present(files.Local), present(files.Conf))
		}
		if !step("read old "+stickDir+"/", out, err) {
			return res, http.StatusInternalServerError
		}
	}

	limit := size
	if avail := memAvailable() - imageRAMReserve; avail > 0 && avail < limit {
		limit = avail
	}
	path, n, err := fetchImage(url, want, "", limit)
	if !step("download", fmt.Sprintf("%d bytes, sha256 %s", n, want), err) {
		if errors.Is(err, errImage) {
			return res, http.StatusUnprocessableEntity
		}
		return res, http.StatusBadGateway
	}
	defer os.Remove(path)

	gbs, err := gptBlockSize(path)
	switch {
	case err != nil:
	case gbs == 0:
		res.GPT = "none"
	case int64(gbs) != lbs:
		err = fmt.Errorf("%w: its GPT is at %d-byte blocks, %s's at %d", errImage, gbs, dev, lbs)
	default:
		res.GPT = fmt.Sprintf("%d-byte blocks", gbs)
	}
	if !step("gpt", res.GPT, err) {
		return res, http.StatusUnprocessableEntity
	}
	if why := imageRefusal(disk); why != "" {
		step("refusals (before writing)", "", errors.New(why))
		return res, http.StatusConflict
	}

	if size-n >= imageTailZero {
		err := zeroDisk(dev, []byteRange{{size - imageTailZero, imageTailZero}})
		if !step("zero old tail", "last 1 MiB", err) {
			return res, http.StatusInternalServerError
		}
	}
	w, err := writeImage(path, dev)
	if !step("write", fmt.Sprintf("%d bytes, fsync", w), err) {
		return res, http.StatusInternalServerError
	}
	res.Written = w
	got, err := readBackSHA256(dev, n, int(lbs))
	if err == nil && got != want {
		err = fmt.Errorf("read back sha256 %s, want %s", got, want)
	}
	if !step("verify", fmt.Sprintf("read back %d bytes, sha256 matches", n), err) {
		return res, http.StatusInternalServerError
	}
	res.SHA256 = got
	res.Verified = true

	if gbs != 0 {
		out, err := runCommand("sgdisk", "-e", dev)
		if !step("sgdisk -e (backup GPT to the end)", out, err) {
			return res, http.StatusInternalServerError
		}
		out, err = runCommand("sgdisk", "-v", dev)
		if err == nil && !strings.Contains(out, "No problems found") {
			err = errors.New("sgdisk -v found problems")
		}
		if !step("sgdisk -v", lastLine(out), err) {
			return res, http.StatusInternalServerError
		}
	}
	f, err := os.Open(dev)
	if err == nil {
		err = blockIoctl(f, blkrrpart)
		f.Close()
	}
	if !step("re-read partition table", "", err) {
		return res, http.StatusInternalServerError
	}

	if keepLocal && (old.Local != nil || old.Conf != nil) {
		part, kept, err := carryLocalConf(disk, old)
		out := "nothing to carry"
		if len(kept) > 0 {
			out = "/dev/" + part + ": kept " + strings.Join(kept, ", ")
		}
		if !step("keep "+stickLocalConf, out, err) {
			return res, http.StatusInternalServerError
		}
		res.LocalConf = kept
	}
	return res, http.StatusOK
}

func present(b []byte) string {
	if b == nil {
		return "absent"
	}
	return fmt.Sprintf("%d bytes", len(b))
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l[len(l)-1])
}

func handleDiskImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/disks/image/"), "dev/")
	if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Invalid device name: " + name})
		return
	}
	url := r.FormValue("url")
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "url= must be an http(s) URL of a raw image"})
		return
	}
	want := strings.ToLower(r.FormValue("sha256"))
	if b, err := hex.DecodeString(want); err != nil || len(b) != sha256.Size {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "sha256= (64 hex digits) is required"})
		return
	}
	keep, _ := strconv.ParseBool(r.FormValue("keep_local_conf"))
	if _, err := os.Stat(filepath.Join(sysBlockDir, name, "size")); err != nil {
		sendJSON(w, http.StatusNotFound, APIResponse{Status: "error", Error: "/dev/" + name + " is not a whole disk"})
		return
	}
	if !imageMu.TryLock() {
		sendJSON(w, http.StatusConflict, APIResponse{Status: "error", Error: "another image write is running"})
		return
	}
	defer imageMu.Unlock()

	res, status := writeDiskImage(name, url, want, keep)
	if status != http.StatusOK {
		sendJSON(w, status, APIResponse{Status: "error", Error: res.Error, Data: res})
		return
	}
	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: fmt.Sprintf("Wrote and verified %d bytes on %s", res.Written, res.Device),
		Data:    res,
	})
}
