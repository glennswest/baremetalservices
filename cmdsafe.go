// Commands without a shell (#38, review finding d20f640fc5ce).
//
// Every command that carries a value from a request, a sysfs listing or a
// tool's output runs as an argv through exec (runCommand, runStdout): no
// shell ever parses it, so `;`, `$(...)`, quotes or spaces in a value are
// just bytes of one argument. runShell is kept for fixed pipelines only, and
// TestRunShellOnlyTakesLiterals fails the build if any call passes it
// anything but a string literal.
//
// Request values are also checked before anything runs: a block device name
// must be a plain kernel name that exists under /sys/class/block, a
// firmware device a PCI address, a firmware URL an http(s) URL.
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// sysClassBlockDir lists every block device and partition; tests point it at
// a fake.
var sysClassBlockDir = "/sys/class/block"

// runStdout runs name with args (no shell) and returns its stdout only: the
// replacement for a shell command ending in `2>/dev/null`. On a non-zero
// exit, what it wrote to stdout is still returned with the error.
func runStdout(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// readFile returns a (sysfs) file's contents, as `cat` did.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

// linkBase is `basename $(readlink path)`.
func linkBase(path string) (string, error) {
	t, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	return filepath.Base(t), nil
}

// firstLineContaining returns the first line of out containing sub (matched
// case-insensitively when fold is set), or "".
func firstLineContaining(out, sub string, fold bool) string {
	if fold {
		sub = strings.ToLower(sub)
	}
	for _, line := range strings.Split(out, "\n") {
		l := line
		if fold {
			l = strings.ToLower(l)
		}
		if strings.Contains(l, sub) {
			return line
		}
	}
	return ""
}

// ipAddrs picks the addresses out of `ip -4|-6 addr show` output: the second
// field of each line whose first field is kw ("inet" or "inet6"), skipping
// link-local (fe80) ones when noLinkLocal is set. One address per line.
func ipAddrs(out, kw string, noLinkLocal bool) string {
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != kw {
			continue
		}
		if noLinkLocal && strings.HasPrefix(strings.ToLower(f[1]), "fe80") {
			continue
		}
		addrs = append(addrs, f[1])
	}
	return strings.Join(addrs, "\n")
}

var (
	blockNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	pciAddrRe   = regexp.MustCompile(`^([0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$`)
)

// checkBlockDevice validates a disk or partition name from a request (sda,
// sda1, nvme0n1p2): a plain kernel name, no path, no shell or option syntax,
// and present under /sys/class/block. It returns the HTTP status to answer
// with (200 when the name is good) and the error text.
func checkBlockDevice(name string) (int, string) {
	if !blockNameRe.MatchString(name) {
		return http.StatusBadRequest, fmt.Sprintf("Invalid device name: %q", name)
	}
	if _, err := os.Stat(filepath.Join(sysClassBlockDir, name)); err != nil {
		return http.StatusNotFound, "/dev/" + name + " is not a block device"
	}
	return http.StatusOK, ""
}

// checkPCIAddr validates the device= of /firmware/update: a PCI address
// (05:00.0 or 0000:05:00.0).
func checkPCIAddr(dev string) error {
	if !pciAddrRe.MatchString(dev) {
		return fmt.Errorf("invalid 'device' %q: must be a PCI address like 05:00.0", dev)
	}
	return nil
}

// checkFirmwareURL validates the url= of /firmware/update: an absolute
// http(s) URL with a host and no whitespace or control characters.
func checkFirmwareURL(raw string) error {
	for _, c := range raw {
		if c <= ' ' || c == 0x7f {
			return fmt.Errorf("invalid 'url': contains whitespace or control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid 'url' %q: must be an http(s) URL", raw)
	}
	return nil
}
