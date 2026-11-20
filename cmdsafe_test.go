package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The finding (#38, d20f640fc5ce): HTTP parameters were formatted into
// `sh -c` strings. runShell may only ever run a fixed string: any call
// that passes it something other than a string literal fails here.
func TestRunShellOnlyTakesLiterals(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "runShell" {
				return true
			}
			calls++
			if len(call.Args) != 1 {
				t.Errorf("%s: runShell with %d args", fset.Position(call.Pos()), len(call.Args))
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
				t.Errorf("%s: runShell takes a non-literal command; run it with runCommand/runStdout (an argv, no shell)", fset.Position(call.Pos()))
			}
			return true
		})
	}
	if calls == 0 {
		t.Fatal("found no runShell calls at all: the scan is not looking at the sources")
	}
}

// An argument full of shell syntax reaches the program as one literal
// argument: nothing runs it.
func TestRunCommandNoShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	payload := "x'; touch " + marker + "; echo '$(touch " + marker + ")`touch " + marker + "`"
	out, err := runCommand("echo", payload)
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	if strings.TrimSpace(out) != payload {
		t.Errorf("echo printed %q, want the payload verbatim", out)
	}
	out, _ = runStdout("echo", payload)
	if strings.TrimSpace(out) != payload {
		t.Errorf("runStdout echo printed %q, want the payload verbatim", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the payload ran as a shell command")
	}
}

func TestCheckBlockDevice(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"sda", "sda1", "nvme0n1p2", "dm-0"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := sysClassBlockDir
	sysClassBlockDir = dir
	defer func() { sysClassBlockDir = old }()

	for _, n := range []string{"sda", "sda1", "nvme0n1p2", "dm-0"} {
		if st, msg := checkBlockDevice(n); st != http.StatusOK {
			t.Errorf("%q: %d %s", n, st, msg)
		}
	}
	if st, _ := checkBlockDevice("sdz"); st != http.StatusNotFound {
		t.Errorf("sdz (absent): %d, want 404", st)
	}
	for _, n := range []string{"", "sda;reboot", "sda $(id)", "`id`", "../sda", "sda/..", ".", "..",
		"-sda", "sda|id", "sda&", "sda'", "sda\"", "sda\n", "sda>x", strings.Repeat("a", 65)} {
		if st, _ := checkBlockDevice(n); st != http.StatusBadRequest {
			t.Errorf("%q: %d, want 400", n, st)
		}
	}
}

func TestCheckPCIAddr(t *testing.T) {
	for _, a := range []string{"05:00.0", "0000:05:00.0", "af:1f.7"} {
		if err := checkPCIAddr(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
	for _, a := range []string{"", "05:00.0;reboot", "05:00.0 q", "$(id)", "05:00.8", "/dev/mst/x", "-y"} {
		if checkPCIAddr(a) == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestCheckFirmwareURL(t *testing.T) {
	for _, u := range []string{"http://h/fw.bin", "https://h:8443/a/b.bin?x=1"} {
		if err := checkFirmwareURL(u); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"", "file:///etc/shadow", "-O/etc/passwd", "http://h/a b", "http://h/a\nb",
		"http:///nohost", "ftp://h/x", "h/x"} {
		if checkFirmwareURL(u) == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestIPAddrs(t *testing.T) {
	out := `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.10.5/24 brd 192.168.10.255 scope global eth0
    inet 10.0.0.2/8 scope global eth0
    inet6 fe80::1/64 scope link
    inet6 2001:db8::5/64 scope global
`
	if got := ipAddrs(out, "inet", false); got != "192.168.10.5/24\n10.0.0.2/8" {
		t.Errorf("inet: %q", got)
	}
	if got := ipAddrs(out, "inet6", true); got != "2001:db8::5/64" {
		t.Errorf("inet6: %q", got)
	}
}

func TestFirstLineContaining(t *testing.T) {
	out := "Image type: FS2\nFW Version: 2.42.5000\nPSID: MT_1090120019\n"
	if got := firstLineContaining(out, "FW Version", false); got != "FW Version: 2.42.5000" {
		t.Errorf("got %q", got)
	}
	attrs := "194 Temperature_Celsius 0x0022 036 040 000 Old_age Always - 36\n"
	if got := firstLineContaining(attrs, "temperature", true); !strings.Contains(got, "Temperature_Celsius") {
		t.Errorf("fold: %q", got)
	}
	if firstLineContaining(out, "nope", false) != "" {
		t.Error("absent match should be empty")
	}
}

// Each disk route and /firmware/update refuses a payload with 400 before
// anything is run (the fake /sys/class/block holds only sda, so nothing
// valid would reach a real disk either).
func TestHandlersRefuseInjection(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sda"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := sysClassBlockDir
	sysClassBlockDir = dir
	defer func() { sysClassBlockDir = old }()

	bad := []string{"sda;reboot", "sda%20$(id)", "%60id%60", "sda%7Cid", "sda'"}
	cases := []struct {
		route string
		h     http.HandlerFunc
	}{
		{"/disks/detail/", handleDiskDetail},
		{"/disks/partition/", handleDiskPartition},
		{"/disks/format/", handleDiskFormat},
		{"/disks/secure-erase/", handleDiskSecureErase},
	}
	for _, c := range cases {
		for _, b := range bad {
			method := http.MethodPost
			if c.route == "/disks/detail/" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, c.route+b, nil)
			rec := httptest.NewRecorder()
			c.h(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s%s: %d %s, want 400", c.route, b, rec.Code, rec.Body.String())
			}
		}
		// A good name for a disk that does not exist: 404, nothing run.
		method := http.MethodPost
		if c.route == "/disks/detail/" {
			method = http.MethodGet
		}
		rec := httptest.NewRecorder()
		c.h(rec, httptest.NewRequest(method, c.route+"sdz", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%ssdz: %d, want 404", c.route, rec.Code)
		}
	}

	post := func(h http.HandlerFunc, target string, form url.Values) int {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}
	if c := post(handleDiskPartition, "/disks/partition/sda", url.Values{"label": {"gpt; reboot"}}); c != http.StatusBadRequest {
		t.Errorf("partition label payload: %d, want 400", c)
	}
	if c := post(handleDiskFormat, "/disks/format/sda", url.Values{"fstype": {"ext4;reboot"}}); c != http.StatusBadRequest {
		t.Errorf("format fstype payload: %d, want 400", c)
	}
	for _, f := range []url.Values{
		{"device": {"05:00.0; reboot"}},
		{"device": {"$(reboot)"}},
		{"device": {"05:00.0"}, "url": {"http://h/x'; reboot; '"}},
		{"device": {"05:00.0"}, "url": {"file:///etc/shadow"}},
	} {
		if c := post(handleFirmwareUpdate, "/firmware/update", f); c != http.StatusBadRequest {
			t.Errorf("firmware update %v: %d, want 400", f, c)
		}
	}
}
