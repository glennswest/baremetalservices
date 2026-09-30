package main

// Fleet-wide BIOS configuration and EFI boot order (issue #2).
//
//   GET  /bios/config  the whole `sum -c GetCurrentBiosCfg` file, as-is
//   POST /bios/config  body is such a file; applied with `sum -c ChangeBiosCfg`
//   GET  /boot/order   efibootmgr state as JSON
//   POST /boot/order   {"order": [...], "next": "..."} via efibootmgr -o / -n
//
// GET one blade's /bios/config and POST it to the rest to copy a BIOS setup
// across the fleet without ssh.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// maxBIOSConfigBytes bounds a POSTed BIOS config (an X9 dump is ~100 KB).
const maxBIOSConfigBytes = 8 << 20

type BootEntry struct {
	Num    string `json:"num"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Path   string `json:"path,omitempty"`
}

type BootOrder struct {
	BootCurrent string      `json:"boot_current,omitempty"`
	BootNext    string      `json:"boot_next,omitempty"`
	Timeout     string      `json:"timeout,omitempty"`
	Order       []string    `json:"order"`
	Entries     []BootEntry `json:"entries"`
}

type BootOrderRequest struct {
	Order []string `json:"order,omitempty"`
	Next  string   `json:"next,omitempty"`
}

var bootNumRe = regexp.MustCompile(`^[0-9A-Fa-f]{4}$`)
var bootEntryRe = regexp.MustCompile(`^Boot([0-9A-Fa-f]{4})(\*?)\s+(.*)$`)

// parseEfibootmgr parses `efibootmgr -v` output.
func parseEfibootmgr(out string) BootOrder {
	bo := BootOrder{Order: []string{}, Entries: []BootEntry{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "BootCurrent:"):
			bo.BootCurrent = strings.TrimSpace(strings.TrimPrefix(line, "BootCurrent:"))
		case strings.HasPrefix(line, "BootNext:"):
			bo.BootNext = strings.TrimSpace(strings.TrimPrefix(line, "BootNext:"))
		case strings.HasPrefix(line, "Timeout:"):
			bo.Timeout = strings.TrimSpace(strings.TrimPrefix(line, "Timeout:"))
		case strings.HasPrefix(line, "BootOrder:"):
			for _, n := range strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "BootOrder:")), ",") {
				if n = strings.TrimSpace(n); n != "" {
					bo.Order = append(bo.Order, n)
				}
			}
		default:
			m := bootEntryRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			e := BootEntry{Num: m[1], Active: m[2] == "*"}
			// -v appends the device path after a tab (efibootmgr >= 18) or
			// after the first run of whitespace following the description.
			rest := m[3]
			if i := strings.Index(rest, "\t"); i >= 0 {
				e.Name, e.Path = strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+1:])
			} else {
				e.Name = strings.TrimSpace(rest)
			}
			bo.Entries = append(bo.Entries, e)
		}
	}
	return bo
}

// validateBootOrder checks a request against the entries that exist.
func validateBootOrder(req BootOrderRequest, cur BootOrder) error {
	if len(req.Order) == 0 && req.Next == "" {
		return fmt.Errorf("nothing to do: give \"order\" and/or \"next\"")
	}
	known := map[string]bool{}
	for _, e := range cur.Entries {
		known[strings.ToUpper(e.Num)] = true
	}
	seen := map[string]bool{}
	for _, n := range req.Order {
		if !bootNumRe.MatchString(n) {
			return fmt.Errorf("bad boot number %q (want 4 hex digits, e.g. 0003)", n)
		}
		u := strings.ToUpper(n)
		if seen[u] {
			return fmt.Errorf("boot number %s given twice", n)
		}
		seen[u] = true
		if !known[u] {
			return fmt.Errorf("no boot entry Boot%s", n)
		}
	}
	if req.Next != "" {
		if !bootNumRe.MatchString(req.Next) {
			return fmt.Errorf("bad boot number %q for next", req.Next)
		}
		if !known[strings.ToUpper(req.Next)] {
			return fmt.Errorf("no boot entry Boot%s", req.Next)
		}
	}
	return nil
}

func readBootOrder() (BootOrder, error) {
	runShell("mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null")
	out, err := exec.Command("efibootmgr", "-v").CombinedOutput()
	if err != nil {
		return BootOrder{}, fmt.Errorf("efibootmgr: %v: %s (is the system booted in UEFI mode?)", err, strings.TrimSpace(string(out)))
	}
	return parseEfibootmgr(string(out)), nil
}

func handleBootOrder(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		bo, err := readBootOrder()
		if err != nil {
			sendJSON(w, http.StatusServiceUnavailable, APIResponse{Status: "error", Error: err.Error()})
			return
		}
		sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: bo})
	case http.MethodPost:
		var req BootOrderRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Invalid JSON: " + err.Error()})
			return
		}
		cur, err := readBootOrder()
		if err != nil {
			sendJSON(w, http.StatusServiceUnavailable, APIResponse{Status: "error", Error: err.Error()})
			return
		}
		if err := validateBootOrder(req, cur); err != nil {
			sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: err.Error()})
			return
		}
		if len(req.Order) > 0 {
			if out, err := exec.Command("efibootmgr", "-o", strings.Join(req.Order, ",")).CombinedOutput(); err != nil {
				sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: fmt.Sprintf("efibootmgr -o: %v: %s", err, strings.TrimSpace(string(out)))})
				return
			}
		}
		if req.Next != "" {
			if out, err := exec.Command("efibootmgr", "-n", req.Next).CombinedOutput(); err != nil {
				sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: fmt.Sprintf("efibootmgr -n: %v: %s", err, strings.TrimSpace(string(out)))})
				return
			}
		}
		bo, err := readBootOrder()
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: err.Error()})
			return
		}
		sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Message: "boot order updated", Data: bo})
	default:
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
	}
}

// biosConfigContentType is XML for newer SUM dumps, plain text for X9's.
func biosConfigContentType(b []byte) string {
	if strings.HasPrefix(strings.TrimSpace(string(b)), "<?xml") {
		return "application/xml"
	}
	return "text/plain; charset=utf-8"
}

func handleBIOSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}
	if _, err := exec.LookPath("sum"); err != nil {
		sendJSON(w, http.StatusServiceUnavailable, APIResponse{Status: "error", Error: "sum (Supermicro Update Manager) not available"})
		return
	}
	dir, err := os.MkdirTemp("", "bioscfg")
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: err.Error()})
		return
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "bios.cfg")

	if r.Method == http.MethodGet {
		out, err := exec.Command("sum", "-c", "GetCurrentBiosCfg", "--file", file, "--overwrite").CombinedOutput()
		b, rerr := os.ReadFile(file)
		if err != nil || rerr != nil || len(b) == 0 {
			sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: fmt.Sprintf("sum GetCurrentBiosCfg failed: %v", err), Data: strings.TrimSpace(string(out))})
			return
		}
		w.Header().Set("Content-Type", biosConfigContentType(b))
		w.Header().Set("Content-Disposition", `attachment; filename="bios.cfg"`)
		w.Write(b)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBIOSConfigBytes+1))
	if err != nil {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: err.Error()})
		return
	}
	if len(body) == 0 || len(body) > maxBIOSConfigBytes {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "body must be a sum GetCurrentBiosCfg file (non-empty, at most 8 MiB)"})
		return
	}
	if err := os.WriteFile(file, body, 0600); err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: err.Error()})
		return
	}
	out, err := exec.Command("sum", "-c", "ChangeBiosCfg", "--file", file).CombinedOutput()
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: fmt.Sprintf("sum ChangeBiosCfg failed: %v", err), Data: strings.TrimSpace(string(out))})
		return
	}
	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "BIOS configuration applied; takes effect on next reboot",
		Data:    map[string]interface{}{"reboot_required": true, "output": strings.TrimSpace(string(out))},
	})
}
