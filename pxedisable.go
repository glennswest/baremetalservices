package main

import (
	"fmt"
	"sort"
	"strings"
)

// PXE disable planning for POST /bios/configure disable_pxe_nics (finding
// 8fe507b0417b). A filter names NIC drivers or vendors ("mellanox",
// "mlx4_core"); it is resolved to the physical NICs it matches, and an EFI
// network boot entry is removed only when it carries the MAC of one of those
// NICs. A filter never matches entry description text, so "PXE" cannot
// remove every network entry. Nothing is removed when no network entry of a
// kept NIC would remain: the blade must keep a network boot path.

type pxeBootEntry struct {
	Num  string // "0003"
	Desc string // as efibootmgr prints it
	NIC  string // interface the entry's MAC belongs to, "" if none
}

// pxeEntryMAC finds which physical NIC's MAC an efibootmgr -v line carries,
// in any of the forms it appears in: MAC(002590abcdef,1), 00:25:90:ab:cd:ef
// or 00-25-90-ab-cd-ef.
func pxeEntryMAC(lineLower string, nics []NetworkInterface) string {
	for _, nic := range nics {
		mac := strings.ToLower(nic.MAC)
		hex := strings.ReplaceAll(mac, ":", "")
		if len(hex) != 12 {
			continue
		}
		if strings.Contains(lineLower, "mac("+hex) || strings.Contains(lineLower, mac) ||
			strings.Contains(lineLower, strings.ReplaceAll(mac, ":", "-")) {
			return nic.Name
		}
	}
	return ""
}

// parsePXEEntries lists the network boot entries of `efibootmgr -v` output.
func parsePXEEntries(efiOut string, nics []NetworkInterface) []pxeBootEntry {
	var out []pxeBootEntry
	for _, line := range strings.Split(efiOut, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Boot") || len(line) < 8 {
			continue
		}
		num := line[4:8]
		if !bootNumRe.MatchString(num) {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "pxe") && !strings.Contains(lower, "network") {
			continue
		}
		desc := strings.TrimLeft(strings.TrimSpace(line[8:]), "* ")
		out = append(out, pxeBootEntry{Num: num, Desc: desc, NIC: pxeEntryMAC(lower, nics)})
	}
	return out
}

// planPXEDisable says which EFI entries to delete for filters, or why none
// (skipped). interfaces is what getNetworkInterfaces reports.
func planPXEDisable(efiOut string, interfaces []NetworkInterface, filters []string) (del []pxeBootEntry, skipped []string) {
	var physical []NetworkInterface
	targeted := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Driver == "" || iface.Name == "lo" || iface.MAC == "" {
			continue
		}
		physical = append(physical, iface)
		if nicMatchesFilter(iface.Driver, filters) {
			targeted[iface.Name] = true
		}
	}
	if len(targeted) == 0 {
		return nil, []string{fmt.Sprintf("PXE disable: no NIC driver or vendor matches %s", strings.Join(filters, ","))}
	}
	if len(targeted) == len(physical) {
		vendors := map[string]bool{}
		for _, nic := range physical {
			vendors[driverToVendor(strings.ToLower(nic.Driver))] = true
		}
		var vl []string
		for v := range vendors {
			vl = append(vl, v)
		}
		sort.Strings(vl)
		return nil, []string{fmt.Sprintf("PXE disable: all NICs are %s, skipping to preserve PXE capability", strings.Join(vl, "/"))}
	}

	kept := 0
	for _, e := range parsePXEEntries(efiOut, physical) {
		switch {
		case e.NIC == "":
			// not tied to a known NIC: never deleted, not counted as a path
		case targeted[e.NIC]:
			del = append(del, e)
		default:
			kept++
		}
	}
	if len(del) == 0 {
		var names []string
		for n := range targeted {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, []string{fmt.Sprintf("PXE disable: no EFI network boot entry carries the MAC of %s", strings.Join(names, ","))}
	}
	if kept == 0 {
		return nil, []string{fmt.Sprintf("PXE disable: refused, removing %d network boot entries would leave no network boot entry of a kept NIC", len(del))}
	}
	return del, nil
}
