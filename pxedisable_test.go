package main

import (
	"strings"
	"testing"
)

// An X9 blade: onboard Intel (igb) eth0/eth1, a Mellanox CX3 eth2.
var pxeNICs = []NetworkInterface{
	{Name: "lo", MAC: "00:00:00:00:00:00"},
	{Name: "eth0", MAC: "00:25:90:aa:bb:01", Driver: "igb"},
	{Name: "eth1", MAC: "00:25:90:aa:bb:02", Driver: "igb"},
	{Name: "eth2", MAC: "f4:52:14:11:22:33", Driver: "mlx4_core"},
}

const pxeEFI = `BootCurrent: 0001
BootOrder: 0001,0002,0003,0004,0005
Boot0001* UEFI: PXE IP4 Intel(R) I350 Gigabit Network Connection	PciRoot(0x0)/Pci(0x1,0x0)/Pci(0x0,0x0)/MAC(002590aabb01,1)/IPv4(0.0.0.0,0,DHCP)
Boot0002* UEFI: PXE IP4 Intel(R) I350 Gigabit Network Connection	PciRoot(0x0)/Pci(0x1,0x0)/Pci(0x0,0x1)/MAC(002590aabb02,1)/IPv4(0.0.0.0,0,DHCP)
Boot0003* UEFI: PXE IP4 Mellanox ConnectX-3	PciRoot(0x0)/Pci(0x2,0x0)/Pci(0x0,0x0)/MAC(f45214112233,1)/IPv4(0.0.0.0,0,DHCP)
Boot0004* UEFI: Built-in EFI Shell	VenMedia(5023b95c-db26-429b-a648-bd47664c8012)
Boot0005* UEFI: PXE IP4 Something Else	PciRoot(0x0)/Pci(0x3,0x0)/MAC(001122334455,1)
`

func nums(es []pxeBootEntry) string {
	var n []string
	for _, e := range es {
		n = append(n, e.Num+"="+e.NIC)
	}
	return strings.Join(n, ",")
}

func TestPlanPXEDisable(t *testing.T) {
	cases := []struct {
		name    string
		filters []string
		del     string
		skipped string
	}{
		// the finding: "PXE" matches no NIC driver, and must not match
		// every entry's description and delete them all
		{"description text", []string{"PXE"}, "", "no NIC driver or vendor matches"},
		{"vendor", []string{"mellanox"}, "0003=eth2", ""},
		{"driver", []string{"mlx4"}, "0003=eth2", ""},
		{"intel keeps mellanox", []string{"intel"}, "0001=eth0,0002=eth1", ""},
		{"every NIC", []string{"intel", "mellanox"}, "", "all NICs are"},
	}
	for _, c := range cases {
		del, skipped := planPXEDisable(pxeEFI, pxeNICs, c.filters)
		if nums(del) != c.del {
			t.Errorf("%s: deletes %q, want %q", c.name, nums(del), c.del)
		}
		if c.skipped != "" && !strings.Contains(strings.Join(skipped, ";"), c.skipped) {
			t.Errorf("%s: skipped %q, want %q", c.name, skipped, c.skipped)
		}
		if c.skipped == "" && len(skipped) != 0 {
			t.Errorf("%s: unexpected skip %q", c.name, skipped)
		}
	}
}

// The Mellanox card is the only NIC with a PXE entry: removing it would leave
// no network boot path, so nothing is removed.
func TestPlanPXEDisableLastEntry(t *testing.T) {
	efi := `Boot0003* UEFI: PXE IP4 Mellanox ConnectX-3	PciRoot(0x0)/Pci(0x2,0x0)/MAC(f45214112233,1)
Boot0005* UEFI: PXE IP4 Unknown	PciRoot(0x0)/Pci(0x3,0x0)/MAC(001122334455,1)
`
	del, skipped := planPXEDisable(efi, pxeNICs, []string{"mellanox"})
	if len(del) != 0 || !strings.Contains(strings.Join(skipped, ";"), "refused") {
		t.Errorf("deletes %q, skipped %q: want a refusal", nums(del), skipped)
	}
}

func TestPlanPXEDisableNoMACEntry(t *testing.T) {
	efi := "Boot0003* UEFI: PXE IP4 Mellanox ConnectX-3\tPciRoot(0x0)/Pci(0x2,0x0)\n"
	del, skipped := planPXEDisable(efi, pxeNICs, []string{"mellanox"})
	if len(del) != 0 || !strings.Contains(strings.Join(skipped, ";"), "no EFI network boot entry") {
		t.Errorf("deletes %q, skipped %q", nums(del), skipped)
	}
}

func TestPXEEntryMACForms(t *testing.T) {
	for _, l := range []string{
		"boot0001* x mac(002590aabb01,1)",
		"boot0001* pxe 00:25:90:aa:bb:01",
		"boot0001* pxe 00-25-90-aa-bb-01",
	} {
		if n := pxeEntryMAC(l, pxeNICs); n != "eth0" {
			t.Errorf("%q: NIC %q, want eth0", l, n)
		}
	}
	if n := pxeEntryMAC("boot0001* pxe ipv4", pxeNICs); n != "" {
		t.Errorf("no MAC: NIC %q", n)
	}
}
