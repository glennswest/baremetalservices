package main

import (
	"strings"
	"testing"
)

const efibootmgrV = `BootCurrent: 0003
BootNext: 0001
Timeout: 1 seconds
BootOrder: 0003,0001,0000
Boot0000* UEFI: Built-in EFI Shell	VenMedia(5023b95c-db26-429b-a648-bd47664c8012)..BO
Boot0001* UEFI: IP4 Intel(R) 82599 10 Gigabit Dual Port Network Connection	PciRoot(0x0)/Pci(0x2,0x0)/Pci(0x0,0x0)/MAC(0025905f1234,0)/IPv4(0.0.0.00.0.0.0,0,0)..BO
Boot0003  UEFI: stormbootx	PciRoot(0x0)/Pci(0x1f,0x2)/Sata(0,0,0)/CDROM(1,0x1c8,0x2000)..BO
`

func TestParseEfibootmgr(t *testing.T) {
	bo := parseEfibootmgr(efibootmgrV)
	if bo.BootCurrent != "0003" || bo.BootNext != "0001" || bo.Timeout != "1 seconds" {
		t.Fatalf("header fields: %+v", bo)
	}
	if strings.Join(bo.Order, ",") != "0003,0001,0000" {
		t.Fatalf("order: %v", bo.Order)
	}
	if len(bo.Entries) != 3 {
		t.Fatalf("entries: %+v", bo.Entries)
	}
	e := bo.Entries[1]
	if e.Num != "0001" || !e.Active || !strings.HasPrefix(e.Name, "UEFI: IP4 Intel") || !strings.HasPrefix(e.Path, "PciRoot(") {
		t.Fatalf("entry 1: %+v", e)
	}
	if bo.Entries[2].Active || bo.Entries[2].Name != "UEFI: stormbootx" {
		t.Fatalf("entry 2 (inactive): %+v", bo.Entries[2])
	}
}

func TestParseEfibootmgrNoVerbose(t *testing.T) {
	bo := parseEfibootmgr("BootOrder: 0001\nBoot0001* Hard Drive\n")
	if len(bo.Entries) != 1 || bo.Entries[0].Name != "Hard Drive" || bo.Entries[0].Path != "" {
		t.Fatalf("%+v", bo)
	}
}

func TestValidateBootOrder(t *testing.T) {
	cur := parseEfibootmgr(efibootmgrV)
	ok := []BootOrderRequest{
		{Order: []string{"0001", "0003", "0000"}},
		{Order: []string{"0001"}},
		{Next: "0000"},
		{Order: []string{"0003"}, Next: "0001"},
	}
	for _, r := range ok {
		if err := validateBootOrder(r, cur); err != nil {
			t.Errorf("%+v: unexpected %v", r, err)
		}
	}
	bad := []BootOrderRequest{
		{},
		{Order: []string{"1"}},
		{Order: []string{"0001", "0001"}},
		{Order: []string{"0009"}},
		{Order: []string{"0001;reboot"}},
		{Next: "0009"},
		{Next: "zz"},
	}
	for _, r := range bad {
		if err := validateBootOrder(r, cur); err == nil {
			t.Errorf("%+v: accepted", r)
		}
	}
}

func TestBIOSConfigContentType(t *testing.T) {
	if biosConfigContentType([]byte("  <?xml version=\"1.0\"?><BiosCfg/>")) != "application/xml" {
		t.Fatal("xml not detected")
	}
	if !strings.HasPrefix(biosConfigContentType([]byte("[Advanced]\nQuick Boot=Enabled\n")), "text/plain") {
		t.Fatal("text not detected")
	}
}
