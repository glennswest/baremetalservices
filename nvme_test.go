package main

import "testing"

// nvme-cli 2.x `nvme smart-log /dev/nvme0n1` (as QEMU's emulated NVMe answers).
const smartLogOK = `Smart Log for NVME device:nvme0n1 namespace-id:ffffffff
critical_warning			: 0
temperature				: 50 °C (323 Kelvin)
available_spare				: 0%
available_spare_threshold		: 0%
percentage_used				: 0%
endurance group critical warning summary: 0
Data Units Read				: 0 (0.00 B)
power_on_hours				: 1
media_errors				: 0
`

func TestParseNVMeSmartLog(t *testing.T) {
	cases := []struct {
		name, out, health string
	}{
		{"no warning", smartLogOK, "PASSED"},
		{"reliability degraded", "critical_warning : 0x4\npower_on_hours : 9\n", "FAILED"},
		{"spare low (decimal)", "critical_warning\t\t\t: 1\n", "FAILED"},
		{"read-only", "critical_warning : 0x8\n", "FAILED"},
		{"unreadable value", "critical_warning : ??\n", ""},
		{"no critical_warning", "temperature : 40 °C\npower_on_hours : 3\n", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		_, _, h := parseNVMeSmartLog(c.out)
		if h != c.health {
			t.Errorf("%s: health %q, want %q", c.name, h, c.health)
		}
	}
	temp, poh, _ := parseNVMeSmartLog(smartLogOK)
	if temp != "50 °C (323 Kelvin)" || poh != "1" {
		t.Errorf("temperature %q, power_on_hours %q", temp, poh)
	}
}
