package main

import (
	"strconv"
	"strings"
)

// parseNVMeSmartLog reads `nvme smart-log` text output: the temperature and
// power-on hours as printed, and the health the way smartctl derives it for
// NVMe (finding be3bdc3dcdf0): "PASSED" when critical_warning is 0,
// "FAILED" when any warning bit is set (spare below threshold, temperature,
// reliability degraded, read-only, volatile backup failed), and "" (unknown)
// when critical_warning is not in the output or cannot be read.
func parseNVMeSmartLog(out string) (temperature, powerOnHours, health string) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "temperature":
			temperature = val
		case "power_on_hours":
			powerOnHours = val
		case "critical_warning":
			// "0", "0x4", or "0x4 ..." in some nvme-cli versions
			f := strings.Fields(val)
			if len(f) == 0 {
				continue
			}
			n, err := strconv.ParseUint(f[0], 0, 8)
			switch {
			case err != nil:
				health = ""
			case n == 0:
				health = "PASSED"
			default:
				health = "FAILED"
			}
		}
	}
	return temperature, powerOnHours, health
}
