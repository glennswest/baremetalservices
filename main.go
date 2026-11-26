package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultPort = "8080"

type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type SystemInfo struct {
	Hostname  string            `json:"hostname"`
	CPU       string            `json:"cpu"`
	CPUCores  string            `json:"cpu_cores"`
	Memory    map[string]string `json:"memory"`
	Network   []string          `json:"network"`
	Uptime    string            `json:"uptime"`
	Kernel    string            `json:"kernel"`
}

type NetworkInterface struct {
	Name     string `json:"name"`
	MAC      string `json:"mac"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	State    string `json:"state"`
	Speed    string `json:"speed"`
	Driver   string `json:"driver"`
	Firmware string `json:"firmware,omitempty"`
	Model    string `json:"model,omitempty"`
}

type DiskInfo struct {
	Name         string       `json:"name"`
	Size         string       `json:"size"`
	Type         string       `json:"type"`
	Model        string       `json:"model"`
	Serial       string       `json:"serial,omitempty"`
	MountPoint   string       `json:"mountpoint,omitempty"`
	Firmware     string       `json:"firmware,omitempty"`
	Transport    string       `json:"transport,omitempty"`
	RotationRate string       `json:"rotation_rate,omitempty"`
	MediaType    string       `json:"media_type,omitempty"`
	SmartHealth  string       `json:"smart_health,omitempty"`
	Temperature  string       `json:"temperature,omitempty"`
	PowerOnHours string       `json:"power_on_hours,omitempty"`
	Partitions   []PartInfo   `json:"partitions,omitempty"`
	// #47: what makes the all-disks wipe skip it (empty wipe_all_skips: it
	// would be wiped). Naming the disk wipes it regardless.
	BootDevice   bool   `json:"boot_device"`
	USB          bool   `json:"usb"`
	Removable    bool   `json:"removable"`
	Stormbootx   string `json:"stormbootx,omitempty"`
	WipeAllSkips string `json:"wipe_all_skips,omitempty"`
}

type PartInfo struct {
	Name       string `json:"name"`
	Size       string `json:"size"`
	FSType     string `json:"fstype,omitempty"`
	MountPoint string `json:"mountpoint,omitempty"`
}

type MemoryDIMM struct {
	Locator      string `json:"locator"`
	Size         string `json:"size"`
	Type         string `json:"type"`
	Speed        string `json:"speed"`
	Manufacturer string `json:"manufacturer"`
	PartNumber   string `json:"part_number"`
	SerialNumber string `json:"serial_number"`
}

type IPMIInfo struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	IPSource   string `json:"ip_source"`
	Subnet     string `json:"subnet_mask"`
	Gateway    string `json:"gateway"`
	Users      string `json:"users"`
}

type AssetInfo struct {
	System    SystemAsset    `json:"system"`
	BIOS      BIOSAsset      `json:"bios"`
	Chassis   ChassisAsset   `json:"chassis"`
	Baseboard BaseboardAsset `json:"baseboard"`
}

type SystemAsset struct {
	Manufacturer string `json:"manufacturer"`
	ProductName  string `json:"product_name"`
	SerialNumber string `json:"serial_number"`
	UUID         string `json:"uuid"`
}

type BIOSAsset struct {
	Vendor      string `json:"vendor"`
	Version     string `json:"version"`
	ReleaseDate string `json:"release_date"`
}

type ChassisAsset struct {
	Type         string `json:"type"`
	Manufacturer string `json:"manufacturer"`
	SerialNumber string `json:"serial_number"`
	AssetTag     string `json:"asset_tag"`
}

type BaseboardAsset struct {
	Manufacturer string `json:"manufacturer"`
	ProductName  string `json:"product_name"`
	SerialNumber string `json:"serial_number"`
	Version      string `json:"version"`
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runShell(command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// mstflintCache holds each Mellanox card's `mstflint q` output, by PCI
// address. HTTP handlers run concurrently (/network, the web UI), so it is
// read and written only under mstflintMu, and an entry is published only once
// it is filled (finding c2bfa5d76292).
var (
	mstflintMu    sync.Mutex
	mstflintCache = map[string]map[string]string{}
)

func getMellanoxFirmwareInfo(pciAddr string) map[string]string {
	mstflintMu.Lock()
	info, ok := mstflintCache[pciAddr]
	mstflintMu.Unlock()
	if ok {
		return info
	}

	info = make(map[string]string)
	if out, err := runStdout("mstflint", "-d", pciAddr, "q"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				info[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	mstflintMu.Lock()
	defer mstflintMu.Unlock()
	if cached, ok := mstflintCache[pciAddr]; ok {
		return cached // another request filled it first
	}
	mstflintCache[pciAddr] = info
	return info
}

func readDMI(field string) string {
	path := "/sys/class/dmi/id/" + field
	if out, err := readFile(path); err == nil {
		val := strings.TrimSpace(out)
		if val != "" && val != "To Be Filled By O.E.M." && val != "Default string" && val != "Not Specified" {
			return val
		}
	}
	return ""
}

func getAssetInfo() AssetInfo {
	return AssetInfo{
		System: SystemAsset{
			Manufacturer: readDMI("sys_vendor"),
			ProductName:  readDMI("product_name"),
			SerialNumber: readDMI("product_serial"),
			UUID:         readDMI("product_uuid"),
		},
		BIOS: BIOSAsset{
			Vendor:      readDMI("bios_vendor"),
			Version:     readDMI("bios_version"),
			ReleaseDate: readDMI("bios_date"),
		},
		Chassis: ChassisAsset{
			Type:         readDMI("chassis_type"),
			Manufacturer: readDMI("chassis_vendor"),
			SerialNumber: readDMI("chassis_serial"),
			AssetTag:     readDMI("chassis_asset_tag"),
		},
		Baseboard: BaseboardAsset{
			Manufacturer: readDMI("board_vendor"),
			ProductName:  readDMI("board_name"),
			SerialNumber: readDMI("board_serial"),
			Version:      readDMI("board_version"),
		},
	}
}

func getNICFirmware(iface string, driver string) (firmware string, model string) {
	// Get PCI device path
	pciPath, err := linkBase("/sys/class/net/" + iface + "/device")
	if err != nil {
		return "", ""
	}
	pciAddr := strings.TrimSpace(pciPath)

	if driver == "mlx4_core" || driver == "mlx4_en" || driver == "mlx5_core" {
		// Use mstflint for Mellanox firmware
		mlxInfo := getMellanoxFirmwareInfo(pciAddr)
		firmware = mlxInfo["FW Version"]
		model = mlxInfo["PSID"]
		if model == "" {
			model = mlxInfo["Description"]
		}
		// Try VPD for model info if mstflint didn't provide it
		if model == "" || model == "PSID" {
			if vpd, err := runStdout("strings", "/sys/class/net/"+iface+"/device/vpd"); err == nil {
				lines := strings.Split(vpd, "\n")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "MCX") || strings.HasPrefix(line, "CX") {
						model = line
						break
					}
					if i == 0 && strings.Contains(line, "ConnectX") {
						model = line
					}
				}
			}
		}
	} else if driver == "ixgbe" || driver == "i40e" || driver == "ice" {
		// Intel NICs - get model from device/subsystem info
		if vendor, err := readFile("/sys/class/net/" + iface + "/device/subsystem_vendor"); err == nil {
			if device, err := readFile("/sys/class/net/" + iface + "/device/subsystem_device"); err == nil {
				model = fmt.Sprintf("Intel %s (subsys %s:%s)", driver,
					strings.TrimSpace(strings.TrimPrefix(vendor, "0x")),
					strings.TrimSpace(strings.TrimPrefix(device, "0x")))
			}
		}
		// Intel firmware is in EEPROM, typically updated via motherboard BIOS
		firmware = "EEPROM (via BIOS)"
	}
	return firmware, model
}

func loadIPMIModules() {
	runShell("modprobe ipmi_devintf 2>/dev/null; modprobe ipmi_si 2>/dev/null")
	time.Sleep(2 * time.Second)
}

func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		sendJSON(w, http.StatusNotFound, APIResponse{Status: "error", Error: "Not found"})
		return
	}

	endpoints := map[string]string{
		"GET /":                       "API documentation",
		"GET /health":                 "Health check",
		"GET /system":                 "System information",
		"GET /asset":                  "Asset information (serial numbers, UUIDs)",
		"GET /network":                "Network interfaces with firmware info",
		"GET /macs":                   "MAC addresses for eth0, eth1, and IPMI",
		"GET /memory":                 "Memory DIMM info (model, serial, speed)",
		"GET /ipmi":                   "IPMI information",
		"GET /disks":                  "List all disks with details (serial, firmware, SMART, type)",
		"GET /disks/detail/{dev}":     "Detailed info for a specific disk",
		"POST /ipmi/reset":            "Reset IPMI to ADMIN/ADMIN with full access and DHCP",
		"POST /disks/partition/{dev}": "Create partition table (label=gpt|msdos, default gpt)",
		"POST /disks/format/{dev}":    "Format partition (fstype=ext4|xfs|vfat, default ext4)",
		"POST /disks/secure-erase/{dev}": "ATA Secure Erase / NVMe format (DESTRUCTIVE)",
		"POST /disks/wipe":            "Wipe and verify ALL disks (DESTRUCTIVE)",
		"POST /disks/wipe/{dev}":      "Wipe and verify one disk (DESTRUCTIVE)",
		"POST /disks/image/{dev}":     "Write a raw image to a whole disk and verify it (url=, sha256=, keep_local_conf=true) (DESTRUCTIVE)",
		"GET /firmware":               "List bundled firmware files",
		"POST /firmware/update":       "Update Mellanox NIC firmware (device=<pci_addr>, optional url=<firmware_url>)",
		"GET /bios":                   "BIOS version and update availability",
		"POST /bios/update":           "Update BIOS if needed (checks board compatibility first)",
		"POST /bios/configure":        "Configure BIOS settings (quick_boot, quiet_boot, disable_pxe_nics)",
		"GET /bios/config":            "Whole BIOS configuration file (sum GetCurrentBiosCfg)",
		"POST /bios/config":           "Apply a BIOS configuration file from GET /bios/config (sum ChangeBiosCfg; reboot to apply)",
		"GET /boot/order":             "EFI boot entries and order (efibootmgr)",
		"POST /boot/order":            "Set EFI boot order and/or next boot ({\"order\":[\"0003\",\"0001\"],\"next\":\"0003\"})",
	}

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "Bare Metal Services API",
		Data:    endpoints,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Message: "healthy"})
}

func getNetworkInterfaces() []NetworkInterface {
	var interfaces []NetworkInterface

	out, err := runShell("ls /sys/class/net/")
	if err != nil {
		return interfaces
	}

	for _, iface := range strings.Split(strings.TrimSpace(out), "\n") {
		if iface == "" || iface == "lo" {
			continue
		}

		ni := NetworkInterface{Name: iface}

		// MAC address
		if mac, err := readFile("/sys/class/net/" + iface + "/address"); err == nil {
			ni.MAC = strings.TrimSpace(mac)
		}

		// State
		if state, err := readFile("/sys/class/net/" + iface + "/operstate"); err == nil {
			ni.State = strings.TrimSpace(state)
		}

		// Speed
		if speed, err := readFile("/sys/class/net/" + iface + "/speed"); err == nil {
			s := strings.TrimSpace(speed)
			if s != "" && s != "-1" {
				ni.Speed = s + " Mbps"
			}
		}

		// Driver
		if driver, err := linkBase("/sys/class/net/" + iface + "/device/driver"); err == nil {
			ni.Driver = strings.TrimSpace(driver)
		}

		// Firmware and model
		ni.Firmware, ni.Model = getNICFirmware(iface, ni.Driver)

		// IPv4
		if out, err := runStdout("ip", "-4", "addr", "show", "dev", iface); err == nil {
			ni.IPv4 = ipAddrs(out, "inet", false)
		}

		// IPv6
		if out, err := runStdout("ip", "-6", "addr", "show", "dev", iface); err == nil {
			ni.IPv6 = ipAddrs(out, "inet6", true)
		}

		interfaces = append(interfaces, ni)
	}

	return interfaces
}

var cachedTimezone *time.Location
var cachedTzName string
var timezoneChecked bool

func getTimezone() (*time.Location, string) {
	if timezoneChecked {
		return cachedTimezone, cachedTzName
	}
	timezoneChecked = true

	// Try IP geolocation to detect timezone with offset
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/?fields=timezone,offset")
	if err == nil {
		defer resp.Body.Close()
		var result struct {
			Timezone string `json:"timezone"`
			Offset   int    `json:"offset"` // offset in seconds
		}
		if json.NewDecoder(resp.Body).Decode(&result) == nil && result.Timezone != "" {
			// Create fixed timezone from offset
			cachedTimezone = time.FixedZone(result.Timezone, result.Offset)
			cachedTzName = result.Timezone
			return cachedTimezone, cachedTzName
		}
	}

	// Fall back to UTC
	cachedTimezone = time.UTC
	cachedTzName = "UTC"
	return cachedTimezone, cachedTzName
}

func handleWebUI(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	cpu, _ := runShell("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
	cores, _ := runShell("nproc")
	kernel, _ := runShell("uname -r")
	memInfo, _ := runShell("free -h | grep Mem")
	memFields := strings.Fields(memInfo)
	memTotal, memUsed, memFree := "", "", ""
	if len(memFields) >= 4 {
		memTotal = memFields[1]
		memUsed = memFields[2]
		memFree = memFields[3]
	}

	loc, tzName := getTimezone()
	currentTime := time.Now().In(loc).Format("2006-01-02 15:04:05") + " " + tzName
	uptime, _ := runShell("uptime | sed 's/.*up/up/' | cut -d, -f1,2")

	interfaces := getNetworkInterfaces()
	asset := getAssetInfo()

	// Get lspci and lsblk output for raw display
	lspciOut, _ := runShell("lspci 2>/dev/null")
	lsblkOut, _ := runShell("lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL 2>/dev/null")

	// Get detailed disk info
	var disks []DiskInfo
	if diskListOut, err := runShell("lsblk -d -n -o NAME,TYPE"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(diskListOut), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "disk" {
				disks = append(disks, getDiskDetail(fields[0]))
			}
		}
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s - Bare Metal Services</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #00d4ff; margin-top: 30px; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; margin: 15px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        table { width: 100%%; border-collapse: collapse; margin: 10px 0; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #2a2a4a; }
        th { color: #00d4ff; font-weight: 500; }
        .label { color: #888; }
        .value { color: #fff; font-weight: 500; }
        .status-up { color: #00ff88; }
        .status-down { color: #ff4444; }
        .time { font-size: 1.5em; color: #00d4ff; }
        .mac { font-family: monospace; color: #ffaa00; }
        .ip { font-family: monospace; color: #00ff88; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 500; }
        .badge-ssd { background: #1b4332; color: #52b788; }
        .badge-hdd { background: #3d2b1f; color: #e09f3e; }
        .badge-nvme { background: #1a1b4b; color: #818cf8; }
        .badge-passed { background: #1b4332; color: #52b788; }
        .badge-failed { background: #4a1525; color: #ff4444; }
        .btn { display: inline-block; padding: 4px 12px; border-radius: 4px; border: 1px solid #444; background: #2a2a4a; color: #ccc; cursor: pointer; font-size: 0.8em; text-decoration: none; margin: 2px; }
        .btn:hover { background: #3a3a5a; color: #fff; }
        .btn-danger { border-color: #ff4444; color: #ff4444; }
        .btn-danger:hover { background: #4a1525; }
        .serial { font-family: monospace; color: #aaa; font-size: 0.9em; }
        pre { background: #0d1117; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; color: #c9d1d9; line-height: 1.5; }
        footer { margin-top: 40px; text-align: center; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>%s</h1>
        <p class="time">%s</p>
        <p class="label">Uptime: <span class="value">%s</span></p>

        <div class="grid">
            <div class="card">
                <h2>System</h2>
                <table>
                    <tr><td class="label">Hostname</td><td class="value">%s</td></tr>
                    <tr><td class="label">Kernel</td><td class="value">%s</td></tr>
                    <tr><td class="label">CPU</td><td class="value">%s</td></tr>
                    <tr><td class="label">Cores</td><td class="value">%s</td></tr>
                </table>
            </div>
            <div class="card">
                <h2>Memory</h2>
                <table>
                    <tr><td class="label">Total</td><td class="value">%s</td></tr>
                    <tr><td class="label">Used</td><td class="value">%s</td></tr>
                    <tr><td class="label">Free</td><td class="value">%s</td></tr>
                </table>
            </div>
            <div class="card">
                <h2>Asset Info</h2>
                <table>
                    <tr><td class="label">Manufacturer</td><td class="value">%s</td></tr>
                    <tr><td class="label">Product</td><td class="value">%s</td></tr>
                    <tr><td class="label">Serial</td><td class="value mac">%s</td></tr>
                    <tr><td class="label">BIOS</td><td class="value">%s %s</td></tr>
                    <tr><td class="label">Board</td><td class="value">%s</td></tr>
                </table>
            </div>
        </div>

        <div class="card">
            <h2>Network Interfaces</h2>
            <table>
                <tr><th>Interface</th><th>MAC Address</th><th>IPv4</th><th>State</th><th>Speed</th><th>Driver</th><th>Firmware</th><th>Model</th></tr>
`, hostname, hostname, currentTime, strings.TrimSpace(uptime),
		hostname, strings.TrimSpace(kernel), strings.TrimSpace(cpu), strings.TrimSpace(cores),
		memTotal, memUsed, memFree,
		asset.System.Manufacturer, asset.System.ProductName, asset.System.SerialNumber,
		asset.BIOS.Vendor, asset.BIOS.Version, asset.Baseboard.ProductName)

	for _, iface := range interfaces {
		stateClass := "status-down"
		if iface.State == "up" {
			stateClass = "status-up"
		}
		html += fmt.Sprintf(`                <tr>
                    <td class="value">%s</td>
                    <td class="mac">%s</td>
                    <td class="ip">%s</td>
                    <td class="%s">%s</td>
                    <td class="value">%s</td>
                    <td class="value">%s</td>
                    <td class="value">%s</td>
                    <td class="value">%s</td>
                </tr>
`, iface.Name, iface.MAC, iface.IPv4, stateClass, iface.State, iface.Speed, iface.Driver, iface.Firmware, iface.Model)
	}

	html += `            </table>
        </div>

        <div class="card">
            <h2>Disks</h2>
            <table>
                <tr><th>Device</th><th>Size</th><th>Type</th><th>Model</th><th>Serial</th><th>Firmware</th><th>Health</th><th>Temp</th><th>Hours</th><th>Actions</th></tr>
`

	for _, disk := range disks {
		typeBadge := ""
		switch disk.MediaType {
		case "SSD":
			typeBadge = `<span class="badge badge-ssd">SSD</span>`
		case "HDD":
			typeBadge = `<span class="badge badge-hdd">HDD</span>`
		case "NVMe":
			typeBadge = `<span class="badge badge-nvme">NVMe</span>`
		default:
			typeBadge = disk.MediaType
		}
		healthBadge := ""
		if disk.SmartHealth == "PASSED" {
			healthBadge = `<span class="badge badge-passed">PASSED</span>`
		} else if disk.SmartHealth != "" {
			healthBadge = fmt.Sprintf(`<span class="badge badge-failed">%s</span>`, disk.SmartHealth)
		}
		html += fmt.Sprintf(`                <tr>
                    <td class="value">/dev/%s</td>
                    <td class="value">%s</td>
                    <td>%s</td>
                    <td class="value">%s</td>
                    <td class="serial">%s</td>
                    <td class="value">%s</td>
                    <td>%s</td>
                    <td class="value">%s</td>
                    <td class="value">%s</td>
                    <td>
                        <a class="btn btn-danger" href="javascript:void(0)" onclick="diskAction('wipe','%s')">Wipe</a>
                        <a class="btn btn-danger" href="javascript:void(0)" onclick="diskAction('secure-erase','%s')">Secure Erase</a>
                    </td>
                </tr>
`, disk.Name, disk.Size, typeBadge, disk.Model, disk.Serial, disk.Firmware, healthBadge, disk.Temperature, disk.PowerOnHours, disk.Name, disk.Name)
	}

	html += `            </table>
        </div>

        <div class="grid">
            <div class="card">
                <h2>lspci</h2>
                <pre>` + lspciOut + `</pre>
            </div>
            <div class="card">
                <h2>lsblk</h2>
                <pre>` + lsblkOut + `</pre>
            </div>
        </div>

        <footer>
            <p>Bare Metal Services API at <a href="/api/" style="color: #00d4ff;">/api/</a> (and on :8080)</p>
        </footer>
    </div>
` + webUIScript + `</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	info := SystemInfo{
		Memory: make(map[string]string),
	}

	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// CPU
	if out, err := runShell("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2"); err == nil {
		info.CPU = strings.TrimSpace(out)
	}

	// CPU Cores
	if out, err := runShell("nproc"); err == nil {
		info.CPUCores = strings.TrimSpace(out)
	}

	// Memory
	if out, err := runShell("free -h | grep Mem"); err == nil {
		fields := strings.Fields(out)
		if len(fields) >= 4 {
			info.Memory["total"] = fields[1]
			info.Memory["used"] = fields[2]
			info.Memory["free"] = fields[3]
		}
	}

	// Network
	if out, err := runShell("ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2, $NF}'"); err == nil {
		info.Network = strings.Split(strings.TrimSpace(out), "\n")
	}

	// Uptime
	if out, err := runShell("uptime -p"); err == nil {
		info.Uptime = strings.TrimSpace(out)
	}

	// Kernel
	if out, err := runShell("uname -r"); err == nil {
		info.Kernel = strings.TrimSpace(out)
	}

	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: info})
}

func handleIPMI(w http.ResponseWriter, r *http.Request) {
	loadIPMIModules()

	info := IPMIInfo{}

	// Parse lan print output even if ipmitool returns non-zero (some BMCs do this)
	out, _ := runShell("ipmitool lan print 1 2>/dev/null")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			switch key {
			case "IP Address Source":
				info.IPSource = val
			case "IP Address":
				info.IPAddress = val
			case "MAC Address":
				info.MACAddress = val
			case "Subnet Mask":
				info.Subnet = val
			case "Default Gateway IP":
				info.Gateway = val
			}
		}
	}

	if out, err := runShell("ipmitool user list 1 2>/dev/null"); err == nil {
		info.Users = out
	}

	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: info})
}

func handleIPMIReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	loadIPMIModules()

	results := make(map[string]string)

	// Enable user 2
	if out, err := runShell("ipmitool user enable 2"); err == nil {
		results["enable_user"] = "success"
	} else {
		results["enable_user"] = out
	}

	// Set username to ADMIN
	if out, err := runShell("ipmitool user set name 2 ADMIN"); err == nil {
		results["set_username"] = "success"
	} else {
		results["set_username"] = out
	}

	// Set password to ADMIN
	if out, err := runShell("ipmitool user set password 2 ADMIN"); err == nil {
		results["set_password"] = "success"
	} else {
		results["set_password"] = out
	}

	// Set channel access with full administrator privileges
	if out, err := runShell("ipmitool channel setaccess 1 2 link=on ipmi=on callin=on privilege=4"); err == nil {
		results["channel_access"] = "success"
	} else {
		results["channel_access"] = out
	}

	// Set SOL access for user 2
	if out, err := runShell("ipmitool sol payload enable 1 2 2>/dev/null"); err == nil {
		results["sol_access"] = "success"
	} else {
		results["sol_access"] = out
	}

	// Set IPMI LAN to DHCP
	if out, err := runShell("ipmitool lan set 1 ipsrc dhcp"); err == nil {
		results["set_dhcp"] = "success"
	} else {
		results["set_dhcp"] = out
	}

	// Get IPMI IP after DHCP change
	if out, err := runShell("ipmitool lan print 1 2>/dev/null | grep 'IP Address' | head -1"); err == nil {
		results["ipmi_ip"] = strings.TrimSpace(out)
	}

	// Cold reset BMC to apply all changes (credentials, network)
	if _, err := runShell("ipmitool mc reset cold 2>/dev/null"); err == nil {
		results["bmc_reset"] = "success"
	} else {
		results["bmc_reset"] = "failed (non-critical)"
	}

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "IPMI reset to ADMIN/ADMIN with DHCP (BMC cold reset applied)",
		Data:    results,
	})
}

type MACAddresses struct {
	Eth0 string `json:"eth0,omitempty"`
	Eth1 string `json:"eth1,omitempty"`
	IPMI string `json:"ipmi,omitempty"`
}

func handleMACs(w http.ResponseWriter, r *http.Request) {
	macs := MACAddresses{}

	// Get eth0 MAC
	if mac, err := runShell("cat /sys/class/net/eth0/address 2>/dev/null"); err == nil {
		macs.Eth0 = strings.TrimSpace(mac)
	}

	// Get eth1 MAC
	if mac, err := runShell("cat /sys/class/net/eth1/address 2>/dev/null"); err == nil {
		macs.Eth1 = strings.TrimSpace(mac)
	}

	// Get IPMI MAC via ipmitool
	loadIPMIModules()
	if out, err := runShell("ipmitool lan print 1 2>/dev/null | grep 'MAC Address' | awk '{print $4}'"); err == nil {
		macs.IPMI = strings.TrimSpace(out)
	}

	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: macs})
}

func handleAsset(w http.ResponseWriter, r *http.Request) {
	info := getAssetInfo()
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: info})
}

func handleNetwork(w http.ResponseWriter, r *http.Request) {
	interfaces := getNetworkInterfaces()
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: interfaces})
}

func handleMemory(w http.ResponseWriter, r *http.Request) {
	var dimms []MemoryDIMM

	out, err := runShell("dmidecode -t memory 2>/dev/null")
	if err != nil {
		sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: dimms, Message: "dmidecode not available"})
		return
	}

	var currentDIMM *MemoryDIMM
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Memory Device") {
			if currentDIMM != nil && currentDIMM.Size != "" && currentDIMM.Size != "No Module Installed" {
				dimms = append(dimms, *currentDIMM)
			}
			currentDIMM = &MemoryDIMM{}
		} else if currentDIMM != nil && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "Locator":
				currentDIMM.Locator = val
			case "Size":
				currentDIMM.Size = val
			case "Type":
				currentDIMM.Type = val
			case "Speed":
				currentDIMM.Speed = val
			case "Manufacturer":
				if val != "Unknown" && val != "" {
					currentDIMM.Manufacturer = val
				}
			case "Part Number":
				if val != "Unknown" && val != "" {
					currentDIMM.PartNumber = strings.TrimSpace(val)
				}
			case "Serial Number":
				if val != "Unknown" && val != "" {
					currentDIMM.SerialNumber = val
				}
			}
		}
	}
	if currentDIMM != nil && currentDIMM.Size != "" && currentDIMM.Size != "No Module Installed" {
		dimms = append(dimms, *currentDIMM)
	}

	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: dimms})
}

func handleFirmwareList(w http.ResponseWriter, r *http.Request) {
	var files []string
	out, err := runShell("ls /usr/share/firmware/mellanox/*.bin 2>/dev/null")
	if err == nil {
		for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
			if f != "" {
				files = append(files, f)
			}
		}
	}
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: files})
}

func handleFirmwareUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	r.ParseForm()
	device := r.FormValue("device")
	firmwareURL := r.FormValue("url")

	if device == "" {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Missing 'device' parameter (PCI address like 05:00.0)"})
		return
	}
	if err := checkPCIAddr(device); err != nil {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: err.Error()})
		return
	}
	if firmwareURL != "" {
		if err := checkFirmwareURL(firmwareURL); err != nil {
			sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: err.Error()})
			return
		}
	}

	results := make(map[string]string)
	var firmwarePath string

	// Try bundled firmware first (auto-detect based on device PSID)
	if firmwareURL == "" {
		// Get device PSID
		psid := ""
		if q, _ := runStdout("mstflint", "-d", device, "q"); q != "" {
			if f := strings.Fields(firstLineContaining(q, "PSID", false)); len(f) >= 2 {
				psid = f[1]
			}
		}
		results["device_psid"] = psid

		// Find matching firmware
		fwFiles, _ := runShell("ls /usr/share/firmware/mellanox/*.bin 2>/dev/null")
		for _, fwFile := range strings.Split(strings.TrimSpace(fwFiles), "\n") {
			if fwFile != "" {
				firmwarePath = fwFile
				results["firmware_file"] = firmwarePath
				break
			}
		}
		if firmwarePath == "" {
			sendJSON(w, http.StatusBadRequest, APIResponse{
				Status: "error",
				Error:  "No bundled firmware found. Provide 'url' parameter to download firmware.",
			})
			return
		}
	} else {
		// Download firmware from URL
		firmwarePath = "/tmp/firmware.bin"
		results["download_url"] = firmwareURL
		if out, err := runCommand("wget", "-q", "-O", firmwarePath, firmwareURL); err != nil {
			sendJSON(w, http.StatusInternalServerError, APIResponse{
				Status: "error",
				Error:  "Failed to download firmware: " + out,
			})
			return
		}
		results["download"] = "success"
	}

	// Get current firmware version
	if out, err := runCommand("mstflint", "-d", device, "q"); err == nil {
		results["old_version"] = strings.TrimSpace(firstLineContaining(out, "FW Version", false))
	}

	// Verify firmware file matches device
	if out, err := runCommand("mstflint", "-d", device, "-i", firmwarePath, "v"); err != nil {
		results["verify"] = out
		sendJSON(w, http.StatusBadRequest, APIResponse{
			Status: "error",
			Error:  "Firmware verification failed - PSID may not match",
			Data:   results,
		})
		return
	}
	results["verify"] = "success"

	// Burn firmware
	if out, err := runCommand("mstflint", "-d", device, "-i", firmwarePath, "-y", "burn"); err != nil {
		results["burn"] = out
		sendJSON(w, http.StatusInternalServerError, APIResponse{
			Status: "error",
			Error:  "Firmware burn failed",
			Data:   results,
		})
		return
	}
	results["burn"] = "success"

	// Query new firmware version
	if out, err := runCommand("mstflint", "-d", device, "q"); err == nil {
		results["new_version"] = strings.TrimSpace(firstLineContaining(out, "FW Version", false))
	}

	results["note"] = "Reboot required for firmware to take effect"

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "Firmware updated successfully",
		Data:    results,
	})
}

type BIOSInfo struct {
	Board           string `json:"board"`
	CurrentVersion  string `json:"current_version"`
	CurrentDate     string `json:"current_date"`
	LatestVersion   string `json:"latest_version,omitempty"`
	LatestFile      string `json:"latest_file,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	UpdateMethod    string `json:"update_method,omitempty"`
}

type BIOSConfigureRequest struct {
	QuickBoot      *bool    `json:"quick_boot"`
	QuietBoot      *bool    `json:"quiet_boot"`
	DisablePXENICs []string `json:"disable_pxe_nics"`
}

type BIOSConfigureResponse struct {
	Changes        []string `json:"changes"`
	Skipped        []string `json:"skipped,omitempty"`
	RebootRequired bool     `json:"reboot_required"`
}

var biosDatabase = map[string]struct {
	LatestVersion string
	FileName      string
}{
	"X9SRD-F": {LatestVersion: "3.2b", FileName: "X9SRD-F_3.2b.bin"},
}

func handleBIOS(w http.ResponseWriter, r *http.Request) {
	info := BIOSInfo{}

	// Get board name
	info.Board = readDMI("board_name")
	info.CurrentVersion = readDMI("bios_version")
	info.CurrentDate = readDMI("bios_date")

	// Check if we have an update for this board
	if dbEntry, ok := biosDatabase[info.Board]; ok {
		info.LatestVersion = dbEntry.LatestVersion
		// Check if file exists
		filePath := "/usr/share/firmware/bios/" + dbEntry.FileName
		if st, err := os.Stat(filePath); err == nil && st.Mode().IsRegular() {
			info.LatestFile = filePath
		}
		// Compare versions (simple string compare, works for Supermicro versioning)
		if info.CurrentVersion != "" && info.LatestVersion != "" && info.CurrentVersion < info.LatestVersion {
			info.UpdateAvailable = true
			info.UpdateMethod = "flashrom or BMC web interface"
		}
	}

	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: info})
}

func handleBIOSUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	results := make(map[string]interface{})

	// Get board info
	board := readDMI("board_name")
	currentVersion := readDMI("bios_version")
	results["board"] = board
	results["current_version"] = currentVersion

	// Check if we support this board
	dbEntry, ok := biosDatabase[board]
	if !ok {
		sendJSON(w, http.StatusBadRequest, APIResponse{
			Status: "error",
			Error:  fmt.Sprintf("No BIOS update available for board: %s", board),
			Data:   results,
		})
		return
	}

	results["latest_version"] = dbEntry.LatestVersion

	// Check if update is needed
	if currentVersion >= dbEntry.LatestVersion {
		results["status"] = "up_to_date"
		sendJSON(w, http.StatusOK, APIResponse{
			Status:  "ok",
			Message: "BIOS is already up to date",
			Data:    results,
		})
		return
	}

	// Check if firmware file exists
	filePath := "/usr/share/firmware/bios/" + dbEntry.FileName
	if st, err := os.Stat(filePath); err != nil || !st.Mode().IsRegular() {
		sendJSON(w, http.StatusInternalServerError, APIResponse{
			Status: "error",
			Error:  fmt.Sprintf("BIOS file not found: %s", filePath),
			Data:   results,
		})
		return
	}
	results["bios_file"] = filePath

	// Check if flashrom is available and probe the chip
	chipInfo, err := runShell("flashrom -p internal 2>&1")
	if err != nil {
		// flashrom probe failed - suggest BMC update instead
		results["flashrom_error"] = strings.TrimSpace(chipInfo)
		results["recommendation"] = "Use BMC web interface for BIOS update"

		// Get IPMI IP for BMC access
		if ipmiIP, err := runShell("ipmitool lan print 1 2>/dev/null | grep 'IP Address' | grep -v Source | awk '{print $4}'"); err == nil {
			results["bmc_url"] = fmt.Sprintf("http://%s/", strings.TrimSpace(ipmiIP))
		}

		sendJSON(w, http.StatusOK, APIResponse{
			Status:  "ok",
			Message: "flashrom not supported on this board - use BMC web interface",
			Data:    results,
		})
		return
	}
	results["flashrom_probe"] = strings.TrimSpace(chipInfo)

	// Attempt BIOS update with flashrom
	r.ParseForm()
	force := r.FormValue("force") == "true"

	if !force {
		results["status"] = "ready"
		results["warning"] = "BIOS update is risky. Add force=true to proceed."
		sendJSON(w, http.StatusOK, APIResponse{
			Status:  "ok",
			Message: "BIOS update ready - add force=true to proceed",
			Data:    results,
		})
		return
	}

	// Actually perform the update
	updateOut, err := runCommand("flashrom", "-p", "internal", "-w", filePath)
	results["flashrom_output"] = strings.TrimSpace(updateOut)

	if err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{
			Status: "error",
			Error:  "BIOS update failed",
			Data:   results,
		})
		return
	}

	results["status"] = "success"
	results["note"] = "Reboot required for new BIOS to take effect"

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "BIOS updated successfully",
		Data:    results,
	})
}

func driverToVendor(driver string) string {
	switch strings.ToLower(driver) {
	case "mlx4_core", "mlx4_en", "mlx5_core":
		return "mellanox"
	case "ixgbe", "i40e", "ice", "igb", "e1000", "e1000e":
		return "intel"
	case "bnxt_en", "tg3":
		return "broadcom"
	case "r8169":
		return "realtek"
	case "virtio_net":
		return "virtio"
	}
	return driver
}

func nicMatchesFilter(driver string, filters []string) bool {
	driverLower := strings.ToLower(driver)
	vendor := driverToVendor(driverLower)
	for _, filter := range filters {
		filterLower := strings.ToLower(filter)
		if strings.Contains(driverLower, filterLower) || strings.Contains(vendor, filterLower) {
			return true
		}
	}
	return false
}

func handleBIOSConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	var req BIOSConfigureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Invalid JSON: " + err.Error()})
		return
	}

	var changes []string
	var skipped []string
	rebootRequired := false

	// Handle quick_boot and quiet_boot via Supermicro SUM
	if req.QuickBoot != nil || req.QuietBoot != nil {
		sumAvailable := false
		if _, err := runShell("which sum 2>/dev/null"); err == nil {
			sumAvailable = true
		}
		if sumAvailable {
			if req.QuickBoot != nil {
				val := "Disabled"
				if *req.QuickBoot {
					val = "Enabled"
				}
				if _, err := runCommand("sum", "-c", "ChangeBiosCfg", "--setting", "Quick Boot="+val); err == nil {
					changes = append(changes, fmt.Sprintf("quick_boot: %s", strings.ToLower(val)))
					rebootRequired = true
				} else {
					changes = append(changes, "quick_boot: failed (SUM error)")
				}
			}
			if req.QuietBoot != nil {
				val := "Disabled"
				if *req.QuietBoot {
					val = "Enabled"
				}
				if _, err := runCommand("sum", "-c", "ChangeBiosCfg", "--setting", "Quiet Boot="+val); err == nil {
					changes = append(changes, fmt.Sprintf("quiet_boot: %s", strings.ToLower(val)))
					rebootRequired = true
				} else {
					changes = append(changes, "quiet_boot: failed (SUM error)")
				}
			}
		} else {
			if req.QuickBoot != nil {
				skipped = append(skipped, "quick_boot: SUM not available, configure via BIOS setup or BMC web UI")
			}
			if req.QuietBoot != nil {
				skipped = append(skipped, "quiet_boot: SUM not available, configure via BIOS setup or BMC web UI")
			}
		}
	}

	// Handle disable_pxe_nics via efibootmgr (planPXEDisable, finding 8fe507b0417b)
	if len(req.DisablePXENICs) > 0 {
		runShell("mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null")
		efiOut, err := runStdout("efibootmgr", "-v")
		if err != nil {
			skipped = append(skipped, "PXE disable: efibootmgr not available or system not EFI-booted")
		} else {
			del, why := planPXEDisable(efiOut, getNetworkInterfaces(), req.DisablePXENICs)
			skipped = append(skipped, why...)
			for _, e := range del {
				if _, err := runCommand("efibootmgr", "-b", e.Num, "-B"); err == nil {
					changes = append(changes, fmt.Sprintf("PXE disabled on %s: %s", e.NIC, e.Desc))
					rebootRequired = true
				} else {
					changes = append(changes, fmt.Sprintf("PXE disable failed for Boot%s", e.Num))
				}
			}
		}
	}

	if len(changes) == 0 && len(skipped) == 0 {
		changes = append(changes, "no changes requested")
	}

	sendJSON(w, http.StatusOK, APIResponse{
		Status: "ok",
		Data: BIOSConfigureResponse{
			Changes:        changes,
			Skipped:        skipped,
			RebootRequired: rebootRequired,
		},
	})
}

func getDiskDetail(name string) DiskInfo {
	disk := DiskInfo{Name: name, Type: "disk"}

	// Basic info from lsblk
	if out, err := runStdout("lsblk", "-d", "-n", "-o", "SIZE,MODEL", "/dev/"+name); err == nil {
		fields := strings.Fields(strings.TrimSpace(out))
		if len(fields) >= 1 {
			disk.Size = fields[0]
		}
		if len(fields) > 1 {
			disk.Model = strings.Join(fields[1:], " ")
		}
	}

	// Partitions
	if out, err := runStdout("lsblk", "-n", "-o", "NAME,SIZE,FSTYPE,MOUNTPOINT", "/dev/"+name); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pName := strings.TrimLeft(fields[0], "├─└─│ ")
				if pName != name {
					p := PartInfo{Name: pName, Size: fields[1]}
					if len(fields) >= 3 {
						p.FSType = fields[2]
					}
					if len(fields) >= 4 {
						p.MountPoint = fields[3]
					}
					disk.Partitions = append(disk.Partitions, p)
				}
			}
		}
	}

	// SMART info via smartctl
	smartOut, smartErr := runStdout("smartctl", "-i", "-H", "/dev/"+name)
	if smartErr == nil || smartOut != "" {
		for _, line := range strings.Split(smartOut, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "Serial Number":
					disk.Serial = val
				case "Firmware Version":
					disk.Firmware = val
				case "Rotation Rate":
					disk.RotationRate = val
					if strings.Contains(val, "Solid State") {
						disk.MediaType = "SSD"
					} else if val != "" {
						disk.MediaType = "HDD"
					}
				case "SATA Version is", "Transport protocol":
					disk.Transport = val
				case "SMART overall-health self-assessment test result":
					disk.SmartHealth = val
				}
			}
		}
	}

	// NVMe detection
	if strings.HasPrefix(name, "nvme") {
		disk.MediaType = "NVMe"
		disk.Transport = "NVMe"
		if nvmeOut, err := runStdout("nvme", "id-ctrl", "/dev/"+name); err == nil {
			for _, line := range strings.Split(nvmeOut, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "fr ") || strings.HasPrefix(line, "fr\t") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						disk.Firmware = strings.TrimSpace(parts[1])
					}
				}
				if strings.HasPrefix(line, "sn ") || strings.HasPrefix(line, "sn\t") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 && disk.Serial == "" {
						disk.Serial = strings.TrimSpace(parts[1])
					}
				}
				if strings.HasPrefix(line, "mn ") || strings.HasPrefix(line, "mn\t") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 && disk.Model == "" {
						disk.Model = strings.TrimSpace(parts[1])
					}
				}
			}
		}
		// NVMe SMART health (finding be3bdc3dcdf0): from critical_warning,
		// unknown when the log cannot be read.
		if nvmeSmart, err := runStdout("nvme", "smart-log", "/dev/"+name); err == nil {
			temp, poh, health := parseNVMeSmartLog(nvmeSmart)
			if temp != "" {
				disk.Temperature = temp
			}
			if poh != "" {
				disk.PowerOnHours = poh
			}
			disk.SmartHealth = health
		}
	}

	// Fallback serial from sysfs
	if disk.Serial == "" {
		if serial, err := readFile(filepath.Join(sysBlockDir, name, "device", "serial")); err == nil && strings.TrimSpace(serial) != "" {
			disk.Serial = strings.TrimSpace(serial)
		}
	}

	// Fallback media type from sysfs rotational flag
	if disk.MediaType == "" {
		if rot, err := readFile(filepath.Join(sysBlockDir, name, "queue", "rotational")); err == nil {
			if strings.TrimSpace(rot) == "0" {
				disk.MediaType = "SSD"
			} else {
				disk.MediaType = "HDD"
			}
		}
	}

	// Temperature from SMART attributes
	if disk.Temperature == "" {
		if attrs, _ := runStdout("smartctl", "-A", "/dev/"+name); attrs != "" { // smartctl exits non-zero on any status bit
			fields := strings.Fields(strings.TrimSpace(firstLineContaining(attrs, "temperature", true)))
			if len(fields) >= 10 {
				disk.Temperature = fields[9] + " C"
			}
		}
	}

	// Power-on hours from SMART attributes
	if disk.PowerOnHours == "" {
		if attrs, _ := runStdout("smartctl", "-A", "/dev/"+name); attrs != "" { // smartctl exits non-zero on any status bit
			fields := strings.Fields(strings.TrimSpace(firstLineContaining(attrs, "Power_On_Hours", false)))
			if len(fields) >= 10 {
				disk.PowerOnHours = fields[9]
			}
		}
	}

	return disk
}

func handleDisks(w http.ResponseWriter, r *http.Request) {
	var disks []DiskInfo

	out, err := runShell("lsblk -d -n -o NAME,TYPE")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "disk" {
				disks = append(disks, getDiskDetail(fields[0]))
			}
		}
	}

	markProtection(disks)
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: disks})
}

// markProtection fills in what the all-disks wipe would skip (#47). The
// stormbootx check mounts ESPs read-only, so it runs only when no disk
// operation holds the lock.
func markProtection(disks []DiskInfo) {
	var names []string
	for _, d := range disks {
		names = append(names, d.Name)
	}
	boot, bootWhy, bootErr := bootDiskSet(names)
	check := diskOpMu.TryLock()
	if check {
		defer diskOpMu.Unlock()
	}
	for i := range disks {
		p := protectDisk(disks[i].Name, boot, bootWhy, check)
		disks[i].BootDevice, disks[i].USB, disks[i].Removable, disks[i].Stormbootx = p.BootDevice, p.USB, p.Removable, p.Stormbootx
		reasons := p.Reasons
		if bootErr != nil {
			reasons = append(reasons, "boot device unknown, the all-disks wipe refuses: "+bootErr.Error())
		}
		disks[i].WipeAllSkips = strings.Join(reasons, "; ")
	}
}

func handleDiskDetail(w http.ResponseWriter, r *http.Request) {
	dev := strings.TrimPrefix(r.URL.Path, "/disks/detail/")
	dev = strings.TrimPrefix(dev, "/dev/")
	if dev == "" {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Missing device name"})
		return
	}
	if status, msg := checkBlockDevice(dev); status != http.StatusOK {
		sendJSON(w, status, APIResponse{Status: "error", Error: msg})
		return
	}
	disk := []DiskInfo{getDiskDetail(dev)}
	if _, err := os.Stat(filepath.Join(sysBlockDir, dev)); err == nil {
		markProtection(disk) // a whole disk, not a partition
	}
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: disk[0]})
}

func handleDiskPartition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	dev := strings.TrimPrefix(r.URL.Path, "/disks/partition/")
	dev = strings.TrimPrefix(dev, "/dev/")
	if dev == "" {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Missing device name"})
		return
	}

	r.ParseForm()
	label := r.FormValue("label") // gpt or msdos, default gpt
	if label == "" {
		label = "gpt"
	}
	if label != "gpt" && label != "msdos" {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: fmt.Sprintf("Unsupported label %q: use gpt or msdos", label)})
		return
	}
	if !lockDiskOp(w) {
		return
	}
	defer diskOpMu.Unlock()
	if status, msg := checkBlockDevice(dev); status != http.StatusOK {
		sendJSON(w, status, APIResponse{Status: "error", Error: msg})
		return
	}

	devPath := "/dev/" + dev
	results := make(map[string]string)

	// Create partition table
	if out, err := runCommand("parted", "-s", devPath, "mklabel", label); err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Failed to create partition table: " + strings.TrimSpace(out)})
		return
	}
	results["label"] = label

	// Create single partition spanning entire disk
	if out, err := runCommand("parted", "-s", devPath, "mkpart", "primary", "0%", "100%"); err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Failed to create partition: " + strings.TrimSpace(out)})
		return
	}
	results["partition"] = dev + "1"

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: fmt.Sprintf("Created %s partition table on %s with single partition", label, devPath),
		Data:    results,
	})
}

func handleDiskFormat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	dev := strings.TrimPrefix(r.URL.Path, "/disks/format/")
	dev = strings.TrimPrefix(dev, "/dev/")
	if dev == "" {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Missing device/partition name (e.g., sda1)"})
		return
	}

	r.ParseForm()
	fstype := r.FormValue("fstype")
	if fstype == "" {
		fstype = "ext4"
	}

	devPath := "/dev/" + dev
	results := make(map[string]string)

	var mkfs []string
	switch fstype {
	case "ext4":
		mkfs = []string{"mkfs.ext4", "-F", devPath}
	case "xfs":
		mkfs = []string{"mkfs.xfs", "-f", devPath}
	case "vfat", "fat32":
		mkfs = []string{"mkfs.vfat", "-F", "32", devPath}
	default:
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: fmt.Sprintf("Unsupported filesystem %q: use ext4, xfs, or vfat", fstype)})
		return
	}
	if !lockDiskOp(w) {
		return
	}
	defer diskOpMu.Unlock()
	if status, msg := checkBlockDevice(dev); status != http.StatusOK {
		sendJSON(w, status, APIResponse{Status: "error", Error: msg})
		return
	}

	if out, err := runCommand(mkfs[0], mkfs[1:]...); err != nil {
		sendJSON(w, http.StatusInternalServerError, APIResponse{
			Status: "error",
			Error:  "Format failed: " + strings.TrimSpace(out),
		})
		return
	}
	results["device"] = devPath
	results["filesystem"] = fstype

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: fmt.Sprintf("Formatted %s as %s", devPath, fstype),
		Data:    results,
	})
}

func handleDiskSecureErase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	dev := strings.TrimPrefix(r.URL.Path, "/disks/secure-erase/")
	dev = strings.TrimPrefix(dev, "/dev/")
	if dev == "" {
		sendJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Error: "Missing device name"})
		return
	}
	if !lockDiskOp(w) {
		return
	}
	defer diskOpMu.Unlock()
	if status, msg := checkBlockDevice(dev); status != http.StatusOK {
		sendJSON(w, status, APIResponse{Status: "error", Error: msg})
		return
	}

	devPath := "/dev/" + dev
	results := make(map[string]string)

	// NVMe secure erase
	if strings.HasPrefix(dev, "nvme") {
		results["method"] = "nvme-format"
		if out, err := runCommand("nvme", "format", devPath, "--ses=1"); err != nil {
			results["error"] = strings.TrimSpace(out)
			// Fallback to blkdiscard
			results["method"] = "blkdiscard (nvme format failed)"
			if out2, err2 := runCommand("blkdiscard", devPath); err2 != nil {
				results["blkdiscard_error"] = strings.TrimSpace(out2)
				sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Secure erase failed", Data: results})
				return
			}
		}
		results["status"] = "success"
		sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Message: "NVMe secure erase complete", Data: results})
		return
	}

	// SATA ATA Secure Erase via hdparm
	results["method"] = "ata-secure-erase"

	// Check if drive supports secure erase
	hdparmOut, _ := runStdout("hdparm", "-I", devPath)
	if !strings.Contains(hdparmOut, "supported: enhanced erase") && !strings.Contains(hdparmOut, "supported") {
		// Check basic support
		if !strings.Contains(hdparmOut, "Security") {
			// No ATA security: discard (best effort), then zero the whole
			// device and read it back (zeroAndVerify, finding 516e4f885acb).
			results["method"] = "blkdiscard+zero (no ATA secure erase support)"
			if out, err := runCommand("blkdiscard", devPath); err == nil {
				results["blkdiscard"] = "success"
			} else {
				results["blkdiscard"] = strings.TrimSpace(out)
			}
			size, err := blockDeviceSize(dev)
			if err == nil {
				results["size_bytes"] = strconv.FormatInt(size, 10)
				err = zeroAndVerify(devPath, size)
			}
			if err != nil {
				results["zero"] = err.Error()
				sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Secure erase failed: " + err.Error(), Data: results})
				return
			}
			results["zero"] = "success"
			results["verified"] = fmt.Sprintf("zero at %d points (head, tail, between)", len(eraseSampleOffsets(size)))
			results["status"] = "success"
			sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Message: "Disk zeroed and verified (ATA secure erase not supported)", Data: results})
			return
		}
	}

	// Check if drive is frozen
	if strings.Contains(hdparmOut, "frozen") && !strings.Contains(hdparmOut, "not\tfrozen") && !strings.Contains(hdparmOut, "not frozen") {
		results["error"] = "Drive is frozen. Try suspending and waking the system first."
		results["hint"] = "Run: echo mem > /sys/power/state  (then wake the system)"
		sendJSON(w, http.StatusConflict, APIResponse{Status: "error", Error: "Drive is frozen", Data: results})
		return
	}

	// Set security password for erase
	if out, err := runCommand("hdparm", "--user-master", "u", "--security-set-pass", "Erase", devPath); err != nil {
		results["set_password"] = strings.TrimSpace(out)
		sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Failed to set security password", Data: results})
		return
	}
	results["set_password"] = "success"

	// Check for enhanced erase support
	useEnhanced := strings.Contains(hdparmOut, "supported: enhanced erase")
	if useEnhanced {
		results["erase_type"] = "enhanced"
		if out, err := runCommand("hdparm", "--user-master", "u", "--security-erase-enhanced", "Erase", devPath); err != nil {
			results["erase_error"] = strings.TrimSpace(out)
			// Try standard erase as fallback
			if out2, err2 := runCommand("hdparm", "--user-master", "u", "--security-erase", "Erase", devPath); err2 != nil {
				results["erase_fallback_error"] = strings.TrimSpace(out2)
				sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Secure erase failed", Data: results})
				return
			}
			results["erase_type"] = "standard (enhanced failed)"
		}
	} else {
		results["erase_type"] = "standard"
		if out, err := runCommand("hdparm", "--user-master", "u", "--security-erase", "Erase", devPath); err != nil {
			results["erase_error"] = strings.TrimSpace(out)
			sendJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: "Secure erase failed", Data: results})
			return
		}
	}

	results["status"] = "success"
	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Message: "ATA Secure Erase complete", Data: results})
}

// webUIScript is the web UI's disk-action script. It posts to /api/ on the
// page's own origin (#41).
const webUIScript = `    <script>
    function diskAction(action, dev) {
        if (!confirm('Are you sure you want to ' + action + ' /dev/' + dev + '? This is DESTRUCTIVE and cannot be undone.')) return;
        // Same origin as this page (/api/ on the web port, #41): the browser
        // lets the script read the answer, so a wipe that worked shows as one.
        fetch('/api/disks/' + action + '/' + encodeURIComponent(dev), {method: 'POST'})
            .then(r => r.text().then(t => {
                let d = t;
                try { d = JSON.stringify(JSON.parse(t), null, 2); } catch (e) {}
                alert((r.ok ? 'OK' : 'FAILED') + ' (HTTP ' + r.status + ') ' + action + ' /dev/' + dev + '\n\n' + d);
                location.reload();
            }))
            .catch(e => alert('No answer from the agent for ' + action + ' /dev/' + dev + ': outcome unknown, check /disks before retrying.\n' + e));
    }
    </script>
`

// newAPIMux is the JSON API (port 8080, PORT env).
func newAPIMux() *http.ServeMux {
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/", handleRoot)
	apiMux.HandleFunc("/health", handleHealth)
	apiMux.HandleFunc("/system", handleSystem)
	apiMux.HandleFunc("/asset", handleAsset)
	apiMux.HandleFunc("/network", handleNetwork)
	apiMux.HandleFunc("/macs", handleMACs)
	apiMux.HandleFunc("/firmware", handleFirmwareList)
	apiMux.HandleFunc("/firmware/update", handleFirmwareUpdate)
	apiMux.HandleFunc("/bios", handleBIOS)
	apiMux.HandleFunc("/bios/update", handleBIOSUpdate)
	apiMux.HandleFunc("/bios/configure", handleBIOSConfigure)
	apiMux.HandleFunc("/bios/config", handleBIOSConfig)
	apiMux.HandleFunc("/boot/order", handleBootOrder)
	apiMux.HandleFunc("/memory", handleMemory)
	apiMux.HandleFunc("/ipmi", handleIPMI)
	apiMux.HandleFunc("/ipmi/reset", handleIPMIReset)
	apiMux.HandleFunc("/disks", handleDisks)
	apiMux.HandleFunc("/disks/detail/", handleDiskDetail)
	apiMux.HandleFunc("/disks/partition/", handleDiskPartition)
	apiMux.HandleFunc("/disks/format/", handleDiskFormat)
	apiMux.HandleFunc("/disks/secure-erase/", handleDiskSecureErase)
	apiMux.HandleFunc("/disks/wipe", handleDiskWipe)
	apiMux.HandleFunc("/disks/wipe/", handleDiskWipe)
	apiMux.HandleFunc("/disks/image/", handleDiskImage)
	return apiMux
}

// newWebMux is the web UI (port 80). It also serves the API under /api/, so
// the UI's requests are same-origin and the browser hands their answers to
// the page (#41; the API sends no CORS headers).
func newWebMux(api http.Handler) *http.ServeMux {
	webMux := http.NewServeMux()
	webMux.HandleFunc("/", handleWebUI)
	webMux.Handle("/api/", http.StripPrefix("/api", api))
	return webMux
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	apiMux := newAPIMux()
	webMux := newWebMux(apiMux)

	// Start API server
	go func() {
		log.Printf("Bare Metal Services API starting on port %s", port)
		log.Fatal(http.ListenAndServe(":"+port, apiMux))
	}()

	// Start Web UI server
	log.Printf("Bare Metal Services Web UI starting on port 80")
	log.Fatal(http.ListenAndServe(":80", webMux))
}
