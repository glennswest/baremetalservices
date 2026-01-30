package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
	Name       string `json:"name"`
	Size       string `json:"size"`
	Type       string `json:"type"`
	Model      string `json:"model"`
	Serial     string `json:"serial,omitempty"`
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

var mstflintCache map[string]map[string]string
var mstflintCached bool

func getMellanoxFirmwareInfo(pciAddr string) map[string]string {
	if mstflintCache == nil {
		mstflintCache = make(map[string]map[string]string)
	}

	if info, ok := mstflintCache[pciAddr]; ok {
		return info
	}

	info := make(map[string]string)
	mstflintCache[pciAddr] = info

	out, err := runShell(fmt.Sprintf("mstflint -d %s q 2>/dev/null", pciAddr))
	if err != nil {
		return info
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			info[key] = val
		}
	}
	return info
}

func readDMI(field string) string {
	path := "/sys/class/dmi/id/" + field
	if out, err := runShell(fmt.Sprintf("cat %s 2>/dev/null", path)); err == nil {
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
	pciPath, err := runShell(fmt.Sprintf("basename $(readlink /sys/class/net/%s/device 2>/dev/null) 2>/dev/null", iface))
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
			if vpd, err := runShell(fmt.Sprintf("strings /sys/class/net/%s/device/vpd 2>/dev/null", iface)); err == nil {
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
		if vendor, err := runShell(fmt.Sprintf("cat /sys/class/net/%s/device/subsystem_vendor 2>/dev/null", iface)); err == nil {
			if device, err := runShell(fmt.Sprintf("cat /sys/class/net/%s/device/subsystem_device 2>/dev/null", iface)); err == nil {
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
		"GET /memory":                 "Memory DIMM info (model, serial, speed)",
		"GET /ipmi":                   "IPMI information",
		"GET /disks":                  "List all disks with serial numbers",
		"POST /ipmi/reset":            "Reset IPMI to ADMIN/ADMIN",
		"POST /disks/wipe":            "Wipe ALL disks (DESTRUCTIVE)",
		"POST /disks/wipe/{dev}":      "Wipe specific disk (DESTRUCTIVE)",
		"GET /firmware":               "List bundled firmware files",
		"POST /firmware/update":       "Update Mellanox NIC firmware (device=<pci_addr>, optional url=<firmware_url>)",
		"GET /bios":                   "BIOS version and update availability",
		"POST /bios/update":           "Update BIOS if needed (checks board compatibility first)",
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
		if mac, err := runShell(fmt.Sprintf("cat /sys/class/net/%s/address", iface)); err == nil {
			ni.MAC = strings.TrimSpace(mac)
		}

		// State
		if state, err := runShell(fmt.Sprintf("cat /sys/class/net/%s/operstate", iface)); err == nil {
			ni.State = strings.TrimSpace(state)
		}

		// Speed
		if speed, err := runShell(fmt.Sprintf("cat /sys/class/net/%s/speed 2>/dev/null", iface)); err == nil {
			s := strings.TrimSpace(speed)
			if s != "" && s != "-1" {
				ni.Speed = s + " Mbps"
			}
		}

		// Driver
		if driver, err := runShell(fmt.Sprintf("basename $(readlink /sys/class/net/%s/device/driver 2>/dev/null) 2>/dev/null", iface)); err == nil {
			ni.Driver = strings.TrimSpace(driver)
		}

		// Firmware and model
		ni.Firmware, ni.Model = getNICFirmware(iface, ni.Driver)

		// IPv4
		if ipv4, err := runShell(fmt.Sprintf("ip -4 addr show %s 2>/dev/null | grep 'inet ' | awk '{print $2}'", iface)); err == nil {
			ni.IPv4 = strings.TrimSpace(ipv4)
		}

		// IPv6
		if ipv6, err := runShell(fmt.Sprintf("ip -6 addr show %s 2>/dev/null | grep 'inet6 ' | grep -v fe80 | awk '{print $2}'", iface)); err == nil {
			ni.IPv6 = strings.TrimSpace(ipv6)
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

	// Get disks
	disksOut, _ := runShell("lsblk -d -n -o NAME,SIZE,TYPE,MODEL | grep disk")
	diskLines := strings.Split(strings.TrimSpace(disksOut), "\n")

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
                <tr><th>Device</th><th>Size</th><th>Model</th></tr>
`

	for _, line := range diskLines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := fields[0]
			size := fields[1]
			model := ""
			if len(fields) > 3 {
				model = strings.Join(fields[3:], " ")
			}
			html += fmt.Sprintf(`                <tr><td class="value">/dev/%s</td><td class="value">%s</td><td class="value">%s</td></tr>
`, name, size, model)
		}
	}

	html += `            </table>
        </div>

        <footer>
            <p>Bare Metal Services API available at <a href="/api/" style="color: #00d4ff;">:8080</a></p>
        </footer>
    </div>
</body>
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

	if out, err := runShell("ipmitool lan print 1 2>/dev/null"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])

				switch key {
				case "IP Address":
					info.IPAddress = val
				case "MAC Address":
					info.MACAddress = val
				case "IP Address Source":
					info.IPSource = val
				case "Subnet Mask":
					info.Subnet = val
				case "Default Gateway IP":
					info.Gateway = val
				}
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

	// Set channel access
	if out, err := runShell("ipmitool channel setaccess 1 2 link=on privilege=4"); err == nil {
		results["channel_access"] = "success"
	} else {
		results["channel_access"] = out
	}

	// Set password to ADMIN
	if out, err := runShell("ipmitool user set password 2 'ADMIN'"); err == nil {
		results["set_password"] = "success"
	} else {
		results["set_password"] = out
	}

	// Get IPMI IP
	if out, err := runShell("ipmitool lan print 1 2>/dev/null | grep 'IP Address' | head -1"); err == nil {
		results["ipmi_ip"] = strings.TrimSpace(out)
	}

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "IPMI reset to ADMIN/ADMIN",
		Data:    results,
	})
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

	results := make(map[string]string)
	var firmwarePath string

	// Try bundled firmware first (auto-detect based on device PSID)
	if firmwareURL == "" {
		// Get device PSID
		psidOut, _ := runShell(fmt.Sprintf("mstflint -d %s q 2>/dev/null | grep PSID | awk '{print $2}'", device))
		psid := strings.TrimSpace(psidOut)
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
		if out, err := runShell(fmt.Sprintf("wget -q -O %s '%s' 2>&1", firmwarePath, firmwareURL)); err != nil {
			sendJSON(w, http.StatusInternalServerError, APIResponse{
				Status: "error",
				Error:  "Failed to download firmware: " + out,
			})
			return
		}
		results["download"] = "success"
	}

	// Get current firmware version
	if out, err := runShell(fmt.Sprintf("mstflint -d %s q 2>&1 | grep 'FW Version'", device)); err == nil {
		results["old_version"] = strings.TrimSpace(out)
	}

	// Verify firmware file matches device
	if out, err := runShell(fmt.Sprintf("mstflint -d %s -i %s v 2>&1", device, firmwarePath)); err != nil {
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
	if out, err := runShell(fmt.Sprintf("mstflint -d %s -i %s -y burn 2>&1", device, firmwarePath)); err != nil {
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
	if out, err := runShell(fmt.Sprintf("mstflint -d %s q 2>&1 | grep 'FW Version'", device)); err == nil {
		results["new_version"] = strings.TrimSpace(out)
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
		if _, err := runShell(fmt.Sprintf("test -f %s && echo exists", filePath)); err == nil {
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
	if out, err := runShell(fmt.Sprintf("test -f %s && echo exists", filePath)); err != nil || strings.TrimSpace(out) != "exists" {
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
	updateCmd := fmt.Sprintf("flashrom -p internal -w %s 2>&1", filePath)
	updateOut, err := runShell(updateCmd)
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

func handleDisks(w http.ResponseWriter, r *http.Request) {
	var disks []DiskInfo

	out, err := runShell("lsblk -d -n -o NAME,SIZE,TYPE,MODEL")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] == "disk" {
				disk := DiskInfo{
					Name: fields[0],
					Size: fields[1],
					Type: fields[2],
				}
				if len(fields) > 3 {
					disk.Model = strings.Join(fields[3:], " ")
				}
				// Get serial number via smartctl or sysfs
				if serial, err := runShell(fmt.Sprintf("smartctl -i /dev/%s 2>/dev/null | grep 'Serial Number' | awk '{print $3}'", disk.Name)); err == nil && strings.TrimSpace(serial) != "" {
					disk.Serial = strings.TrimSpace(serial)
				} else if serial, err := runShell(fmt.Sprintf("cat /sys/block/%s/device/serial 2>/dev/null", disk.Name)); err == nil && strings.TrimSpace(serial) != "" {
					disk.Serial = strings.TrimSpace(serial)
				}
				disks = append(disks, disk)
			}
		}
	}

	sendJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: disks})
}

func handleDiskWipe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "Method not allowed"})
		return
	}

	// Check if specific disk requested
	path := strings.TrimPrefix(r.URL.Path, "/disks/wipe")
	path = strings.TrimPrefix(path, "/")

	var disksToWipe []string

	if path != "" {
		// Wipe specific disk
		if !strings.HasPrefix(path, "/dev/") {
			path = "/dev/" + path
		}
		disksToWipe = append(disksToWipe, path)
	} else {
		// Wipe all disks
		out, err := runShell("lsblk -d -n -o NAME,TYPE | grep disk | awk '{print $1}'")
		if err == nil {
			for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
				if name != "" {
					disksToWipe = append(disksToWipe, "/dev/"+name)
				}
			}
		}
	}

	results := make(map[string]interface{})

	for _, disk := range disksToWipe {
		diskResult := make(map[string]string)

		// Try blkdiscard first (fast for SSDs), fall back to dd
		if out, err := runShell(fmt.Sprintf("blkdiscard %s 2>&1", disk)); err == nil {
			diskResult["blkdiscard"] = "success"
		} else {
			diskResult["blkdiscard"] = out
			// Fall back to zeroing first 100MB
			if out2, err2 := runShell(fmt.Sprintf("dd if=/dev/zero of=%s bs=1M count=100 2>&1", disk)); err2 == nil {
				diskResult["dd_zero"] = "success"
			} else {
				diskResult["dd_zero"] = out2
			}
		}

		// Wipe partition table
		if out, err := runShell(fmt.Sprintf("wipefs -a %s 2>&1", disk)); err == nil {
			diskResult["wipefs"] = "success"
		} else {
			diskResult["wipefs"] = out
		}

		results[disk] = diskResult
	}

	sendJSON(w, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: fmt.Sprintf("Wiped %d disk(s)", len(disksToWipe)),
		Data:    results,
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// API server mux (port 8080)
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/", handleRoot)
	apiMux.HandleFunc("/health", handleHealth)
	apiMux.HandleFunc("/system", handleSystem)
	apiMux.HandleFunc("/asset", handleAsset)
	apiMux.HandleFunc("/network", handleNetwork)
	apiMux.HandleFunc("/firmware", handleFirmwareList)
	apiMux.HandleFunc("/firmware/update", handleFirmwareUpdate)
	apiMux.HandleFunc("/bios", handleBIOS)
	apiMux.HandleFunc("/bios/update", handleBIOSUpdate)
	apiMux.HandleFunc("/memory", handleMemory)
	apiMux.HandleFunc("/ipmi", handleIPMI)
	apiMux.HandleFunc("/ipmi/reset", handleIPMIReset)
	apiMux.HandleFunc("/disks", handleDisks)
	apiMux.HandleFunc("/disks/wipe", handleDiskWipe)
	apiMux.HandleFunc("/disks/wipe/", handleDiskWipe)

	// Web UI server mux (port 80)
	webMux := http.NewServeMux()
	webMux.HandleFunc("/", handleWebUI)

	// Start API server
	go func() {
		log.Printf("Bare Metal Services API starting on port %s", port)
		log.Fatal(http.ListenAndServe(":"+port, apiMux))
	}()

	// Start Web UI server
	log.Printf("Bare Metal Services Web UI starting on port 80")
	log.Fatal(http.ListenAndServe(":80", webMux))
}
