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
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	State   string `json:"state"`
	Speed   string `json:"speed"`
	Driver  string `json:"driver"`
}

type DiskInfo struct {
	Name       string `json:"name"`
	Size       string `json:"size"`
	Type       string `json:"type"`
	Model      string `json:"model"`
	MountPoint string `json:"mountpoint,omitempty"`
}

type IPMIInfo struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	IPSource   string `json:"ip_source"`
	Subnet     string `json:"subnet_mask"`
	Gateway    string `json:"gateway"`
	Users      string `json:"users"`
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
		"GET /":                 "API documentation",
		"GET /health":           "Health check",
		"GET /system":           "System information",
		"GET /ipmi":             "IPMI information",
		"GET /disks":            "List all disks",
		"POST /ipmi/reset":      "Reset IPMI to ADMIN/ADMIN",
		"POST /disks/wipe":      "Wipe ALL disks (DESTRUCTIVE)",
		"POST /disks/wipe/{dev}": "Wipe specific disk (DESTRUCTIVE)",
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

	currentTime := time.Now().Format("2006-01-02 15:04:05 MST")
	uptime, _ := runShell("uptime | sed 's/.*up/up/' | cut -d, -f1,2")

	interfaces := getNetworkInterfaces()

	// Get disks
	disksOut, _ := runShell("lsblk -d -n -o NAME,SIZE,TYPE,MODEL | grep disk")
	diskLines := strings.Split(strings.TrimSpace(disksOut), "\n")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
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
        <h1>🖥️ %s</h1>
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
        </div>

        <div class="card">
            <h2>Network Interfaces</h2>
            <table>
                <tr><th>Interface</th><th>MAC Address</th><th>IPv4</th><th>State</th><th>Speed</th><th>Driver</th></tr>
`, hostname, hostname, currentTime, strings.TrimSpace(uptime),
		hostname, strings.TrimSpace(kernel), strings.TrimSpace(cpu), strings.TrimSpace(cores),
		memTotal, memUsed, memFree)

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
                </tr>
`, iface.Name, iface.MAC, iface.IPv4, stateClass, iface.State, iface.Speed, iface.Driver)
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
