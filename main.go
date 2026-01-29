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

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/system", handleSystem)
	http.HandleFunc("/ipmi", handleIPMI)
	http.HandleFunc("/ipmi/reset", handleIPMIReset)
	http.HandleFunc("/disks", handleDisks)
	http.HandleFunc("/disks/wipe", handleDiskWipe)
	http.HandleFunc("/disks/wipe/", handleDiskWipe)

	log.Printf("Bare Metal Services API starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
