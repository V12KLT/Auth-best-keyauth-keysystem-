package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var xk = []byte{0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33}
var hEnc = []byte{0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82}

const port = "3389"
const projectID = "ENTER_PROJECT_ID_HERE"

func xd(data []byte) string {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ xk[i%len(xk)]
	}
	return string(result)
}

func xe(input string) []byte {
	raw := []byte(input)
	result := make([]byte, len(raw))
	for i := range raw {
		result[i] = raw[i] ^ xk[i%len(xk)]
	}
	return result
}

func fnv1a(data []byte) uint32 {
	h := uint32(0x811C9DC5)
	for _, b := range data {
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h ^ 0xDEADBEEF
}

type tokenStore struct {
	enc     []byte
	canary  uint32
	present bool
	mu      sync.Mutex
}

var ts = &tokenStore{}

func (t *tokenStore) store(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enc = xe(token)
	t.canary = fnv1a(t.enc)
	t.present = true
}

func (t *tokenStore) get() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.present || len(t.enc) == 0 {
		return ""
	}
	if fnv1a(t.enc) != t.canary {
		os.Exit(0)
	}
	return xd(t.enc)
}

func (t *tokenStore) valid() bool {
	token := t.get()
	if token == "" {
		return false
	}
	if !strings.HasPrefix(token, "AUTH_TOKEN_V2|") {
		return false
	}
	return len(token) > 22
}

func host() string {
	return xd(hEnc)
}

func hmacSha256(key, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func getHWID() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID")
		output, err := cmd.Output()
		if err == nil {
			uuid := strings.TrimSpace(string(output))
			if uuid != "" && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
				return uuid
			}
		}
		cmd = exec.Command("reg", "query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "MachineGuid") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						return parts[2]
					}
				}
			}
		}
	} else if runtime.GOOS == "linux" {
		for _, p := range []string{"/sys/class/dmi/id/product_uuid", "/etc/machine-id"} {
			data, err := os.ReadFile(p)
			if err == nil {
				uuid := strings.TrimSpace(string(data))
				if uuid != "" {
					return uuid
				}
			}
		}
	} else if runtime.GOOS == "darwin" {
		cmd := exec.Command("system_profiler", "SPHardwareDataType")
		output, err := cmd.Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "Hardware UUID:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) >= 2 {
						uuid := strings.TrimSpace(parts[1])
						if uuid != "" {
							return uuid
						}
					}
				}
			}
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "UNKNOWN"
	}
	return hostname
}

func checkBadProcesses() {
	if runtime.GOOS != "windows" {
		return
	}
	bad := []string{"x64dbg", "x32dbg", "ollydbg", "ida", "ida64", "wireshark",
		"fiddler", "charles", "httpdebugger", "processhacker", "procmon",
		"procexp", "dnspy", "de4dot", "cheatengine"}
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	lower := strings.ToLower(string(output))
	for _, b := range bad {
		if strings.Contains(lower, b) {
			os.Exit(0)
		}
	}
}

func authenticate(key string) bool {
	checkBadProcesses()

	h := host()
	config := &tls.Config{ServerName: h}
	conn, err := tls.Dial("tcp", h+":"+port, config)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	_, err = conn.Write([]byte("2"))
	if err != nil {
		return false
	}
	time.Sleep(200 * time.Millisecond)

	authData := fmt.Sprintf("%s|%s|%s", projectID, key, getHWID())
	_, err = conn.Write([]byte(authData))
	if err != nil {
		return false
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}
	response := string(buffer[:n])

	if strings.HasPrefix(response, "CHALLENGE|") {
		parts := strings.Split(response, "|")
		if len(parts) != 3 {
			return false
		}
		sig := hmacSha256(key, parts[2])
		responseMsg := fmt.Sprintf("RESPONSE|%s|%s", parts[1], sig)
		_, err = conn.Write([]byte(responseMsg))
		if err != nil {
			return false
		}
		n, err = conn.Read(buffer)
		if err != nil {
			return false
		}
		response = string(buffer[:n])
	}

	if strings.HasPrefix(response, "ACCESS|") {
		serverData := response[7:]
		rawToken := fmt.Sprintf("AUTH_TOKEN_V2|%s|%s", serverData, hmacSha256(key, serverData))
		ts.store(rawToken)
		return true
	}
	return false
}

func verifySession(key string) bool {
	if !ts.valid() {
		os.Exit(0)
	}
	h := host()
	config := &tls.Config{ServerName: h}
	conn, err := tls.Dial("tcp", h+":"+port, config)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	conn.Write([]byte("3"))
	time.Sleep(100 * time.Millisecond)
	verifyData := fmt.Sprintf("%s|%s|%s", projectID, key, getHWID())
	conn.Write([]byte(verifyData))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n <= 0 {
		return false
	}
	return strings.HasPrefix(string(buffer[:n]), "VALID")
}

func startSessionValidation(key string) {
	go func() {
		failures := 0
		for {
			time.Sleep(60 * time.Second)
			checkBadProcesses()
			if verifySession(key) {
				failures = 0
			} else {
				failures++
				if failures >= 3 {
					os.Exit(0)
				}
			}
		}
	}()
}

func main() {
	checkBadProcesses()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your license key: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)

	if authenticate(key) {
		fmt.Println("Authenticated.")
		startSessionValidation(key)
		select {}
	} else {
		os.Exit(1)
	}
}