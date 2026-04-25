package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var cfEnc = []byte{0x94, 0x7E, 0xB1, 0x6A, 0xD4, 0xF0, 0x5A, 0x3D, 0xDA, 0x3C, 0x55, 0xFA, 0x77, 0x97, 0xB2, 0x71, 0xE5, 0x0F, 0xC4, 0x68, 0xD3, 0x80, 0x29, 0x3F, 0xA0, 0x39, 0x23, 0x89, 0x0A, 0xE7, 0xC0, 0x72, 0xE2, 0x0F, 0xC4, 0x68, 0xA7, 0x87, 0x2C, 0x3F, 0xA7, 0x3E, 0x57, 0x88, 0x09, 0xE3, 0xC6, 0x70, 0x95, 0x0F, 0xB6, 0x6D, 0xD5, 0xF3, 0x2D, 0x39, 0xD2, 0x4B, 0x25, 0x8C, 0x09, 0xEA, 0xB3, 0x75}
var skEnc = []byte{0xB8, 0xBF, 0xD5, 0x63, 0x73, 0xEC, 0x9C, 0x4B, 0x82, 0x8D, 0xAF, 0x84, 0x32, 0x17, 0x3D, 0x78, 0xF8, 0xCC, 0x41, 0xCB, 0x8A, 0x5D, 0x3B, 0xCD, 0xE9, 0x7C, 0x60, 0x7C, 0x2E, 0x32, 0x0E, 0x33, 0x5B, 0xB5, 0x7C, 0x8D, 0xEE, 0x21, 0x14, 0x56, 0x70, 0x9F, 0xA3, 0x6D, 0x4D, 0x6F, 0x4B, 0xE8, 0x02, 0xC5, 0x6E, 0xE5, 0x7F, 0x33, 0xBC, 0x21, 0x8C, 0x7E, 0xF4, 0xAB, 0x7B, 0x56, 0x1C, 0xA2}

func verifySig(data string, sigHex string) bool {
	if len(skEnc) == 0 {
		return true
	}
	raw := make([]byte, len(skEnc))
	for i := range skEnc {
		raw[i] = skEnc[i] ^ xk[i%len(xk)]
	}
	x := new(big.Int).SetBytes(raw[:32])
	y := new(big.Int).SetBytes(raw[32:])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if len(sigHex) != 128 {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	hash := sha256.Sum256([]byte(data))
	return ecdsa.Verify(pub, hash[:], r, s)
}

func verifyCertPin(conn *tls.Conn) bool {
	if len(cfEnc) == 0 {
		return true
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false
	}
	certDER := state.PeerCertificates[0].Raw
	hash := sha256.Sum256(certDER)
	certHash := strings.ToUpper(hex.EncodeToString(hash[:]))
	expected := strings.ToUpper(xd(cfEnc))
	return certHash == expected
}

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

	if !verifyCertPin(conn) {
		return false
	}

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

	if !strings.HasPrefix(response, "CHALLENGE|") {
		return false
	}
	parts := strings.Split(response, "|")
	if len(parts) != 3 {
		return false
	}
	challenge := parts[2]
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

	if !strings.HasPrefix(response, "ACCESS|") {
		return false
	}
	accessParts := strings.SplitN(response, "|", 4)
	if len(accessParts) < 4 {
		return false
	}
	accessToken := accessParts[1]
	serverProof := accessParts[2]
	authSig := accessParts[3]
	expectedProof := hmacSha256(key, challenge+"|"+accessToken)
	if serverProof != expectedProof {
		return false
	}
	if !verifySig(challenge+"|"+accessToken, authSig) {
		return false
	}
	rawToken := fmt.Sprintf("AUTH_TOKEN_V2|%s|%s", accessToken, hmacSha256(key, accessToken))
	ts.store(rawToken)
	return true
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

	if !verifyCertPin(conn) {
		os.Exit(0)
	}

	conn.Write([]byte("3"))
	time.Sleep(100 * time.Millisecond)
	verifyData := fmt.Sprintf("%s|%s|%s", projectID, key, getHWID())
	conn.Write([]byte(verifyData))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n <= 0 {
		return false
	}
	response := string(buffer[:n])
	if !strings.HasPrefix(response, "VALID|") {
		return false
	}
	vParts := strings.SplitN(response, "|", 5)
	if len(vParts) < 5 {
		return false
	}
	remaining := vParts[2]
	verifyProof := vParts[3]
	vSig := vParts[4]
	verifyData := fmt.Sprintf("VERIFY:%s:%s", projectID, remaining)
	expected := hmacSha256(key, verifyData)
	return verifyProof == expected && verifySig(verifyData, vSig)
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
