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
    "time"
)

const (
    SERVER_HOST = "socket.keyauth.shop"
    SERVER_PORT = "3389"
    PROJECT_ID  = "ENTER_PROJECT_ID_HERE"
)

func getHWID() string {
    if runtime.GOOS == "windows" {
        cmd := exec.Command("powershell", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID")
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
        cmd := exec.Command("cat", "/sys/class/dmi/id/product_uuid")
        output, err := cmd.Output()
        if err == nil {
            uuid := strings.TrimSpace(string(output))
            if uuid != "" {
                return uuid
            }
        }
        cmd = exec.Command("dmidecode", "-s", "system-uuid")
        output, err = cmd.Output()
        if err == nil {
            uuid := strings.TrimSpace(string(output))
            if uuid != "" {
                return uuid
            }
        }
        cmd = exec.Command("cat", "/etc/machine-id")
        output, err = cmd.Output()
        if err == nil {
            uuid := strings.TrimSpace(string(output))
            if uuid != "" {
                return uuid
            }
        }
    } else if runtime.GOOS == "darwin" {
        cmd := exec.Command("system_profiler", "SPHardwareDataType")
        output, err := cmd.Output()
        if err == nil {
            lines := strings.Split(string(output), "\n")
            for _, line := range lines {
                if strings.Contains(line, "Hardware UUID:") {
                    parts := strings.Split(line, ":")
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

func hmacSha256(key, data string) string {
    h := hmac.New(sha256.New, []byte(key))
    h.Write([]byte(data))
    return hex.EncodeToString(h.Sum(nil))
}

func authenticate(key string) bool {
    config := &tls.Config{}

    conn, err := tls.Dial("tcp", SERVER_HOST+":"+SERVER_PORT, config)
    if err != nil {
        fmt.Printf("[KeyAuth] Connection error: %v\n", err)
        return false
    }
    defer conn.Close()

    _, err = conn.Write([]byte("2"))
    if err != nil {
        fmt.Printf("[KeyAuth] Write error: %v\n", err)
        return false
    }

    time.Sleep(200 * time.Millisecond)

    authData := fmt.Sprintf("%s|%s|%s", PROJECT_ID, key, getHWID())
    _, err = conn.Write([]byte(authData))
    if err != nil {
        fmt.Printf("[KeyAuth] Write error: %v\n", err)
        return false
    }

    buffer := make([]byte, 1024)
    n, err := conn.Read(buffer)
    if err != nil {
        fmt.Printf("[KeyAuth] Read error: %v\n", err)
        return false
    }

    response := string(buffer[:n])

    if strings.HasPrefix(response, "CHALLENGE|") {
        parts := strings.Split(response, "|")
        if len(parts) == 3 {
            challengeId := parts[1]
            challenge := parts[2]
            
            signature := hmacSha256(key, challenge)
            
            responseMsg := fmt.Sprintf("RESPONSE|%s|%s", challengeId, signature)
            _, err = conn.Write([]byte(responseMsg))
            if err != nil {
                fmt.Printf("[KeyAuth] Write error: %v\n", err)
                return false
            }

            n, err = conn.Read(buffer)
            if err != nil {
                fmt.Printf("[KeyAuth] Read error: %v\n", err)
                return false
            }

            result := string(buffer[:n])

            if strings.HasPrefix(result, "ACCESS|") {
                fmt.Println("[KeyAuth] Authenticated.")
                return true
            } else {
                fmt.Printf("[KeyAuth] Refused: %s\n", result)
                return false
            }
        } else {
            fmt.Println("[KeyAuth] Invalid challenge format")
            return false
        }
    } else if strings.HasPrefix(response, "ACCESS|") {
        fmt.Println("[KeyAuth] Authenticated.")
        return true
    } else {
        fmt.Printf("[KeyAuth] Refused: %s\n", response)
        return false
    }
}

func main() {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter your license key: ")
    key, _ := reader.ReadString('\n')
    key = strings.TrimSpace(key)

    if authenticate(key) {
    } else {
        os.Exit(1)
    }
}