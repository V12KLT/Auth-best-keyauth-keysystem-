use std::io::{self, Read, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;
use native_tls::TlsConnector;
use std::net::TcpStream;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const SERVER_HOST: &str = "socket.keyauth.shop";
const SERVER_PORT: u16 = 3389;
const PROJECT_ID: &str = "ENTER_PROJECT_ID_HERE";

fn get_hwid() -> String {
    if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("powershell")
            .args(&["-Command", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"])
            .output()
        {
            let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !uuid.is_empty() && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
                return uuid;
            }
        }
        if let Ok(output) = Command::new("reg")
            .args(&["query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("MachineGuid") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        return parts[2].to_string();
                    }
                }
            }
        }
    } else if cfg!(target_os = "linux") {
        if let Ok(uuid) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            let uuid = uuid.trim();
            if !uuid.is_empty() {
                return uuid.to_string();
            }
        }
        if let Ok(output) = Command::new("dmidecode")
            .args(&["-s", "system-uuid"])
            .output()
        {
            let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !uuid.is_empty() {
                return uuid;
            }
        }
        if let Ok(uuid) = std::fs::read_to_string("/etc/machine-id") {
            let uuid = uuid.trim();
            if !uuid.is_empty() {
                return uuid.to_string();
            }
        }
    } else if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("system_profiler")
            .args(&["SPHardwareDataType"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("Hardware UUID:") {
                    if let Some(uuid_part) = line.split(':').nth(1) {
                        let uuid = uuid_part.trim();
                        if !uuid.is_empty() {
                            return uuid.to_string();
                        }
                    }
                }
            }
        }
    }
    
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "UNKNOWN".to_string())
}

fn hmac_sha256(key: &str, data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

fn authenticate(key: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let tcp_stream = TcpStream::connect((SERVER_HOST, SERVER_PORT))?;
    let connector = TlsConnector::new()?;
    
    let mut tls_stream = connector.connect(SERVER_HOST, tcp_stream)?;
    
    tls_stream.write_all(b"2")?;
    
    thread::sleep(Duration::from_millis(200));
    
    let auth_data = format!("{}|{}|{}", PROJECT_ID, key, get_hwid());
    tls_stream.write_all(auth_data.as_bytes())?;
    
    let mut buffer = [0; 1024];
    let bytes_read = tls_stream.read(&mut buffer)?;
    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
    
    if response.starts_with("CHALLENGE|") {
        let parts: Vec<&str> = response.split('|').collect();
        if parts.len() == 3 {
            let challenge_id = parts[1];
            let challenge = parts[2];
            
            let signature = hmac_sha256(key, challenge);
            
            let response_msg = format!("RESPONSE|{}|{}", challenge_id, signature);
            tls_stream.write_all(response_msg.as_bytes())?;
            
            let bytes_read = tls_stream.read(&mut buffer)?;
            let result = String::from_utf8_lossy(&buffer[..bytes_read]);
            
            if result.starts_with("ACCESS|") {
                println!("[KeyAuth] Authenticated.");
                Ok(true)
            } else {
                println!("[KeyAuth] Refused: {}", result);
                Ok(false)
            }
        } else {
            println!("[KeyAuth] Invalid challenge format");
            Ok(false)
        }
    } else if response.starts_with("ACCESS|") {
        println!("[KeyAuth] Authenticated.");
        Ok(true)
    } else {
        println!("[KeyAuth] Refused: {}", response);
        Ok(false)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!("Enter your license key: ");
    io::stdout().flush()?;
    
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim();
    
    match authenticate(key) {
        Ok(true) => {
        }
        Ok(false) => {
            std::process::exit(1);
        }
        Err(e) => {
            println!("[KeyAuth] Connection error: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}