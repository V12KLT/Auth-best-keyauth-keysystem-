use std::io::{self, Read, Write};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use native_tls::TlsConnector;
use std::net::TcpStream;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const XK: [u8; 16] = [0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33];
const H_ENC: [u8; 19] = [0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82];
const PORT: u16 = 3389;
const PROJECT_ID: &str = "ENTER_PROJECT_ID_HERE";

fn xd(data: &[u8]) -> String {
    let result: Vec<u8> = data.iter().enumerate().map(|(i, b)| b ^ XK[i % XK.len()]).collect();
    String::from_utf8_lossy(&result).to_string()
}

fn xe(input: &str) -> Vec<u8> {
    input.bytes().enumerate().map(|(i, b)| b ^ XK[i % XK.len()]).collect()
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811C9DC5;
    for &b in data { h ^= b as u32; h = h.wrapping_mul(0x01000193); }
    h ^ 0xDEADBEEF
}

struct TokenStore {
    enc: Vec<u8>,
    canary: u32,
    present: bool,
}

impl TokenStore {
    fn new() -> Self { TokenStore { enc: Vec::new(), canary: 0, present: false } }
    fn store(&mut self, token: &str) {
        self.enc = xe(token);
        self.canary = fnv1a(&self.enc);
        self.present = true;
    }
    fn get(&self) -> Option<String> {
        if !self.present || self.enc.is_empty() { return None; }
        if fnv1a(&self.enc) != self.canary { std::process::exit(0); }
        Some(xd(&self.enc))
    }
    fn valid(&self) -> bool {
        match self.get() {
            Some(token) => token.starts_with("AUTH_TOKEN_V2|") && token.len() > 22,
            None => false,
        }
    }
}

fn host() -> String { xd(&H_ENC) }

fn get_hwid() -> String {
    if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("powershell")
            .args(&["-Command", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"])
            .output()
        {
            let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !uuid.is_empty() && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" { return uuid; }
        }
        if let Ok(output) = Command::new("reg")
            .args(&["query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("MachineGuid") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 { return parts[2].to_string(); }
                }
            }
        }
    } else if cfg!(target_os = "linux") {
        for p in &["/sys/class/dmi/id/product_uuid", "/etc/machine-id"] {
            if let Ok(uuid) = std::fs::read_to_string(p) {
                let uuid = uuid.trim();
                if !uuid.is_empty() { return uuid.to_string(); }
            }
        }
    } else if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("system_profiler").args(&["SPHardwareDataType"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("Hardware UUID:") {
                    if let Some(uuid_part) = line.split(':').nth(1) {
                        let uuid = uuid_part.trim();
                        if !uuid.is_empty() { return uuid.to_string(); }
                    }
                }
            }
        }
    }
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "UNKNOWN".to_string())
}

fn hmac_sha256(key: &str, data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC error");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn check_bad_processes() {
    if !cfg!(target_os = "windows") { return; }
    let bad = ["x64dbg", "x32dbg", "ollydbg", "ida", "ida64", "wireshark",
        "fiddler", "charles", "httpdebugger", "processhacker", "procmon",
        "procexp", "dnspy", "de4dot", "cheatengine"];
    if let Ok(output) = Command::new("tasklist").args(&["/FO", "CSV", "/NH"]).output() {
        let lower = String::from_utf8_lossy(&output.stdout).to_lowercase();
        for b in &bad { if lower.contains(b) { std::process::exit(0); } }
    }
}

fn authenticate(key: &str, token_store: &Arc<Mutex<TokenStore>>) -> Result<bool, Box<dyn std::error::Error>> {
    check_bad_processes();

    let h = host();
    let tcp_stream = TcpStream::connect((&*h, PORT))?;
    tcp_stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp_stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let connector = TlsConnector::new()?;
    let mut tls_stream = connector.connect(&h, tcp_stream)?;

    tls_stream.write_all(b"2")?;
    thread::sleep(Duration::from_millis(200));

    let auth_data = format!("{}|{}|{}", PROJECT_ID, key, get_hwid());
    tls_stream.write_all(auth_data.as_bytes())?;

    let mut buffer = [0u8; 4096];
    let bytes_read = tls_stream.read(&mut buffer)?;
    let mut response = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

    if response.starts_with("CHALLENGE|") {
        let parts: Vec<&str> = response.split('|').collect();
        if parts.len() != 3 { return Ok(false); }
        let sig = hmac_sha256(key, parts[2]);
        let response_msg = format!("RESPONSE|{}|{}", parts[1], sig);
        tls_stream.write_all(response_msg.as_bytes())?;
        let bytes_read = tls_stream.read(&mut buffer)?;
        response = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
    }

    if response.starts_with("ACCESS|") {
        let server_data = &response[7..];
        let raw_token = format!("AUTH_TOKEN_V2|{}|{}", server_data, hmac_sha256(key, server_data));
        token_store.lock().unwrap().store(&raw_token);
        return Ok(true);
    }
    Ok(false)
}

fn verify_session(key: &str, token_store: &Arc<Mutex<TokenStore>>) -> bool {
    if !token_store.lock().unwrap().valid() { std::process::exit(0); }

    let h = host();
    let tcp_stream = match TcpStream::connect((&*h, PORT)) { Ok(s) => s, Err(_) => return false };
    let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(10)));
    let connector = match TlsConnector::new() { Ok(c) => c, Err(_) => return false };
    let mut tls_stream = match connector.connect(&h, tcp_stream) { Ok(s) => s, Err(_) => return false };

    let _ = tls_stream.write_all(b"3");
    thread::sleep(Duration::from_millis(100));
    let verify_data = format!("{}|{}|{}", PROJECT_ID, key, get_hwid());
    let _ = tls_stream.write_all(verify_data.as_bytes());
    let mut buffer = [0u8; 1024];
    match tls_stream.read(&mut buffer) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buffer[..n]).starts_with("VALID"),
        _ => false,
    }
}

fn start_session_validation(key: String, token_store: Arc<Mutex<TokenStore>>) {
    thread::spawn(move || {
        let mut failures = 0;
        loop {
            thread::sleep(Duration::from_secs(60));
            check_bad_processes();
            if verify_session(&key, &token_store) { failures = 0; }
            else { failures += 1; if failures >= 3 { std::process::exit(0); } }
        }
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_bad_processes();

    print!("Enter your license key: ");
    io::stdout().flush()?;
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();

    let token_store = Arc::new(Mutex::new(TokenStore::new()));

    match authenticate(&key, &token_store) {
        Ok(true) => {
            println!("Authenticated.");
            start_session_validation(key, token_store);
            loop { thread::sleep(Duration::from_secs(3600)); }
        }
        _ => { std::process::exit(1); }
    }
}