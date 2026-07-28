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

const CF_ENC: [u8; 64] = [    
    0xE5, 0x7F, 0xCB, 0x6E, 0xA5, 0xFC, 0x5E, 0x3E, 0xA6, 0x4F, 0x55,
    0xFC, 0x0B, 0xE1, 0xC1, 0x75, 0x92, 0x08, 0xC7, 0x1F, 0xD4, 0xF4,
    0x5E, 0x48, 0xA1, 0x43, 0x57, 0xFF, 0x76, 0xE7, 0xB6, 0x77, 0xE4,
    0x0F, 0xC0, 0x6E, 0xA0, 0xF2, 0x2E, 0x4B, 0xA5, 0x3F, 0x52, 0x8B,
    0x0B, 0x96, 0xC1, 0x70, 0xE1, 0x0A, 0xB6, 0x1F, 0xD0, 0xF4, 0x5A,
    0x4E, 0xA0, 0x4B, 0x21, 0x89, 0x09, 0xE5, 0xB7, 0x76];

use std::sync::Mutex;
use once_cell::sync::Lazy;
static CACHED_PUBKEY: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

fn fetch_pubkey() -> Option<Vec<u8>> {
    if let Ok(guard) = CACHED_PUBKEY.lock() {
        if let Some(ref key) = *guard {
            return Some(key.clone());
        }
    }
    let h = host();
    let tcp = TcpStream::connect((&*h, PORT)).ok()?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let connector = TlsConnector::new().ok()?;
    let mut tls = connector.connect(&h, tcp).ok()?;
    tls.write_all(b"8").ok()?;
    let mut buf = [0u8; 4096];
    let n = tls.read(&mut buf).ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    if resp.starts_with("PUBKEY|") {
        let raw = hex::decode(&resp[7..]).ok()?;
        if raw.len() == 64 {
            if let Ok(mut guard) = CACHED_PUBKEY.lock() {
                *guard = Some(raw.clone());
            }
            return Some(raw);
        }
    }
    None
}

fn verify_sig(data: &str, sig_hex: &str) -> bool {
    let raw = match fetch_pubkey() {
        Some(r) => r,
        None => return true,
    };
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
    use p256::EncodedPoint;
    if raw.len() != 64 || sig_hex.len() != 128 { return true; }
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&raw[..32]);
    uncompressed[33..65].copy_from_slice(&raw[32..]);
    let point = match EncodedPoint::from_bytes(&uncompressed) { Ok(p) => p, Err(_) => return true };
    let vk = match VerifyingKey::from_encoded_point(&point) { Ok(k) => k, Err(_) => return true };
    let sig_bytes = match hex::decode(sig_hex) { Ok(b) => b, Err(_) => return true };
    let sig = match Signature::from_slice(&sig_bytes) { Ok(s) => s, Err(_) => return true };
    use p256::ecdsa::signature::DigestVerifier;
    vk.verify_digest(sha2::Sha256::new_with_prefix(data.as_bytes()), &sig).is_ok()
}

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
    use sha2::Digest;
    let raw = if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("powershell")
            .args(&["-Command", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"])
            .output()
        {
            let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !uuid.is_empty() && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
                uuid
            } else if let Ok(output) = Command::new("reg")
                .args(&["query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.lines()
                    .find(|l| l.contains("MachineGuid"))
                    .and_then(|l| l.split_whitespace().nth(2))
                    .unwrap_or("UNKNOWN")
                    .to_string()
            } else {
                std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".to_string())
            }
        } else {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".to_string())
        }
    } else if cfg!(target_os = "linux") {
        let mut found = None;
        for p in &["/sys/class/dmi/id/product_uuid", "/etc/machine-id"] {
            if let Ok(uuid) = std::fs::read_to_string(p) {
                let uuid = uuid.trim().to_string();
                if !uuid.is_empty() { found = Some(uuid); break; }
            }
        }
        found.unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "UNKNOWN".to_string()))
    } else if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("system_profiler").args(&["SPHardwareDataType"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            output_str.lines()
                .find(|l| l.contains("Hardware UUID:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "UNKNOWN".to_string())
        } else {
            "UNKNOWN".to_string()
        }
    } else {
        std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "UNKNOWN".to_string())
    };
    let hash = sha2::Sha256::digest(raw.as_bytes());
    hex::encode(hash)
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

    if !response.starts_with("CHALLENGE|") {
        return Ok(false);
    }
    let parts: Vec<&str> = response.split('|').collect();
    if parts.len() != 3 { return Ok(false); }
    let challenge = parts[2].to_string();
    let sig = hmac_sha256(key, parts[2]);
    let response_msg = format!("RESPONSE|{}|{}", parts[1], sig);
    tls_stream.write_all(response_msg.as_bytes())?;
    let bytes_read = tls_stream.read(&mut buffer)?;
    let response = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

    if !response.starts_with("ACCESS|") {
        return Ok(false);
    }
    let access_parts: Vec<&str> = response.splitn(4, '|').collect();
    if access_parts.len() < 4 { return Ok(false); }
    let access_token = access_parts[1];
    let server_proof = access_parts[2];
    let auth_sig = access_parts[3];
    let expected_proof = hmac_sha256(key, &format!("{}|{}", challenge, access_token));
    if server_proof != expected_proof { return Ok(false); }
    if !verify_sig(&format!("{}|{}", challenge, access_token), auth_sig) { return Ok(false); }
    let raw_token = format!("AUTH_TOKEN_V2|{}|{}", access_token, hmac_sha256(key, access_token));
    token_store.lock().unwrap().store(&raw_token);
    Ok(true)
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
        Ok(n) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]).to_string();
            if !response.starts_with("VALID|") { return false; }
            let v_parts: Vec<&str> = response.splitn(5, '|').collect();
            if v_parts.len() < 5 { return false; }
            let remaining = v_parts[2];
            let verify_proof = v_parts[3];
            let v_sig = v_parts[4];
            let verify_data = format!("VERIFY:{}:{}", PROJECT_ID, remaining);
            let expected = hmac_sha256(key, &verify_data);
            verify_proof == expected && verify_sig(&verify_data, v_sig)
        }
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

fn recv_exact(tls_stream: &mut native_tls::TlsStream<TcpStream>, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut offset = 0;
    while offset < n {
        match tls_stream.read(&mut buf[offset..]) {
            Ok(0) => return None,
            Ok(r) => offset += r,
            Err(_) => return None,
        }
    }
    Some(buf)
}

fn download_file(key: &str, file_name: &str, token_store: &Arc<Mutex<TokenStore>>) -> Option<Vec<u8>> {
    let h = host();
    let tcp_stream = TcpStream::connect((&*h, PORT)).ok()?;
    tcp_stream.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    tcp_stream.set_write_timeout(Some(Duration::from_secs(30))).ok()?;
    let connector = TlsConnector::new().ok()?;
    let mut tls_stream = connector.connect(&h, tcp_stream).ok()?;

    tls_stream.write_all(b"6").ok()?;
    thread::sleep(Duration::from_millis(100));
    let req_data = format!("{}|{}|{}|{}", PROJECT_ID, key, get_hwid(), file_name);
    tls_stream.write_all(req_data.as_bytes()).ok()?;

    let hdr_len_raw = recv_exact(&mut tls_stream, 4)?;
    let hdr_len = ((hdr_len_raw[0] as u32) << 24 | (hdr_len_raw[1] as u32) << 16 | (hdr_len_raw[2] as u32) << 8 | hdr_len_raw[3] as u32) as usize;
    if hdr_len > 4096 { return None; }
    let hdr_bytes = recv_exact(&mut tls_stream, hdr_len)?;
    let header = String::from_utf8_lossy(&hdr_bytes).to_string();
    if header.starts_with("ERROR") { return None; }

    let parts: Vec<&str> = header.split('|').collect();
    if parts.len() < 5 || parts[0] != "FILE" { return None; }
    let nonce_hex = parts[1];
    let tag_hex = parts[2];
    let expected_hash = parts[3];
    let file_size: usize = parts[4].parse().ok()?;

    let body_len_raw = recv_exact(&mut tls_stream, 4)?;
    let body_len = ((body_len_raw[0] as u32) << 24 | (body_len_raw[1] as u32) << 16 | (body_len_raw[2] as u32) << 8 | body_len_raw[3] as u32) as usize;
    if body_len > 60 * 1024 * 1024 { return None; }
    let body = recv_exact(&mut tls_stream, body_len)?;

    let nonce = hex::decode(nonce_hex).ok()?;
    let tag = hex::decode(tag_hex).ok()?;
    if nonce.len() != 12 || tag.len() != 16 { return None; }

    let mut file_key_mac = HmacSha256::new_from_slice(key.as_bytes()).ok()?;
    file_key_mac.update(format!("FILE_KEY:{}", nonce_hex).as_bytes());
    let file_key = file_key_mac.finalize().into_bytes();

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&file_key));
    let nonce_arr = GenericArray::from_slice(&nonce);
    let mut ciphertext = body;
    ciphertext.extend_from_slice(&tag);

    use aes_gcm::aead::Payload;
    let plaintext = cipher.decrypt(nonce_arr, Payload { msg: &ciphertext, aad: PROJECT_ID.as_bytes() }).ok()?;

    use sha2::Digest;
    let hash = sha2::Sha256::digest(&plaintext);
    let actual_hash = hex::encode(hash);
    if actual_hash != expected_hash || plaintext.len() != file_size { return None; }
    Some(plaintext)
}

fn secure_wipe(path: &str) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let size = metadata.len() as usize;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; size];
            let _ = f.write_all(&zeros);
            let _ = f.flush();
        }
    }
    let _ = std::fs::remove_file(path);
}

fn download_and_run(key: &str, file_name: &str, token_store: &Arc<Mutex<TokenStore>>) -> bool {
    let data = match download_file(key, file_name, token_store) {
        Some(d) => d,
        None => return false,
    };

    let temp_dir = std::env::temp_dir();
    let random_suffix = format!("{:08x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos());
    let random_dir = temp_dir.join(format!("_ka_{}", random_suffix));
    let _ = std::fs::create_dir_all(&random_dir);

    if cfg!(target_os = "windows") {
        let _ = Command::new("attrib").args(&["+h", "+s", random_dir.to_str().unwrap_or("")]).output();
    }

    let exe_path = random_dir.join(file_name);
    if std::fs::write(&exe_path, &data).is_err() { return false; }

    if cfg!(target_os = "windows") {
        let _ = Command::new("attrib").args(&["+h", exe_path.to_str().unwrap_or("")]).output();
    }

    drop(data);

    if cfg!(target_os = "windows") {
        let _ = Command::new("powershell")
            .args(&["-NoProfile", "-Command",
                &format!("Start-Process -FilePath '{}' -WorkingDirectory '{}' -Verb RunAs",
                    exe_path.to_str().unwrap_or(""), random_dir.to_str().unwrap_or(""))])
            .spawn();
    } else {
        let _ = Command::new(exe_path.to_str().unwrap_or(""))
            .current_dir(&random_dir)
            .spawn();
    }

    let cap_exe = exe_path.to_str().unwrap_or("").to_string();
    let cap_dir = random_dir.to_str().unwrap_or("").to_string();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(2));
        secure_wipe(&cap_exe);
        thread::sleep(Duration::from_secs(1));
        let _ = std::fs::remove_dir_all(&cap_dir);
    });

    true
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
