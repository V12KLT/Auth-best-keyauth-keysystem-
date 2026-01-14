import os
from bcrypt import hashpw, gensalt, checkpw
import sqlite3
sqlite3.threadsafety = 3
import time
from socket import AF_INET, SOCK_STREAM, socket, SO_REUSEADDR, SOL_SOCKET
from threading import Thread, Lock
import random
import schedule
import secrets
import string
import ssl
import secrets
import hmac
import hashlib
import re
from collections import defaultdict

host = "0.0.0.0"
port = 3389

server = socket(AF_INET, SOCK_STREAM)
server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(5)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="Change to your fullchain.pem",
    keyfile="Change to your privkey.pem"
)
context.set_ciphers('Change to your cipher suite')
context.minimum_version = ssl.TLSVersion.TLSv1_2

print(f"Server listening on {host}:{port}")

_ = os.path.dirname(os.path.abspath(__file__))
os.chdir(_)

db_lock = Lock()
active_users = {}
active_sessions = {}        
project_active_users = {}      
active_users_lock = Lock()
active_sessions_lock = Lock()
rate_limit_login = defaultdict(list)
rate_limit_create = defaultdict(list)
rate_limit_auth = defaultdict(list)
rate_limit_lock = Lock()
connection_count = defaultdict(int)
connection_lock = Lock()

SECRET_KEY = secrets.token_hex(32)
MAX_CONN = 10

def get_db():
    conn = sqlite3.connect("keyauth.db", timeout=60, check_same_thread=False)  
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=60000;")  
    conn.execute("PRAGMA synchronous=NORMAL;") 
    return conn

def init_db():
    conn = sqlite3.connect("keyauth.db")
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        hwid TEXT,
        created_at INTEGER
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        project_name TEXT UNIQUE,
        project_id TEXT UNIQUE,
        created_at INTEGER,
        FOREIGN KEY(username) REFERENCES accounts(username)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS project_keys (
        project_id TEXT,
        key TEXT,
        hwid TEXT,
        timestamp INTEGER,
        expiration_type TEXT,
        expiration_timestamp INTEGER,
        PRIMARY KEY(project_id, key),
        FOREIGN KEY(project_id) REFERENCES projects(project_id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS project_bans (
        project_id TEXT,
        ip TEXT,
        key TEXT,
        hwid TEXT,
        FOREIGN KEY(project_id) REFERENCES projects(project_id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS project_activity (
        project_id TEXT,
        key TEXT,
        last_active INTEGER,
        FOREIGN KEY(project_id) REFERENCES projects(project_id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS project_ips (
        project_id TEXT,
        ip_list TEXT,
        FOREIGN KEY(project_id) REFERENCES projects(project_id)
    )
    """)
    conn.commit()
    conn.close()

init_db()

def cleanup():
    def full_cleanup():
        try:
            with db_lock:
                conn = get_db()
                try:
                    c = conn.cursor()
                    c.execute("DELETE FROM project_keys WHERE expiration_timestamp IS NOT NULL AND expiration_timestamp < ?", (int(time.time()),))
                    conn.commit()
                finally:
                    conn.close()
            
            current_time = int(time.time())
            with active_sessions_lock:
                expired = [token for token, data in active_sessions.items()
                        if data.get("expires", 0) < current_time]
                for token in expired:
                    del active_sessions[token]
            
            with rate_limit_lock:
                cutoff = time.time() - 3600
                for ip in list(rate_limit_login.keys()):
                    rate_limit_login[ip] = [t for t in rate_limit_login[ip] if t > cutoff]
                    if not rate_limit_login[ip]:
                        del rate_limit_login[ip]
                for ip in list(rate_limit_create.keys()):
                    rate_limit_create[ip] = [t for t in rate_limit_create[ip] if t > cutoff]
                    if not rate_limit_create[ip]:
                        del rate_limit_create[ip]
                for ip in list(rate_limit_auth.keys()):
                    rate_limit_auth[ip] = [t for t in rate_limit_auth[ip] if t > cutoff]
                    if not rate_limit_auth[ip]:
                        del rate_limit_auth[ip]
        except Exception as e:
            pass
    
    schedule.every(60).seconds.do(full_cleanup)
    while True:
        schedule.run_pending()
        time.sleep(1)

cleanup_thread = Thread(target=cleanup, daemon=True)
cleanup_thread.start()

def rate_limit(ip, limit_dict, max_attempts, window):
    current_time = time.time()
    with rate_limit_lock:
        limit_dict[ip] = [t for t in limit_dict[ip] if t > current_time - window]
        if len(limit_dict[ip]) >= max_attempts:
            return False
        limit_dict[ip].append(current_time)
        return True

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 32:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

def validate_password(password):
    if not password or len(password) < 8 or len(password) > 128:
        return False
    return True

def validate_project_name(project_name):
    if not project_name or len(project_name) < 3 or len(project_name) > 64:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', project_name))

def validate_project_id(project_id):
    if not project_id or len(project_id) != 32:
        return False
    return bool(re.match(r'^[a-f0-9]{32}$', project_id))

def validate_key(key):
    if not key or len(key) > 128:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', key))

def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def validate_hwid(hwid):
    if not hwid or len(hwid) > 128:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', hwid))

def parse_time(time_key):
    current_time = int(time.time())
    if time_key == "1 minute": return current_time + 60
    elif time_key == "1 day": return current_time + 86400
    elif time_key == "1 week": return current_time + 604800
    elif time_key == "1 month": return current_time + 2592000
    elif time_key == "1 year": return current_time + 31536000
    else: return None

def generate_key():
    return secrets.token_hex(32)

def generate_session_token():
    return secrets.token_hex(32)  

def generate_project_id():
    return secrets.token_hex(16)  

def check_banned(project_id, key, hwid, ip):
    with db_lock:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT 1 FROM project_bans WHERE project_id = ? AND (key = ? OR hwid = ? OR ip = ?)", (project_id, key, hwid, ip))
        result = c.fetchone()
        conn.close()
        return result is not None

def sanitize_project_id_path(project_id):
    if not validate_project_id(project_id):
        return None
    return project_id

def log_activity(project_id, key, ip):
    try:
        safe_project_id = sanitize_project_id_path(project_id)
        if not safe_project_id:
            return
        
        activity_file = f"{safe_project_id}_activity.txt"
        timestamp = int(time.time() * 1000)
        log_entry = f"{timestamp}|User authenticated|{key[:16]}|{ip}\n"
        
        if os.path.exists(activity_file):
            size = os.path.getsize(activity_file)
            if size > 1048576:
                with open(activity_file, "r") as f:
                    lines = f.readlines()
                with open(activity_file, "w") as f:
                    f.writelines(lines[-100:])
        
        with open(activity_file, "a") as f:
            f.write(log_entry)
    except:
        pass

def create_account(client, ip):
    try:
        if not rate_limit(ip, rate_limit_create, 5, 3600):
            client.send("Rate limit exceeded".encode("utf-8"))
            return
        
        data = client.recv(1024).decode("utf-8")
        parts = data.split("|")
        if len(parts) != 3:
            client.send("Invalid format".encode("utf-8"))
            return
        
        username, password, hwid = parts
        
        if not validate_username(username):
            client.send("Invalid username format".encode("utf-8"))
            return
        
        if not validate_password(password):
            client.send("Invalid password format".encode("utf-8"))
            return
        
        if not validate_hwid(hwid):
            client.send("Invalid HWID format".encode("utf-8"))
            return
        
        with db_lock:
            conn = get_db()
            try:
                c = conn.cursor()
                c.execute("SELECT 1 FROM accounts WHERE username = ?", (username,))
                if c.fetchone():
                    client.send("Invalid credentials".encode("utf-8"))
                else:
                    hashed = hashpw(password.encode(), gensalt()).decode()
                    c.execute("INSERT INTO accounts (username, password, hwid, created_at) VALUES (?, ?, ?, ?)", (username, hashed, hwid, int(time.time())))
                    conn.commit()
                    client.send("Account successfully created!".encode("utf-8"))
            finally:
                conn.close()
    except Exception as e:
        print(f"[-] Error {e}")

def login_account(client, ip):
    try:
        if not rate_limit(ip, rate_limit_login, 10, 600):
            client.send("invalid|Rate limit exceeded".encode("utf-8"))
            time.sleep(0.75)
            return False
        data = client.recv(1024).decode("utf-8")
        parts = data.split("|")
        if len(parts) != 3:
            client.send("invalid|Invalid format".encode("utf-8"))
            time.sleep(0.75)
            return False

        username, password, hwid = parts  

        if not validate_username(username) or not validate_password(password):
            client.send("invalid|Invalid credentials".encode("utf-8"))
            time.sleep(0.75)
            return False
        
        with db_lock:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT username, password FROM accounts WHERE username = ?", (username,))
            row = c.fetchone()
            conn.close()
        
        if not row:
            client.send("invalid|Invalid credentials".encode("utf-8"))
            time.sleep(0.75)
            return False

        username_db, password_db = row
        hashed = password_db.startswith("$2a$") or password_db.startswith("$2b$") or password_db.startswith("$2y$")

        if hashed:
            if not checkpw(password.encode(), password_db.encode()):
                client.send("invalid|Invalid credentials".encode("utf-8"))
                time.sleep(0.75)
                return False
        else:
            if not secrets.compare_digest(password, password_db):
                client.send("invalid|Invalid credentials".encode("utf-8"))
                time.sleep(0.75)
                return False
            new_pw = hashpw(password.encode(), gensalt()).decode()
            with db_lock:
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE accounts SET password = ? WHERE username = ?", (new_pw, username))
                conn.commit()
                conn.close()
        
        token = generate_session_token()
        exp = int(time.time()) + 3600 
        with active_sessions_lock:
            active_sessions[token] = {"username": username, "expires": exp}

        client.send(f"TOKEN|{token}|Login success!".encode("utf-8"))
        return True, token

    except Exception as e:
        try:
            client.send("invalid|Server error".encode("utf-8"))
        except:
            pass
        return False

def create_project(client, username):
    try:
        project_name = client.recv(1024).decode("utf-8")
        
        if not validate_project_name(project_name):
            client.send("Invalid project name format".encode("utf-8"))
            return
        
        with db_lock:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM projects WHERE username = ?", (username,))
            count = c.fetchone()[0]
            if count >= 10:
                client.send("Max projects reached!".encode("utf-8"))
                conn.close()
                return
            c.execute("SELECT 1 FROM projects WHERE project_name = ?", (project_name,))
            if c.fetchone():
                client.send("Project name taken!".encode("utf-8"))
            else:
                project_id = generate_project_id()
                c.execute("INSERT INTO projects (username, project_name, project_id, created_at) VALUES (?, ?, ?, ?)", (username, project_name, project_id, int(time.time())))
                c.execute("INSERT INTO project_ips (project_id, ip_list) VALUES (?, ?)", (project_id, ""))
                conn.commit()
                client.send("Project created!".encode("utf-8"))
            conn.close()
    except Exception as e:
        print(f"[-] Error {e}")

def list_projects(client, username):
    try:
        with db_lock:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT project_name, project_id FROM projects WHERE username = ?", (username,))
            projects = c.fetchall()
            conn.close()
        
        project_list = "|".join([f"{p[0]}:{p[1]}" for p in projects])
        client.send(project_list.encode("utf-8"))
    except Exception as e:
        print(f"[-] Error {e}")

def client_auth(client, address):
    try:
        if not rate_limit(address[0], rate_limit_auth, 30, 60):
            client.send("Rate limit exceeded".encode("utf-8"))
            client.close()
            return False
        
        received_data = client.recv(1024).decode("utf-8")
        parts = received_data.split("|")
        if len(parts) != 3:
            client.send("Invalid data format".encode("utf-8"))
            client.close()
            return False
        
        project_id, key, hwid = parts
        
        if not validate_project_id(project_id):
            client.send("Invalid project ID".encode("utf-8"))
            client.close()
            return False
        
        if not validate_key(key):
            client.send("Invalid key format".encode("utf-8"))
            client.close()
            return False
        
        if not validate_hwid(hwid):
            client.send("Invalid HWID format".encode("utf-8"))
            client.close()
            return False
        
        if check_banned(project_id, key, hwid, address[0]):
            client.send("Banned".encode("utf-8"))
            client.close()
            return False
        
        with db_lock:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT key, hwid, expiration_timestamp FROM project_keys WHERE project_id = ? AND key = ?", (project_id, key))
            key_data = c.fetchone()
            
            if not key_data:
                client.send("Invalid key".encode("utf-8"))
                conn.close()
                client.close()
                return False
            
            db_key, stored_hwid, expiration_timestamp = key_data
            
            if expiration_timestamp and expiration_timestamp < int(time.time()):
                client.send("Key expired".encode("utf-8"))
                conn.close()
                client.close()
                return False
            
            if not stored_hwid:
                c.execute("UPDATE project_keys SET hwid = ? WHERE project_id = ? AND key = ?", (hwid, project_id, key))
                conn.commit()
                stored_hwid = hwid
            
            if not secrets.compare_digest(stored_hwid, hwid):
                client.send("HWID Mismatch".encode("utf-8"))
                conn.close()
                client.close()
                return False
            
            c.execute("SELECT ip_list FROM project_ips WHERE project_id = ?", (project_id,))
            ip_result = c.fetchone()
            if ip_result and ip_result[0]:
                allowed_ips = ip_result[0].split("\n")
                if address[0] not in allowed_ips:
                    client.send("IP not authorized".encode("utf-8"))
                    conn.close()
                    client.close()
                    return False
            
            secret = "S3rv3rS3cr3t"
            token = secrets.token_hex(16)
            access_token = hashlib.sha256((token + secret).encode()).hexdigest()
            client.send(f"ACCESS:{access_token}".encode("utf-8"))
            
            with active_users_lock:
                if project_id not in active_users:
                    active_users[project_id] = set()
                active_users[project_id].add(address)
            
            with active_sessions_lock:
                if project_id not in project_active_users:
                    project_active_users[project_id] = set()
                project_active_users[project_id].add((key, address))

            
            log_activity(project_id, key, address[0])
            
            c.execute("INSERT OR REPLACE INTO project_activity (project_id, key, last_active) VALUES (?, ?, ?)", (project_id, key, int(time.time())))
            conn.commit()
            conn.close()
            
            return True, project_id, key
    except:
        return False

def handle_commands(client, username, project_id, address):
    try:
        if not validate_project_id(project_id):
            client.close()
            return

        with db_lock:
            conn = get_db()
            c = conn.cursor()
            row = c.execute("SELECT username FROM projects WHERE project_id = ?", (project_id,)).fetchone()
            conn.close()

        if row is None:
            client.close()
            return

        project_owner = row[0]

        if not secrets.compare_digest(username, project_owner):
            client.close()
            return

        while True:
            command_data = client.recv(1024).decode("utf-8")
            if not command_data:
                break
            
            if "|" not in command_data:
                command_type = command_data
                parts = []
            else:
                parts = command_data.split("|")
                command_type = parts[0]
            
            if command_type == "add_key":
                if len(parts) < 3:
                    continue
                new_key = parts[1]
                time_key = parts[2]
                
                if not validate_key(new_key):
                    continue
                
                expiration = parse_time(time_key)
                with db_lock:
                    conn = get_db()
                    try:
                        c = conn.cursor()
                        c.execute("SELECT COUNT(*) FROM project_keys WHERE project_id = ?", (project_id,))
                        count = c.fetchone()[0]
                        if count < 1000:
                            c.execute("SELECT 1 FROM project_keys WHERE project_id = ? AND key = ?", (project_id, new_key))
                            if c.fetchone():
                                pass
                            else:
                                c.execute("INSERT INTO project_keys (project_id, key, hwid, timestamp, expiration_type, expiration_timestamp) VALUES (?, ?, ?, ?, ?, ?)", 
                                        (project_id, new_key, "", int(time.time()), time_key, expiration))
                                conn.commit()
                    except sqlite3.IntegrityError as e:
                        conn.rollback()
                    except Exception as e:
                        conn.rollback()
                    finally:
                        conn.close()
            
            elif command_type == "remove_keys":
                if len(parts) < 2:
                    continue
                key_to_remove = parts[1]
                
                if not validate_key(key_to_remove):
                    continue
                
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("DELETE FROM project_keys WHERE project_id = ? AND key = ?", (project_id, key_to_remove))
                    conn.commit()
                    conn.close()
            
            elif command_type == "remove_bans":
                if len(parts) < 3:
                    continue
                option = parts[1]
                if option == "1":
                    ip = parts[2]
                    if not validate_ip(ip):
                        continue
                    with db_lock:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("DELETE FROM project_bans WHERE project_id = ? AND ip = ?", (project_id, ip))
                        conn.commit()
                        conn.close()
                elif option == "2" or option == "key":
                    key = parts[2]
                    if not validate_key(key):
                        continue
                    with db_lock:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("DELETE FROM project_bans WHERE project_id = ? AND key = ?", (project_id, key))
                        conn.commit()
                        conn.close()
                elif option == "3" or option == "hwid":
                    hwid = parts[2]
                    if not validate_hwid(hwid):
                        continue
                    with db_lock:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("DELETE FROM project_bans WHERE project_id = ? AND hwid = ?", (project_id, hwid))
                        conn.commit()
                        conn.close()
            
            elif command_type == "mass_key":
                if len(parts) < 3:
                    continue
                try:
                    num_keys = int(parts[1])
                    if num_keys > 100 or num_keys < 1:
                        continue
                except:
                    continue
                time_key = parts[2]
                expiration = parse_time(time_key)
                with db_lock:
                    conn = get_db()
                    try:
                        c = conn.cursor()
                        c.execute("SELECT COUNT(*) FROM project_keys WHERE project_id = ?", (project_id,))
                        count = c.fetchone()[0]
                        if count + num_keys <= 1000:
                            for _ in range(num_keys):
                                max_attempts = 5
                                for attempt in range(max_attempts):
                                    new_key = generate_key()
                                    try:
                                        c.execute("INSERT INTO project_keys (project_id, key, hwid, timestamp, expiration_type, expiration_timestamp) VALUES (?, ?, ?, ?, ?, ?)", 
                                                (project_id, new_key, "", int(time.time()), time_key, expiration))
                                        break
                                    except sqlite3.IntegrityError:
                                        if attempt == max_attempts - 1:
                                            pass
                            conn.commit()
                    except Exception as e:
                        conn.rollback()
                    finally:
                        conn.close()
            
            elif command_type == "ban_pepole":
                if len(parts) < 3:
                    continue
                option = parts[1]
                if option == "1":
                    ip = parts[2]
                    if not validate_ip(ip):
                        continue
                    with db_lock:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("INSERT INTO project_bans (project_id, ip) VALUES (?, ?)", (project_id, ip))
                        conn.commit()
                        conn.close()
                elif option == "2" or option == "key":
                    key = parts[2]
                    if not validate_key(key):
                        continue
                    with db_lock:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("INSERT INTO project_bans (project_id, key) VALUES (?, ?)", (project_id, key))
                        conn.commit()
                        conn.close()
                elif option == "3" or option == "hwid":
                    hwid = parts[2]
                    if not validate_hwid(hwid):
                        continue
                    with db_lock:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("INSERT INTO project_bans (project_id, hwid) VALUES (?, ?)", (project_id, hwid))
                        conn.commit()
                        conn.close()
            
            elif command_type == "change_expire_date":
                if len(parts) < 3:
                    continue
                key = parts[1]
                time_key = parts[2]
                
                if not validate_key(key):
                    continue
                
                expiration = parse_time(time_key)
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("UPDATE project_keys SET expiration_type = ?, expiration_timestamp = ? WHERE project_id = ? AND key = ?", (time_key, expiration, project_id, key))
                    conn.commit()
                    conn.close()
            
            elif command_type == "hwid":
                if len(parts) < 2:
                    continue
                key = parts[1]
                
                if not validate_key(key):
                    continue
                
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("UPDATE project_keys SET hwid = '' WHERE project_id = ? AND key = ?", (project_id, key))
                    conn.commit()
                    conn.close()
            
            elif command_type == "Statistics":
                current_time = int(time.time())
                thirty_min_ago = current_time - 1800
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT COUNT(DISTINCT key) FROM project_activity WHERE project_id = ? AND last_active > ?", (project_id, thirty_min_ago))
                    active_count = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM project_keys WHERE project_id = ?", (project_id,))
                    total_keys = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM project_keys WHERE project_id = ? AND hwid IS NOT NULL AND TRIM(hwid) != ''", (project_id,))
                    keys_with_hwid = c.fetchone()[0]
                    conn.close()
                with active_users_lock:
                    dynamic_count = len(active_users.get(project_id, set()))
                data = f"{active_count}|{dynamic_count}|{total_keys}|{keys_with_hwid}"
                client.send(data.encode("utf-8"))
            
            elif command_type == "r_all_keys":
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("DELETE FROM project_keys WHERE project_id = ?", (project_id,))
                    conn.commit()
                    conn.close()
            
            elif command_type == "recent_activity":
                safe_project_id = sanitize_project_id_path(project_id)
                if not safe_project_id:
                    client.send("<END_OF_ACTIVITY>".encode())
                    continue
                
                activity_file = f"{safe_project_id}_activity.txt"
                activity_data = ""
                if os.path.exists(activity_file):
                    with open(activity_file, "r") as f:
                        lines = f.readlines()
                    recent_lines = lines[-20:]
                    recent_lines.reverse()
                    for line in recent_lines:
                        if line.strip():
                            parts = line.strip().split("|")
                            if len(parts) >= 3:
                                timestamp, action, key = parts[0], parts[1], parts[2]
                                activity_data += f"{action}|{key}|{timestamp}\n"
                activity_data += "<END_OF_ACTIVITY>"
                client.send(activity_data.encode())
            
            elif command_type == "user_distribution":
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM project_keys WHERE project_id = ? AND hwid IS NOT NULL AND TRIM(hwid) != ''", (project_id,))
                    active = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM project_keys WHERE project_id = ? AND (hwid IS NULL OR TRIM(hwid) = '')", (project_id,))
                    inactive = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM project_bans WHERE project_id = ?", (project_id,))
                    banned = c.fetchone()[0]
                    conn.close()
                data = f"{active}|{inactive}|{banned}"
                client.send(data.encode())
            
            elif command_type == "stats_comparison":
                client.send("12.0|8.5|15.2|6.8".encode())
            
            elif command_type == "list_bans":
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT ip, key, hwid FROM project_bans WHERE project_id = ?", (project_id,))
                    rows = c.fetchall()
                    conn.close()
                all_bans = ""
                for ip, key, hwid in rows:
                    if ip and ip.strip():
                        all_bans += f"IP: {ip}\n"
                    if key and key.strip():
                        all_bans += f"Key: {key}\n"
                    if hwid and hwid.strip():
                        all_bans += f"HWID: {hwid}\n"
                all_bans += "<END_OF_BANS>"
                client.send(all_bans.encode())
            
            elif command_type == "active_keys":
                with db_lock:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT key, hwid, expiration_timestamp FROM project_keys WHERE project_id = ?", (project_id,))
                    rows = c.fetchall()
                    conn.close()
                all_keys = ""
                for key, hwid, expiration in rows:
                    all_keys += f"Key: {key}, HWID: {hwid}, Expiration: {expiration}\n"
                all_keys += "<END_OF_KEYS>"
                client.send(all_keys.encode())
            
            elif command_type == "get_project_id":
                client.send(project_id.encode("utf-8"))
    except:
        pass
    finally:
        with active_sessions_lock:
            if project_id in project_active_users:
                project_active_users[project_id] = {
                    entry for entry in project_active_users[project_id]
                    if entry[1] != address
        }


def main(client, address):
    print(address)
    project_id = None
    key = None
    try:
        with connection_lock:
            if connection_count[address[0]] >= MAX_CONN:
                client.close()
                return
            connection_count[address[0]] += 1
        
        try:
            check = client.recv(1024).decode("utf-8")
        except:
            return
        
        if not check:
            client.close()
            return
        
        if check == "create_account":
            create_account(client, address[0])
            client.close()
            return
        
        if check == "login_account":
            result = login_account(client, address[0])

            if result and len(result) == 2:
                success, returned = result
                if success:
                    session_token = returned

                    with active_sessions_lock:
                        session = active_sessions.get(session_token)

                    if not session or session.get("expires", 0) < int(time.time()):
                        client.send("SESSION_INVALID_OR_EXPIRED".encode("utf-8"))
                        client.close()
                        return

                    username = session["username"]

                    while True:
                        try:
                            action = client.recv(1024).decode("utf-8")
                        except:
                            break

                        if not action:
                            break

                        if action == "create_project":
                            create_project(client, username)

                        elif action == "list_projects":
                            list_projects(client, username)

                        elif action == "select_project":
                            while True:
                                try:
                                    project_data = client.recv(1024).decode("utf-8")
                                except:
                                    break
                                project_id = project_data

                                if not validate_project_id(project_id):
                                    break

                                handle_commands(client, username, project_id, address)
                                break

            client.close()
            return

        
        if check == "2":
            result = client_auth(client, address)
            if result and len(result) == 3:
                success, project_id, key = result
                if success:
                    try:
                        while True:
                            data = client.recv(1024)
                            if not data:
                                break
                    finally:
                        with active_users_lock:
                            if project_id in active_users:
                                active_users[project_id].discard(address)
                        with active_sessions_lock:
                            if project_id in active_sessions:
                                active_sessions[project_id].discard(f"{key}, {address}")
            return
        
        client.close()
        
    except Exception as e:
        pass
    finally:
        with connection_lock:
            connection_count[address[0]] -= 1
            if connection_count[address[0]] <= 0:
                del connection_count[address[0]]
        try:
            client.close()
        except:
            pass

while True:
    client, address = server.accept()
    try:
        tls_client = context.wrap_socket(client, server_side=True)
        client_thread = Thread(target=main, args=(tls_client, address), daemon=True)
        client_thread.start()
    except ssl.SSLError as e:
        client.close()
    except Exception as e:
        client.close()