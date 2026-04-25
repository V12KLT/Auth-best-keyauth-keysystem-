import os
import urllib.request
import time
import sys
import ssl
import json
import hashlib
import tempfile
import subprocess
import shutil
import base64
from socket import AF_INET, SOCK_STREAM, socket

try:
    from .config import SERVER_HOST, SERVER_PORT, CLIENT_VERSION, CLIENT_DIR
except ImportError:
    from config import SERVER_HOST, SERVER_PORT, CLIENT_VERSION, CLIENT_DIR

def is_frozen():
    if getattr(sys, 'frozen', False):
         return True
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if "onefile_" in current_dir or "_MEI" in current_dir:
         return True
         
    return False

def get_current_version():
    return CLIENT_VERSION

def check_for_updates():
    s = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(10)
        s.connect((SERVER_HOST, SERVER_PORT))
        
        client = context.wrap_socket(s, server_hostname=SERVER_HOST)
        client.settimeout(10)
        
        update_type = "EXE" if is_frozen() else "CODE"
        request = f"VERSION_CHECK\n{CLIENT_VERSION}\n{update_type}"
        client.send(request.encode("utf-8"))
        
        response = client.recv(1024).decode("utf-8")
        client.close()
        
        if response.startswith("UPDATE_REQUIRED"):
            parts = response.split("|")
            if len(parts) >= 2:
                return {
                    "update_available": True,
                    "new_version": parts[1]
                }
        elif response == "UP_TO_DATE":
            return {"update_available": False}
        
        return {"update_available": False}
    except Exception as e:
        if s:
            try:
                s.close()
            except:
                pass
        return {"update_available": False, "error": True}

def download_code_update():
    s = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(30)
        s.connect((SERVER_HOST, SERVER_PORT))
        
        client = context.wrap_socket(s, server_hostname=SERVER_HOST)
        client.settimeout(30)
        
        client.send("GET_CLIENT_CODE".encode("utf-8"))
        
        data = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"<END_OF_CODE>" in data:
                break
        
        client.close()
        
        content = data.decode("utf-8").replace("<END_OF_CODE>", "")
        
        try:
            files_data = json.loads(content)
            return files_data, None
        except json.JSONDecodeError as e:
            return None, f"Invalid response: {e}"
            
    except Exception as e:
        if s:
            try:
                s.close()
            except:
                pass
        return None, str(e)




def download_exe_update():
    url = "https://github.com/V12KLT/Auth-best-keyauth-keysystem-/releases/download/keysystem/auth.exe"
    try:
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "auth_update.exe")
        
        urllib.request.urlretrieve(url, temp_file)
        
        if os.path.exists(temp_file):
             with open(temp_file, "rb") as f:
                 header = f.read(2)
                 if header != b"MZ":
                      return None, "Downloaded file is not a valid executable (missing MZ header). Likely a MediaFire error page."

        if os.path.getsize(temp_file) < 1000:
             return None, "Downloaded file too small, likely an error page"

        return temp_file, None
            
    except Exception as e:
        return None, str(e)

def backup_client_files():
    backup_dir = os.path.join(CLIENT_DIR, ".backup")
    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)
    os.makedirs(backup_dir)
    
    for filename in os.listdir(CLIENT_DIR):
        if filename.endswith(".py") and filename != "updater.py":
            src = os.path.join(CLIENT_DIR, filename)
            dst = os.path.join(backup_dir, filename)
            shutil.copy2(src, dst)
    
    return backup_dir

def restore_from_backup(backup_dir):
    for filename in os.listdir(backup_dir):
        src = os.path.join(backup_dir, filename)
        dst = os.path.join(CLIENT_DIR, filename)
        shutil.copy2(src, dst)

def install_code_update(files_data):
    try:
        backup_dir = backup_client_files()
        
        for filename, content in files_data.items():
            if not filename.endswith(".py"):
                continue
            if filename == "updater.py":
                continue
            
            filepath = os.path.join(CLIENT_DIR, filename)
            decoded_content = base64.b64decode(content).decode("utf-8")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(decoded_content)
        
        if "config.py" in files_data:
            config_path = os.path.join(CLIENT_DIR, "config.py")
            with open(config_path, "r", encoding="utf-8") as f:
                new_config = f.read()
            
            old_config_path = os.path.join(backup_dir, "config.py")
            if os.path.exists(old_config_path):
                with open(old_config_path, "r", encoding="utf-8") as f:
                    old_config = f.read()
                
                import re
                host_match = re.search(r'SERVER_HOST\s*=\s*["\']([^"\']+)["\']', old_config)
                port_match = re.search(r'SERVER_PORT\s*=\s*(\d+)', old_config)
                
                if host_match:
                    new_config = re.sub(r'SERVER_HOST\s*=\s*["\'][^"\']+["\']', 
                                       f'SERVER_HOST = "{host_match.group(1)}"', new_config)
                if port_match:
                    new_config = re.sub(r'SERVER_PORT\s*=\s*\d+', 
                                       f'SERVER_PORT = {port_match.group(1)}', new_config)
                
                with open(config_path, "w", encoding="utf-8") as f:
                    f.write(new_config)
        
        return True, None
        
    except Exception as e:
        try:
            restore_from_backup(backup_dir)
        except:
            pass
        return False, str(e)

def install_exe_update(new_exe_path):
    try:
        current_exe = sys.executable
        
        if "onefile_" in current_exe or "_MEI" in current_exe:
             current_exe = os.path.abspath(sys.argv[0])

        exe_dir = os.path.dirname(current_exe)
        backup_exe = os.path.join(exe_dir, "auth_backup.exe")
        
        if os.path.exists(backup_exe):
            try:
                os.remove(backup_exe)
            except:
                pass
        
        batch_script = f'''@echo off
timeout /t 3 /nobreak > nul
del /f /q "{backup_exe}" > nul 2>&1
move /y "{current_exe}" "{backup_exe}" > nul 2>&1
move /y "{new_exe_path}" "{current_exe}" > nul 2>&1
start "" "{current_exe}"

:DEL_LOOP
if exist "{backup_exe}" (
    del /f /q "{backup_exe}" > nul 2>&1
    timeout /t 1 /nobreak > nul
    goto DEL_LOOP
)
del "%~f0"
'''
        
        batch_path = os.path.join(tempfile.gettempdir(), "keyauth_update.bat")
        with open(batch_path, "w") as f:
            f.write(batch_script)
        
        subprocess.Popen(
            ["cmd", "/c", batch_path],
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        
        return True, None
    except Exception as e:
        return False, str(e)

def perform_update():
    if is_frozen():
        exe_path, error = download_exe_update()
        if error:
            return False, f"Download failed: {error}"
        if not exe_path:
            return False, "No exe received"
        
        success, error = install_exe_update(exe_path)
        if not success:
            return False, f"Install failed: {error}"
        
        return True, "EXE"
    else:
        files_data, error = download_code_update()
        if error:
            return False, f"Download failed: {error}"
        if not files_data:
            return False, "No code received"
        
        success, error = install_code_update(files_data)
        if not success:
            return False, f"Install failed: {error}"
        
        return True, "CODE"

def restart_client():
    if is_frozen():
        pass
    else:
        python = sys.executable
        os.execl(python, python, *sys.argv)
