import os
import json
import time
import base64
from cryptography.fernet import Fernet

DATA_FOLDER = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), '.keyauth_data')
if not os.path.exists(DATA_FOLDER):
    try:
        os.makedirs(DATA_FOLDER)
    except Exception:
        pass

CREDENTIALS_FILE = os.path.join(DATA_FOLDER, 'credentials.dat')
KEY_FILE = os.path.join(DATA_FOLDER, 'security.key')

SERVER_HOST = "socket.keyauth.shop"
SERVER_PORT = 3389

CLIENT_VERSION = "V1.6"
CLIENT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_encryption_key():
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                return f.read()
        except Exception:
            pass
    
    key = Fernet.generate_key()
    try:
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    except Exception:
        pass
    return key

CIPHER = Fernet(load_encryption_key())

def load_past_logins():
    try:
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_past_login(user, pwd):
    try:
        logins = load_past_logins()
        encrypted_pwd = CIPHER.encrypt(pwd.encode()).decode()
        
        logins = [l for l in logins if l.get("username") != user]
        logins.append({"username": user, "password": encrypted_pwd, "last_login": int(time.time())})
        
        if len(logins) > 10:
            logins = logins[-10:]
            
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(logins, f)
    except Exception:
        pass

def delete_past_login(user):
    logins = load_past_logins()
    logins = [l for l in logins if l.get("username") != user]
    try:
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(logins, f)
    except Exception:
        pass

def get_past_login_password(user):
    logins = load_past_logins()
    for login in logins:
        if login.get("username") == user:
            try:
                encrypted = login["password"]
                try:
                    return CIPHER.decrypt(encrypted.encode()).decode()
                except Exception:
                    try:
                        return base64.b64decode(encrypted.encode()).decode()
                    except Exception:
                        pass
            except Exception:
                pass
    return None
