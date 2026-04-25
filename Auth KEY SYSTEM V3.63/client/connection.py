import ssl
import requests
import wmi
import hashlib
import threading
import time
from socket import AF_INET, SOCK_STREAM, socket

try:
    from .config import SERVER_HOST, SERVER_PORT
except ImportError:
    from config import SERVER_HOST, SERVER_PORT

client = None

SERVER_CERT_FINGERPRINT = None

def get_motherboard_serial():
    try:
        c = wmi.WMI()
        for item in c.Win32_ComputerSystemProduct():
            return item.UUID
    except Exception:
        return "UNKNOWN-HWID"

motherboard = get_motherboard_serial()

def ipv4():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except Exception:
        return "127.0.0.1"

ip_address = ipv4()

def verify_certificate(cert, hostname):
    if SERVER_CERT_FINGERPRINT:
        cert_der = ssl.PEM_cert_to_DER_cert(ssl.DER_cert_to_PEM_cert(cert))
        cert_hash = hashlib.sha256(cert_der).hexdigest()
        return cert_hash.lower() == SERVER_CERT_FINGERPRINT.lower()
    return True

def connect_to_server():
    global client
    if client:
        try:
            client.getpeername()
            return client
        except Exception:
            client = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        s = socket(AF_INET, SOCK_STREAM)
        client = context.wrap_socket(s, server_hostname=SERVER_HOST)
        client.settimeout(10)
        client.connect((SERVER_HOST, SERVER_PORT))
        
        if SERVER_CERT_FINGERPRINT:
            cert = client.getpeercert(binary_form=True)
            if cert:
                cert_hash = hashlib.sha256(cert).hexdigest()
                if cert_hash.lower() != SERVER_CERT_FINGERPRINT.lower():
                    client.close()
                    client = None
                    raise ssl.SSLError("Certificate fingerprint mismatch")
        
        return client
    except Exception as e:
        client = None
        raise e

def get_client():
    global client
    return client

def set_client(new_client):
    global client
    client = new_client

def close_client():
    global client
    if client:
        try:
            client.close()
        except Exception:
            pass
        client = None

def start_heartbeat():
    def heartbeat():
        global client
        while True:
            time.sleep(15)
            if client:
                try:
                    client.send("PING".encode("utf-8"))
                except Exception:
                    pass
            else:
                pass
                
    t = threading.Thread(target=heartbeat, daemon=True)
    t.start()
