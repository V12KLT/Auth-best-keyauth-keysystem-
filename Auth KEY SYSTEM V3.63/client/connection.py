import ssl
import requests
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

import platform
import subprocess

def get_motherboard_serial():
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                stderr=subprocess.DEVNULL
            ).decode().strip().splitlines()
            for line in result:
                line = line.strip()
                if line and line != "UUID":
                    return line
        elif system == "Linux":
            try:
                with open("/etc/machine-id", "r") as f:
                    return f.read().strip()
            except Exception:
                result = subprocess.check_output(
                    ["cat", "/proc/cpuinfo"],
                    stderr=subprocess.DEVNULL
                ).decode()
                for line in result.splitlines():
                    if "Serial" in line:
                        return line.split(":")[-1].strip()
        elif system == "Darwin":
            result = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in result.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
    except Exception:
        pass
    raw = platform.node() + platform.processor() + platform.machine()
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

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
