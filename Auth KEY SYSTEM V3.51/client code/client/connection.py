import ssl
import requests
import wmi
from socket import AF_INET, SOCK_STREAM, socket

try:
    from .config import SERVER_HOST, SERVER_PORT
except ImportError:
    from config import SERVER_HOST, SERVER_PORT

client = None

def get_motherboard_serial():
    try:
        c = wmi.WMI()
        for item in c.Win32_ComputerSystemProduct():
            return item.UUID
    except:
        return "UNKNOWN-HWID"

motherboard = get_motherboard_serial()

def ipv4():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return "127.0.0.1"

ip_address = ipv4()

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
        except:
            pass
        client = None
