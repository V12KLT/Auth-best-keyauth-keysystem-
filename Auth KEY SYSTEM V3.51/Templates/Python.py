import ssl, wmi, hashlib, sys, time, hmac
from socket import socket, AF_INET, SOCK_STREAM
from colorama import Fore, init

init(autoreset=True)

def authenticate(PROJECT_ID, key):
    try:
        hwid = hashlib.sha256(wmi.WMI().Win32_ComputerSystemProduct()[0].UUID.encode()).hexdigest()
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket(AF_INET, SOCK_STREAM), server_hostname="socket.keyauth.shop")
        s.connect(("socket.keyauth.shop", 3389))
        s.send(b"2")     
        time.sleep(0.2)     
        s.send(f"{PROJECT_ID}|{key}|{hwid}".encode())
        
        r = s.recv(1024).decode()
        
        if r.startswith("CHALLENGE|"):
            parts = r.split("|")
            if len(parts) != 3:
                print(Fore.RED+f"[KeyAuth] Invalid challenge format")
                return False
            
            challenge_id = parts[1]
            challenge = parts[2]
            
            signature = hmac.new(
                key.encode(),
                challenge.encode(),
                hashlib.sha256
            ).hexdigest()
            
            s.send(f"RESPONSE|{challenge_id}|{signature}".encode())
            
            r = s.recv(1024).decode()
        
        if r.startswith("ACCESS|"):
            print(Fore.GREEN+"[KeyAuth] Authenticated.")
            return True
        
        print(Fore.RED+f"[KeyAuth] Refused: {r}")
        return False
        
    except Exception as e:
        print(Fore.RED+f"[KeyAuth] Error: {e}")
        return False

PROJECT_ID = "e0bc069afb6a0e4de767700dab2e8b90"
key = input("Enter your license key: ")
if authenticate(PROJECT_ID, key):
    pass
else:
    sys.exit(1)