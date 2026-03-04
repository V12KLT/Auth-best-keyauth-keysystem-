import ssl, hashlib, sys, time, hmac, os, struct, threading, ctypes
from socket import socket, AF_INET, SOCK_STREAM

_XK = bytes([0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33])

def _xd(data, key=_XK):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

_H_ENC = bytes([0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82])
_P_VAL = 3389

def _gh():
    return _xd(_H_ENC).decode()

def _hwid():
    try:
        if sys.platform == 'win32':
            import subprocess
            r = subprocess.run(['powershell', '-Command', 'Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID'], capture_output=True, text=True, timeout=10)
            uid = r.stdout.strip()
            if uid and uid != 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF':
                return hashlib.sha256(uid.encode()).hexdigest()
        else:
            for p in ['/sys/class/dmi/id/product_uuid', '/etc/machine-id']:
                if os.path.exists(p):
                    with open(p) as f:
                        uid = f.read().strip()
                        if uid:
                            return hashlib.sha256(uid.encode()).hexdigest()
    except Exception:
        pass
    import platform
    return hashlib.sha256(platform.node().encode()).hexdigest()

def _fnv1a(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h ^ 0xDEADBEEF

class _TokenStore:
    def __init__(self):
        self._enc = bytearray()
        self._canary = 0
        self._present = False
        self._lock = threading.Lock()

    def store(self, token):
        with self._lock:
            raw = token.encode()
            self._enc = bytearray(_xd(raw))
            self._canary = _fnv1a(self._enc)
            self._present = True

    def get(self):
        with self._lock:
            if not self._present or not self._enc:
                return None
            if _fnv1a(self._enc) != self._canary:
                os._exit(0)
            return _xd(bytes(self._enc)).decode()

    @property
    def valid(self):
        with self._lock:
            if not self._present or not self._enc:
                return False
            return _fnv1a(self._enc) == self._canary

_ts = _TokenStore()

def _adbg():
    try:
        if sys.platform == 'win32':
            k32 = ctypes.windll.kernel32
            if k32.IsDebuggerPresent():
                os._exit(0)
            bp = ctypes.c_int(0)
            k32.CheckRemoteDebuggerPresent(k32.GetCurrentProcess(), ctypes.byref(bp))
            if bp.value:
                os._exit(0)
        import subprocess
        bad = {'x64dbg', 'x32dbg', 'ollydbg', 'ida', 'ida64', 'idag', 'idag64', 'idaw', 'idaw64',
               'wireshark', 'fiddler', 'charles', 'httpdebugger', 'processhacker', 'procmon',
               'procexp', 'dnspy', 'de4dot', 'cheatengine', 'cheat engine'}
        if sys.platform == 'win32':
            r = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True, text=True, timeout=5)
            for line in r.stdout.lower().split('\n'):
                for b in bad:
                    if b in line:
                        os._exit(0)
    except Exception:
        pass

def authenticate(project_id, key):
    _adbg()
    try:
        hw = _hwid()
        host = _gh()
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket(AF_INET, SOCK_STREAM), server_hostname=host)
        s.settimeout(15)
        s.connect((host, _P_VAL))
        s.send(b"2")
        time.sleep(0.2)
        s.send(f"{project_id}|{key}|{hw}".encode())

        r = s.recv(4096).decode()

        if r.startswith("CHALLENGE|"):
            parts = r.split("|")
            if len(parts) != 3:
                s.close()
                return False
            sig = hmac.new(key.encode(), parts[2].encode(), hashlib.sha256).hexdigest()
            s.send(f"RESPONSE|{parts[1]}|{sig}".encode())
            r = s.recv(4096).decode()

        s.close()

        if r.startswith("ACCESS|"):
            server_data = r[7:]
            raw_token = f"AUTH_TOKEN_V2|{server_data}|{hmac.new(key.encode(), server_data.encode(), hashlib.sha256).hexdigest()}"
            _ts.store(raw_token)
            return True

        return False

    except Exception:
        return False

def _vsess(project_id, key):
    try:
        if not _ts.valid:
            os._exit(0)
        hw = _hwid()
        host = _gh()
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket(AF_INET, SOCK_STREAM), server_hostname=host)
        s.settimeout(15)
        s.connect((host, _P_VAL))
        s.send(b"3")
        time.sleep(0.1)
        s.send(f"{project_id}|{key}|{hw}".encode())
        r = s.recv(4096).decode()
        s.close()
        return r.startswith("VALID")
    except Exception:
        return False

def _session_loop(project_id, key):
    fails = 0
    while True:
        time.sleep(60)
        _adbg()
        if _vsess(project_id, key):
            fails = 0
        else:
            fails += 1
            if fails >= 3:
                os._exit(0)

def start_session(project_id, key):
    t = threading.Thread(target=_session_loop, args=(project_id, key), daemon=True)
    t.start()

PROJECT_ID = "ENTER_PROJECT_ID"
key = input("Enter your license key: ")
if authenticate(PROJECT_ID, key):
    start_session(PROJECT_ID, key)
    print("Authenticated.")
else:
    sys.exit(1)