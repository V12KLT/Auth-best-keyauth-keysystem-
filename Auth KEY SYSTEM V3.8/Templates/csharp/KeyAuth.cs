using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public class KeyAuth
{
    private static readonly byte[] _xk = { 0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33 };
    private static readonly byte[] _hEnc = { 0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82 };
    private const int _port = 3389;
    private const string PROJECT_ID = "ENTER_PROJECT_ID_HERE";

    private static readonly byte[] _cfEnc = new byte[] { 0x94, 0x7E, 0xB1, 0x6A, 0xD4, 0xF0, 0x5A, 0x3D, 0xDA, 0x3C, 0x55, 0xFA, 0x77, 0x97, 0xB2, 0x71, 0xE5, 0x0F, 0xC4, 0x68, 0xD3, 0x80, 0x29, 0x3F, 0xA0, 0x39, 0x23, 0x89, 0x0A, 0xE7, 0xC0, 0x72, 0xE2, 0x0F, 0xC4, 0x68, 0xA7, 0x87, 0x2C, 0x3F, 0xA7, 0x3E, 0x57, 0x88, 0x09, 0xE3, 0xC6, 0x70, 0x95, 0x0F, 0xB6, 0x6D, 0xD5, 0xF3, 0x2D, 0x39, 0xD2, 0x4B, 0x25, 0x8C, 0x09, 0xEA, 0xB3, 0x75 };
    private static byte[] _cachedPubKey = null;
    private static string _lastCertHash = null;

    private static byte[] _encToken = null;
    private static uint _tokenCanary = 0;
    private static bool _tokenPresent = false;
    private static readonly object _tokenLock = new object();
    private static volatile bool _sessionActive = false;

    private static string Xd(byte[] data)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) result[i] = (byte)(data[i] ^ _xk[i % _xk.Length]);
        return Encoding.UTF8.GetString(result);
    }

    private static byte[] Xe(string input)
    {
        byte[] raw = Encoding.UTF8.GetBytes(input);
        byte[] result = new byte[raw.Length];
        for (int i = 0; i < raw.Length; i++) result[i] = (byte)(raw[i] ^ _xk[i % _xk.Length]);
        return result;
    }

    private static uint Fnv1a(byte[] data)
    {
        uint hash = 0x811C9DC5;
        foreach (byte b in data) { hash ^= b; hash *= 0x01000193; }
        return hash ^ 0xDEADBEEF;
    }

    private static void StoreToken(string token)
    {
        lock (_tokenLock)
        {
            _encToken = Xe(token);
            _tokenCanary = Fnv1a(_encToken);
            _tokenPresent = true;
        }
    }

    private static string GetToken()
    {
        lock (_tokenLock)
        {
            if (!_tokenPresent || _encToken == null) return null;
            if (Fnv1a(_encToken) != _tokenCanary) Environment.Exit(0);
            return Xd(_encToken);
        }
    }

    private static bool TokenValid()
    {
        string token = GetToken();
        if (string.IsNullOrEmpty(token)) return false;
        if (!token.StartsWith("AUTH_TOKEN_V2|")) return false;
        return token.Length > 22;
    }

    private static string Host() { return Xd(_hEnc); }

    public static string GetHWID()
    {
        string raw;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    string uuid = obj["UUID"]?.ToString();
                    if (!string.IsNullOrEmpty(uuid) && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
                    {
                        raw = uuid;
                        using (var sha = SHA256.Create())
                        {
                            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
                            return BitConverter.ToString(hash).Replace("-", "").ToLower();
                        }
                    }
                }
            }
        }
        catch { }
        raw = Environment.MachineName ?? "UNKNOWN";
        using (var sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }

    public static string HmacSha256(string key, string data)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();
        }
    }

    private static byte[] FetchPubKey()
    {
        if (_cachedPubKey != null) return _cachedPubKey;
        try
        {
            string h = Host();
            using (var tcp = new TcpClient(h, _port))
            using (var ssl = new SslStream(tcp.GetStream(), false, (s, c, ch, e) => true))
            {
                ssl.AuthenticateAsClient(h);
                byte[] cmd = Encoding.UTF8.GetBytes("8");
                ssl.Write(cmd, 0, cmd.Length);
                ssl.Flush();
                byte[] buf = new byte[4096];
                int n = ssl.Read(buf, 0, buf.Length);
                string resp = Encoding.UTF8.GetString(buf, 0, n);
                if (resp.StartsWith("PUBKEY|"))
                {
                    string hex = resp.Substring(7);
                    byte[] raw = new byte[hex.Length / 2];
                    for (int i = 0; i < raw.Length; i++)
                        raw[i] = (byte)(HexVal(hex[i * 2]) * 16 + HexVal(hex[i * 2 + 1]));
                    if (raw.Length == 64)
                    {
                        _cachedPubKey = raw;
                        return raw;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private static bool VerifySig(string data, string sigHex)
    {
        byte[] raw = FetchPubKey();
        if (raw == null) return true;
        try
        {
            byte[] x = new byte[32], y = new byte[32];
            Array.Copy(raw, 0, x, 0, 32);
            Array.Copy(raw, 32, y, 0, 32);
            using (var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            }))
            {
                byte[] sig = new byte[64];
                for (int i = 0; i < 64; i++)
                {
                    int v1 = HexVal(sigHex[i * 2]), v2 = HexVal(sigHex[i * 2 + 1]);
                    sig[i] = (byte)(v1 * 16 + v2);
                }
                byte[] hash;
                using (var sha = SHA256.Create()) { hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data)); }
                return ecdsa.VerifyHash(hash, sig);
            }
        }
        catch { return true; }
    }

    private static int HexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return 0;
    }

    private static void CheckDebugger()
    {

        string[] bad = { "x64dbg", "x32dbg", "ollydbg", "ida", "ida64", "idag", "idag64",
            "idaw", "idaw64", "wireshark", "fiddler", "charles", "httpdebugger",
            "processhacker", "procmon", "procexp", "dnspy", "de4dot", "cheatengine" };
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLower();
                    if (bad.Any(b => name.Contains(b))) Environment.Exit(0);
                }
                catch { }
            }
        }
        catch { }
    }

    public static bool Authenticate(string key)
    {
        CheckDebugger();
        try
        {
            string host = Host();
            Console.WriteLine($"[DEBUG] Connecting to {host}:{_port}...");
            using (var client = new TcpClient())
            {
                if (!client.ConnectAsync(host, _port).Wait(15000))
                {
                    Console.WriteLine("[DEBUG] Connection timed out");
                    return false;
                }
                Console.WriteLine("[DEBUG] Connected, starting TLS...");
                using (var sslStream = new SslStream(client.GetStream(), false, ValidateCert))
                {
                    sslStream.AuthenticateAsClient(host);
                    Console.WriteLine($"[DEBUG] TLS established, cert hash: {_lastCertHash}");

                    if (_cfEnc.Length > 0 && _lastCertHash != null)
                    {
                        string expected = Xd(_cfEnc).ToUpper();
                        if (_lastCertHash != expected)
                        {
                            Console.WriteLine($"[DEBUG] Cert pin FAILED: expected={expected}, got={_lastCertHash}");
                            return false;
                        }
                        Console.WriteLine("[DEBUG] Cert pin OK");
                    }

                    byte[] handshake = Encoding.UTF8.GetBytes("2");
                    sslStream.Write(handshake, 0, handshake.Length);
                    Thread.Sleep(200);

                    string hwid = GetHWID();
                    Console.WriteLine($"[DEBUG] HWID: {hwid}");
                    string authData = $"{PROJECT_ID}|{key}|{hwid}";
                    byte[] data = Encoding.UTF8.GetBytes(authData);
                    sslStream.Write(data, 0, data.Length);

                    byte[] buffer = new byte[4096];
                    int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Console.WriteLine($"[DEBUG] Server response: {response}");

                    if (!response.StartsWith("CHALLENGE|"))
                    {
                        Console.WriteLine($"[DEBUG] Expected CHALLENGE, got: {response}");
                        return false;
                    }

                    string[] parts = response.Split('|');
                    if (parts.Length != 3) { Console.WriteLine($"[DEBUG] Bad challenge parts: {parts.Length}"); return false; }
                    string challenge = parts[2];
                    string sig = HmacSha256(key, parts[2]);
                    byte[] respBytes = Encoding.UTF8.GetBytes($"RESPONSE|{parts[1]}|{sig}");
                    sslStream.Write(respBytes, 0, respBytes.Length);
                    bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Console.WriteLine($"[DEBUG] Final response: {response}");

                    if (!response.StartsWith("ACCESS|"))
                    {
                        Console.WriteLine($"[DEBUG] Expected ACCESS, got: {response}");
                        return false;
                    }

                    string[] accessParts = response.Split('|');
                    if (accessParts.Length < 4) { Console.WriteLine("[DEBUG] Bad access parts"); return false; }
                    string accessToken = accessParts[1];
                    string serverProof = accessParts[2];
                    string authSig = accessParts[3];
                    string expectedProof = HmacSha256(key, challenge + "|" + accessToken);
                    if (serverProof != expectedProof) { Console.WriteLine("[DEBUG] Server proof mismatch"); return false; }
                    if (!VerifySig(challenge + "|" + accessToken, authSig)) { Console.WriteLine("[DEBUG] Sig verify failed"); return false; }

                    string rawToken = $"AUTH_TOKEN_V2|{accessToken}|{HmacSha256(key, accessToken)}";
                    StoreToken(rawToken);
                    Console.WriteLine("[DEBUG] Auth success!");
                    return true;
                }
            }
        }
        catch (Exception ex) { Console.WriteLine($"[DEBUG] Exception: {ex}"); return false; }
    }

    private static bool ValidateCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        if (cert != null)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(cert.GetRawCertData());
                _lastCertHash = BitConverter.ToString(hash).Replace("-", "").ToUpper();
            }
        }

        if (_cfEnc.Length > 0 && _lastCertHash != null)
        {
            string expected = Xd(_cfEnc).ToUpper();
            return _lastCertHash == expected;
        }

        return errors == SslPolicyErrors.None;
    }

    private static bool VerifySession(string key)
    {
        if (!TokenValid()) { Environment.Exit(0); return false; }
        try
        {
            string host = Host();
            using (var client = new TcpClient())
            {
                client.ConnectAsync(host, _port).Wait(10000);
                using (var sslStream = new SslStream(client.GetStream(), false, ValidateCert))
                {
                    sslStream.AuthenticateAsClient(host);

                    if (_cfEnc.Length > 0 && _lastCertHash != null)
                    {
                        string expectedHash = Xd(_cfEnc).ToUpper();
                        if (_lastCertHash != expectedHash)
                        {
                            Environment.Exit(0);
                            return false;
                        }
                    }

                    sslStream.Write(Encoding.UTF8.GetBytes("3"), 0, 1);
                    Thread.Sleep(100);
                    string verifyData = $"{PROJECT_ID}|{key}|{GetHWID()}";
                    byte[] data = Encoding.UTF8.GetBytes(verifyData);
                    sslStream.Write(data, 0, data.Length);
                    byte[] buffer = new byte[1024];
                    int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead <= 0) return false;
                    string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    if (!response.StartsWith("VALID|")) return false;
                    string[] vParts = response.Split('|');
                    if (vParts.Length < 5) return false;
                    string remaining = vParts[2];
                    string verifyProof = vParts[3];
                    string vSig = vParts[4];
                    verifyData = $"VERIFY:{PROJECT_ID}:{remaining}";
                    string expectedVerifyProof = HmacSha256(key, verifyData);
                    return verifyProof == expectedVerifyProof && VerifySig(verifyData, vSig);
                }
            }
        }
        catch { return false; }
    }

    public static void StartSessionValidation(string key)
    {
        _sessionActive = true;
        var thread = new Thread(() =>
        {
            int failures = 0;
            while (_sessionActive)
            {
                Thread.Sleep(60000);
                if (!_sessionActive) break;
                CheckDebugger();
                if (VerifySession(key)) { failures = 0; }
                else { failures++; if (failures >= 3) Environment.Exit(0); }
            }
        });
        thread.IsBackground = true;
        thread.Start();
    }

    [System.Runtime.InteropServices.DllImport("shell32.dll", SetLastError = true)]
    private static extern bool ShellExecuteExW(ref SHELLEXECUTEINFO lpExecInfo);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private struct SHELLEXECUTEINFO
    {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        public string lpVerb;
        public string lpFile;
        public string lpParameters;
        public string lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        public string lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIconOrMonitor;
        public IntPtr hProcess;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private static byte[] RecvExact(SslStream stream, int n)
    {
        byte[] buf = new byte[n];
        int offset = 0;
        while (offset < n)
        {
            int read = stream.Read(buf, offset, n - offset);
            if (read <= 0) return null;
            offset += read;
        }
        return buf;
    }

    public static byte[] DownloadFile(string key, string fileName)
    {
        try
        {
            string host = Host();
            using (var client = new TcpClient())
            {
                client.ConnectAsync(host, _port).Wait(30000);
                using (var sslStream = new SslStream(client.GetStream(), false, ValidateCert))
                {
                    sslStream.AuthenticateAsClient(host);
                    if (_cfEnc.Length > 0 && _lastCertHash != null)
                    {
                        string expected = Xd(_cfEnc).ToUpper();
                        if (_lastCertHash != expected) return null;
                    }

                    sslStream.Write(Encoding.UTF8.GetBytes("6"));
                    Thread.Sleep(100);
                    string reqData = $"{PROJECT_ID}|{key}|{GetHWID()}|{fileName}";
                    sslStream.Write(Encoding.UTF8.GetBytes(reqData));

                    byte[] hdrLenRaw = RecvExact(sslStream, 4);
                    if (hdrLenRaw == null) return null;
                    int hdrLen = (hdrLenRaw[0] << 24) | (hdrLenRaw[1] << 16) | (hdrLenRaw[2] << 8) | hdrLenRaw[3];
                    if (hdrLen > 4096) return null;
                    byte[] hdrBytes = RecvExact(sslStream, hdrLen);
                    if (hdrBytes == null) return null;
                    string header = Encoding.UTF8.GetString(hdrBytes);
                    if (header.StartsWith("ERROR")) return null;

                    string[] parts = header.Split('|');
                    if (parts.Length < 5 || parts[0] != "FILE") return null;
                    string nonceHex = parts[1], tagHex = parts[2], expectedHash = parts[3];
                    int fileSize = int.Parse(parts[4]);

                    byte[] bodyLenRaw = RecvExact(sslStream, 4);
                    if (bodyLenRaw == null) return null;
                    int bodyLen = (bodyLenRaw[0] << 24) | (bodyLenRaw[1] << 16) | (bodyLenRaw[2] << 8) | bodyLenRaw[3];
                    if (bodyLen > 60 * 1024 * 1024) return null;
                    byte[] body = RecvExact(sslStream, bodyLen);
                    if (body == null) return null;

                    byte[] nonce = HexToBytes(nonceHex);
                    byte[] tag = HexToBytes(tagHex);
                    if (nonce.Length != 12 || tag.Length != 16) return null;

                    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
                    {
                        byte[] fileKey = hmac.ComputeHash(Encoding.UTF8.GetBytes("FILE_KEY:" + nonceHex));
                        using (var aes = new System.Security.Cryptography.AesGcm(fileKey))
                        {
                            byte[] plaintext = new byte[body.Length];
                            aes.Decrypt(nonce, body, tag, plaintext, Encoding.UTF8.GetBytes(PROJECT_ID));
                            using (var sha = SHA256.Create())
                            {
                                string actualHash = BitConverter.ToString(sha.ComputeHash(plaintext)).Replace("-", "").ToLower();
                                if (actualHash != expectedHash || plaintext.Length != fileSize) return null;
                            }
                            return plaintext;
                        }
                    }
                }
            }
        }
        catch { return null; }
    }

    private static byte[] HexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static void SecureWipe(string path)
    {
        try
        {
            long size = new FileInfo(path).Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write))
            {
                byte[] zeros = new byte[size];
                fs.Write(zeros, 0, zeros.Length);
                fs.Flush();
            }
            File.Delete(path);
        }
        catch { try { File.Delete(path); } catch { } }
    }

    public static bool DownloadAndRun(string key, string fileName)
    {
        byte[] data = DownloadFile(key, fileName);
        if (data == null) return false;
        try
        {
            string tempBase = Path.GetTempPath();
            string randomDir = Path.Combine(tempBase, "_ka_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(randomDir);
            File.SetAttributes(randomDir, FileAttributes.Hidden | FileAttributes.System);

            string exePath = Path.Combine(randomDir, fileName);
            File.WriteAllBytes(exePath, data);
            File.SetAttributes(exePath, FileAttributes.Hidden | FileAttributes.Temporary);
            Array.Clear(data, 0, data.Length);

            var sei = new SHELLEXECUTEINFO();
            sei.cbSize = System.Runtime.InteropServices.Marshal.SizeOf(sei);
            sei.fMask = 0x00000040;
            sei.lpVerb = "runas";
            sei.lpFile = exePath;
            sei.lpDirectory = randomDir;
            sei.nShow = 1;
            if (!ShellExecuteExW(ref sei)) return false;
            if (sei.hProcess != IntPtr.Zero) CloseHandle(sei.hProcess);

            string capExe = exePath, capDir = randomDir;
            var cleanupThread = new Thread(() =>
            {
                Thread.Sleep(2000);
                SecureWipe(capExe);
                Thread.Sleep(1000);
                try { Directory.Delete(capDir, true); } catch { }
            });
            cleanupThread.IsBackground = true;
            cleanupThread.Start();
            return true;
        }
        catch { return false; }
    }

    static void Main()
    {
        CheckDebugger();
        Console.Write("Enter your license key: ");
        string key = Console.ReadLine();
        if (Authenticate(key))
        {
            Console.WriteLine("Authenticated.");
            StartSessionValidation(key);
            Console.WriteLine("\nPress any key to keep the session alive (or close this window to exit).");
            Console.ReadKey();
        }
        else
        {
            Console.WriteLine("failed");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        }
    }
}
