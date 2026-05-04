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
    private static readonly byte[] _skEnc = new byte[] { 0xB8, 0xBF, 0xD5, 0x63, 0x73, 0xEC, 0x9C, 0x4B, 0x82, 0x8D, 0xAF, 0x84, 0x32, 0x17, 0x3D, 0x78, 0xF8, 0xCC, 0x41, 0xCB, 0x8A, 0x5D, 0x3B, 0xCD, 0xE9, 0x7C, 0x60, 0x7C, 0x2E, 0x32, 0x0E, 0x33, 0x5B, 0xB5, 0x7C, 0x8D, 0xEE, 0x21, 0x14, 0x56, 0x70, 0x9F, 0xA3, 0x6D, 0x4D, 0x6F, 0x4B, 0xE8, 0x02, 0xC5, 0x6E, 0xE5, 0x7F, 0x33, 0xBC, 0x21, 0x8C, 0x7E, 0xF4, 0xAB, 0x7B, 0x56, 0x1C, 0xA2 };
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
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    string uuid = obj["UUID"]?.ToString();
                    if (!string.IsNullOrEmpty(uuid) && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
                        return uuid;
                }
            }
        }
        catch { }
        return Environment.MachineName ?? "UNKNOWN";
    }

    public static string HmacSha256(string key, string data)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();
        }
    }

    private static bool VerifySig(string data, string sigHex)
    {
        if (_skEnc.Length == 0) return true;
        try
        {
            byte[] raw = new byte[_skEnc.Length];
            for (int i = 0; i < raw.Length; i++) raw[i] = (byte)(_skEnc[i] ^ _xk[i % _xk.Length]);
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
        if (Debugger.IsAttached) Environment.Exit(0);

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
            using (var client = new TcpClient())
            {
                client.ConnectAsync(host, _port).Wait(15000);
                using (var sslStream = new SslStream(client.GetStream(), false, ValidateCert))
                {
                    sslStream.AuthenticateAsClient(host);

                    if (_cfEnc.Length > 0 && _lastCertHash != null)
                    {
                        string expected = Xd(_cfEnc).ToUpper();
                        if (_lastCertHash != expected)
                            return false;
                    }

                    byte[] handshake = Encoding.UTF8.GetBytes("2");
                    sslStream.Write(handshake, 0, handshake.Length);
                    Thread.Sleep(200);

                    string authData = $"{PROJECT_ID}|{key}|{GetHWID()}";
                    byte[] data = Encoding.UTF8.GetBytes(authData);
                    sslStream.Write(data, 0, data.Length);

                    byte[] buffer = new byte[4096];
                    int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    if (!response.StartsWith("CHALLENGE|"))
                        return false;

                    string[] parts = response.Split('|');
                    if (parts.Length != 3) return false;
                    string challenge = parts[2];
                    string sig = HmacSha256(key, parts[2]);
                    byte[] respBytes = Encoding.UTF8.GetBytes($"RESPONSE|{parts[1]}|{sig}");
                    sslStream.Write(respBytes, 0, respBytes.Length);
                    bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    if (!response.StartsWith("ACCESS|"))
                        return false;

                    string[] accessParts = response.Split('|');
                    if (accessParts.Length < 4) return false;
                    string accessToken = accessParts[1];
                    string serverProof = accessParts[2];
                    string authSig = accessParts[3];
                    string expectedProof = HmacSha256(key, challenge + "|" + accessToken);
                    if (serverProof != expectedProof) return false;
                    if (!VerifySig(challenge + "|" + accessToken, authSig)) return false;

                    string rawToken = $"AUTH_TOKEN_V2|{accessToken}|{HmacSha256(key, accessToken)}";
                    StoreToken(rawToken);
                    return true;
                }
            }
        }
        catch { return false; }
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
                        string expected = Xd(_cfEnc).ToUpper();
                        if (_lastCertHash != expected)
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
                    string verifyData = $"VERIFY:{PROJECT_ID}:{remaining}";
                    string expected = HmacSha256(key, verifyData);
                    return verifyProof == expected && VerifySig(verifyData, vSig);
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

    static void Main()
    {
        CheckDebugger();
        Console.Write("Enter your license key: ");
        string key = Console.ReadLine();
        if (Authenticate(key))
        {
            Console.WriteLine("Authenticated.");
            StartSessionValidation(key);
        }
        else
        {
            Environment.Exit(1);
        }
    }
}
