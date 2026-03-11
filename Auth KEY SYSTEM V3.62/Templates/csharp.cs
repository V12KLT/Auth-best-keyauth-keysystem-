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

                    byte[] handshake = Encoding.UTF8.GetBytes("2");
                    sslStream.Write(handshake, 0, handshake.Length);
                    Thread.Sleep(200);

                    string authData = $"{PROJECT_ID}|{key}|{GetHWID()}";
                    byte[] data = Encoding.UTF8.GetBytes(authData);
                    sslStream.Write(data, 0, data.Length);

                    byte[] buffer = new byte[4096];
                    int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    if (response.StartsWith("CHALLENGE|"))
                    {
                        string[] parts = response.Split('|');
                        if (parts.Length != 3) return false;
                        string sig = HmacSha256(key, parts[2]);
                        byte[] respBytes = Encoding.UTF8.GetBytes($"RESPONSE|{parts[1]}|{sig}");
                        sslStream.Write(respBytes, 0, respBytes.Length);
                        bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                        response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    }

                    if (response.StartsWith("ACCESS|"))
                    {
                        string serverData = response.Substring(7);
                        string rawToken = $"AUTH_TOKEN_V2|{serverData}|{HmacSha256(key, serverData)}";
                        StoreToken(rawToken);
                        return true;
                    }
                    return false;
                }
            }
        }
        catch { return false; }
    }

    private static bool ValidateCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        return errors == SslPolicyErrors.None || errors == SslPolicyErrors.RemoteCertificateChainErrors;
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
                    sslStream.Write(Encoding.UTF8.GetBytes("3"), 0, 1);
                    Thread.Sleep(100);
                    string verifyData = $"{PROJECT_ID}|{key}|{GetHWID()}";
                    byte[] data = Encoding.UTF8.GetBytes(verifyData);
                    sslStream.Write(data, 0, data.Length);
                    byte[] buffer = new byte[1024];
                    int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead <= 0) return false;
                    string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    return response.StartsWith("VALID");
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