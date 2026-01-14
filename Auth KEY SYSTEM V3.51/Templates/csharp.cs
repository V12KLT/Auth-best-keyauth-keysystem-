using System;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Management;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class KeyAuth
{
    private const string SERVER_HOST = "socket.keyauth.shop";
    private const int SERVER_PORT = 3389;
    private const string PROJECT_ID = "ENTER_PROJECT_ID_HERE";
    
    public static string GetHWID()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["UUID"].ToString();
                }
            }
        }
        catch (Exception)
        {
            return Environment.MachineName;
        }
        return "UNKNOWN";
    }
    
    public static string HmacSha256(string key, string data)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }
    
    public static bool Authenticate(string key)
    {
        try
        {
            using (var client = new TcpClient(SERVER_HOST, SERVER_PORT))
            {
                var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate);
                
                sslStream.AuthenticateAsClient(SERVER_HOST);
                
                byte[] handshake = Encoding.UTF8.GetBytes("2");
                sslStream.Write(handshake, 0, handshake.Length);
                
                System.Threading.Thread.Sleep(200);
                
                string authData = $"{PROJECT_ID}|{key}|{GetHWID()}";
                byte[] data = Encoding.UTF8.GetBytes(authData);
                sslStream.Write(data, 0, data.Length);
                
                byte[] buffer = new byte[1024];
                int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                
                if (response.StartsWith("CHALLENGE|"))
                {
                    string[] parts = response.Split('|');
                    if (parts.Length == 3)
                    {
                        string challengeId = parts[1];
                        string challenge = parts[2];
                        
                        string signature = HmacSha256(key, challenge);
                        
                        string responseMsg = $"RESPONSE|{challengeId}|{signature}";
                        byte[] responseBytes = Encoding.UTF8.GetBytes(responseMsg);
                        sslStream.Write(responseBytes, 0, responseBytes.Length);
                        
                        bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                        string result = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        
                        if (result.StartsWith("ACCESS|"))
                        {
                            Console.WriteLine("[KeyAuth] Authenticated.");
                            return true;
                        }
                        else
                        {
                            Console.WriteLine($"[KeyAuth] Refused: {result}");
                            return false;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[KeyAuth] Invalid challenge format");
                        return false;
                    }
                }
                else if (response.StartsWith("ACCESS|"))
                {
                    Console.WriteLine("[KeyAuth] Authenticated.");
                    return true;
                }
                else
                {
                    Console.WriteLine($"[KeyAuth] Refused: {response}");
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KeyAuth] Connection error: {ex.Message}");
            return false;
        }
    }
    
    private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        return true; 
    }
    
    static void Main()
    {
        Console.Write("Enter your license key: ");
        string key = Console.ReadLine();
        
        if (Authenticate(key))
        {
        }
        else
        {
            Environment.Exit(1);
        }
    }
}