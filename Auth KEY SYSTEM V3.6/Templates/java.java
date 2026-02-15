import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

public class KeyAuth {
    private static final String SERVER_HOST = "socket.keyauth.shop";
    private static final int SERVER_PORT = 3389;
    private static final String PROJECT_ID = "ENTER_PROJECT_ID_HERE";
    
    public static String getHWID() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            
            if (os.contains("win")) {
                try {
                    Process process = Runtime.getRuntime().exec("powershell \"Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID\"");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String uuid = reader.readLine();
                    if (uuid != null && !uuid.trim().isEmpty() && !uuid.equals("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")) {
                        return uuid.trim();
                    }
                } catch (Exception e) {
                    Process process = Runtime.getRuntime().exec("reg query \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\" /v MachineGuid");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("MachineGuid")) {
                            String[] parts = line.trim().split("\\s+");
                            if (parts.length >= 3) {
                                return parts[2];
                            }
                        }
                    }
                }
            } else if (os.contains("linux")) {
                try {
                    Process process = Runtime.getRuntime().exec("cat /sys/class/dmi/id/product_uuid");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String uuid = reader.readLine();
                    if (uuid != null && !uuid.trim().isEmpty()) {
                        return uuid.trim();
                    }
                } catch (Exception e) {
                    try {
                        Process process = Runtime.getRuntime().exec("dmidecode -s system-uuid");
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String uuid = reader.readLine();
                        if (uuid != null && !uuid.trim().isEmpty()) {
                            return uuid.trim();
                        }
                    } catch (Exception ex) {
                        Process process = Runtime.getRuntime().exec("cat /etc/machine-id");
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String uuid = reader.readLine();
                        if (uuid != null && !uuid.trim().isEmpty()) {
                            return uuid.trim();
                        }
                    }
                }
            } else if (os.contains("mac")) {
                Process process = Runtime.getRuntime().exec("system_profiler SPHardwareDataType");
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Hardware UUID:")) {
                        String[] parts = line.split(":");
                        if (parts.length >= 2) {
                            String uuid = parts[1].trim();
                            if (!uuid.isEmpty()) {
                                return uuid;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore errors and fall back to hostname
        }
        
        String hostname = System.getenv("COMPUTERNAME");
        if (hostname == null) {
            hostname = System.getenv("HOSTNAME");
        }
        return hostname != null ? hostname : "UNKNOWN";
    }
    
    private static String hmacSha256(String key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(data.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static boolean authenticate(String key) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT);
            
            try (OutputStream out = sslSocket.getOutputStream();
                 InputStream in = sslSocket.getInputStream()) {
                
                out.write("2".getBytes());
                
                Thread.sleep(200);
                
                String authData = PROJECT_ID + "|" + key + "|" + getHWID();
                out.write(authData.getBytes());
                
                byte[] buffer = new byte[1024];
                int bytesRead = in.read(buffer);
                String response = new String(buffer, 0, bytesRead);
                
                if (response.startsWith("CHALLENGE|")) {
                    String[] parts = response.split("\\|");
                    if (parts.length == 3) {
                        String challengeId = parts[1];
                        String challenge = parts[2];
                        
                        String signature = hmacSha256(key, challenge);
                        
                        String responseMsg = "RESPONSE|" + challengeId + "|" + signature;
                        out.write(responseMsg.getBytes());
                        
                        bytesRead = in.read(buffer);
                        String result = new String(buffer, 0, bytesRead);
                        
                        if (result.startsWith("ACCESS|")) {
                            System.out.println("[KeyAuth] Authenticated.");
                            return true;
                        } else {
                            System.out.println("[KeyAuth] Refused: " + result);
                            return false;
                        }
                    } else {
                        System.out.println("[KeyAuth] Invalid challenge format");
                        return false;
                    }
                } else if (response.startsWith("ACCESS|")) {
                    System.out.println("[KeyAuth] Authenticated.");
                    return true;
                } else {
                    System.out.println("[KeyAuth] Refused: " + response);
                    return false;
                }
            } finally {
                sslSocket.close();
            }
            
        } catch (Exception e) {
            System.out.println("[KeyAuth] Connection error: " + e.getMessage());
            return false;
        }
    }
    
    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.print("Enter your license key: ");
            String key = reader.readLine();
            
            if (authenticate(key)) {
                // Your program code here
            } else {
                System.exit(1);
            }
        } catch (IOException e) {
            System.out.println("Error reading input: " + e.getMessage());
            System.exit(1);
        }
    }
}