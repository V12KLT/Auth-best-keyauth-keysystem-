import java.io.*;
import java.lang.management.ManagementFactory;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

public class KeyAuth {
    private static final byte[] XK = {(byte)0xA7, 0x3B, (byte)0xF2, 0x5E, (byte)0x91, (byte)0xC4, 0x68, 0x0D, (byte)0xE3, 0x7A, 0x16, (byte)0xB9, 0x4F, (byte)0xD2, (byte)0x85, 0x33};
    private static final byte[] H_ENC = {(byte)0xD4, 0x54, (byte)0x91, 0x35, (byte)0xF4, (byte)0xB0, 0x46, 0x66, (byte)0x86, 0x03, 0x77, (byte)0xCC, 0x3B, (byte)0xBA, (byte)0xAB, 0x40, (byte)0xCF, 0x54, (byte)0x82};
    private static final int PORT = 3389;
    private static final String PROJECT_ID = "ENTER_PROJECT_ID_HERE";

    private static byte[] encToken = null;
    private static long tokenCanary = 0;
    private static volatile boolean tokenPresent = false;
    private static final Object tokenLock = new Object();
    private static final AtomicBoolean sessionActive = new AtomicBoolean(false);

    private static String xd(byte[] data) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) result[i] = (byte)(data[i] ^ XK[i % XK.length]);
        return new String(result, StandardCharsets.UTF_8);
    }

    private static byte[] xe(String input) {
        byte[] raw = input.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) result[i] = (byte)(raw[i] ^ XK[i % XK.length]);
        return result;
    }

    private static long fnv1a(byte[] data) {
        long h = 0x811C9DC5L;
        for (byte b : data) { h ^= (b & 0xFF); h = (h * 0x01000193L) & 0xFFFFFFFFL; }
        return (h ^ 0xDEADBEEFL) & 0xFFFFFFFFL;
    }

    private static void storeToken(String token) {
        synchronized (tokenLock) {
            encToken = xe(token);
            tokenCanary = fnv1a(encToken);
            tokenPresent = true;
        }
    }

    private static String getToken() {
        synchronized (tokenLock) {
            if (!tokenPresent || encToken == null) return null;
            if (fnv1a(encToken) != tokenCanary) System.exit(0);
            return xd(encToken);
        }
    }

    private static boolean tokenValid() {
        String token = getToken();
        if (token == null || token.isEmpty()) return false;
        if (!token.startsWith("AUTH_TOKEN_V2|")) return false;
        return token.length() > 22;
    }

    private static String host() { return xd(H_ENC); }

    public static String getHWID() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                Process p = Runtime.getRuntime().exec(new String[]{"powershell", "-Command", "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"});
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String uuid = reader.readLine();
                if (uuid != null && !uuid.trim().isEmpty() && !uuid.equals("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"))
                    return uuid.trim();
            } else if (os.contains("linux")) {
                for (String path : new String[]{"/sys/class/dmi/id/product_uuid", "/etc/machine-id"}) {
                    File f = new File(path);
                    if (f.exists()) {
                        BufferedReader reader = new BufferedReader(new FileReader(f));
                        String uuid = reader.readLine();
                        reader.close();
                        if (uuid != null && !uuid.trim().isEmpty()) return uuid.trim();
                    }
                }
            } else if (os.contains("mac")) {
                Process p = Runtime.getRuntime().exec("system_profiler SPHardwareDataType");
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Hardware UUID:")) {
                        String[] parts = line.split(":");
                        if (parts.length >= 2) return parts[1].trim();
                    }
                }
            }
        } catch (Exception e) { }
        String hostname = System.getenv("COMPUTERNAME");
        if (hostname == null) hostname = System.getenv("HOSTNAME");
        return hostname != null ? hostname : "UNKNOWN";
    }

    private static String hmacSha256(String key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static void checkDebugger() {
        String inputArgs = ManagementFactory.getRuntimeMXBean().getInputArguments().toString();
        if (inputArgs.contains("-agentlib:jdwp") || inputArgs.contains("-Xdebug") || inputArgs.contains("-Xrunjdwp"))
            System.exit(0);

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            String[] bad = {"x64dbg", "x32dbg", "ollydbg", "ida", "ida64", "wireshark",
                "fiddler", "charles", "httpdebugger", "processhacker", "procmon",
                "procexp", "dnspy", "de4dot", "cheatengine"};
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"tasklist", "/FO", "CSV", "/NH"});
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    String lower = line.toLowerCase();
                    for (String b : bad) { if (lower.contains(b)) System.exit(0); }
                }
            } catch (Exception e) { }
        }
    }

    public static boolean authenticate(String key) {
        checkDebugger();
        try {
            String h = host();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(h, PORT);
            sslSocket.setSoTimeout(15000);

            OutputStream out = sslSocket.getOutputStream();
            InputStream in = sslSocket.getInputStream();

            out.write("2".getBytes(StandardCharsets.UTF_8));
            out.flush();
            Thread.sleep(200);

            String authData = PROJECT_ID + "|" + key + "|" + getHWID();
            out.write(authData.getBytes(StandardCharsets.UTF_8));
            out.flush();

            byte[] buffer = new byte[4096];
            int bytesRead = in.read(buffer);
            if (bytesRead <= 0) { sslSocket.close(); return false; }
            String response = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);

            if (response.startsWith("CHALLENGE|")) {
                String[] parts = response.split("\\|");
                if (parts.length != 3) { sslSocket.close(); return false; }
                String sig = hmacSha256(key, parts[2]);
                String responseMsg = "RESPONSE|" + parts[1] + "|" + sig;
                out.write(responseMsg.getBytes(StandardCharsets.UTF_8));
                out.flush();
                bytesRead = in.read(buffer);
                if (bytesRead <= 0) { sslSocket.close(); return false; }
                response = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
            }

            sslSocket.close();

            if (response.startsWith("ACCESS|")) {
                String serverData = response.substring(7);
                String rawToken = "AUTH_TOKEN_V2|" + serverData + "|" + hmacSha256(key, serverData);
                storeToken(rawToken);
                return true;
            }
            return false;
        } catch (Exception e) { return false; }
    }

    private static boolean verifySession(String key) {
        if (!tokenValid()) { System.exit(0); return false; }
        try {
            String h = host();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(h, PORT);
            sslSocket.setSoTimeout(10000);
            OutputStream out = sslSocket.getOutputStream();
            InputStream in = sslSocket.getInputStream();
            out.write("3".getBytes(StandardCharsets.UTF_8));
            out.flush();
            Thread.sleep(100);
            String verifyData = PROJECT_ID + "|" + key + "|" + getHWID();
            out.write(verifyData.getBytes(StandardCharsets.UTF_8));
            out.flush();
            byte[] buffer = new byte[1024];
            int bytesRead = in.read(buffer);
            sslSocket.close();
            if (bytesRead <= 0) return false;
            return new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).startsWith("VALID");
        } catch (Exception e) { return false; }
    }

    public static void startSessionValidation(String key) {
        sessionActive.set(true);
        Thread t = new Thread(() -> {
            int failures = 0;
            while (sessionActive.get()) {
                try { Thread.sleep(60000); } catch (InterruptedException e) { break; }
                if (!sessionActive.get()) break;
                checkDebugger();
                if (verifySession(key)) { failures = 0; }
                else { failures++; if (failures >= 3) System.exit(0); }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    public static void main(String[] args) {
        checkDebugger();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.print("Enter your license key: ");
            String key = reader.readLine();
            if (authenticate(key)) {
                System.out.println("Authenticated.");
                startSessionValidation(key);
                Thread.currentThread().join();
            } else {
                System.exit(1);
            }
        } catch (Exception e) { System.exit(1); }
    }
}