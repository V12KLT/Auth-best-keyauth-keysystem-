import java.io.*;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.*;
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

    private static final byte[] CF_ENC = {
    (byte)0xE5, 0x7F, (byte)0xCB, 0x6E, (byte)0xA5, (byte)0xFC, 0x5E, 0x3E,
    (byte)0xA6, 0x4F, 0x55, (byte)0xFC, 0x0B, (byte)0xE1, (byte)0xC1, 0x75,
    (byte)0x92, 0x08, (byte)0xC7, 0x1F, (byte)0xD4, (byte)0xF4, 0x5E, 0x48,
    (byte)0xA1, 0x43, 0x57, (byte)0xFF, 0x76, (byte)0xE7, (byte)0xB6, 0x77,
    (byte)0xE4, 0x0F, (byte)0xC0, 0x6E, (byte)0xA0, (byte)0xF2, 0x2E, 0x4B,
    (byte)0xA5, 0x3F, 0x52, (byte)0x8B, 0x0B, (byte)0x96, (byte)0xC1, 0x70,
    (byte)0xE1, 0x0A, (byte)0xB6, 0x1F, (byte)0xD0, (byte)0xF4, 0x5A, 0x4E,
    (byte)0xA0, 0x4B, 0x21, (byte)0x89, 0x09, (byte)0xE5, (byte)0xB7, 0x76
};
    private static byte[] cachedPubKey = null;

    private static boolean verifyCertPin(SSLSocket socket) {
        if (CF_ENC.length == 0) return true;
        try {
            Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs == null || certs.length == 0) return false;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(certs[0].getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02X", b & 0xFF));
            String certHash = sb.toString();
            String expected = xd(CF_ENC).toUpperCase();
            return certHash.equals(expected);
        } catch (Exception e) { return false; }
    }

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
                    return sha256Hex(uuid.trim());
            } else if (os.contains("linux")) {
                for (String path : new String[]{"/sys/class/dmi/id/product_uuid", "/etc/machine-id"}) {
                    File f = new File(path);
                    if (f.exists()) {
                        BufferedReader reader = new BufferedReader(new FileReader(f));
                        String uuid = reader.readLine();
                        reader.close();
                        if (uuid != null && !uuid.trim().isEmpty()) return sha256Hex(uuid.trim());
                    }
                }
            } else if (os.contains("mac")) {
                Process p = Runtime.getRuntime().exec("system_profiler SPHardwareDataType");
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Hardware UUID:")) {
                        String[] parts = line.split(":");
                        if (parts.length >= 2) return sha256Hex(parts[1].trim());
                    }
                }
            }
        } catch (Exception e) { }
        String hostname = System.getenv("COMPUTERNAME");
        if (hostname == null) hostname = System.getenv("HOSTNAME");
        return sha256Hex(hostname != null ? hostname : "UNKNOWN");
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
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

    private static byte[] fetchPubKey() {
        if (cachedPubKey != null) return cachedPubKey;
        try {
            String h = host();
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            SSLSocket sock = (SSLSocket) ctx.getSocketFactory().createSocket(h, PORT);
            sock.setSoTimeout(10000);
            sock.startHandshake();
            OutputStream out = sock.getOutputStream();
            InputStream in = sock.getInputStream();
            out.write("8".getBytes(StandardCharsets.UTF_8));
            out.flush();
            byte[] buf = new byte[4096];
            int n = in.read(buf);
            sock.close();
            if (n > 0) {
                String resp = new String(buf, 0, n, StandardCharsets.UTF_8);
                if (resp.startsWith("PUBKEY|")) {
                    String hex = resp.substring(7);
                    byte[] raw = new byte[hex.length() / 2];
                    for (int i = 0; i < raw.length; i++)
                        raw[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                    if (raw.length == 64) { cachedPubKey = raw; return raw; }
                }
            }
        } catch (Exception e) { }
        return null;
    }

    private static boolean verifySig(String data, String sigHex) {
        byte[] raw = fetchPubKey();
        if (raw == null) return true;
        try {
            BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 0, 32));
            BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 32, 64));
            ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(x, y), getP256Params());
            PublicKey pub = KeyFactory.getInstance("EC").generatePublic(spec);
            byte[] sig = new byte[64];
            for (int i = 0; i < 64; i++) sig[i] = (byte) Integer.parseInt(sigHex.substring(i*2, i*2+2), 16);
            byte[] derSig = toDER(java.util.Arrays.copyOfRange(sig,0,32), java.util.Arrays.copyOfRange(sig,32,64));
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(pub);
            verifier.update(data.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(derSig);
        } catch (Exception e) { return true; }
    }

    private static ECParameterSpec getP256Params() throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        return params.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] toDER(byte[] r, byte[] s) {
        byte[] rr = r[0] < 0 ? prepend0(r) : stripLeading0(r);
        byte[] ss = s[0] < 0 ? prepend0(s) : stripLeading0(s);
        byte[] der = new byte[6 + rr.length + ss.length];
        der[0] = 0x30; der[1] = (byte)(4 + rr.length + ss.length);
        der[2] = 0x02; der[3] = (byte)rr.length;
        System.arraycopy(rr, 0, der, 4, rr.length);
        der[4 + rr.length] = 0x02; der[5 + rr.length] = (byte)ss.length;
        System.arraycopy(ss, 0, der, 6 + rr.length, ss.length);
        return der;
    }
    private static byte[] prepend0(byte[] b) { byte[] r = new byte[b.length+1]; System.arraycopy(b,0,r,1,b.length); return r; }
    private static byte[] stripLeading0(byte[] b) { int i=0; while(i<b.length-1 && b[i]==0) i++; return i==0?b:java.util.Arrays.copyOfRange(b,i,b.length); }


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
            sslSocket.startHandshake();

            if (!verifyCertPin(sslSocket)) { sslSocket.close(); return false; }

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

            if (!response.startsWith("CHALLENGE|")) { sslSocket.close(); return false; }

            String[] parts = response.split("\\|");
            if (parts.length != 3) { sslSocket.close(); return false; }
            String challenge = parts[2];
            String sig = hmacSha256(key, parts[2]);
            String responseMsg = "RESPONSE|" + parts[1] + "|" + sig;
            out.write(responseMsg.getBytes(StandardCharsets.UTF_8));
            out.flush();
            bytesRead = in.read(buffer);
            if (bytesRead <= 0) { sslSocket.close(); return false; }
            response = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);

            sslSocket.close();

            if (!response.startsWith("ACCESS|")) return false;
            String[] accessParts = response.split("\\|", 4);
            if (accessParts.length < 4) return false;
            String accessToken = accessParts[1];
            String serverProof = accessParts[2];
            String authSig = accessParts[3];
            String expectedProof = hmacSha256(key, challenge + "|" + accessToken);
            if (!serverProof.equals(expectedProof)) return false;
            if (!verifySig(challenge + "|" + accessToken, authSig)) return false;
            String rawToken = "AUTH_TOKEN_V2|" + accessToken + "|" + hmacSha256(key, accessToken);
            storeToken(rawToken);
            return true;
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
            sslSocket.startHandshake();

            if (!verifyCertPin(sslSocket)) { sslSocket.close(); System.exit(0); return false; }

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
            String resp = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
            if (!resp.startsWith("VALID|")) return false;
            String[] vParts = resp.split("\\|", 5);
            if (vParts.length < 5) return false;
            String remaining = vParts[2];
            String verifyProof = vParts[3];
            String vSig = vParts[4];
            verifyData = "VERIFY:" + PROJECT_ID + ":" + remaining;
            String expected = hmacSha256(key, verifyData);
            return verifyProof.equals(expected) && verifySig(verifyData, vSig);
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

    private static byte[] recvExact(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int offset = 0;
        while (offset < n) {
            int r = in.read(buf, offset, n - offset);
            if (r <= 0) return null;
            offset += r;
        }
        return buf;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }

    public static byte[] downloadFile(String key, String fileName) {
        try {
            String h = host();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(h, PORT);
            sslSocket.setSoTimeout(30000);
            sslSocket.startHandshake();
            if (!verifyCertPin(sslSocket)) { sslSocket.close(); return null; }

            OutputStream out = sslSocket.getOutputStream();
            InputStream in = sslSocket.getInputStream();
            out.write("6".getBytes(StandardCharsets.UTF_8)); out.flush();
            Thread.sleep(100);
            String reqData = PROJECT_ID + "|" + key + "|" + getHWID() + "|" + fileName;
            out.write(reqData.getBytes(StandardCharsets.UTF_8)); out.flush();

            byte[] hdrLenRaw = recvExact(in, 4);
            if (hdrLenRaw == null) { sslSocket.close(); return null; }
            int hdrLen = ((hdrLenRaw[0] & 0xFF) << 24) | ((hdrLenRaw[1] & 0xFF) << 16) | ((hdrLenRaw[2] & 0xFF) << 8) | (hdrLenRaw[3] & 0xFF);
            if (hdrLen > 4096) { sslSocket.close(); return null; }
            byte[] hdrBytes = recvExact(in, hdrLen);
            if (hdrBytes == null) { sslSocket.close(); return null; }
            String header = new String(hdrBytes, StandardCharsets.UTF_8);
            if (header.startsWith("ERROR")) { sslSocket.close(); return null; }

            String[] parts = header.split("\\|");
            if (parts.length < 5 || !parts[0].equals("FILE")) { sslSocket.close(); return null; }
            String nonceHex = parts[1], tagHex = parts[2], expectedHash = parts[3];
            int fileSize = Integer.parseInt(parts[4]);

            byte[] bodyLenRaw = recvExact(in, 4);
            if (bodyLenRaw == null) { sslSocket.close(); return null; }
            int bodyLen = ((bodyLenRaw[0] & 0xFF) << 24) | ((bodyLenRaw[1] & 0xFF) << 16) | ((bodyLenRaw[2] & 0xFF) << 8) | (bodyLenRaw[3] & 0xFF);
            if (bodyLen > 60 * 1024 * 1024) { sslSocket.close(); return null; }
            byte[] body = recvExact(in, bodyLen);
            sslSocket.close();
            if (body == null) return null;

            byte[] nonce = hexToBytes(nonceHex);
            byte[] tag = hexToBytes(tagHex);
            if (nonce.length != 12 || tag.length != 16) return null;

            Mac fileKeyMac = Mac.getInstance("HmacSHA256");
            fileKeyMac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] fileKey = fileKeyMac.doFinal(("FILE_KEY:" + nonceHex).getBytes(StandardCharsets.UTF_8));

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, nonce);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new SecretKeySpec(fileKey, "AES"), gcmSpec);
            cipher.updateAAD(PROJECT_ID.getBytes(StandardCharsets.UTF_8));
            byte[] cipherWithTag = new byte[body.length + tag.length];
            System.arraycopy(body, 0, cipherWithTag, 0, body.length);
            System.arraycopy(tag, 0, cipherWithTag, body.length, tag.length);
            byte[] plaintext = cipher.doFinal(cipherWithTag);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(plaintext);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b & 0xFF));
            if (!sb.toString().equals(expectedHash) || plaintext.length != fileSize) return null;
            return plaintext;
        } catch (Exception e) { return null; }
    }

    private static void secureWipe(String path) {
        try {
            java.io.File f = new java.io.File(path);
            long size = f.length();
            try (FileOutputStream fos = new FileOutputStream(f)) {
                byte[] zeros = new byte[(int) size];
                fos.write(zeros);
                fos.flush();
                fos.getFD().sync();
            }
            f.delete();
        } catch (Exception e) { new java.io.File(path).delete(); }
    }

    public static boolean downloadAndRun(String key, String fileName) {
        byte[] data = downloadFile(key, fileName);
        if (data == null) return false;
        try {
            String tempBase = System.getProperty("java.io.tmpdir");
            String randomDir = tempBase + java.io.File.separator + "_ka_" + Long.toHexString(System.nanoTime()).substring(0, 8);
            new java.io.File(randomDir).mkdirs();

            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("win")) {
                Runtime.getRuntime().exec(new String[]{"attrib", "+h", "+s", randomDir}).waitFor();
            }

            String exePath = randomDir + java.io.File.separator + fileName;
            try (FileOutputStream fos = new FileOutputStream(exePath)) {
                fos.write(data);
                fos.flush();
                fos.getFD().sync();
            }

            if (osName.contains("win")) {
                Runtime.getRuntime().exec(new String[]{"attrib", "+h", exePath}).waitFor();
            }

            java.util.Arrays.fill(data, (byte) 0);

            if (osName.contains("win")) {
                new ProcessBuilder("powershell", "-NoProfile", "-Command",
                    String.format("Start-Process -FilePath '%s' -WorkingDirectory '%s' -Verb RunAs", exePath, randomDir))
                    .start();
            } else {
                new ProcessBuilder(exePath).directory(new java.io.File(randomDir)).start();
            }

            String capExe = exePath, capDir = randomDir;
            Thread cleanupThread = new Thread(() -> {
                try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
                secureWipe(capExe);
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                try { deleteDir(new java.io.File(capDir)); } catch (Exception e) { }
            });
            cleanupThread.setDaemon(true);
            cleanupThread.start();
            return true;
        } catch (Exception e) { return false; }
    }

    private static void deleteDir(java.io.File dir) {
        java.io.File[] files = dir.listFiles();
        if (files != null) { for (java.io.File f : files) { if (f.isDirectory()) deleteDir(f); else f.delete(); } }
        dir.delete();
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
