<?php

$_xk = [0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33];
$_hEnc = [0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82];
$_port = 3389;
$PROJECT_ID = 'ENTER_PROJECT_ID_HERE';

$_cfEnc = [0x94, 0x7E, 0xB1, 0x6A, 0xD4, 0xF0, 0x5A, 0x3D, 0xDA, 0x3C, 0x55, 0xFA, 0x77, 0x97, 0xB2, 0x71, 0xE5, 0x0F, 0xC4, 0x68, 0xD3, 0x80, 0x29, 0x3F, 0xA0, 0x39, 0x23, 0x89, 0x0A, 0xE7, 0xC0, 0x72, 0xE2, 0x0F, 0xC4, 0x68, 0xA7, 0x87, 0x2C, 0x3F, 0xA7, 0x3E, 0x57, 0x88, 0x09, 0xE3, 0xC6, 0x70, 0x95, 0x0F, 0xB6, 0x6D, 0xD5, 0xF3, 0x2D, 0x39, 0xD2, 0x4B, 0x25, 0x8C, 0x09, 0xEA, 0xB3, 0x75];
$_skEnc = [0xB8, 0xBF, 0xD5, 0x63, 0x73, 0xEC, 0x9C, 0x4B, 0x82, 0x8D, 0xAF, 0x84, 0x32, 0x17, 0x3D, 0x78, 0xF8, 0xCC, 0x41, 0xCB, 0x8A, 0x5D, 0x3B, 0xCD, 0xE9, 0x7C, 0x60, 0x7C, 0x2E, 0x32, 0x0E, 0x33, 0x5B, 0xB5, 0x7C, 0x8D, 0xEE, 0x21, 0x14, 0x56, 0x70, 0x9F, 0xA3, 0x6D, 0x4D, 0x6F, 0x4B, 0xE8, 0x02, 0xC5, 0x6E, 0xE5, 0x7F, 0x33, 0xBC, 0x21, 0x8C, 0x7E, 0xF4, 0xAB, 0x7B, 0x56, 0x1C, 0xA2];

function verify_sig($data, $sigHex)
{
    global $_skEnc, $_xk;
    if (empty($_skEnc))
        return true;
    try {
        $raw = array_map(function ($i) use ($_skEnc, $_xk) {
            return $_skEnc[$i] ^ $_xk[$i % count($_xk)];
        }, range(0, count($_skEnc) - 1));
        $rawBytes = pack('C*', ...$raw);
        $x = substr($rawBytes, 0, 32);
        $y = substr($rawBytes, 32, 32);
        $point = "\x04" . $x . $y;
        $derPub = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" . $point;
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($derPub), 64, "\n") . "-----END PUBLIC KEY-----";
        $pubKey = openssl_pkey_get_public($pem);
        if (!$pubKey)
            return true;
        $sig = hex2bin($sigHex);
        $r = substr($sig, 0, 32);
        $s = substr($sig, 32, 32);
        $rr = ($r[0] & "\x80") ? "\x00" . $r : ltrim($r, "\x00") ?: "\x00";
        $ss = ($s[0] & "\x80") ? "\x00" . $s : ltrim($s, "\x00") ?: "\x00";
        $derSig = "\x30" . chr(strlen($rr) + strlen($ss) + 4) . "\x02" . chr(strlen($rr)) . $rr . "\x02" . chr(strlen($ss)) . $ss;
        return openssl_verify($data, $derSig, $pubKey, OPENSSL_ALGO_SHA256) === 1;
    } catch (\Exception $e) {
        return true;
    }
}

function verifyCertPin($socket)
{
    global $_cfEnc;
    if (empty($_cfEnc))
        return true;
    $params = stream_context_get_params($socket);
    if (!isset($params['options']['ssl']['peer_certificate']))
        return false;
    $cert = $params['options']['ssl']['peer_certificate'];
    openssl_x509_export($cert, $certPem);
    $certHash = strtoupper(openssl_x509_fingerprint($cert, 'sha256'));
    $expected = strtoupper(xd($_cfEnc));
    return $certHash === $expected;
}

function xd($data, $key = null)
{
    global $_xk;
    if ($key === null)
        $key = $_xk;
    $result = '';
    for ($i = 0; $i < count($data); $i++) {
        $result .= chr($data[$i] ^ $key[$i % count($key)]);
    }
    return $result;
}

function xe($input)
{
    global $_xk;
    $raw = array_values(unpack('C*', $input));
    $result = [];
    for ($i = 0; $i < count($raw); $i++) {
        $result[] = $raw[$i] ^ $_xk[$i % count($_xk)];
    }
    return $result;
}

function fnv1a($data)
{
    $h = 0x811C9DC5;
    foreach ($data as $b) {
        $h ^= $b;
        $h = ($h * 0x01000193) & 0xFFFFFFFF;
    }
    return ($h ^ 0xDEADBEEF) & 0xFFFFFFFF;
}

$_encToken = null;
$_tokenCanary = 0;
$_tokenPresent = false;

function storeToken($token)
{
    global $_encToken, $_tokenCanary, $_tokenPresent;
    $_encToken = xe($token);
    $_tokenCanary = fnv1a($_encToken);
    $_tokenPresent = true;
}

function getToken()
{
    global $_encToken, $_tokenCanary, $_tokenPresent;
    if (!$_tokenPresent || $_encToken === null)
        return null;
    if (fnv1a($_encToken) !== $_tokenCanary)
        exit(0);
    return xd($_encToken);
}

function tokenValid()
{
    $token = getToken();
    if ($token === null || $token === '')
        return false;
    if (strpos($token, 'AUTH_TOKEN_V2|') !== 0)
        return false;
    return strlen($token) > 22;
}

function host()
{
    global $_hEnc;
    return xd($_hEnc);
}

function getHWID()
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $output = @shell_exec('powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"');
        $uuid = trim($output ?? '');
        if ($uuid && $uuid !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF')
            return $uuid;
        $output = @shell_exec('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /v MachineGuid');
        if (preg_match('/MachineGuid\s+REG_SZ\s+(.+)/', $output, $matches))
            return trim($matches[1]);
    } elseif (PHP_OS === 'Linux') {
        foreach (['/sys/class/dmi/id/product_uuid', '/etc/machine-id'] as $p) {
            if (file_exists($p)) {
                $uuid = trim(file_get_contents($p));
                if ($uuid)
                    return $uuid;
            }
        }
    } elseif (PHP_OS === 'Darwin') {
        $output = @shell_exec('system_profiler SPHardwareDataType | grep "Hardware UUID"');
        if (preg_match('/Hardware UUID:\s*(.+)/', $output, $matches))
            return trim($matches[1]);
    }
    return gethostname() ?: 'UNKNOWN';
}

function checkDebugger()
{
    if (extension_loaded('xdebug'))
        exit(0);
    if (function_exists('xdebug_is_debugger_active') && xdebug_is_debugger_active())
        exit(0);

    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $bad = [
            'x64dbg',
            'x32dbg',
            'ollydbg',
            'ida',
            'ida64',
            'wireshark',
            'fiddler',
            'charles',
            'httpdebugger',
            'processhacker',
            'procmon',
            'procexp',
            'dnspy',
            'de4dot',
            'cheatengine'
        ];
        $output = @shell_exec('tasklist /FO CSV /NH');
        if ($output) {
            $lower = strtolower($output);
            foreach ($bad as $b) {
                if (strpos($lower, $b) !== false)
                    exit(0);
            }
        }
    }
}

function authenticate($key)
{
    global $PROJECT_ID, $_port;
    checkDebugger();

    $h = host();
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $h,
            'capture_peer_cert' => true
        ]
    ]);

    $socket = @stream_socket_client(
        'ssl://' . $h . ':' . $_port,
        $errno,
        $errstr,
        15,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if (!$socket)
        return false;

    if (!verifyCertPin($socket)) {
        fclose($socket);
        return false;
    }

    stream_set_timeout($socket, 15);

    fwrite($socket, '2');
    usleep(200000);

    $authData = $PROJECT_ID . '|' . $key . '|' . getHWID();
    fwrite($socket, $authData);

    $response = fread($socket, 4096);
    if (!$response) {
        fclose($socket);
        return false;
    }

    if (strpos($response, 'CHALLENGE|') !== 0) {
        fclose($socket);
        return false;
    }

    $parts = explode('|', $response);
    if (count($parts) != 3) {
        fclose($socket);
        return false;
    }
    $challenge = $parts[2];
    $sig = hash_hmac('sha256', $parts[2], $key);
    fwrite($socket, "RESPONSE|{$parts[1]}|{$sig}");
    $response = fread($socket, 4096);

    fclose($socket);

    if (strpos($response, 'ACCESS|') !== 0)
        return false;
    $accessParts = explode('|', $response, 4);
    if (count($accessParts) < 4)
        return false;
    $accessToken = $accessParts[1];
    $serverProof = $accessParts[2];
    $authSig = $accessParts[3];
    $expectedProof = hash_hmac('sha256', $challenge . '|' . $accessToken, $key);
    if (!hash_equals($serverProof, $expectedProof))
        return false;
    if (!verify_sig($challenge . '|' . $accessToken, $authSig))
        return false;
    $rawToken = "AUTH_TOKEN_V2|{$accessToken}|" . hash_hmac('sha256', $accessToken, $key);
    storeToken($rawToken);
    return true;
}

function verifySession($key)
{
    global $PROJECT_ID, $_port;
    if (!tokenValid())
        exit(0);

    $h = host();
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $h,
            'capture_peer_cert' => true
        ]
    ]);

    $socket = @stream_socket_client(
        'ssl://' . $h . ':' . $_port,
        $errno,
        $errstr,
        10,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if (!$socket)
        return false;

    if (!verifyCertPin($socket)) {
        fclose($socket);
        exit(0);
    }

    stream_set_timeout($socket, 10);
    fwrite($socket, '3');
    usleep(100000);
    $verifyData = $PROJECT_ID . '|' . $key . '|' . getHWID();
    fwrite($socket, $verifyData);
    $response = fread($socket, 1024);
    fclose($socket);
    if (!$response)
        return false;
    if (strpos($response, 'VALID|') !== 0)
        return false;
    $vParts = explode('|', $response, 5);
    if (count($vParts) < 5)
        return false;
    $remaining = $vParts[2];
    $verifyProof = $vParts[3];
    $vSig = $vParts[4];
    $verifyData = "VERIFY:{$PROJECT_ID}:{$remaining}";
    $expected = hash_hmac('sha256', $verifyData, $key);
    return hash_equals($verifyProof, $expected) && verify_sig($verifyData, $vSig);
}

function recvExact($socket, $n)
{
    $buf = '';
    while (strlen($buf) < $n) {
        $chunk = fread($socket, $n - strlen($buf));
        if ($chunk === false || $chunk === '')
            return null;
        $buf .= $chunk;
    }
    return $buf;
}

function download_file($key, $fileName)
{
    global $PROJECT_ID, $_port;
    $h = host();
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $h,
            'capture_peer_cert' => true
        ]
    ]);
    $socket = @stream_socket_client('ssl://' . $h . ':' . $_port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
    if (!$socket)
        return null;
    if (!verifyCertPin($socket)) {
        fclose($socket);
        return null;
    }
    stream_set_timeout($socket, 30);

    fwrite($socket, '6');
    usleep(100000);
    fwrite($socket, $PROJECT_ID . '|' . $key . '|' . getHWID() . '|' . $fileName);

    $hdrLenRaw = recvExact($socket, 4);
    if ($hdrLenRaw === null) {
        fclose($socket);
        return null;
    }
    $hdrLen = unpack('N', $hdrLenRaw)[1];
    if ($hdrLen > 4096) {
        fclose($socket);
        return null;
    }
    $hdrBytes = recvExact($socket, $hdrLen);
    if ($hdrBytes === null) {
        fclose($socket);
        return null;
    }
    if (strpos($hdrBytes, 'ERROR') === 0) {
        fclose($socket);
        return null;
    }

    $parts = explode('|', $hdrBytes);
    if (count($parts) < 5 || $parts[0] !== 'FILE') {
        fclose($socket);
        return null;
    }
    $nonceHex = $parts[1];
    $tagHex = $parts[2];
    $expectedHash = $parts[3];
    $fileSize = (int) $parts[4];

    $bodyLenRaw = recvExact($socket, 4);
    if ($bodyLenRaw === null) {
        fclose($socket);
        return null;
    }
    $bodyLen = unpack('N', $bodyLenRaw)[1];
    if ($bodyLen > 60 * 1024 * 1024) {
        fclose($socket);
        return null;
    }
    $body = recvExact($socket, $bodyLen);
    fclose($socket);
    if ($body === null)
        return null;

    $nonce = hex2bin($nonceHex);
    $tag = hex2bin($tagHex);
    if (strlen($nonce) !== 12 || strlen($tag) !== 16)
        return null;

    $fileKey = hash_hmac('sha256', 'FILE_KEY:' . $nonceHex, $key, true);
    $plaintext = openssl_decrypt($body, 'aes-256-gcm', $fileKey, OPENSSL_RAW_DATA, $nonce, $tag, $PROJECT_ID);
    if ($plaintext === false)
        return null;

    $actualHash = hash('sha256', $plaintext);
    if ($actualHash !== $expectedHash || strlen($plaintext) !== $fileSize)
        return null;
    return $plaintext;
}

function secure_wipe($path)
{
    try {
        $size = filesize($path);
        $f = fopen($path, 'r+b');
        if ($f) {
            fwrite($f, str_repeat("\x00", $size));
            fflush($f);
            fclose($f);
        }
        @unlink($path);
    } catch (\Exception $e) {
        @unlink($path);
    }
}

function download_and_run($key, $fileName)
{
    $data = download_file($key, $fileName);
    if ($data === null)
        return false;
    try {
        $tempBase = sys_get_temp_dir();
        $randomDir = $tempBase . DIRECTORY_SEPARATOR . '_ka_' . substr(bin2hex(random_bytes(4)), 0, 8);
        @mkdir($randomDir, 0700, true);

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            @shell_exec("attrib +h +s \"$randomDir\"");
        }

        $exePath = $randomDir . DIRECTORY_SEPARATOR . $fileName;
        file_put_contents($exePath, $data);

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            @shell_exec("attrib +h \"$exePath\"");
        }

        $data = str_repeat("\x00", strlen($data));

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            @shell_exec("powershell -NoProfile -Command \"Start-Process -FilePath '$exePath' -WorkingDirectory '$randomDir' -Verb RunAs\"");
        } else {
            @shell_exec("chmod +x '$exePath' && '$exePath' &");
        }

        sleep(2);
        secure_wipe($exePath);
        sleep(1);
        @rmdir($randomDir);

        return true;
    } catch (\Exception $e) {
        return false;
    }
}

checkDebugger();
echo "Enter your license key: ";
$key = trim(fgets(STDIN));

if (authenticate($key)) {
    echo "Authenticated.\n";
} else {
    exit(1);
}

?>