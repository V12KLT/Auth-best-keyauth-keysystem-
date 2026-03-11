<?php

$_xk = [0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33];
$_hEnc = [0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82];
$_port = 3389;
$PROJECT_ID = 'ENTER_PROJECT_ID_HERE';

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
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $h]
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

    if (strpos($response, 'CHALLENGE|') === 0) {
        $parts = explode('|', $response);
        if (count($parts) != 3) {
            fclose($socket);
            return false;
        }
        $sig = hash_hmac('sha256', $parts[2], $key);
        fwrite($socket, "RESPONSE|{$parts[1]}|{$sig}");
        $response = fread($socket, 4096);
    }

    fclose($socket);

    if (strpos($response, 'ACCESS|') === 0) {
        $serverData = substr($response, 7);
        $rawToken = "AUTH_TOKEN_V2|{$serverData}|" . hash_hmac('sha256', $serverData, $key);
        storeToken($rawToken);
        return true;
    }
    return false;
}

function verifySession($key)
{
    global $PROJECT_ID, $_port;
    if (!tokenValid())
        exit(0);

    $h = host();
    $context = stream_context_create([
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $h]
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

    stream_set_timeout($socket, 10);
    fwrite($socket, '3');
    usleep(100000);
    $verifyData = $PROJECT_ID . '|' . $key . '|' . getHWID();
    fwrite($socket, $verifyData);
    $response = fread($socket, 1024);
    fclose($socket);
    if (!$response)
        return false;
    return strpos($response, 'VALID') === 0;
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