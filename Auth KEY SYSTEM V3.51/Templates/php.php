<?php

const SERVER_HOST = 'socket.keyauth.shop';
const SERVER_PORT = 3389;
const PROJECT_ID = 'ENTER_PROJECT_ID_HERE';

function getHWID() {
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $output = shell_exec('powershell "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"');
        $uuid = trim($output);
        if ($uuid && $uuid !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') {
            return $uuid;
        }
        
        $output = shell_exec('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /v MachineGuid');
        if (preg_match('/MachineGuid\s+REG_SZ\s+(.+)/', $output, $matches)) {
            return trim($matches[1]);
        }
    } elseif (PHP_OS === 'Linux') {
        if (file_exists('/sys/class/dmi/id/product_uuid')) {
            $uuid = trim(file_get_contents('/sys/class/dmi/id/product_uuid'));
            if ($uuid) {
                return $uuid;
            }
        }
        
        $uuid = trim(shell_exec('dmidecode -s system-uuid 2>/dev/null'));
        if ($uuid) {
            return $uuid;
        }
        
        if (file_exists('/etc/machine-id')) {
            $uuid = trim(file_get_contents('/etc/machine-id'));
            if ($uuid) {
                return $uuid;
            }
        }
    } elseif (PHP_OS === 'Darwin') {
        $output = shell_exec('system_profiler SPHardwareDataType | grep "Hardware UUID"');
        if (preg_match('/Hardware UUID:\s*(.+)/', $output, $matches)) {
            return trim($matches[1]);
        }
    }
    
    return gethostname() ?: 'UNKNOWN';
}

function authenticate($key) {
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true
        ]
    ]);
    
    $socket = stream_socket_client(
        'ssl://' . SERVER_HOST . ':' . SERVER_PORT,
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $context
    );
    
    if (!$socket) {
        echo "[KeyAuth] Connection error: $errstr ($errno)\n";
        return false;
    }
    
    fwrite($socket, '2');
    usleep(200000); 
    
    $authData = PROJECT_ID . '|' . $key . '|' . getHWID();
    fwrite($socket, $authData);
    
    $response = fread($socket, 1024);
    
    $result = false;
    
    if (strpos($response, 'CHALLENGE|') === 0) {
        $parts = explode('|', $response);
        if (count($parts) == 3) {
            $challengeId = $parts[1];
            $challenge = $parts[2];
            
            $signature = hash_hmac('sha256', $challenge, $key);
            
            $responseMsg = "RESPONSE|$challengeId|$signature";
            fwrite($socket, $responseMsg);
            
            $finalResult = fread($socket, 1024);
            
            if (strpos($finalResult, 'ACCESS|') === 0) {
                echo "[KeyAuth] Authenticated.\n";
                $result = true;
            } else {
                echo "[KeyAuth] Refused: $finalResult\n";
                $result = false;
            }
        } else {
            echo "[KeyAuth] Invalid challenge format\n";
            $result = false;
        }
    } elseif (strpos($response, 'ACCESS|') === 0) {
        echo "[KeyAuth] Authenticated.\n";
        $result = true;
    } else {
        echo "[KeyAuth] Refused: $response\n";
        $result = false;
    }
    
    fclose($socket);
    return $result;
}

echo "Enter your license key: ";
$key = trim(fgets(STDIN));

if (authenticate($key)) {
} else {
    exit(1);
}

?>