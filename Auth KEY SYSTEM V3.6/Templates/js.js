const tls = require('tls');
const crypto = require('crypto');
const os = require('os');
const { execSync } = require('child_process');

const SERVER_HOST = 'socket.keyauth.shop';
const SERVER_PORT = 3389;
const PROJECT_ID = 'ENTER_PROJECT_ID_HERE';

function getHWID() {
    try {
        if (os.platform() === 'win32') {
            try {
                const output = execSync('powershell "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"', { encoding: 'utf8' });
                const uuid = output.trim();
                if (uuid && uuid !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') {
                    return uuid;
                }
            } catch {
                const output = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { encoding: 'utf8' });
                const match = output.match(/MachineGuid\s+REG_SZ\s+(.+)/);
                if (match && match[1]) {
                    return match[1].trim();
                }
            }
        } else if (os.platform() === 'linux') {
            try {
                const output = execSync('cat /sys/class/dmi/id/product_uuid', { encoding: 'utf8' });
                return output.trim();
            } catch {
                try {
                    const output = execSync('dmidecode -s system-uuid', { encoding: 'utf8' });
                    return output.trim();
                } catch {
                    const output = execSync('cat /etc/machine-id', { encoding: 'utf8' });
                    return output.trim();
                }
            }
        } else if (os.platform() === 'darwin') {
            const output = execSync('system_profiler SPHardwareDataType | grep "Hardware UUID"', { encoding: 'utf8' });
            const match = output.match(/Hardware UUID: (.+)/);
            if (match && match[1]) {
                return match[1].trim();
            }
        }
    } catch (error) {
        console.log('[KeyAuth] Warning: Could not get hardware UUID, using hostname fallback');
    }
    
    return os.hostname() || 'UNKNOWN';
}

function authenticate(key) {
    return new Promise((resolve, reject) => {
        const options = {
            host: SERVER_HOST,
            port: SERVER_PORT
        };
        
        const client = tls.connect(options, () => {
            console.log('[KeyAuth] SSL connection established');
            
            client.write('2');
            
            setTimeout(() => {
                const authData = `${PROJECT_ID}|${key}|${getHWID()}`;
                client.write(authData);
            }, 200);
        });
        
        let responseHandled = false;
        
        client.on('data', (data) => {
            if (responseHandled) return;
            
            const response = data.toString();
            
            if (response.startsWith('CHALLENGE|')) {
                const parts = response.split('|');
                if (parts.length === 3) {
                    const challengeId = parts[1];
                    const challenge = parts[2];
                    
                    const signature = crypto.createHmac('sha256', key).update(challenge).digest('hex');
                    
                    const responseMsg = `RESPONSE|${challengeId}|${signature}`;
                    client.write(responseMsg);
                    
                    responseHandled = true;
                    
                    client.once('data', (finalData) => {
                        const result = finalData.toString();
                        
                        if (result.startsWith('ACCESS|')) {
                            console.log('[KeyAuth] Authenticated.');
                            client.end();
                            resolve(true);
                        } else {
                            console.log(`[KeyAuth] Refused: ${result}`);
                            client.end();
                            resolve(false);
                        }
                    });
                } else {
                    console.log('[KeyAuth] Invalid challenge format');
                    client.end();
                    resolve(false);
                }
            } else if (response.startsWith('ACCESS|')) {
                console.log('[KeyAuth] Authenticated.');
                client.end();
                resolve(true);
            } else {
                console.log(`[KeyAuth] Refused: ${response}`);
                client.end();
                resolve(false);
            }
        });
        
        client.on('error', (err) => {
            console.log(`[KeyAuth] Connection error: ${err.message}`);
            resolve(false);
        });
    });
}

const readline = require('readline');
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter your license key: ', async (key) => {
    const success = await authenticate(key);
    
    if (success) {
    } else {
        process.exit(1);
    }
    
    rl.close();
});