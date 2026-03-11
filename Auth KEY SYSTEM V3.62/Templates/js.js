const tls = require('tls');
const crypto = require('crypto');
const os = require('os');
const { execSync } = require('child_process');

const _xk = Buffer.from([0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33]);
const _hEnc = Buffer.from([0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82]);
const _port = 3389;
const PROJECT_ID = 'ENTER_PROJECT_ID_HERE';

function _xd(data) {
    const result = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) result[i] = data[i] ^ _xk[i % _xk.length];
    return result.toString('utf8');
}

function _xe(input) {
    const raw = Buffer.from(input, 'utf8');
    const result = Buffer.alloc(raw.length);
    for (let i = 0; i < raw.length; i++) result[i] = raw[i] ^ _xk[i % _xk.length];
    return result;
}

function _fnv1a(data) {
    let h = 0x811C9DC5 >>> 0;
    for (let i = 0; i < data.length; i++) {
        h ^= data[i];
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return (h ^ 0xDEADBEEF) >>> 0;
}

let _encToken = null;
let _tokenCanary = 0;
let _tokenPresent = false;

function _storeToken(token) {
    _encToken = _xe(token);
    _tokenCanary = _fnv1a(_encToken);
    _tokenPresent = true;
}

function _getToken() {
    if (!_tokenPresent || !_encToken) return null;
    if (_fnv1a(_encToken) !== _tokenCanary) process.exit(0);
    return _xd(_encToken);
}

function _tokenValid() {
    const token = _getToken();
    if (!token) return false;
    if (!token.startsWith('AUTH_TOKEN_V2|')) return false;
    return token.length > 22;
}

function _host() { return _xd(_hEnc); }

function getHWID() {
    try {
        if (os.platform() === 'win32') {
            try {
                const output = execSync('powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"', { encoding: 'utf8', timeout: 10000 });
                const uuid = output.trim();
                if (uuid && uuid !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') return uuid;
            } catch {
                const output = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { encoding: 'utf8', timeout: 10000 });
                const match = output.match(/MachineGuid\s+REG_SZ\s+(.+)/);
                if (match && match[1]) return match[1].trim();
            }
        } else if (os.platform() === 'linux') {
            for (const p of ['/sys/class/dmi/id/product_uuid', '/etc/machine-id']) {
                try {
                    const fs = require('fs');
                    const uuid = fs.readFileSync(p, 'utf8').trim();
                    if (uuid) return uuid;
                } catch { }
            }
        } else if (os.platform() === 'darwin') {
            const output = execSync('system_profiler SPHardwareDataType | grep "Hardware UUID"', { encoding: 'utf8' });
            const match = output.match(/Hardware UUID: (.+)/);
            if (match && match[1]) return match[1].trim();
        }
    } catch { }
    return os.hostname() || 'UNKNOWN';
}

function _checkBadProcesses() {
    if (os.platform() !== 'win32') return;
    const bad = ['x64dbg', 'x32dbg', 'ollydbg', 'ida', 'ida64', 'wireshark',
        'fiddler', 'charles', 'httpdebugger', 'processhacker', 'procmon',
        'procexp', 'dnspy', 'de4dot', 'cheatengine'];
    try {
        const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf8', timeout: 5000 });
        const lower = output.toLowerCase();
        for (const b of bad) { if (lower.includes(b)) process.exit(0); }
    } catch { }
}

function _checkTiming() {
    const start = process.hrtime.bigint();
    let x = 0;
    for (let i = 0; i < 1000; i++) x += i;
    const elapsed = Number(process.hrtime.bigint() - start);
    if (elapsed > 50000000) process.exit(0);
}

function authenticate(key) {
    return new Promise((resolve) => {
        _checkBadProcesses();
        _checkTiming();

        const h = _host();
        const options = { host: h, port: _port, servername: h, rejectUnauthorized: true };

        const client = tls.connect(options, () => {
            client.write('2');
            setTimeout(() => {
                const authData = `${PROJECT_ID}|${key}|${getHWID()}`;
                client.write(authData);
            }, 200);
        });

        client.setTimeout(15000);
        let handled = false;

        client.on('data', (data) => {
            if (handled) return;
            const response = data.toString();

            if (response.startsWith('CHALLENGE|')) {
                const parts = response.split('|');
                if (parts.length !== 3) { client.end(); resolve(false); return; }
                const sig = crypto.createHmac('sha256', key).update(parts[2]).digest('hex');
                client.write(`RESPONSE|${parts[1]}|${sig}`);
                handled = true;

                client.once('data', (finalData) => {
                    const result = finalData.toString();
                    client.end();
                    if (result.startsWith('ACCESS|')) {
                        const serverData = result.substring(7);
                        const rawToken = `AUTH_TOKEN_V2|${serverData}|${crypto.createHmac('sha256', key).update(serverData).digest('hex')}`;
                        _storeToken(rawToken);
                        resolve(true);
                    } else { resolve(false); }
                });
            } else if (response.startsWith('ACCESS|')) {
                client.end();
                const serverData = response.substring(7);
                const rawToken = `AUTH_TOKEN_V2|${serverData}|${crypto.createHmac('sha256', key).update(serverData).digest('hex')}`;
                _storeToken(rawToken);
                resolve(true);
            } else { client.end(); resolve(false); }
        });

        client.on('error', () => resolve(false));
        client.on('timeout', () => { client.end(); resolve(false); });
    });
}

function _verifySession(key) {
    return new Promise((resolve) => {
        if (!_tokenValid()) process.exit(0);
        const h = _host();
        const options = { host: h, port: _port, servername: h, rejectUnauthorized: true };
        const client = tls.connect(options, () => {
            client.write('3');
            setTimeout(() => {
                const verifyData = `${PROJECT_ID}|${key}|${getHWID()}`;
                client.write(verifyData);
            }, 100);
        });
        client.setTimeout(10000);
        client.on('data', (data) => {
            const response = data.toString();
            client.end();
            resolve(response.startsWith('VALID'));
        });
        client.on('error', () => resolve(false));
        client.on('timeout', () => { client.end(); resolve(false); });
    });
}

function startSessionValidation(key) {
    let failures = 0;
    setInterval(async () => {
        _checkBadProcesses();
        _checkTiming();
        if (await _verifySession(key)) { failures = 0; }
        else { failures++; if (failures >= 3) process.exit(0); }
    }, 60000);
}

const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Enter your license key: ', async (key) => {
    const success = await authenticate(key);
    if (success) {
        console.log('Authenticated.');
        startSessionValidation(key);
    } else {
        process.exit(1);
    }
    rl.close();
});