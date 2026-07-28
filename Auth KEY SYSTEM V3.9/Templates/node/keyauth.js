const tls = require('tls');
const crypto = require('crypto');
const os = require('os');
const { execSync } = require('child_process');

const _xk = Buffer.from([0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33]);
const _hEnc = Buffer.from([0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82]);
const _port = 3389;
const PROJECT_ID = 'ENTER_PROJECT_ID_HERE';

const _cfEnc = Buffer.from([    
    0xE5, 0x7F, 0xCB, 0x6E, 0xA5, 0xFC, 0x5E, 0x3E, 0xA6, 0x4F, 0x55,
    0xFC, 0x0B, 0xE1, 0xC1, 0x75, 0x92, 0x08, 0xC7, 0x1F, 0xD4, 0xF4,
    0x5E, 0x48, 0xA1, 0x43, 0x57, 0xFF, 0x76, 0xE7, 0xB6, 0x77, 0xE4,
    0x0F, 0xC0, 0x6E, 0xA0, 0xF2, 0x2E, 0x4B, 0xA5, 0x3F, 0x52, 0x8B,
    0x0B, 0x96, 0xC1, 0x70, 0xE1, 0x0A, 0xB6, 0x1F, 0xD0, 0xF4, 0x5A,
    0x4E, 0xA0, 0x4B, 0x21, 0x89, 0x09, 0xE5, 0xB7, 0x76]);
let _cachedPubKey = null;

function _fetchPubKey() {
    if (_cachedPubKey) return _cachedPubKey;
    return new Promise((resolve) => {
        const h = _xd(_hEnc);
        const socket = tls.connect(_port, h, { servername: h }, () => {
            socket.write('8');
        });
        let data = '';
        socket.on('data', (chunk) => { data += chunk.toString(); });
        socket.on('end', () => {
            if (data.startsWith('PUBKEY|')) {
                const raw = Buffer.from(data.slice(7), 'hex');
                if (raw.length === 64) { _cachedPubKey = raw; resolve(raw); return; }
            }
            resolve(null);
        });
        socket.on('error', () => resolve(null));
        socket.setTimeout(10000, () => { socket.destroy(); resolve(null); });
    });
}

function _fetchPubKeySync() {
    if (_cachedPubKey) return _cachedPubKey;
    try {
        const net = require('net');
        const rawSock = new net.Socket();
        rawSock.connect(_port, _xd(_hEnc));
        const tlsSock = tls.connect({ socket: rawSock, servername: _xd(_hEnc) });
        let resp = '';
        tlsSock.on('secureConnect', () => tlsSock.write('8'));
        tlsSock.on('data', (d) => { resp += d.toString(); });
        const { execSync: es } = require('child_process');
        es('sleep 0', { timeout: 2000 });
        if (resp.startsWith('PUBKEY|')) {
            const raw = Buffer.from(resp.slice(7), 'hex');
            if (raw.length === 64) { _cachedPubKey = raw; return raw; }
        }
    } catch {}
    return null;
}

function _verifySig(data, sigHex) {
    const raw = _cachedPubKey;
    if (!raw) return true;
    try {
        const x = raw.slice(0, 32).toString('base64url');
        const y = raw.slice(32).toString('base64url');
        const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x, y }, format: 'jwk' });
        const r = Buffer.from(sigHex.slice(0, 64), 'hex');
        const s = Buffer.from(sigHex.slice(64), 'hex');
        const rLen = r[0] & 0x80 ? 33 : 32; const sLen = s[0] & 0x80 ? 33 : 32;
        const derSig = Buffer.alloc(6 + rLen + sLen);
        let off = 0;
        derSig[off++] = 0x30; derSig[off++] = 4 + rLen + sLen;
        derSig[off++] = 0x02; derSig[off++] = rLen;
        if (rLen === 33) derSig[off++] = 0;
        r.copy(derSig, off); off += 32;
        derSig[off++] = 0x02; derSig[off++] = sLen;
        if (sLen === 33) derSig[off++] = 0;
        s.copy(derSig, off);
        return crypto.verify('SHA256', Buffer.from(data), key, derSig);
    } catch { return false; }
}

function _verifyCertPin(socket) {
    if (_cfEnc.length === 0) return true;
    const cert = socket.getPeerCertificate(true);
    if (!cert || !cert.raw) return false;
    const hash = crypto.createHash('sha256').update(cert.raw).digest('hex').toUpperCase();
    const expected = _xd(_cfEnc).toUpperCase();
    return hash === expected;
}

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
    const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
    try {
        if (os.platform() === 'win32') {
            try {
                const output = execSync('powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"', { encoding: 'utf8', timeout: 10000 });
                const uuid = output.trim();
                if (uuid && uuid !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') return hash(uuid);
            } catch {
                const output = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { encoding: 'utf8', timeout: 10000 });
                const match = output.match(/MachineGuid\s+REG_SZ\s+(.+)/);
                if (match && match[1]) return hash(match[1].trim());
            }
        } else if (os.platform() === 'linux') {
            for (const p of ['/sys/class/dmi/id/product_uuid', '/etc/machine-id']) {
                try {
                    const fs = require('fs');
                    const uuid = fs.readFileSync(p, 'utf8').trim();
                    if (uuid) return hash(uuid);
                } catch { }
            }
        } else if (os.platform() === 'darwin') {
            const output = execSync('system_profiler SPHardwareDataType | grep "Hardware UUID"', { encoding: 'utf8' });
            const match = output.match(/Hardware UUID: (.+)/);
            if (match && match[1]) return hash(match[1].trim());
        }
    } catch { }
    return hash(os.hostname() || 'UNKNOWN');
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
    return new Promise(async (resolve) => {
        _checkBadProcesses();
        _checkTiming();
        await _fetchPubKey();

        const h = _host();
        const options = { host: h, port: _port, servername: h, rejectUnauthorized: true };

        const client = tls.connect(options, () => {
            if (!_verifyCertPin(client)) {
                client.end();
                resolve(false);
                return;
            }

            client.write('2');
            setTimeout(() => {
                const authData = `${PROJECT_ID}|${key}|${getHWID()}`;
                client.write(authData);
            }, 200);
        });

        client.setTimeout(15000);
        let challenge = null;
        let handled = false;

        client.on('data', (data) => {
            if (handled) return;
            const response = data.toString();

            if (response.startsWith('CHALLENGE|')) {
                const parts = response.split('|');
                if (parts.length !== 3) { client.end(); resolve(false); return; }
                challenge = parts[2];
                const sig = crypto.createHmac('sha256', key).update(parts[2]).digest('hex');
                client.write(`RESPONSE|${parts[1]}|${sig}`);
                handled = true;

                client.once('data', (finalData) => {
                    const result = finalData.toString();
                    client.end();
                    if (result.startsWith('ACCESS|')) {
                        const accessParts = result.split('|');
                        if (accessParts.length < 4) { resolve(false); return; }
                        const serverData = accessParts[1];
                        const serverProof = accessParts[2];
                        const authSig = accessParts[3];
                        const expectedProof = crypto.createHmac('sha256', key).update(challenge + '|' + serverData).digest('hex');
                        if (serverProof !== expectedProof) { resolve(false); return; }
                        if (!_verifySig(challenge + '|' + serverData, authSig)) { resolve(false); return; }
                        const rawToken = `AUTH_TOKEN_V2|${serverData}|${crypto.createHmac('sha256', key).update(serverData).digest('hex')}`;
                        _storeToken(rawToken);
                        resolve(true);
                    } else { resolve(false); }
                });
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
            if (!_verifyCertPin(client)) {
                client.end();
                process.exit(0);
            }

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
            if (!response.startsWith('VALID|')) { resolve(false); return; }
            const parts = response.split('|');
            if (parts.length < 5) { resolve(false); return; }
            const remaining = parts[2];
            const verifyProof = parts[3];
            const verifySig = parts[4];
            const expected = crypto.createHmac('sha256', key).update(`VERIFY:${PROJECT_ID}:${remaining}`).digest('hex');
            if (verifyProof !== expected) { resolve(false); return; }
            resolve(_verifySig(`VERIFY:${PROJECT_ID}:${remaining}`, verifySig));
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

function _recvExact(socket, n) {
    return new Promise((resolve) => {
        let buf = Buffer.alloc(0);
        const onData = (chunk) => {
            buf = Buffer.concat([buf, chunk]);
            if (buf.length >= n) {
                socket.removeListener('data', onData);
                resolve(buf.slice(0, n));
            }
        };
        socket.on('data', onData);
        setTimeout(() => { socket.removeListener('data', onData); resolve(null); }, 30000);
    });
}

function downloadFile(key, fileName) {
    return new Promise((resolve) => {
        const h = _host();
        const options = { host: h, port: _port, servername: h, rejectUnauthorized: true };
        const client = tls.connect(options, async () => {
            if (!_verifyCertPin(client)) { client.end(); resolve(null); return; }
            client.write('6');
            await new Promise(r => setTimeout(r, 100));
            client.write(`${PROJECT_ID}|${key}|${getHWID()}|${fileName}`);

            const hdrLenRaw = await _recvExact(client, 4);
            if (!hdrLenRaw) { client.end(); resolve(null); return; }
            const hdrLen = (hdrLenRaw[0] << 24) | (hdrLenRaw[1] << 16) | (hdrLenRaw[2] << 8) | hdrLenRaw[3];
            if (hdrLen > 4096) { client.end(); resolve(null); return; }
            const hdrBytes = await _recvExact(client, hdrLen);
            if (!hdrBytes) { client.end(); resolve(null); return; }
            const header = hdrBytes.toString('utf8');
            if (header.startsWith('ERROR')) { client.end(); resolve(null); return; }

            const parts = header.split('|');
            if (parts.length < 5 || parts[0] !== 'FILE') { client.end(); resolve(null); return; }
            const nonceHex = parts[1], tagHex = parts[2], expectedHash = parts[3], fileSize = parseInt(parts[4]);

            const bodyLenRaw = await _recvExact(client, 4);
            if (!bodyLenRaw) { client.end(); resolve(null); return; }
            const bodyLen = (bodyLenRaw[0] << 24) | (bodyLenRaw[1] << 16) | (bodyLenRaw[2] << 8) | bodyLenRaw[3];
            if (bodyLen > 60 * 1024 * 1024) { client.end(); resolve(null); return; }
            const body = await _recvExact(client, bodyLen);
            client.end();
            if (!body) { resolve(null); return; }

            const nonce = Buffer.from(nonceHex, 'hex');
            const tag = Buffer.from(tagHex, 'hex');
            if (nonce.length !== 12 || tag.length !== 16) { resolve(null); return; }

            const fileKey = crypto.createHmac('sha256', key).update('FILE_KEY:' + nonceHex).digest();
            try {
                const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, nonce);
                decipher.setAuthTag(tag);
                decipher.setAAD(Buffer.from(PROJECT_ID));
                const dec1 = decipher.update(body);
                const dec2 = decipher.final();
                const plaintext = Buffer.concat([dec1, dec2]);
                const actualHash = crypto.createHash('sha256').update(plaintext).digest('hex');
                if (actualHash !== expectedHash || plaintext.length !== fileSize) { resolve(null); return; }
                resolve(plaintext);
            } catch { resolve(null); }
        });
        client.on('error', () => resolve(null));
        client.on('timeout', () => { client.end(); resolve(null); });
    });
}

function _secureWipe(filePath) {
    const fs = require('fs');
    try {
        const size = fs.statSync(filePath).size;
        const fd = fs.openSync(filePath, 'w');
        fs.writeSync(fd, Buffer.alloc(size, 0));
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fs.unlinkSync(filePath);
    } catch { try { fs.unlinkSync(filePath); } catch { } }
}

async function downloadAndRun(key, fileName) {
    const data = await downloadFile(key, fileName);
    if (!data) return false;
    try {
        const fs = require('fs');
        const path = require('path');
        const { spawn } = require('child_process');
        const tempBase = os.tmpdir();
        const randomDir = path.join(tempBase, '_ka_' + crypto.randomBytes(4).toString('hex'));
        fs.mkdirSync(randomDir, { recursive: true });

        if (os.platform() === 'win32') {
            try { execSync(`attrib +h +s "${randomDir}"`, { timeout: 5000 }); } catch { }
        }

        const exePath = path.join(randomDir, fileName);
        fs.writeFileSync(exePath, data);

        if (os.platform() === 'win32') {
            try { execSync(`attrib +h "${exePath}"`, { timeout: 5000 }); } catch { }
        }

        data.fill(0);

        if (os.platform() === 'win32') {
            spawn('powershell', ['-NoProfile', '-Command',
                `Start-Process -FilePath '${exePath}' -WorkingDirectory '${randomDir}' -Verb RunAs`],
                { detached: true, stdio: 'ignore' }).unref();
        } else {
            spawn(exePath, [], { detached: true, stdio: 'ignore', cwd: randomDir }).unref();
        }

        const capExe = exePath, capDir = randomDir;
        setTimeout(() => {
            _secureWipe(capExe);
            setTimeout(() => { try { fs.rmSync(capDir, { recursive: true, force: true }); } catch { } }, 1000);
        }, 2000);

        return true;
    } catch { return false; }
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
