// Mock easy-day-js setup.cjs dropper — tests EasyDayJS_Dropper_Behavior
// Contains obfuscation markers, TLS disable, self-delete, and XOR marker

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const tmpDir = os.tmpdir();
const histFile = path.join(tmpDir, '.pkg_history');
const logFile = path.join(tmpDir, '.pkg_logs');

fs.writeFileSync(histFile, __dirname);

// XOR-0x80 encoded package name written to .pkg_logs
const marker = Buffer.from([0xe5, 0xe1, 0xf3, 0xf9, 0xad, 0xe4, 0xe1, 0xf9, 0xad, 0xea, 0xf3]);
fs.writeFileSync(logFile, marker);

// Checksum validation (obfuscation layer): 0x4c11d
const arr = new Array(40);
// ... rotation logic omitted in mock ...

const payloadPath = path.join(tmpDir, require('crypto').randomBytes(12).toString('hex') + '.js');

const child = execFile(process.execPath, [payloadPath], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true
});
child.unref();

// Self-delete
fs.rmSync(__filename, { force: true });
