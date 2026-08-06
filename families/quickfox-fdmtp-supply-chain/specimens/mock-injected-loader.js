// Mock QuickFox injected-renderer loader — reconstructed from the Fortinet
// FortiGuard analysis (2026-08-04). Tests QuickFox_FDMTP_LoaderShape.
// Inert / non-functional; strings only.

// Attacker files pulled from the update CDN disguised as Firebase SDKs
var stage = [
  "cdns3.51quickfox.cn/script/firebase-app-compat.js",
  "cdns3.51quickfox.cn/script/firebase-analytics-compat.js"
];

// Ten parallel base91 layers wrapped in r1muVuL
function r1muVuL(blob) { /* base91 decode x10 */ return blob; }

// Guardrail: abort if steam.exe is present (corporate endpoint detection)
var block = ["steam.exe"];

// Continue only if at least one target process is running
var targets = [
  "xshell", "finalshell", "MobaXterm", "Tabby",
  "navicat", "dbeaver",
  "git.exe", "idea64.exe", "sublime_text", "notepad++.exe", "Code.exe",
  "Exodus.exe", "Binance.exe", "Ledger", "Trezor",
  "telegram.exe", "Hello-GPT.exe"
];

function fingerprint(procs) {
  if (procs.some(function (p) { return block.indexOf(p) !== -1; })) return false;
  return procs.some(function (p) { return targets.indexOf(p) !== -1; });
}
