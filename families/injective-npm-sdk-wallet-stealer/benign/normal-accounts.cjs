"use strict";
// @injectivelabs/sdk-ts — accounts (clean)
const { PrivateKey } = require("./key");

function fromMnemonic(mnemonic) {
  return PrivateKey.fromMnemonic(mnemonic);
}

function fromHex(privateKeyHex) {
  return PrivateKey.fromHex(privateKeyHex);
}

module.exports = { fromMnemonic, fromHex };
