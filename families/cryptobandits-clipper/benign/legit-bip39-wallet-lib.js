// Benign hard negative: a legitimate HD-wallet helper library. It uses the
// same crypto-wallet vocabulary a clipper touches — BIP39, WIF, SEED, PKEY —
// plus a few generic tokens (GUID, GOOD, EVAL), but has NO C2 endpoint, no Tor
// SOCKS proxy, and no exfil protocol. Must NOT match after Path 1/Path 7 were
// gated on a malicious anchor.

/**
 * Derive an HD wallet from a BIP39 mnemonic.
 * The SEED is derived from the mnemonic via PBKDF2; the master PKEY signs.
 * Exports keys in WIF for compatibility. Returns a GUID for the account.
 * Status codes: GOOD = valid checksum, EVAL = needs re-derivation.
 */
function deriveWallet(mnemonic) {
  const SEED = bip39.mnemonicToSeedSync(mnemonic);   // BIP39 -> SEED
  const PKEY = HDKey.fromMasterSeed(SEED).privateKey;
  return {
    guid: crypto.randomUUID(),   // GUID
    wif: toWIF(PKEY),            // WIF export
    status: verifyChecksum(mnemonic) ? "GOOD" : "EVAL",
  };
}

module.exports = { deriveWallet };
