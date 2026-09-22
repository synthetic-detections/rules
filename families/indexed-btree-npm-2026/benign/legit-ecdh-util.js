// legitimate X25519 key-agreement helper
const crypto = require('crypto');
function agree(myPriv, theirPub) {
  const ecdh = crypto.createECDH('x25519');
  ecdh.setPrivateKey(myPriv);
  const shared = ecdh.computeSecret(theirPub);
  return crypto.createHash('sha256').update(shared).digest();
}
module.exports = { agree };
