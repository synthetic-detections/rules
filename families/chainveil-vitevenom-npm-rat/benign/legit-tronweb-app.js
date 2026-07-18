// Legitimate dApp that uses TronWeb to read a balance. No persistence, no shell spawn.
const TronWeb = require('tronweb');
async function balance(addr) {
  const tw = new TronWeb({ fullHost: 'https://api.trongrid.io' });
  return await tw.trx.getBalance(addr);
}
module.exports = { balance };
