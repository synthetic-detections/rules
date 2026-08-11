// Benign DNS utility: legitimately uses dns.resolveTxt (e.g. SPF/DKIM checks,
// domain verification). Has resolveTxt + OS awareness but none of the
// WEL1DROPPER staging hosts or helper-file entry points.
'use strict';
const dns = require('dns');

function getSpf(domain, cb) {
  dns.resolveTxt(domain, (err, records) => {
    if (err) return cb(err);
    const spf = records.map(r => r.join('')).find(t => t.startsWith('v=spf1'));
    cb(null, spf || null);
  });
}

module.exports = { getSpf, platform: process.platform };
