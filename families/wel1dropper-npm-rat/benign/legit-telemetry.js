// Benign, real-world-shaped npm telemetry helper: reads process.platform /
// process.arch for analytics and posts to a legitimate first-party endpoint.
// Uses helper file names and OS fingerprinting but NO WEL1DROPPER staging.
'use strict';
const https = require('https');

function environment() {
  return {
    os: process.platform,
    cpu: process.arch,
    node: process.version,
    ci: !!process.env.CI,
  };
}

function report(evt) {
  const body = JSON.stringify({ event: evt, env: environment() });
  const req = https.request({
    host: 'telemetry.example-company.com',
    path: '/v1/collect',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
  });
  req.write(body);
  req.end();
}

module.exports = { environment, report };
