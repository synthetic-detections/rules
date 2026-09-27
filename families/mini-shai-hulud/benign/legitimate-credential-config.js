// Benign: a legitimate cloud SDK configuration file
// Uses credential env vars but has no worm markers
const aws = process.env.AWS_ACCESS_KEY_ID;
const azure = process.env.AZURE_CLIENT_SECRET;
const gcp = process.env.GOOGLE_APPLICATION_CREDENTIALS;
const kube = require('fs').readFileSync(process.env.HOME + '/.kube/config');

module.exports = { aws, azure, gcp, kube };
