// Legitimate cloud SDK helper that reads instance metadata.
const IMDS = "http://169.254.169.254/latest/meta-data/";
async function getRegion() {
  const r = await fetch(IMDS + "placement/region");
  return r.text();
}
// runs under bun or node
module.exports = { getRegion };
