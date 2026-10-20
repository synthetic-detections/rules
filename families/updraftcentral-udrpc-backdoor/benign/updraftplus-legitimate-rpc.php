<?php
/*
Plugin Name: UpdraftPlus: WP Backup & Migration Plugin
Description: Backup, restore and migration plugin for WordPress.
Version: 1.26.12
*/
// Legitimate UpdraftPlus code fragment showing the UDRPC callback registration.
// Must NOT trigger YARA rule — no malicious markers present.
class UpdraftPlus_Remote_Communications_V2 {
    public function wp_loaded() {
        if (isset($_POST['udrpc_message'])) {
            $this->process_message($_POST['udrpc_message']);
        }
    }
    private function process_message($msg) {
        $decoded = $this->decrypt_message($msg);
        if ($decoded === false) return;
        do_action('updraft_central_ajaxcallback', $decoded);
    }
    private function decrypt_message($msg) {
        if (!is_string($msg)) return false;
        return json_decode($msg, true);
    }
}
