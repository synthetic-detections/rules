<?php
/*
Plugin Name: Server Health Monitor
Description: Displays server information in the WordPress dashboard.
Version: 1.0.0
*/
// Legitimate plugin that uses system() for server diagnostics.
// Must NOT trigger YARA rule — has system() but none of the unique webshell
// markers used by the OffSeq variant.
function shm_get_server_info() {
    ob_start();
    system('uname -a');
    $uname = ob_get_clean();
    return [
        'uname' => $uname,
        'php_version' => phpversion(),
        'disk_free' => disk_free_space('/'),
    ];
}
add_action('wp_dashboard_setup', function() {
    wp_add_dashboard_widget('shm_info', 'Server Health', function() {
        $info = shm_get_server_info();
        echo '<pre>' . esc_html(print_r($info, true)) . '</pre>';
    });
});
