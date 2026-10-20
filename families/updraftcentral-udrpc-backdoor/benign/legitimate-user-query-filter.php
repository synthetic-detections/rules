<?php
/*
Plugin Name: User Management Pro
Description: Adds custom columns and filters to the WordPress Users screen.
Version: 3.2.1
*/
// Legitimate plugin that uses pre_user_query and pre_count_users for custom filtering.
// Must NOT trigger YARA rule — has user-query hooks but lacks the auth-cookie and hash-validation calls.
add_action('pre_user_query', function($query) {
    if (isset($_GET['role_filter'])) {
        global $wpdb;
        $query->query_where .= $wpdb->prepare(
            " AND {$wpdb->users}.ID IN (SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s)",
            'wp_capabilities'
        );
    }
});
add_filter('pre_count_users', function($result, $strategy, $site_id) {
    if ($strategy === 'time') {
        $result['total_users'] = wp_cache_get('total_users_cached');
    }
    return $result;
}, 10, 3);
