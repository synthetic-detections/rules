<?php
/* Plugin Name: Staff Provisioner (benign) */
add_action('admin_init', function () {
    if (current_user_can('create_users')) {
        wp_insert_user(array('user_login' => 'editor_jane', 'role' => 'editor'));
    }
    // reference to mu-plugins path for docs only
    $dir = WPMU_PLUGIN_DIR; // wp-content/mu-plugins
});
