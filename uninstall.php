<?php
/**
 * Uninstall Wisdom Journal Manager
 * 
 * This file is executed when the plugin is uninstalled.
 * It cleans up all plugin data from the database.
 * 
 * @package Wisdom Journal Manager
 * @version 1.0
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Security check - only allow administrators to uninstall
if (!current_user_can('activate_plugins')) {
    return;
}

// Get plugin options
$options = array(
    'sjm_flush_rewrite_rules',
    'sjm_email_settings',
    'sjm_analytics_settings',
    'sjm_security_settings'
);

// Delete plugin options
foreach ($options as $option) {
    delete_option($option);
}

// Delete transients
delete_transient('sjm_paper_open_access_notice');

// Clean up any remaining transients (paper and issue validation notices) - Fixed SQL injection
global $wpdb;
$wpdb->query($wpdb->prepare(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
    '_transient_sjm_paper_required_notice_%'
));
$wpdb->query($wpdb->prepare(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
    '_transient_sjm_issue_required_notice_%'
));

// Remove custom roles if they exist
$journal_roles = array(
    'journal_editor_in_chief',
    'journal_managing_editor', 
    'journal_guest_editor',
    'journal_reviewer',
    'journal_author'
);

foreach ($journal_roles as $role) {
    if (get_role($role)) {
        remove_role($role);
    }
}

// Note: We don't delete the custom post types or their data
// as this could cause data loss. Users should manually delete
// if they want to remove all journal data.

// Flush rewrite rules
flush_rewrite_rules(); 