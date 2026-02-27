<?php
/*
Plugin Name: Wisdom Journal Manager
Plugin URI: http://wjm.aethex.online
Description: World's First Affordable Journal Manager
Version: 1.0.0
Author: Maaz Ahmad, Shariq Hashme
Author URI: http://aethex.online
Company: Aethex
Text Domain: wisdom-journal-manager
Domain Path: /languages
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Requires at least: 5.0
Tested up to: 6.5
Requires PHP: 7.4
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('WJM_VERSION', '1.0.0');
define('WJM_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WJM_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WJM_PLUGIN_FILE', __FILE__);

// ========================================
// ENHANCED SECURITY SYSTEM
// ========================================

/**
 * Enhanced API Key Encryption System
 */
class WJM_Security_Manager {
    
    private static $encryption_key = null;
    
    /**
     * Get encryption key for API keys
     */
    private static function get_encryption_key() {
        if (self::$encryption_key === null) {
            // Use WordPress salt as base, create unique key for this plugin
            $base_key = wp_salt('auth');
            self::$encryption_key = hash('sha256', $base_key . 'wjm_api_keys');
        }
        return self::$encryption_key;
    }
    
    /**
     * Encrypt API key
     */
    public static function encrypt_api_key($api_key) {
        if (empty($api_key)) {
            return '';
        }
        
        $key = self::get_encryption_key();
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        $encrypted = openssl_encrypt($api_key, 'AES-256-CBC', $key, 0, $iv);
        
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Decrypt API key
     */
    public static function decrypt_api_key($encrypted_api_key) {
        if (empty($encrypted_api_key)) {
            return '';
        }
        
        $key = self::get_encryption_key();
        $data = base64_decode($encrypted_api_key);
        $iv_length = openssl_cipher_iv_length('AES-256-CBC');
        $iv = substr($data, 0, $iv_length);
        $encrypted = substr($data, $iv_length);
        
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }
    
    /**
     * Advanced Rate Limiting System with Best Practices
     */
    public static function check_rate_limit($action, $user_id, $limit = null, $time_window = null) {
        // Get user role and set appropriate limits
        $user = get_user_by('id', $user_id);
        $user_role = $user ? $user->roles[0] : 'subscriber';
        
        // Define limits based on user role and action
        $limits = self::get_rate_limits($user_role, $action);
        
        // Use provided limits or defaults
        $limit = $limit ?: $limits['limit'];
        $time_window = $time_window ?: $limits['time_window'];
        
        $transient_key = "wjm_rate_limit_{$action}_{$user_id}";
        $attempts = get_transient($transient_key);
        
        // Get remaining quota for user feedback
        $remaining = $limit - ($attempts ?: 0);
        
        if ($attempts === false) {
            set_transient($transient_key, 1, $time_window);
            return array('allowed' => true, 'remaining' => $limit - 1);
        }
        
        if ($attempts >= $limit) {
            // Log rate limit violation
            self::log_security_event('rate_limit_exceeded', array(
                'action' => $action,
                'user_id' => $user_id,
                'user_role' => $user_role,
                'limit' => $limit,
                'time_window' => $time_window
            ), 'warning');
            
            return array('allowed' => false, 'remaining' => 0, 'reset_time' => time() + $time_window);
        }
        
        set_transient($transient_key, $attempts + 1, $time_window);
        return array('allowed' => true, 'remaining' => $remaining - 1);
    }
    
    /**
     * Get rate limits based on user role and action
     */
    private static function get_rate_limits($user_role, $action) {
        $base_limits = array(
            'student' => array(
                'api_call' => array('limit' => 50, 'time_window' => 3600),
                'data_fetch' => array('limit' => 30, 'time_window' => 3600),
                'file_upload' => array('limit' => 10, 'time_window' => 86400),
                'login_attempt' => array('limit' => 5, 'time_window' => 900)
            ),
            'researcher' => array(
                'api_call' => array('limit' => 100, 'time_window' => 3600),
                'data_fetch' => array('limit' => 60, 'time_window' => 3600),
                'file_upload' => array('limit' => 20, 'time_window' => 86400),
                'login_attempt' => array('limit' => 5, 'time_window' => 900)
            ),
            'editor' => array(
                'api_call' => array('limit' => 200, 'time_window' => 3600),
                'data_fetch' => array('limit' => 120, 'time_window' => 3600),
                'file_upload' => array('limit' => 50, 'time_window' => 86400),
                'login_attempt' => array('limit' => 10, 'time_window' => 900)
            ),
            'administrator' => array(
                'api_call' => array('limit' => 500, 'time_window' => 3600),
                'data_fetch' => array('limit' => 300, 'time_window' => 3600),
                'file_upload' => array('limit' => 100, 'time_window' => 86400),
                'login_attempt' => array('limit' => 20, 'time_window' => 900)
            )
        );
        
        // Default to researcher limits if role not found
        $role_limits = isset($base_limits[$user_role]) ? $base_limits[$user_role] : $base_limits['researcher'];
        
        return isset($role_limits[$action]) ? $role_limits[$action] : array('limit' => 100, 'time_window' => 3600);
    }
    
    /**
     * Get user-friendly rate limit information
     */
    public static function get_rate_limit_info($action, $user_id) {
        $user = get_user_by('id', $user_id);
        $user_role = $user ? $user->roles[0] : 'subscriber';
        $limits = self::get_rate_limits($user_role, $action);
        
        $transient_key = "wjm_rate_limit_{$action}_{$user_id}";
        $attempts = get_transient($transient_key);
        $remaining = $limits['limit'] - ($attempts ?: 0);
        
        return array(
            'current_usage' => $attempts ?: 0,
            'limit' => $limits['limit'],
            'remaining' => max(0, $remaining),
            'time_window' => $limits['time_window'],
            'reset_time' => time() + $limits['time_window'],
            'user_role' => $user_role
        );
    }
    
    /**
     * Enhanced input sanitization
     */
    public static function sanitize_input($input, $type = 'text', $allowed_html = null) {
        if (is_array($input)) {
            return array_map(function($item) use ($type, $allowed_html) {
                return self::sanitize_input($item, $type, $allowed_html);
            }, $input);
        }
        
        switch ($type) {
            case 'email':
                return sanitize_email($input);
            case 'url':
                return esc_url_raw($input);
            case 'int':
                return intval($input);
            case 'float':
                return floatval($input);
            case 'textarea':
                return sanitize_textarea_field($input);
            case 'html':
                return wp_kses($input, $allowed_html ?: wp_kses_allowed_html('post'));
            case 'filename':
                return sanitize_file_name($input);
            case 'key':
                return sanitize_key($input);
            case 'title':
                return sanitize_title($input);
            case 'api_key':
                // Special handling for API keys - only allow alphanumeric and some special chars
                return preg_replace('/[^a-zA-Z0-9\-_\.]/', '', $input);
            default:
                return sanitize_text_field($input);
        }
    }
    
    /**
     * Enhanced output escaping
     */
    public static function escape_output($content, $context = 'html') {
        switch ($context) {
            case 'html':
                return esc_html($content);
            case 'attr':
                return esc_attr($content);
            case 'url':
                return esc_url($content);
            case 'js':
                return esc_js($content);
            case 'textarea':
                return esc_textarea($content);
            case 'html_attr':
                return esc_attr($content);
            default:
                return esc_html($content);
        }
    }
    
    /**
     * Validate and sanitize file uploads
     */
    public static function validate_file_upload($file, $allowed_types = null) {
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            return new WP_Error('invalid_upload', 'Invalid file upload.');
        }
        
        $allowed_types = $allowed_types ?: array(
            'pdf' => 'application/pdf',
            'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'txt' => 'text/plain',
            'rtf' => 'application/rtf'
        );
        
        $file_type = wp_check_filetype($file['name']);
        $file_mime = $file['type'];
        
        // Check file extension
        if (!in_array($file_type['ext'], array_keys($allowed_types))) {
            return new WP_Error('invalid_file_type', 'File type not allowed.');
        }
        
        // Check MIME type
        if (!in_array($file_mime, array_values($allowed_types))) {
            return new WP_Error('invalid_mime_type', 'File MIME type not allowed.');
        }
        
        // Check file size (10MB limit)
        if ($file['size'] > 10 * 1024 * 1024) {
            return new WP_Error('file_too_large', 'File size exceeds 10MB limit.');
        }
        
        // Scan file content for malicious patterns
        $file_content = file_get_contents($file['tmp_name']);
        $malicious_patterns = array(
            '/<script/i',
            '/javascript:/i',
            '/vbscript:/i',
            '/onload=/i',
            '/onerror=/i',
            '/eval\s*\(/i',
            '/document\./i',
            '/window\./i'
        );
        
        foreach ($malicious_patterns as $pattern) {
            if (preg_match($pattern, $file_content)) {
                return new WP_Error('malicious_content', 'File contains potentially malicious content.');
            }
        }
        
        return true;
    }
    
    /**
     * Enhanced capability checking with custom roles
     */
    public static function check_user_capability($action, $post_id = null) {
        $user = wp_get_current_user();
        
        if (!is_user_logged_in()) {
            return false;
        }
        
        // Rate limiting check
        if (!self::check_rate_limit($action, $user->ID)) {
            return false;
        }
        
        switch ($action) {
            case 'edit_paper':
                return current_user_can('edit_post', $post_id) || 
                       current_user_can('edit_papers') ||
                       self::user_has_journal_roles($user);
                       
            case 'publish_paper':
                return current_user_can('publish_posts') ||
                       in_array('journal_editor_in_chief', $user->roles) ||
                       in_array('journal_managing_editor', $user->roles);
                       
            case 'manage_authors':
                return current_user_can('manage_options') ||
                       self::user_has_journal_roles($user);
                       
            case 'import_export':
                return current_user_can('manage_options') ||
                       in_array('journal_editor_in_chief', $user->roles);
                       
            case 'email_settings':
                return current_user_can('manage_options');
                
            case 'api_access':
                return current_user_can('manage_options');
                
            default:
                return current_user_can('edit_posts');
        }
    }
    
    /**
     * Check if user has journal-specific roles
     */
    private static function user_has_journal_roles($user) {
        $journal_roles = array(
            'journal_editor_in_chief',
            'journal_managing_editor',
            'journal_associate_editor',
            'journal_reviewer',
            'journal_author'
        );
        
        return array_intersect($journal_roles, $user->roles);
    }
    
    /**
     * Log security events
     */
    public static function log_security_event($event, $details = array(), $severity = 'info') {
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'user_id' => get_current_user_id(),
            'user_ip' => self::get_client_ip(),
            'event' => $event,
            'details' => $details,
            'severity' => $severity,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        );
        
        $security_log = get_option('wjm_security_log', array());
        $security_log[] = $log_entry;
        
        // Keep only last 1000 entries
        if (count($security_log) > 1000) {
            $security_log = array_slice($security_log, -1000);
        }
        
        update_option('wjm_security_log', $security_log);
    }
    
    /**
     * Get client IP address
     */
    private static function get_client_ip() {
        $ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }
    
    /**
     * Validate CSRF token
     */
    public static function validate_csrf_token($token, $action) {
        $user_id = get_current_user_id();
        $valid = wp_verify_nonce($token, $action . '_' . $user_id);
        
        if (!$valid) {
            self::log_security_event('csrf_attempt', array('action' => $action), 'warning');
        }
        
        return $valid;
    }
    
    /**
     * Generate CSRF token
     */
    public static function generate_csrf_token($action) {
        $user_id = get_current_user_id();
        return wp_create_nonce($action . '_' . $user_id);
    }
}

// Initialize security manager
WJM_Security_Manager::class;

// Load text domain for translations
function wjm_load_textdomain() {
    load_plugin_textdomain('wisdom-journal-manager', false, dirname(plugin_basename(__FILE__)) . '/languages/');
}
add_action('plugins_loaded', 'wjm_load_textdomain');

// Include automated pages system
require_once plugin_dir_path(__FILE__) . 'automated-pages.php';

// Include updated shortcodes with improved design
require_once plugin_dir_path(__FILE__) . 'updated-shortcodes.php';

// Register Journal Custom Post Type
function sjm_register_journal_cpt() {
    $labels = array(
        'name' => 'Journals',
        'singular_name' => 'Journal',
        'add_new' => 'Add New',
        'add_new_item' => 'Add New Journal',
        'edit_item' => 'Edit Journal',
        'new_item' => 'New Journal',
        'view_item' => 'View Journal',
        'search_items' => 'Search Journals',
        'not_found' => 'No journals found',
        'not_found_in_trash' => 'No journals found in Trash',
        'menu_name' => 'Journals',
    );
    $args = array(
        'labels' => $labels,
        'public' => true,
        'has_archive' => true,
        'supports' => array('title', 'editor'),
        'menu_icon' => 'dashicons-book',
    );
    register_post_type('journal', $args);
}
add_action('init', 'sjm_register_journal_cpt');

// Register Journal Issue Custom Post Type
function sjm_register_journal_issue_cpt() {
    $labels = array(
        'name' => 'Journal Issues',
        'singular_name' => 'Journal Issue',
        'add_new' => 'Add New',
        'add_new_item' => 'Add New Issue',
        'edit_item' => 'Edit Issue',
        'new_item' => 'New Issue',
        'view_item' => 'View Issue',
        'search_items' => 'Search Issues',
        'not_found' => 'No issues found',
        'not_found_in_trash' => 'No issues found in Trash',
        'menu_name' => 'Journal Issues',
    );
    $args = array(
        'labels' => $labels,
        'public' => true,
        'has_archive' => true,
        'supports' => array('title', 'editor'),
        'menu_icon' => 'dashicons-media-document',
    );
    register_post_type('journal_issue', $args);
}
add_action('init', 'sjm_register_journal_issue_cpt');

// Register Paper Custom Post Type
function sjm_register_paper_cpt() {
    $labels = array(
        'name' => 'Papers',
        'singular_name' => 'Paper',
        'add_new' => 'Add New',
        'add_new_item' => 'Add New Paper',
        'edit_item' => 'Edit Paper',
        'new_item' => 'New Paper',
        'view_item' => 'View Paper',
        'search_items' => 'Search Papers',
        'not_found' => 'No papers found',
        'not_found_in_trash' => 'No papers found in Trash',
        'menu_name' => 'Papers',
    );
    $args = array(
        'labels' => $labels,
        'public' => true,
        'has_archive' => true,
        'supports' => array('title', 'editor'),
        'menu_icon' => 'dashicons-media-text',
    );
    register_post_type('paper', $args);
}
add_action('init', 'sjm_register_paper_cpt');



// Add rewrite rules for author profiles and user profiles
function sjm_add_author_rewrite_rules() {
    // Author profiles (from authors database)
    add_rewrite_rule(
        '^author/([^/]+)-([0-9]+)/?$',
        'index.php?author_profile_id=$matches[2]',
        'top'
    );
    
    // User profiles (from WordPress users with journal roles)
    add_rewrite_rule(
        '^user/([^/]+)-([0-9]+)/?$',
        'index.php?user_profile_id=$matches[2]',
        'top'
    );
}
add_action('init', 'sjm_add_author_rewrite_rules', 10, 0);

// Add query vars for author and user profiles
function sjm_add_author_query_vars($vars) {
    $vars[] = 'author_profile_id';
    $vars[] = 'user_profile_id';
    return $vars;
}
add_filter('query_vars', 'sjm_add_author_query_vars');

// Handle author and user profile templates
function sjm_author_profile_template($template) {
    $author_profile_id = get_query_var('author_profile_id');
    $user_profile_id = get_query_var('user_profile_id');
    
    if ($author_profile_id) {
        // Check if author exists in our database
        $author = sjm_get_author_by_id($author_profile_id);
        
        if ($author) {
            $template_path = plugin_dir_path(__FILE__) . 'templates/author-profile.php';
            
            if (file_exists($template_path)) {
                return $template_path;
            }
        }
    }
    
    if ($user_profile_id) {
        // Check if user exists and has journal roles
        $user = get_user_by('ID', $user_profile_id);
        
        if ($user && sjm_user_has_journal_roles($user)) {
            $template_path = plugin_dir_path(__FILE__) . 'templates/user-profile.php';
            
            if (file_exists($template_path)) {
                return $template_path;
            }
        }
    }
    
    return $template;
}
add_filter('template_include', 'sjm_author_profile_template');

// Flush rewrite rules on activation and init
function sjm_flush_rewrite_rules() {
    sjm_add_author_rewrite_rules();
    flush_rewrite_rules();
}
register_activation_hook(__FILE__, 'sjm_flush_rewrite_rules');

// Also flush on init if needed (for development)
add_action('init', function() {
    if (get_option('sjm_flush_rewrite_rules', false)) {
        sjm_add_author_rewrite_rules();
        flush_rewrite_rules();
        delete_option('sjm_flush_rewrite_rules');
    }
});

// Journal User Role Management System
function sjm_add_journal_roles() {
    // Add custom roles for journal management
    $journal_roles = array(
        'journal_editor_in_chief' => array(
            'display_name' => 'Journal Editor-in-Chief',
            'capabilities' => array(
                'read' => true,
                'edit_posts' => true,
                'edit_others_posts' => true,
                'edit_published_posts' => true,
                'publish_posts' => true,
                'delete_posts' => true,
                'delete_others_posts' => true,
                'delete_published_posts' => true,
                'edit_journals' => true,
                'edit_journal_issues' => true,
                'edit_papers' => true,
                'manage_journal_users' => true,
            )
        ),
        'journal_managing_editor' => array(
            'display_name' => 'Journal Managing Editor',
            'capabilities' => array(
                'read' => true,
                'edit_posts' => true,
                'edit_others_posts' => true,
                'edit_published_posts' => true,
                'publish_posts' => true,
                'edit_journals' => true,
                'edit_journal_issues' => true,
                'edit_papers' => true,
            )
        ),
        'journal_guest_editor' => array(
            'display_name' => 'Journal Guest Editor',
            'capabilities' => array(
                'read' => true,
                'edit_posts' => true,
                'edit_journal_issues' => true,
                'edit_papers' => true,
            )
        ),
        'journal_reviewer' => array(
            'display_name' => 'Journal Reviewer',
            'capabilities' => array(
                'read' => true,
                'review_papers' => true,
            )
        ),
        'journal_author' => array(
            'display_name' => 'Journal Author',
            'capabilities' => array(
                'read' => true,
                'edit_own_papers' => true,
                'submit_papers' => true,
            )
        ),
        'journal_copyeditor' => array(
            'display_name' => 'Journal Copyeditor',
            'capabilities' => array(
                'read' => true,
                'edit_papers' => true,
                'copyedit_papers' => true,
            )
        ),
        'journal_proofreader' => array(
            'display_name' => 'Journal Proofreader',
            'capabilities' => array(
                'read' => true,
                'proofread_papers' => true,
            )
        ),
        'journal_layout_editor' => array(
            'display_name' => 'Journal Layout Editor',
            'capabilities' => array(
                'read' => true,
                'layout_papers' => true,
                'edit_journal_issues' => true,
            )
        )
    );
    
    foreach ($journal_roles as $role_name => $role_data) {
        if (!get_role($role_name)) {
            add_role($role_name, $role_data['display_name'], $role_data['capabilities']);
        }
    }
}
add_action('init', 'sjm_add_journal_roles');

// Function to check if user has journal roles
function sjm_user_has_journal_roles($user) {
    $journal_roles = array(
        'journal_editor_in_chief',
        'journal_managing_editor', 
        'journal_guest_editor',
        'journal_reviewer',
        'journal_author',
        'journal_copyeditor',
        'journal_proofreader',
        'journal_layout_editor'
    );
    
    $user_roles = $user->roles;
    foreach ($user_roles as $role) {
        if (in_array($role, $journal_roles)) {
            return true;
        }
    }
    
    return false;
}

// Function to get users by journal role
function sjm_get_users_by_journal_role($role = '') {
    if (empty($role)) {
        // Get all users with journal roles
        $journal_roles = array(
            'journal_editor_in_chief',
            'journal_managing_editor', 
            'journal_guest_editor',
            'journal_reviewer',
            'journal_author',
            'journal_copyeditor',
            'journal_proofreader',
            'journal_layout_editor'
        );
        
        $users = get_users(array(
            'role__in' => $journal_roles,
            'orderby' => 'display_name',
            'order' => 'ASC'
        ));
    } else {
        $users = get_users(array(
            'role' => $role,
            'orderby' => 'display_name',
            'order' => 'ASC'
        ));
    }
    
    return $users;
}

// Function to get all users (for admin selection)
function sjm_get_all_users() {
    return get_users(array(
        'orderby' => 'display_name',
        'order' => 'ASC'
    ));
}

// Function to render user selection dropdown
function sjm_render_user_dropdown($field_name, $selected_user_id = '', $role_filter = '', $required = false, $placeholder = 'Select User') {
    $users = empty($role_filter) ? sjm_get_all_users() : sjm_get_users_by_journal_role($role_filter);
    
    $required_attr = $required ? 'required' : '';
    $placeholder_text = $required ? $placeholder . ' (Required)' : $placeholder;
    
    // Generate unique ID to avoid duplicates
    $unique_id = str_replace(array('[', ']'), array('_', ''), $field_name) . '_' . uniqid();
    
    echo '<select id="' . esc_attr($unique_id) . '" name="' . esc_attr($field_name) . '" style="width:100%" ' . esc_attr($required_attr) . '>';
    echo '<option value="">' . esc_html($placeholder_text) . '</option>';
    
    foreach ($users as $user) {
        $is_selected = ($selected_user_id == $user->ID) ? 'selected' : '';
        $user_roles = implode(', ', $user->roles);
        echo '<option value="' . esc_attr($user->ID) . '" ' . esc_attr($is_selected) . '>';
        echo esc_html($user->display_name) . ' (' . esc_html($user->user_email) . ')';
        if ($user_roles) {
            echo ' - ' . esc_html($user_roles);
        }
        echo '</option>';
    }
    echo '</select>';
}

// Function to get user display info by ID
function sjm_get_user_display_info($user_id) {
    if (empty($user_id)) {
        return null;
    }
    
    $user = get_user_by('ID', $user_id);
    if (!$user) {
        return null;
    }
    
    return array(
        'name' => $user->display_name,
        'email' => $user->user_email,
        'roles' => $user->roles,
        'url' => get_author_posts_url($user->ID)
    );
}

// Admin page for managing journal user roles
function sjm_add_role_management_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'User Role Management',
        'User Roles',
        'manage_options',
        'sjm-user-roles',
        'sjm_user_roles_page'
    );
}
add_action('admin_menu', 'sjm_add_role_management_page');

function sjm_user_roles_page() {
    // Handle role assignment
    if (isset($_POST['assign_role']) && wp_verify_nonce($_POST['sjm_role_nonce'], 'sjm_assign_role')) {
        $user_id = intval($_POST['user_id']);
        $role = sanitize_text_field($_POST['role']);
        
        if ($user_id && $role) {
            $user = get_user_by('ID', $user_id);
            if ($user) {
                $user->add_role($role);
                echo '<div class="notice notice-success"><p>Role assigned successfully!</p></div>';
            }
        }
    }
    
    // Handle role removal
    if (isset($_POST['remove_role']) && wp_verify_nonce($_POST['sjm_role_nonce'], 'sjm_remove_role')) {
        $user_id = intval($_POST['user_id']);
        $role = sanitize_text_field($_POST['role']);
        
        if ($user_id && $role) {
            $user = get_user_by('ID', $user_id);
            if ($user) {
                $user->remove_role($role);
                echo '<div class="notice notice-success"><p>Role removed successfully!</p></div>';
            }
        }
    }
    
    ?>
    <div class="wrap">
        <h1>Journal User Role Management</h1>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
            <!-- Assign Role Section -->
            <div class="postbox">
                <h2 class="hndle">Assign Journal Role</h2>
                <div class="inside">
                    <form method="post">
                        <?php wp_nonce_field('sjm_assign_role', 'sjm_role_nonce'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="user_id">User</label></th>
                                <td>
                                    <select name="user_id" id="user_id" style="width: 100%;">
                                        <option value="">Select User</option>
                                        <?php
                                        $all_users = sjm_get_all_users();
                                        foreach ($all_users as $user) {
                                            echo '<option value="' . esc_attr($user->ID) . '">';
                                            echo esc_html($user->display_name) . ' (' . esc_html($user->user_email) . ')';
                                            echo '</option>';
                                        }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="role">Journal Role</label></th>
                                <td>
                                    <select name="role" id="role" style="width: 100%;">
                                        <option value="">Select Role</option>
                                        <option value="journal_editor_in_chief">Editor-in-Chief</option>
                                        <option value="journal_managing_editor">Managing Editor</option>
                                        <option value="journal_guest_editor">Guest Editor</option> 
                                        <option value="journal_reviewer">Reviewer</option>
                                        <option value="journal_author">Author</option>
                                        <option value="journal_copyeditor">Copyeditor</option>
                                        <option value="journal_proofreader">Proofreader</option>
                                        <option value="journal_layout_editor">Layout Editor</option>
                                    </select>
                                </td>
                            </tr>
                        </table>
                        <p class="submit">
                            <input type="submit" name="assign_role" class="button-primary" value="Assign Role">
                        </p>
                    </form>
                </div>
            </div>
            
            <!-- Current Journal Users Section -->
            <div class="postbox">
                <h2 class="hndle">Current Journal Users</h2>
                <div class="inside">
                    <?php
                    $journal_users = sjm_get_users_by_journal_role();
                    if ($journal_users) {
                        echo '<table class="wp-list-table widefat fixed striped">';
                        echo '<thead><tr><th>User</th><th>Roles</th><th>Actions</th></tr></thead>';
                        echo '<tbody>';
                        
                        foreach ($journal_users as $user) {
                            $journal_roles = array_intersect($user->roles, array(
                                'journal_editor_in_chief',
                                'journal_managing_editor',
                                'journal_guest_editor', 
                                'journal_reviewer',
                                'journal_author',
                                'journal_copyeditor',
                                'journal_proofreader',
                                'journal_layout_editor'
                            ));
                            
                            if (!empty($journal_roles)) {
                                echo '<tr>';
                                echo '<td>' . esc_html($user->display_name) . '<br><small>' . esc_html($user->user_email) . '</small></td>';
                                echo '<td>';
                                foreach ($journal_roles as $role) {
                                    $role_display = str_replace('journal_', '', $role);
                                    $role_display = str_replace('_', ' ', $role_display);
                                    $role_display = ucwords($role_display);
                                    echo '<span class="button button-small" style="margin: 2px;">' . esc_html($role_display) . '</span>';
                                }
                                echo '</td>';
                                echo '<td>';
                                
                                // Add View Profile button
                                echo '<a href="' . esc_url(sjm_get_user_profile_url($user->ID)) . '" class="button button-small" target="_blank" style="margin: 2px;">View Profile</a>';
                                
                                foreach ($journal_roles as $role) {
                                    echo '<form method="post" style="display: inline-block; margin: 2px;">';
                                    wp_nonce_field('sjm_remove_role', 'sjm_role_nonce');
                                    echo '<input type="hidden" name="user_id" value="' . esc_attr($user->ID) . '">';
                                    echo '<input type="hidden" name="role" value="' . esc_attr($role) . '">';
                                    echo '<input type="submit" name="remove_role" class="button button-small" value="Remove ' . esc_attr(str_replace('journal_', '', $role)) . '" onclick="return confirm(\'Are you sure?\');">';
                                    echo '</form>';
                                }
                                echo '</td>';
                                echo '</tr>';
                            }
                        }
                        
                        echo '</tbody>';
                        echo '</table>';
                    } else {
                        echo '<p>No users with journal roles found.</p>';
                    }
                    ?>
                </div>
            </div>
        </div>
    </div>
    <?php
}

// Add Journal Meta Boxes with User Selection
function sjm_add_journal_meta_boxes() {
    add_meta_box('sjm_journal_required', 'Required Information', 'sjm_journal_required_meta_box', 'journal', 'normal');
    add_meta_box('sjm_journal_optional', 'Additional Information', 'sjm_journal_optional_meta_box', 'journal', 'normal');
    add_meta_box('sjm_journal_authors', 'Journal Authors & Contributors', 'sjm_journal_authors_meta_box', 'journal', 'normal');
}
add_action('add_meta_boxes', 'sjm_add_journal_meta_boxes');

function sjm_journal_required_meta_box($post) {
    $issn = get_post_meta($post->ID, '_sjm_issn', true);
    $publisher = get_post_meta($post->ID, '_sjm_publisher', true);
    $editor_in_chief_id = get_post_meta($post->ID, '_sjm_editor_in_chief_id', true);
    $founding_year = get_post_meta($post->ID, '_sjm_founding_year', true);
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_issn">ISSN (Important)</label></th>';
    echo '<td><input type="text" id="sjm_issn" name="sjm_issn" value="' . esc_attr($issn) . '" style="width:100%" placeholder="e.g., 1234-5678" /></td></tr>';
    
    echo '<tr><th><label for="sjm_publisher">Publisher (Important)</label></th>';
    echo '<td><input type="text" id="sjm_publisher" name="sjm_publisher" value="' . esc_attr($publisher) . '" style="width:100%" placeholder="e.g., Academic Press" /></td></tr>';
    
    echo '<tr><th><label for="sjm_editor_in_chief_id">Editor-in-Chief (Important)</label></th>';
    echo '<td>';
    sjm_render_user_dropdown('sjm_editor_in_chief_id', $editor_in_chief_id, 'journal_editor_in_chief', false, 'Select Editor-in-Chief');
    echo '</td></tr>';
    
    echo '<tr><th><label for="sjm_founding_year">Founding Year (Important)</label></th>';
    echo '<td><input type="number" id="sjm_founding_year" name="sjm_founding_year" value="' . esc_attr($founding_year) . '" style="width:100%" min="1800" max="' . gmdate('Y') . '" placeholder="e.g., 1995" /></td></tr>';
    echo '</table>';
}

function sjm_journal_optional_meta_box($post) {
    $doi_prefix = get_post_meta($post->ID, '_sjm_doi_prefix', true);
    $frequency = get_post_meta($post->ID, '_sjm_frequency', true);
    $language = get_post_meta($post->ID, '_sjm_language', true);
    $subject_areas = get_post_meta($post->ID, '_sjm_subject_areas', true);
    $impact_factor = get_post_meta($post->ID, '_sjm_impact_factor', true);
    $website = get_post_meta($post->ID, '_sjm_website', true);
    $email = get_post_meta($post->ID, '_sjm_email', true);
    $peer_reviewed = get_post_meta($post->ID, '_sjm_peer_reviewed', true);
    $open_access = get_post_meta($post->ID, '_sjm_open_access', true);
    $indexed_in = get_post_meta($post->ID, '_sjm_indexed_in', true);
    $journal_logo = get_post_meta($post->ID, '_sjm_journal_logo', true);
    $journal_cover = get_post_meta($post->ID, '_sjm_journal_cover', true);
    $managing_editor_id = get_post_meta($post->ID, '_sjm_managing_editor_id', true);
    $copyeditor_ids = get_post_meta($post->ID, '_sjm_copyeditor_ids', true);
    $layout_editor_ids = get_post_meta($post->ID, '_sjm_layout_editor_ids', true);
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_doi_prefix">DOI Prefix</label></th>';
    echo '<td><input type="text" id="sjm_doi_prefix" name="sjm_doi_prefix" value="' . esc_attr($doi_prefix) . '" style="width:100%" placeholder="e.g., 10.1000" /></td></tr>';
    
    echo '<tr><th><label for="sjm_frequency">Publication Frequency</label></th>';
    echo '<td><select id="sjm_frequency" name="sjm_frequency" style="width:100%">';
    $frequencies = array('', 'Monthly', 'Quarterly', 'Semi-annually', 'Annually', 'Bi-annually', 'Weekly', 'Irregular');
    foreach ($frequencies as $freq) {
        $selected = ($frequency == $freq) ? 'selected' : '';
        echo '<option value="' . esc_attr($freq) . '" ' . $selected . '>' . esc_html($freq) . '</option>';
    }
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_language">Primary Language</label></th>';
    echo '<td><input type="text" id="sjm_language" name="sjm_language" value="' . esc_attr($language) . '" style="width:100%" placeholder="e.g., English" /></td></tr>';
    
    echo '<tr><th><label for="sjm_subject_areas">Subject Areas</label></th>';
    echo '<td><textarea id="sjm_subject_areas" name="sjm_subject_areas" style="width:100%; height:80px" placeholder="e.g., Computer Science, Artificial Intelligence, Machine Learning">' . esc_textarea($subject_areas) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_impact_factor">Impact Factor</label></th>';
    echo '<td><input type="number" id="sjm_impact_factor" name="sjm_impact_factor" value="' . esc_attr($impact_factor) . '" style="width:100%" step="0.001" min="0" placeholder="e.g., 3.245" /></td></tr>';
    
    echo '<tr><th><label for="sjm_website">Website</label></th>';
    echo '<td><input type="url" id="sjm_website" name="sjm_website" value="' . esc_attr($website) . '" style="width:100%" placeholder="https://example.com" /></td></tr>';
    
    echo '<tr><th><label for="sjm_email">Email</label></th>';
    echo '<td><input type="email" id="sjm_email" name="sjm_email" value="' . esc_attr($email) . '" style="width:100%" placeholder="editor@example.com" /></td></tr>';
    
    echo '<tr><th><label for="sjm_managing_editor_id">Managing Editor</label></th>';
    echo '<td>';
    sjm_render_user_dropdown('sjm_managing_editor_id', $managing_editor_id, 'journal_managing_editor', false, 'Select Managing Editor');
    echo '</td></tr>';
    
    echo '<tr><th><label for="sjm_peer_reviewed">Peer Reviewed</label></th>';
    echo '<td><input type="checkbox" id="sjm_peer_reviewed" name="sjm_peer_reviewed" value="1" ' . checked($peer_reviewed, '1', false) . ' /> <label for="sjm_peer_reviewed">Yes, this journal is peer-reviewed</label></td></tr>';
    
    echo '<tr><th><label for="sjm_open_access">Open Access Policy</label></th>';
    echo '<td><input type="checkbox" id="sjm_open_access" name="sjm_open_access" value="1" ' . checked($open_access, '1', false) . ' /> <label for="sjm_open_access">This journal supports open access articles</label>';
    echo '<div style="color:#6b7280;font-size:12px;margin-top:4px;">';
    echo '<strong>Check this for:</strong> Full open access journals OR hybrid journals that allow individual articles to be open access via Article Processing Charges (APC)';
    echo '</div></td></tr>';
    
    echo '<tr><th><label for="sjm_indexed_in">Indexed In</label></th>';
    echo '<td><textarea id="sjm_indexed_in" name="sjm_indexed_in" style="width:100%; height:80px" placeholder="e.g., PubMed, Scopus, Web of Science">' . esc_textarea($indexed_in) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_journal_logo">Journal Logo</label></th>';
    echo '<td><input type="text" id="sjm_journal_logo" name="sjm_journal_logo" value="' . esc_attr($journal_logo) . '" style="width:70%" placeholder="Logo URL" />';
    echo '<button type="button" id="sjm_upload_logo" class="button" style="margin-left: 10px;">Upload Logo</button>';
    echo '<div id="sjm_logo_preview">';
    if ($journal_logo) {
        echo '<img src="' . esc_url($journal_logo) . '" style="max-width: 100px; max-height: 100px; margin-top: 10px;" />';
    }
    echo '</div></td></tr>';
    
    echo '<tr><th><label for="sjm_journal_cover">Journal Cover</label></th>';
    echo '<td><input type="text" id="sjm_journal_cover" name="sjm_journal_cover" value="' . esc_attr($journal_cover) . '" style="width:70%" placeholder="Cover image URL" />';
    echo '<button type="button" id="sjm_upload_cover" class="button" style="margin-left: 10px;">Upload Cover</button>';
    echo '<div id="sjm_cover_preview">';
    if ($journal_cover) {
        echo '<img src="' . esc_url($journal_cover) . '" style="max-width: 150px; max-height: 200px; margin-top: 10px;" />';
    }
    echo '</div></td></tr>';
    echo '</table>';
}

function sjm_journal_authors_meta_box($post) {
    $journal_authors = get_post_meta($post->ID, '_sjm_journal_authors_data', true);
    if (!is_array($journal_authors)) $journal_authors = array();
    
    echo '<div id="sjm-journal-authors-container">';
    
    // Display existing authors
    foreach ($journal_authors as $index => $journal_author) {
        echo '<div class="sjm-journal-author-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #f9f9f9;">';
        echo '<h5 style="margin-top: 0;">Author/Contributor ' . ($index + 1) . '</h5>';
        echo '<table class="form-table" style="margin: 0;">';
        echo '<tr><th style="width: 150px;"><label>Select Author</label></th>';
        echo '<td><select name="sjm_journal_authors_data[' . $index . '][author_id]" style="width:100%">';
        echo '<option value="">Select Author</option>';
        $all_authors = sjm_get_all_authors();
        foreach ($all_authors as $author) {
            $selected = ($journal_author['author_id'] == $author->id) ? 'selected' : '';
            echo '<option value="' . esc_attr($author->id) . '" ' . $selected . '>';
            echo esc_html($author->first_name . ' ' . $author->last_name);
            if ($author->orcid) echo ' (ORCID: ' . esc_html($author->orcid) . ')';
            echo '</option>';
        }
        echo '</select></td></tr>';
        echo '<tr><th><label>Role in Journal</label></th>';
        echo '<td><select name="sjm_journal_authors_data[' . $index . '][role]" style="width:100%">';
        $roles = array('', 'Contributing Author', 'Regular Contributor', 'Guest Author', 'Special Issue Author', 'Board Member', 'Reviewer', 'Editorial Board');
        foreach ($roles as $role) {
            $selected = ($journal_author['role'] == $role) ? 'selected' : '';
            echo '<option value="' . esc_attr($role) . '" ' . $selected . '>' . esc_html($role) . '</option>';
        }
        echo '</select></td></tr>';
        echo '<tr><th><label>Contributions</label></th>';
        echo '<td><textarea name="sjm_journal_authors_data[' . $index . '][contributions]" style="width:100%; height:60px" placeholder="e.g., Editorial oversight, Peer review, Special issue editing">' . esc_textarea($journal_author['contributions']) . '</textarea></td></tr>';
        echo '<tr><th><label>Publication Versions</label></th>';
        echo '<td><textarea name="sjm_journal_authors_data[' . $index . '][versions]" style="width:100%; height:60px" placeholder="e.g., Volume 1-5, Special Issue 2023, Editorial Board 2020-2024">' . esc_textarea($journal_author['versions']) . '</textarea></td></tr>';
        echo '<tr><th><label>Active Period</label></th>';
        echo '<td><input type="text" name="sjm_journal_authors_data[' . $index . '][period]" value="' . esc_attr($journal_author['period']) . '" style="width:100%" placeholder="e.g., 2020-2024, 2023-Present" /></td></tr>';
        echo '</table>';
        echo '<button type="button" class="sjm-remove-journal-author button" style="background: #dc3232; border-color: #dc3232; color: white;">Remove Author</button>';
        echo '</div>';
    }
    
    echo '</div>';
    echo '<button type="button" id="sjm-add-journal-author" class="button">Add Author/Contributor</button>';
    echo '<p class="description">Add authors and contributors associated with this journal. This will be displayed on the journal\'s single page. <a href="' . admin_url('edit.php?post_type=journal&page=sjm-authors') . '" target="_blank">Manage Authors</a></p>';
}

function sjm_save_journal_meta($post_id) {
    // Handle journal authors data
    if (array_key_exists('sjm_journal_authors_data', $_POST) && is_array($_POST['sjm_journal_authors_data'])) {
        $authors_data = array();
        foreach ($_POST['sjm_journal_authors_data'] as $author_data) {
            if (!empty($author_data['author_id'])) {
                $authors_data[] = array(
                    'author_id' => intval($author_data['author_id']),
                    'role' => sanitize_text_field($author_data['role']),
                    'contributions' => sanitize_textarea_field($author_data['contributions']),
                    'versions' => sanitize_textarea_field($author_data['versions']),
                    'period' => sanitize_text_field($author_data['period'])
                );
            }
        }
        update_post_meta($post_id, '_sjm_journal_authors_data', $authors_data);
    }
    
    // No required fields, treat all as optional
    $fields = array('sjm_issn', 'sjm_publisher', 'sjm_editor_in_chief_id', 'sjm_founding_year');
    foreach ($fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_editor_in_chief_id' || $field == 'sjm_managing_editor_id') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, sanitize_text_field($_POST[$field]));
            }
        }
    }
    
    // Optional fields
    $optional_fields = array('sjm_doi_prefix', 'sjm_frequency', 'sjm_language', 'sjm_subject_areas', 'sjm_impact_factor', 'sjm_website', 'sjm_email', 'sjm_indexed_in', 'sjm_journal_logo', 'sjm_journal_cover', 'sjm_managing_editor_id');
    foreach ($optional_fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_website' || $field == 'sjm_journal_logo' || $field == 'sjm_journal_cover') {
                update_post_meta($post_id, '_' . $field, esc_url_raw($_POST[$field]));
            } elseif ($field == 'sjm_email') {
                update_post_meta($post_id, '_' . $field, sanitize_email($_POST[$field]));
            } elseif ($field == 'sjm_impact_factor') {
                update_post_meta($post_id, '_' . $field, floatval($_POST[$field]));
            } elseif ($field == 'sjm_managing_editor_id') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, sanitize_textarea_field($_POST[$field]));
            }
        }
    }
    
    // Checkbox fields
    $checkbox_fields = array('sjm_peer_reviewed', 'sjm_open_access');
    foreach ($checkbox_fields as $field) {
        $value = array_key_exists($field, $_POST) ? '1' : '0';
        update_post_meta($post_id, '_' . $field, $value);
    }
}
add_action('save_post', 'sjm_save_journal_meta');

// Add Year and Volume Meta Boxes to Journal Issues
function sjm_add_issue_meta_boxes() {
    add_meta_box('sjm_issue_required', 'Required Information', 'sjm_issue_required_meta_box', 'journal_issue', 'normal');
    add_meta_box('sjm_issue_optional', 'Additional Information', 'sjm_issue_optional_meta_box', 'journal_issue', 'normal');
}
add_action('add_meta_boxes', 'sjm_add_issue_meta_boxes');

function sjm_issue_required_meta_box($post) {
    $issue_number = get_post_meta($post->ID, '_sjm_issue_number', true);
    $publication_date = get_post_meta($post->ID, '_sjm_publication_date', true);
    $volume = get_post_meta($post->ID, '_sjm_issue_volume', true);
    $year = get_post_meta($post->ID, '_sjm_issue_year', true);
    $selected_journal = get_post_meta($post->ID, '_sjm_issue_journal', true);
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_issue_journal">Journal (Important)</label></th>';
    echo '<td><select id="sjm_issue_journal" name="sjm_issue_journal" style="width:100%" required>';
    echo '<option value="">Select Journal</option>';
    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    foreach ($journals as $journal) {
        $is_selected = ($selected_journal == $journal->ID) ? 'selected' : '';
        echo '<option value="' . esc_attr($journal->ID) . '" ' . $is_selected . '>' . esc_html($journal->post_title) . '</option>';
    }
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_issue_number">Issue Number (Important)</label></th>';
    echo '<td><input type="number" id="sjm_issue_number" name="sjm_issue_number" value="' . esc_attr($issue_number) . '" style="width:100%" min="1" placeholder="e.g., 1" /></td></tr>';
    
    echo '<tr><th><label for="sjm_issue_volume">Volume (Important)</label></th>';
    echo '<td><input type="number" id="sjm_issue_volume" name="sjm_issue_volume" value="' . esc_attr($volume) . '" style="width:100%" min="1" placeholder="e.g., 15" /></td></tr>';
    
    echo '<tr><th><label for="sjm_issue_year">Year (Important)</label></th>';
    echo '<td><input type="number" id="sjm_issue_year" name="sjm_issue_year" value="' . esc_attr($year) . '" style="width:100%" min="1800" max="' . (date('Y') + 5) . '" placeholder="e.g., 2024" /></td></tr>';
    
    echo '<tr><th><label for="sjm_publication_date">Publication Date (Important)</label></th>';
    echo '<td><input type="date" id="sjm_publication_date" name="sjm_publication_date" value="' . esc_attr($publication_date) . '" style="width:100%" /></td></tr>';
    echo '</table>';
    echo '<script>(function($){
        $(document).ready(function(){
            $("form#post").on("submit", function(e){
                var journal = $("#sjm_issue_journal").val();
                if(!journal){
                    alert("Please select a Journal before submitting.");
                    e.preventDefault();
                }
            });
        });
    })(jQuery);</script>';
}

function sjm_issue_optional_meta_box($post) {
    $doi = get_post_meta($post->ID, '_sjm_issue_doi', true);
    $page_range = get_post_meta($post->ID, '_sjm_issue_page_range', true);
    $special_issue = get_post_meta($post->ID, '_sjm_special_issue', true);
    $special_issue_title = get_post_meta($post->ID, '_sjm_special_issue_title', true);
    $keywords = get_post_meta($post->ID, '_sjm_issue_keywords', true);
    $abstract = get_post_meta($post->ID, '_sjm_issue_abstract', true);
    $guest_editor = get_post_meta($post->ID, '_sjm_guest_editor', true);
    $total_papers = get_post_meta($post->ID, '_sjm_total_papers', true);
    $cover_image = get_post_meta($post->ID, '_sjm_cover_image', true);
    $pdf_url = get_post_meta($post->ID, '_sjm_pdf_url', true);
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_issue_doi">DOI</label></th>';
    echo '<td><input type="text" id="sjm_issue_doi" name="sjm_issue_doi" value="' . esc_attr($doi) . '" style="width:100%" placeholder="e.g., 10.1000/issue.2024.1" /></td></tr>';
    
    echo '<tr><th><label for="sjm_issue_page_range">Page Range</label></th>';
    echo '<td><input type="text" id="sjm_issue_page_range" name="sjm_issue_page_range" value="' . esc_attr($page_range) . '" style="width:100%" placeholder="e.g., 1-150" /></td></tr>';
    
    echo '<tr><th><label for="sjm_special_issue">Special Issue</label></th>';
    echo '<td><input type="checkbox" id="sjm_special_issue" name="sjm_special_issue" value="1" ' . checked($special_issue, '1', false) . ' /> <label for="sjm_special_issue">Yes, this is a special issue</label></td></tr>';
    
    echo '<tr><th><label for="sjm_special_issue_title">Special Issue Title</label></th>';
    echo '<td><input type="text" id="sjm_special_issue_title" name="sjm_special_issue_title" value="' . esc_attr($special_issue_title) . '" style="width:100%" placeholder="e.g., Advances in Machine Learning" /></td></tr>';
    
    // Guest Editors (Multiple)
    echo '<tr><th><label for="sjm_guest_editors">Guest Editors</label></th>';
    echo '<td>';
    $guest_editors = get_post_meta($post->ID, '_sjm_guest_editors', true);
    if (!is_array($guest_editors)) $guest_editors = array();
    echo '<div id="sjm-guest-editors-container">';
    
    if (empty($guest_editors)) {
        echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
        sjm_render_user_dropdown('sjm_guest_editors[]', '', 'journal_guest_editor', false, 'Select Guest Editor');
        echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
        echo '</div>';
    } else {
        foreach ($guest_editors as $editor_id) {
            echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
            sjm_render_user_dropdown('sjm_guest_editors[]', $editor_id, 'journal_guest_editor', false, 'Select Guest Editor');
            echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
            echo '</div>';
        }
    }
    
    echo '</div>';
    echo '<button type="button" class="button sjm-add-editor" data-role="journal_guest_editor" data-container="sjm-guest-editors-container" data-name="sjm_guest_editors[]" data-placeholder="Select Guest Editor">Add Another Guest Editor</button>';
    echo '</td></tr>';
    
    // Issue Editors (Multiple)
    echo '<tr><th><label for="sjm_issue_editors">Issue Editors</label></th>';
    echo '<td>';
    $issue_editors = get_post_meta($post->ID, '_sjm_issue_editors', true);
    if (!is_array($issue_editors)) $issue_editors = array();
    echo '<div id="sjm-issue-editors-container">';
    
    if (empty($issue_editors)) {
        echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
        sjm_render_user_dropdown('sjm_issue_editors[]', '', 'journal_managing_editor', false, 'Select Issue Editor');
        echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
        echo '</div>';
    } else {
        foreach ($issue_editors as $editor_id) {
            echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
            sjm_render_user_dropdown('sjm_issue_editors[]', $editor_id, 'journal_managing_editor', false, 'Select Issue Editor');
            echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
            echo '</div>';
        }
    }
    
    echo '</div>';
    echo '<button type="button" class="button sjm-add-editor" data-role="journal_managing_editor" data-container="sjm-issue-editors-container" data-name="sjm_issue_editors[]" data-placeholder="Select Issue Editor">Add Another Issue Editor</button>';
    echo '</td></tr>';
    
    // Issue Reviewers (Multiple)
    echo '<tr><th><label for="sjm_issue_reviewers">Issue Reviewers</label></th>';
    echo '<td>';
    $issue_reviewers = get_post_meta($post->ID, '_sjm_issue_reviewers', true);
    if (!is_array($issue_reviewers)) $issue_reviewers = array();
    echo '<div id="sjm-issue-reviewers-container">';
    
    if (empty($issue_reviewers)) {
        echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
        sjm_render_user_dropdown('sjm_issue_reviewers[]', '', 'journal_reviewer', false, 'Select Reviewer');
        echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
        echo '</div>';
    } else {
        foreach ($issue_reviewers as $reviewer_id) {
            echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
            sjm_render_user_dropdown('sjm_issue_reviewers[]', $reviewer_id, 'journal_reviewer', false, 'Select Reviewer');
            echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
            echo '</div>';
        }
    }
    
    echo '</div>';
    echo '<button type="button" class="button sjm-add-editor" data-role="journal_reviewer" data-container="sjm-issue-reviewers-container" data-name="sjm_issue_reviewers[]" data-placeholder="Select Reviewer">Add Another Reviewer</button>';
    echo '</td></tr>';
    
    // Copyeditors (Multiple)
    echo '<tr><th><label for="sjm_copyeditors">Copyeditors</label></th>';
    echo '<td>';
    $copyeditors = get_post_meta($post->ID, '_sjm_copyeditors', true);
    if (!is_array($copyeditors)) $copyeditors = array();
    echo '<div id="sjm-copyeditors-container">';
    
    if (empty($copyeditors)) {
        echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
        sjm_render_user_dropdown('sjm_copyeditors[]', '', 'journal_copyeditor', false, 'Select Copyeditor');
        echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
        echo '</div>';
    } else {
        foreach ($copyeditors as $editor_id) {
            echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
            sjm_render_user_dropdown('sjm_copyeditors[]', $editor_id, 'journal_copyeditor', false, 'Select Copyeditor');
            echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
            echo '</div>';
        }
    }
    
    echo '</div>';
    echo '<button type="button" class="button sjm-add-editor" data-role="journal_copyeditor" data-container="sjm-copyeditors-container" data-name="sjm_copyeditors[]" data-placeholder="Select Copyeditor">Add Another Copyeditor</button>';
    echo '</td></tr>';
    
    // Layout Editors (Multiple)
    echo '<tr><th><label for="sjm_layout_editors">Layout Editors</label></th>';
    echo '<td>';
    $layout_editors = get_post_meta($post->ID, '_sjm_layout_editors', true);
    if (!is_array($layout_editors)) $layout_editors = array();
    echo '<div id="sjm-layout-editors-container">';
    
    if (empty($layout_editors)) {
        echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
        sjm_render_user_dropdown('sjm_layout_editors[]', '', 'journal_layout_editor', false, 'Select Layout Editor');
        echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
        echo '</div>';
    } else {
        foreach ($layout_editors as $editor_id) {
            echo '<div class="sjm-editor-item" style="margin-bottom: 10px;">';
            sjm_render_user_dropdown('sjm_layout_editors[]', $editor_id, 'journal_layout_editor', false, 'Select Layout Editor');
            echo '<button type="button" class="button sjm-remove-editor" style="margin-left: 10px;">Remove</button>';
            echo '</div>';
        }
    }
    
    echo '</div>';
    echo '<button type="button" class="button sjm-add-editor" data-role="journal_layout_editor" data-container="sjm-layout-editors-container" data-name="sjm_layout_editors[]" data-placeholder="Select Layout Editor">Add Another Layout Editor</button>';
    echo '</td></tr>';
    
    echo '<tr><th><label for="sjm_issue_keywords">Keywords</label></th>';
    echo '<td><textarea id="sjm_issue_keywords" name="sjm_issue_keywords" style="width:100%; height:80px" placeholder="e.g., artificial intelligence, machine learning, deep learning, neural networks">' . esc_textarea($keywords) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_issue_abstract">Issue Abstract</label></th>';
    echo '<td><textarea id="sjm_issue_abstract" name="sjm_issue_abstract" style="width:100%; height:100px" placeholder="Brief description of this issue...">' . esc_textarea($abstract) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_total_papers">Total Papers</label></th>';
    echo '<td><input type="number" id="sjm_total_papers" name="sjm_total_papers" value="' . esc_attr($total_papers) . '" style="width:100%" min="0" placeholder="e.g., 12" /></td></tr>';
    
    echo '<tr><th><label for="sjm_cover_image">Cover Image</label></th>';
    echo '<td><input type="text" id="sjm_cover_image" name="sjm_cover_image" value="' . esc_attr($cover_image) . '" style="width:70%" placeholder="Cover image URL" />';
    echo '<button type="button" id="sjm_upload_issue_cover" class="button" style="margin-left: 10px;">Upload Cover</button>';
    echo '<div id="sjm_issue_cover_preview">';
    if ($cover_image) {
        echo '<img src="' . esc_url($cover_image) . '" style="max-width: 150px; max-height: 100px; margin-top: 10px;" />';
    }
    echo '</div></td></tr>';
    
    echo '<tr><th><label for="sjm_pdf_url">Full Issue PDF URL</label></th>';
    echo '<td><input type="url" id="sjm_pdf_url" name="sjm_pdf_url" value="' . esc_attr($pdf_url) . '" style="width:100%" placeholder="https://example.com/issue.pdf" /></td></tr>';
    echo '</table>';
}

function sjm_save_issue_meta($post_id) {
    // No required fields, treat all as optional
    $fields = array('sjm_issue_number', 'sjm_issue_volume', 'sjm_issue_year', 'sjm_publication_date', 'sjm_issue_journal');
    foreach ($fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_issue_journal') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } elseif ($field == 'sjm_publication_date') {
                update_post_meta($post_id, '_' . $field, sanitize_text_field($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            }
        }
    }
    
    // Optional fields
    $optional_fields = array('sjm_issue_doi', 'sjm_issue_page_range', 'sjm_special_issue_title', 'sjm_issue_keywords', 'sjm_issue_abstract', 'sjm_total_papers', 'sjm_cover_image', 'sjm_pdf_url');
    foreach ($optional_fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_cover_image' || $field == 'sjm_pdf_url') {
                update_post_meta($post_id, '_' . $field, esc_url_raw($_POST[$field]));
            } elseif ($field == 'sjm_total_papers') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, sanitize_textarea_field($_POST[$field]));
            }
        }
    }
    
    // Handle multiple editorial roles arrays
    $editorial_fields = array('sjm_guest_editors', 'sjm_issue_editors', 'sjm_issue_reviewers', 'sjm_copyeditors', 'sjm_layout_editors');
    foreach ($editorial_fields as $field) {
        if (array_key_exists($field, $_POST) && is_array($_POST[$field])) {
            $editors = array_map('intval', array_filter($_POST[$field]));
            update_post_meta($post_id, '_' . $field, $editors);
        } else {
            delete_post_meta($post_id, '_' . $field);
        }
    }
    
    // Checkbox fields
    $checkbox_fields = array('sjm_special_issue');
    foreach ($checkbox_fields as $field) {
        $value = array_key_exists($field, $_POST) ? '1' : '0';
        update_post_meta($post_id, '_' . $field, $value);
    }
    
    // Backend validation for required journal selection
    $selected_journal = isset($_POST['sjm_issue_journal']) ? intval($_POST['sjm_issue_journal']) : 0;
    if (!$selected_journal) {
        set_transient('sjm_issue_required_notice_' . $post_id, array(
            'type' => 'error',
            'message' => 'Journal selection is required for an Issue.'
        ), 45);
        return;
    }
}
add_action('save_post', 'sjm_save_issue_meta');

// Add Issue and Journal Selector to Papers
function sjm_add_paper_meta_boxes() {
    add_meta_box('sjm_paper_required', 'Required Information', 'sjm_paper_required_meta_box', 'paper', 'normal');
    add_meta_box('sjm_paper_optional', 'Additional Information', 'sjm_paper_optional_meta_box', 'paper', 'normal');
    add_meta_box('sjm_academic_compliance', 'Academic Compliance & Ethics', 'sjm_academic_compliance_meta_box', 'paper', 'normal');
    add_meta_box('sjm_copyright_management', 'Copyright & Licensing', 'sjm_copyright_management_meta_box', 'paper', 'side');
    add_meta_box('sjm_manuscript_tracking', 'Manuscript Tracking', 'sjm_manuscript_tracking_meta_box', 'paper', 'side');
}
add_action('add_meta_boxes', 'sjm_add_paper_meta_boxes');

function sjm_paper_required_meta_box($post) {
    // Security: Add nonce field for form verification
    wp_nonce_field('sjm_paper_meta_nonce', 'sjm_paper_meta_nonce');
    
    $authors = get_post_meta($post->ID, '_sjm_paper_authors', true);
    $abstract = get_post_meta($post->ID, '_sjm_paper_abstract', true);
    $selected_issue = get_post_meta($post->ID, '_sjm_paper_issue', true);
    $selected_journal = get_post_meta($post->ID, '_sjm_paper_journal', true);
    $paper_type = get_post_meta($post->ID, '_sjm_paper_type', true);
    $submission_date = get_post_meta($post->ID, '_sjm_submission_date', true);
    $acceptance_date = get_post_meta($post->ID, '_sjm_acceptance_date', true);
    $paper_version = get_post_meta($post->ID, '_sjm_paper_version', true);
    $version_number = get_post_meta($post->ID, '_sjm_version_number', true);
    $version_date = get_post_meta($post->ID, '_sjm_version_date', true);
    $version_notes = get_post_meta($post->ID, '_sjm_version_notes', true);
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_paper_journal">Journal (Important)</label></th>';
    echo '<td><select id="sjm_paper_journal" name="sjm_paper_journal" style="width:100%" required>';
    echo '<option value="">Select Journal (Important)</option>';
    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    foreach ($journals as $journal) {
        $is_selected = ($selected_journal == $journal->ID) ? 'selected' : '';
        echo '<option value="' . esc_attr($journal->ID) . '" ' . $is_selected . '>' . esc_html($journal->post_title) . '</option>';
    }
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_issue">Issue (Important)</label></th>';
    echo '<td><select id="sjm_paper_issue" name="sjm_paper_issue" style="width:100%" required>';
    echo '<option value="">Select Journal first</option>';
    
    // If we have a selected journal, show its issues
    if ($selected_journal) {
        $issues = get_posts(array(
            'post_type' => 'journal_issue',
            'posts_per_page' => -1,
            'meta_query' => array(
                array(
                    'key' => '_sjm_issue_journal',
                    'value' => $selected_journal,
                    'compare' => '='
                )
            )
        ));
        
        foreach ($issues as $issue) {
            $is_selected = ($selected_issue == $issue->ID) ? 'selected' : '';
            echo '<option value="' . esc_attr($issue->ID) . '" ' . $is_selected . '>' . esc_html($issue->post_title) . '</option>';
        }
    }
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_authors">Authors (Important)</label></th>';
    echo '<td>';
    echo '<div id="sjm-authors-container">';
    
    // Get existing paper authors
    $paper_authors = get_post_meta($post->ID, '_sjm_paper_authors_data', true);
    if (!is_array($paper_authors)) $paper_authors = array();
    
    // Display existing authors
    foreach ($paper_authors as $index => $paper_author) {
        echo '<div class="sjm-author-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #f9f9f9;">';
        echo '<h5 style="margin-top: 0;">Author ' . ($index + 1) . '</h5>';
        echo '<table class="form-table" style="margin: 0;">';
        echo '<tr><th style="width: 150px;"><label>Select Author</label></th>';
        echo '<td><select name="sjm_paper_authors_data[' . $index . '][author_id]" style="width:100%">';
        echo '<option value="">Select Author</option>';
        $all_authors = sjm_get_all_authors();
        foreach ($all_authors as $author) {
            $selected = ($paper_author['author_id'] == $author->id) ? 'selected' : '';
            echo '<option value="' . esc_attr($author->id) . '" ' . $selected . '>';
            echo esc_html($author->first_name . ' ' . $author->last_name);
            if ($author->orcid) echo ' (ORCID: ' . esc_html($author->orcid) . ')';
            echo '</option>';
        }
        echo '</select></td></tr>';
        echo '<tr><th><label>Author Order</label></th>';
        echo '<td><input type="number" name="sjm_paper_authors_data[' . $index . '][order]" value="' . esc_attr($paper_author['order'] ?: ($index + 1)) . '" min="1" style="width:100px;" /></td></tr>';
        echo '<tr><th><label>Contributions</label></th>';
        echo '<td><textarea name="sjm_paper_authors_data[' . $index . '][contributions]" style="width:100%; height:60px" placeholder="e.g., Conceptualization, Data analysis, Writing - original draft">' . esc_textarea($paper_author['contributions']) . '</textarea></td></tr>';
        echo '<tr><th><label>Corresponding Author</label></th>';
        echo '<td><input type="checkbox" name="sjm_paper_authors_data[' . $index . '][is_corresponding]" value="1" ' . checked($paper_author['is_corresponding'], '1', false) . ' /> <label>Yes, this is a corresponding author</label></td></tr>';
        echo '</table>';
        echo '<button type="button" class="sjm-remove-author button" style="background: #dc3232; border-color: #dc3232; color: white;">Remove Author</button>';
        echo '</div>';
    }
    
    echo '</div>';
    echo '<button type="button" id="sjm-add-author" class="button">Add Author</button>';
    echo '<p class="description">Select authors from the database. <a href="' . admin_url('edit.php?post_type=journal&page=sjm-authors') . '" target="_blank">Manage Authors</a></p>';
    echo '</td></tr>';
    
    echo '<tr><th><label for="sjm_paper_abstract">Abstract (Important)</label></th>';
    echo '<td><textarea id="sjm_paper_abstract" name="sjm_paper_abstract" style="width:100%; height:120px" placeholder="Brief abstract of the paper...">' . esc_textarea($abstract) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_type">Paper Type (Important)</label></th>';
    echo '<td><select id="sjm_paper_type" name="sjm_paper_type" style="width:100%">';
    $paper_types = array('', 'Manuscript', 'Research Article', 'Review Article', 'Case Study', 'Short Communication', 'Letter to Editor', 'Book Review', 'Conference Paper', 'Technical Note', 'Editorial');
    foreach ($paper_types as $type) {
        $is_selected = ($paper_type == $type) ? 'selected' : '';
        echo '<option value="' . esc_attr($type) . '" ' . $is_selected . '>' . esc_html($type) . '</option>';
    }
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_submission_date">Submission Date (Important)</label></th>';
    echo '<td><input type="date" id="sjm_submission_date" name="sjm_submission_date" value="' . esc_attr($submission_date) . '" style="width:100%" /></td></tr>';
    
    echo '<tr><th><label for="sjm_acceptance_date">Acceptance Date (Important)</label></th>';
    echo '<td><input type="date" id="sjm_acceptance_date" name="sjm_acceptance_date" value="' . esc_attr($acceptance_date) . '" style="width:100%" /></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_version">Paper Version Type (Important)</label></th>';
    echo '<td><select id="sjm_paper_version" name="sjm_paper_version" style="width:100%">';
    echo '<option value="">Select Version Type (Important)</option>';
    $version_types = array('Preprint', 'Submitted', 'Under Review', 'Revised', 'Accepted', 'Published', 'Postprint');
    foreach ($version_types as $version_type) {
        $is_selected = ($paper_version == $version_type) ? 'selected' : '';
        echo '<option value="' . esc_attr($version_type) . '" ' . $is_selected . '>' . esc_html($version_type) . '</option>';
    }
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_version_number">Version Number</label></th>';
    echo '<td><input type="number" id="sjm_version_number" name="sjm_version_number" value="' . esc_attr(get_post_meta($post->ID, '_sjm_version_number', true)) . '" style="width:100%" min="1" placeholder="e.g., 1, 2, 3" /></td></tr>';
    
    echo '<tr><th><label for="sjm_version_date">Version Date</label></th>';
    echo '<td><input type="date" id="sjm_version_date" name="sjm_version_date" value="' . esc_attr(get_post_meta($post->ID, '_sjm_version_date', true)) . '" style="width:100%" /></td></tr>';
    
    echo '<tr><th><label for="sjm_version_notes">Version Notes</label></th>';
    echo '<td><textarea id="sjm_version_notes" name="sjm_version_notes" style="width:100%; height:80px" placeholder="e.g., Major revisions based on reviewer comments, Updated methodology section">' . esc_textarea(get_post_meta($post->ID, '_sjm_version_notes', true)) . '</textarea></td></tr>';
    
    $paper_open_access = get_post_meta($post->ID, '_sjm_paper_open_access', true);
    $journal_open_access = false;
    if ($selected_journal) {
        $journal_open_access = get_post_meta($selected_journal, '_sjm_open_access', true);
    }
    
    // Fix the logic: if journal supports open access, enable the checkbox
    $disabled = ($journal_open_access != '1') ? 'disabled' : '';
    $checked = ($paper_open_access == '1' && $journal_open_access == '1') ? 'checked' : '';
    
    echo '<tr>';
    echo '<th><label for="sjm_paper_open_access">Open Access</label></th>';
    echo '<td>';
    echo '<input type="checkbox" id="sjm_paper_open_access" name="sjm_paper_open_access" value="1" ' . $checked . ' ' . $disabled . ' />';
    echo '<label for="sjm_paper_open_access">Yes, this paper is open access</label>';
    echo '<div id="sjm_paper_open_access_msg" style="color:#b91c1c;font-size:12px;margin-top:4px;' . ($disabled ? '' : 'display:none;') . '">';
    echo 'This option is only available if the selected journal supports open access.';
    echo '</div>';
    
    // Show current journal status
    if ($selected_journal) {
        $journal_title = get_the_title($selected_journal);
        $status_color = ($journal_open_access == '1') ? '#059669' : '#dc2626';
        $status_text = ($journal_open_access == '1') ? 'supports open access' : 'does not support open access';
        echo '<div style="color:' . $status_color . ';font-size:11px;margin-top:4px;font-weight:500;">';
        echo 'Selected journal "' . esc_html($journal_title) . '" ' . $status_text . '.';
        echo '</div>';
    }
    
    echo '<div style="color:#6b7280;font-size:11px;margin-top:6px;font-style:italic;">';
    echo '<strong>Academic Publishing Models:</strong> ';
    echo '<br>• <strong>Open Access Journals:</strong> All articles are freely accessible';
    echo '<br>• <strong>Hybrid Journals:</strong> Subscription-based but allow individual articles to be open access (via APC)';
    echo '<br>• <strong>Traditional Closed:</strong> Subscription-only access (though authors may self-archive)';
    echo '<br><em>This system supports all models. Enable this option for hybrid/open journals.</em>';
    echo '</div>';
    echo '</td>';
    echo '</tr>';
    echo '</table>';
    
    // Version Management System - REDESIGNED FOR REAL ACADEMIC WORKFLOWS
    echo '<h4 style="margin-top: 20px; color: #666;">Version Management System</h4>';
    echo '<p style="color: #666; font-style: italic;">Manage multiple versions of this paper following real academic publishing workflows (arXiv v1, v2, v3 style).</p>';
    echo '<div style="background: #f8f9fa; padding: 12px; border-radius: 6px; margin-bottom: 15px; border-left: 4px solid #0073aa;">';
    echo '<strong>Real Academic Versioning:</strong><br>';
    echo '• <strong>Multiple Versions:</strong> Same type can have v1, v2, v3 (e.g., Preprint v1, Preprint v2)<br>';
    echo '• <strong>Different Types:</strong> Preprint → Submitted → Published → Postprint<br>';
    echo '• <strong>Independent Access:</strong> Each version can have different open access status<br>';
    echo '• <strong>Unique DOIs:</strong> Each version gets its own identifier and file<br>';
    echo '<em>This matches how arXiv, bioRxiv, and major repositories actually work.</em>';
    echo '</div>';
    
    $version_history = get_post_meta($post->ID, '_sjm_version_history', true);
    if (!is_array($version_history)) $version_history = array();
    
    // Get all authors for dropdowns
    $all_authors = sjm_get_all_authors();
    
    // Group versions by type for better display
    $versions_by_type = array();
    foreach ($version_history as $index => $version) {
        $type = $version['type'];
        if (!isset($versions_by_type[$type])) {
            $versions_by_type[$type] = array();
        }
        $version['original_index'] = $index;
        $versions_by_type[$type][] = $version;
    }
    
    echo '<div id="sjm_version_management_container">';
    
    // Display existing versions grouped by type
    foreach ($versions_by_type as $type => $type_versions) {
        echo '<div class="sjm-version-type-group" style="margin-bottom: 25px; border: 2px solid #e1e5e9; border-radius: 8px; padding: 15px; background: #fafbfc;">';
        echo '<h5 style="margin-top: 0; color: #0073aa; font-size: 16px; font-weight: 600;">' . esc_html($type) . ' Versions (' . count($type_versions) . ')</h5>';
        
        foreach ($type_versions as $version_num => $version) {
            $index = $version['original_index'];
            $version_label = $type . ' v' . ($version_num + 1);
            
            echo '<div class="sjm-version-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #ffffff; position: relative;">';
            echo '<div style="position: absolute; top: 10px; right: 10px;">';
            if ($version_num === count($type_versions) - 1) {
                echo '<span style="background: #00a32a; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">LATEST</span>';
            }
            echo '</div>';
            echo '<h6 style="margin-top: 0; color: #2271b1; font-size: 14px; font-weight: 600;">' . esc_html($version_label) . '</h6>';
            echo '<table class="form-table" style="margin: 0;">';
            
            echo '<tr><th style="width: 140px;"><label>Version File</label></th>';
            echo '<td><input type="text" name="sjm_version_history[' . $index . '][file]" value="' . esc_attr($version['file']) . '" style="width:65%" placeholder="File URL or DOI" />';
            echo '<button type="button" class="sjm-upload-version button" data-index="' . $index . '" style="margin-left: 10px;">Upload File</button></td></tr>';
            
            echo '<tr><th><label>Version Date</label></th>';
            echo '<td><input type="date" name="sjm_version_history[' . $index . '][date]" value="' . esc_attr($version['date']) . '" style="width:100%" /></td></tr>';
            
            echo '<tr><th><label>DOI/Identifier</label></th>';
            echo '<td><input type="text" name="sjm_version_history[' . $index . '][doi]" value="' . esc_attr(isset($version['doi']) ? $version['doi'] : '') . '" style="width:100%" placeholder="e.g., 10.48550/arXiv.2024.12345v' . ($version_num + 1) . '" /></td></tr>';
            
            echo '<tr><th><label>Changes Made</label></th>';
            echo '<td><textarea name="sjm_version_history[' . $index . '][description]" style="width:100%; height:60px" placeholder="What changed in this version? (e.g., Fixed methodology section, Added new data analysis)">' . esc_textarea($version['description']) . '</textarea></td></tr>';
            
            // Version-specific open access - Fixed logic
            $version_open_access = isset($version['open_access']) ? $version['open_access'] : '0';
            $version_disabled = ($journal_open_access != '1') ? 'disabled' : '';
            $version_checked = ($version_open_access == '1' && $journal_open_access == '1') ? 'checked' : '';
            
            echo '<tr><th><label>Version Access</label></th>';
            echo '<td>';
            echo '<input type="checkbox" class="sjm-version-open-access" name="sjm_version_history[' . $index . '][open_access]" value="1" ' . $version_checked . ' ' . $version_disabled . ' />';
            echo '<label>This ' . strtolower($type) . ' version is open access</label>';
            echo '<div class="sjm-version-access-warning" style="color:#b91c1c;font-size:11px;margin-top:2px;' . ($version_disabled ? '' : 'display:none;') . '">Only available if journal supports open access</div>';
            echo '<div style="color:#6b7280;font-size:10px;margin-top:4px;font-style:italic;">';
            echo 'Independent access control: This ' . strtolower($type) . ' can be open while other versions are closed';
            echo '</div>';
            echo '</td></tr>';
            
            // Hidden field to preserve version type
            echo '<input type="hidden" name="sjm_version_history[' . $index . '][type]" value="' . esc_attr($type) . '" />';
            
            // Version-specific authors and contributors
            $version_authors = isset($version['authors']) ? $version['authors'] : array();
            echo '<tr><th><label>Version Contributors</label></th>';
            echo '<td>';
            echo '<div class="sjm-version-authors-container" id="sjm-version-authors-' . $index . '">';
            
            if (!empty($version_authors)) {
                foreach ($version_authors as $va_index => $version_author) {
                    echo '<div class="sjm-version-author-item" style="border: 1px solid #ccc; padding: 10px; margin: 5px 0; background: #fff; border-radius: 3px;">';
                    echo '<select name="sjm_version_history[' . $index . '][authors][' . $va_index . '][author_id]" style="width:30%">';
                    echo '<option value="">Select Author</option>';
                    foreach ($all_authors as $author) {
                        $selected = ($version_author['author_id'] == $author->id) ? 'selected' : '';
                        echo '<option value="' . $author->id . '" ' . $selected . '>' . esc_html($author->first_name . ' ' . $author->last_name) . '</option>';
                    }
                    echo '</select>';
                    echo '<select name="sjm_version_history[' . $index . '][authors][' . $va_index . '][role]" style="width:20%; margin-left:5px;">';
                    echo '<option value="author"' . (($version_author['role'] == 'author') ? ' selected' : '') . '>Author</option>';
                    echo '<option value="contributor"' . (($version_author['role'] == 'contributor') ? ' selected' : '') . '>Contributor</option>';
                    echo '<option value="reviewer"' . (($version_author['role'] == 'reviewer') ? ' selected' : '') . '>Reviewer</option>';
                    echo '<option value="editor"' . (($version_author['role'] == 'editor') ? ' selected' : '') . '>Editor</option>';
                    echo '<option value="collaborator"' . (($version_author['role'] == 'collaborator') ? ' selected' : '') . '>Collaborator</option>';
                    echo '</select>';
                    echo '<input type="text" name="sjm_version_history[' . $index . '][authors][' . $va_index . '][contribution]" value="' . esc_attr($version_author['contribution']) . '" placeholder="Contribution" style="width:35%; margin-left:5px;" />';
                    echo '<button type="button" class="sjm-remove-version-author button" style="margin-left:5px; background: #dc3232; border-color: #dc3232; color: white; padding: 2px 8px;">Remove</button>';
                    echo '</div>';
                }
            }
            
            echo '</div>';
            echo '<button type="button" class="sjm-add-version-author button" data-version="' . $index . '" style="margin-top: 5px;">Add Contributor to This Version</button>';
            echo '<p style="font-size: 12px; color: #666; margin-top: 5px;"><em>Track who contributed to this specific version (original authors, reviewers, editors, collaborators).</em></p>';
            echo '</td></tr>';
            
            echo '</table>';
            echo '<button type="button" class="sjm-remove-version button" data-index="' . $index . '" style="background: #dc3232; border-color: #dc3232; color: white; margin-top: 10px;">Remove This Version</button>';
            echo '</div>';
        }
        
        // Add button for more versions of this type
        echo '<button type="button" class="sjm-add-version-of-type button" data-type="' . esc_attr($type) . '" style="background: #2271b1; border-color: #2271b1; color: white; margin-top: 10px;">Add Another ' . esc_html($type) . '</button>';
        echo '</div>';
    }
    
    // Add new version type section
    echo '<div class="sjm-add-new-version-type" style="margin-top: 20px; padding: 15px; border: 2px dashed #c3c4c7; border-radius: 8px; text-align: center; background: #f6f7f7;">';
    echo '<h6 style="margin-top: 0; color: #50575e;">Add New Version Type</h6>';
    echo '<select id="sjm-new-version-type" style="margin-right: 10px;">';
    echo '<option value="">Select Version Type</option>';
    $version_types = array('Preprint', 'Submitted', 'Under Review', 'Revised', 'Accepted', 'Published', 'Postprint');
    foreach ($version_types as $version_type) {
        echo '<option value="' . esc_attr($version_type) . '">' . esc_html($version_type) . '</option>';
    }
    echo '</select>';
    echo '<button type="button" id="sjm-add-new-version-type-btn" class="button button-primary">Add First ' . '<span id="sjm-version-type-name">Version</span></button>';
    echo '<p style="font-size: 12px; color: #646970; margin-top: 8px; margin-bottom: 0;">Start a new version type (e.g., first Preprint, first Published version)</p>';
    echo '</div>';
    
    echo '</div>';
    
    echo '<button type="button" id="sjm-add-version" class="button" style="display: none;">Add Version</button>'; // Hidden legacy button
    
    echo '<script>
    (function($){
        function updatePaperOpenAccessCheckbox() {
            var journalId = $("#sjm_paper_journal").val();
            if (!journalId) {
                $("#sjm_paper_open_access").prop("checked", false).prop("disabled", true);
                $("#sjm_paper_open_access_msg").show();
                // Also disable all version open access checkboxes
                $(".sjm-version-open-access").prop("checked", false).prop("disabled", true);
                $(".sjm-version-access-warning").show();
                return;
            }
            $.ajax({
                url: ajaxurl,
                method: "POST",
                data: { action: "sjm_check_journal_open_access", journal_id: journalId },
                success: function(resp) {
                    if (resp.success && resp.data.open_access) {
                        $("#sjm_paper_open_access").prop("disabled", false);
                        $("#sjm_paper_open_access_msg").hide();
                        // Enable all version open access checkboxes
                        $(".sjm-version-open-access").prop("disabled", false);
                        $(".sjm-version-access-warning").hide();
                    } else {
                        $("#sjm_paper_open_access").prop("checked", false).prop("disabled", true);
                        $("#sjm_paper_open_access_msg").show();
                        // Disable and uncheck all version open access checkboxes
                        $(".sjm-version-open-access").prop("checked", false).prop("disabled", true);
                        $(".sjm-version-access-warning").show();
                    }
                },
                error: function() {
                    $("#sjm_paper_open_access").prop("checked", false).prop("disabled", true);
                    $("#sjm_paper_open_access_msg").show();
                    $(".sjm-version-open-access").prop("checked", false).prop("disabled", true);
                    $(".sjm-version-access-warning").show();
                }
            });
        }
        $(document).ready(function(){
            $("#sjm_paper_journal").on("change", updatePaperOpenAccessCheckbox);
            updatePaperOpenAccessCheckbox();
        });
    })(jQuery);
    </script>';
}

function sjm_paper_optional_meta_box($post) {
    $doi = get_post_meta($post->ID, '_sjm_paper_doi', true);
    $keywords = get_post_meta($post->ID, '_sjm_paper_keywords', true);
    $pages = get_post_meta($post->ID, '_sjm_paper_pages', true);
    $pdf_url = get_post_meta($post->ID, '_sjm_paper_pdf_url', true);
    $corresponding_author = get_post_meta($post->ID, '_sjm_corresponding_author', true);
    $author_affiliations = get_post_meta($post->ID, '_sjm_author_affiliations', true);
    $funding = get_post_meta($post->ID, '_sjm_paper_funding', true);
    $conflicts_of_interest = get_post_meta($post->ID, '_sjm_conflicts_of_interest', true);
    $peer_reviewed = get_post_meta($post->ID, '_sjm_paper_peer_reviewed', true);
    $open_access = get_post_meta($post->ID, '_sjm_paper_open_access', true);
    $citation_count = get_post_meta($post->ID, '_sjm_citation_count', true);
    $views_count = get_post_meta($post->ID, '_sjm_views_count', true);
    $manuscript_file = get_post_meta($post->ID, '_sjm_manuscript_file', true);
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_manuscript_file">Manuscript File</label></th>';
    echo '<td><input type="text" id="sjm_manuscript_file" name="sjm_manuscript_file" value="' . esc_attr($manuscript_file) . '" style="width:70%" placeholder="Manuscript file URL" />';
    echo '<button type="button" id="sjm_upload_manuscript" class="button" style="margin-left: 10px;">Upload Manuscript</button>';
    echo '<div id="sjm_manuscript_preview">';
    if ($manuscript_file) {
        $file_name = basename($manuscript_file);
        echo '<div style="margin-top: 10px; padding: 10px; background: #f0f0f0; border-radius: 3px;">';
        echo '<strong>File:</strong> ' . esc_html($file_name) . '<br>';
        echo '<a href="' . esc_url($manuscript_file) . '" target="_blank" style="color: #0073aa;">View File</a>';
        echo '</div>';
    }
    echo '</div></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_doi">DOI</label></th>';
    echo '<td><input type="text" id="sjm_paper_doi" name="sjm_paper_doi" value="' . esc_attr($doi) . '" style="width:100%" placeholder="e.g., 10.1000/paper.2024.001" /></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_keywords">Keywords</label></th>';
    echo '<td><textarea id="sjm_paper_keywords" name="sjm_paper_keywords" style="width:100%; height:80px" placeholder="e.g., artificial intelligence, machine learning, deep learning, neural networks">' . esc_textarea($keywords) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_pages">Pages</label></th>';
    echo '<td><input type="text" id="sjm_paper_pages" name="sjm_paper_pages" value="' . esc_attr($pages) . '" style="width:100%" placeholder="e.g., 15-25" /></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_pdf_url">PDF URL</label></th>';
    echo '<td><input type="url" id="sjm_paper_pdf_url" name="sjm_paper_pdf_url" value="' . esc_attr($pdf_url) . '" style="width:100%" placeholder="https://example.com/paper.pdf" /></td></tr>';
    
    echo '<tr><th><label for="sjm_corresponding_author_id">Corresponding Author</label></th>';
    echo '<td>';
    $corresponding_author_id = get_post_meta($post->ID, '_sjm_corresponding_author_id', true);
    sjm_render_user_dropdown('sjm_corresponding_author_id', $corresponding_author_id, 'journal_author', false, 'Select Corresponding Author');
    echo '</td></tr>';
    
    echo '<tr><th><label for="sjm_author_affiliations">Author Affiliations</label></th>';
    echo '<td><textarea id="sjm_author_affiliations" name="sjm_author_affiliations" style="width:100%; height:80px" placeholder="e.g., University of Example, Department of Computer Science">' . esc_textarea($author_affiliations) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_funding">Funding Information</label></th>';
    echo '<td><textarea id="sjm_paper_funding" name="sjm_paper_funding" style="width:100%; height:80px" placeholder="e.g., This research was funded by NSF Grant #123456">' . esc_textarea($funding) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_conflicts_of_interest">Conflicts of Interest</label></th>';
    echo '<td><textarea id="sjm_conflicts_of_interest" name="sjm_conflicts_of_interest" style="width:100%; height:80px" placeholder="e.g., The authors declare no conflicts of interest">' . esc_textarea($conflicts_of_interest) . '</textarea></td></tr>';
    
    echo '<tr><th><label for="sjm_paper_peer_reviewed">Peer Reviewed</label></th>';
    echo '<td><input type="checkbox" id="sjm_paper_peer_reviewed" name="sjm_paper_peer_reviewed" value="1" ' . checked($peer_reviewed, '1', false) . ' /> <label for="sjm_paper_peer_reviewed">Yes, this paper was peer-reviewed</label></td></tr>';
    
    // Citation Count (auto only)
    echo '<tr><th><label for="sjm_citation_count">Citation Count</label></th>';
    echo '<td><span id="sjm_citation_count_display">' . esc_html($citation_count) . '</span>';
    echo '<button type="button" id="sjm-auto-update-citations" class="button" style="margin-left: 10px;">Auto Update</button>';
    echo '<span id="sjm-citation-update-status" style="margin-left: 10px;"></span></td></tr>';
    
    // Views Count (read-only, auto-tracked)
    echo '<tr><th><label for="sjm_views_count">Views Count</label></th>';
    echo '<td><span id="sjm_views_count_display">' . esc_html($views_count) . '</span>';
    echo '<span style="margin-left: 10px; color: #888;">(auto-tracked)</span>';
    echo '<span id="sjm-views-update-status" style="margin-left: 10px;"></span></td></tr>';
    echo '</table>';
}

// Manuscript Tracking Meta Box
function sjm_manuscript_tracking_meta_box($post) {
    $manuscript_id = get_post_meta($post->ID, '_sjm_manuscript_id', true);
    $submission_status = get_post_meta($post->ID, '_sjm_submission_status', true);
    $tracking_history = get_post_meta($post->ID, '_sjm_tracking_history', true);
    if (!is_array($tracking_history)) $tracking_history = array();
    
    // Generate manuscript ID if not exists
    if (empty($manuscript_id)) {
        $manuscript_id = sjm_generate_manuscript_id($post->ID);
        update_post_meta($post->ID, '_sjm_manuscript_id', $manuscript_id);
    }
    
    echo '<div style="padding: 10px; background: #f0f6ff; border: 1px solid #0073aa; border-radius: 5px; margin-bottom: 15px;">';
    echo '<h4 style="margin: 0 0 10px 0; color: #0073aa;">📋 Manuscript Tracking</h4>';
    echo '<p style="margin: 0; font-size: 14px;"><strong>Manuscript ID:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px;">' . esc_html($manuscript_id) . '</code></p>';
    echo '</div>';
    
    echo '<table class="form-table" style="margin-top: 0;">';
    echo '<tr><th><label for="sjm_submission_status">Submission Status</label></th>';
    echo '<td><select id="sjm_submission_status" name="sjm_submission_status" style="width:100%">';
    $statuses = array(
        'draft' => 'Draft',
        'submitted' => 'Submitted',
        'under_review' => 'Under Review',
        'revision_requested' => 'Revision Requested',
        'revised' => 'Revised',
        'accepted' => 'Accepted',
        'published' => 'Published',
        'rejected' => 'Rejected',
        'withdrawn' => 'Withdrawn'
    );
    foreach ($statuses as $value => $label) {
        $selected = ($submission_status == $value) ? 'selected' : '';
        echo '<option value="' . esc_attr($value) . '" ' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select></td></tr>';
    echo '</table>';
    
    // Tracking History
    echo '<h4 style="margin: 20px 0 10px 0; color: #666;">📝 Tracking History</h4>';
    echo '<div id="sjm-tracking-history" style="max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; background: #fafafa;">';
    if (!empty($tracking_history)) {
        foreach ($tracking_history as $entry) {
            echo '<div style="margin-bottom: 10px; padding: 8px; background: #fff; border-left: 3px solid #0073aa; border-radius: 3px;">';
            echo '<strong>' . esc_html($entry['status']) . '</strong> - ' . esc_html($entry['date']) . '<br>';
            if (!empty($entry['notes'])) {
                echo '<small style="color: #666;">' . esc_html($entry['notes']) . '</small>';
            }
            echo '</div>';
        }
    } else {
        echo '<p style="margin: 0; color: #666; font-style: italic;">No tracking history yet.</p>';
    }
    echo '</div>';
    
    echo '<div style="margin-top: 10px;">';
    echo '<input type="text" id="sjm_tracking_note" placeholder="Add tracking note..." style="width: 70%; margin-right: 5px;">';
    echo '<button type="button" id="sjm_add_tracking_note" class="button">Add Note</button>';
    echo '</div>';
    
    echo '<script>
    jQuery(document).ready(function($) {
        $("#sjm_add_tracking_note").click(function() {
            var note = $("#sjm_tracking_note").val();
            if (note.trim()) {
                var date = new Date().toISOString().split("T")[0];
                var status = $("#sjm_submission_status").val();
                var entry = "<div style=\"margin-bottom: 10px; padding: 8px; background: #fff; border-left: 3px solid #0073aa; border-radius: 3px;\">" +
                           "<strong>" + status + "</strong> - " + date + "<br>" +
                           "<small style=\"color: #666;\">" + note + "</small></div>";
                $("#sjm-tracking-history").prepend(entry);
                $("#sjm_tracking_note").val("");
                
                // Add to hidden field for saving
                var historyField = $("<input type=\"hidden\" name=\"sjm_tracking_history[]\" value=\"" + 
                                   JSON.stringify({status: status, date: date, notes: note}).replace(/"/g, "&quot;") + "\">");
                $("form").append(historyField);
            }
        });
    });
    </script>';
}

// Academic Compliance Meta Box
function sjm_academic_compliance_meta_box($post) {
    // Security: Add nonce field for compliance form
    wp_nonce_field('sjm_compliance_meta_nonce', 'sjm_compliance_meta_nonce');
    
    $coi_declaration = get_post_meta($post->ID, '_sjm_coi_declaration', true);
    $coi_details = get_post_meta($post->ID, '_sjm_coi_details', true);
    $ethics_approval = get_post_meta($post->ID, '_sjm_ethics_approval', true);
    $ethics_approval_number = get_post_meta($post->ID, '_sjm_ethics_approval_number', true);
    $ethics_committee = get_post_meta($post->ID, '_sjm_ethics_committee', true);
    $human_subjects = get_post_meta($post->ID, '_sjm_human_subjects', true);
    $animal_subjects = get_post_meta($post->ID, '_sjm_animal_subjects', true);
    $data_availability = get_post_meta($post->ID, '_sjm_data_availability', true);
    $data_availability_statement = get_post_meta($post->ID, '_sjm_data_availability_statement', true);
    $funding_structured = get_post_meta($post->ID, '_sjm_funding_structured', true);
    if (!is_array($funding_structured)) $funding_structured = array();
    
    echo '<div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin-bottom: 15px;">';
    echo '<h4 style="margin: 0 0 5px 0; color: #856404;">⚖️ Academic Compliance Requirements</h4>';
    echo '<p style="margin: 0; font-size: 12px; color: #856404;">These declarations are required for academic integrity and compliance.</p>';
    echo '</div>';
    
    echo '<table class="form-table">';
    
    // Conflict of Interest
    echo '<tr><th colspan="2" style="background: #f8f9fa; padding: 10px; font-weight: bold; border-bottom: 2px solid #dee2e6;">🔍 Conflict of Interest Declaration</th></tr>';
    echo '<tr><th><label for="sjm_coi_declaration">COI Declaration</label></th>';
    echo '<td><select id="sjm_coi_declaration" name="sjm_coi_declaration" style="width:100%">';
    echo '<option value="">Select Declaration (Important)</option>';
    echo '<option value="no_conflicts"' . selected($coi_declaration, 'no_conflicts', false) . '>No conflicts of interest</option>';
    echo '<option value="conflicts_declared"' . selected($coi_declaration, 'conflicts_declared', false) . '>Conflicts of interest declared</option>';
    echo '<option value="potential_conflicts"' . selected($coi_declaration, 'potential_conflicts', false) . '>Potential conflicts identified</option>';
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_coi_details">COI Details</label></th>';
    echo '<td><textarea id="sjm_coi_details" name="sjm_coi_details" style="width:100%; height:80px" placeholder="If conflicts exist, provide detailed description...">' . esc_textarea($coi_details) . '</textarea></td></tr>';
    
    // Ethics Approval
    echo '<tr><th colspan="2" style="background: #f8f9fa; padding: 10px; font-weight: bold; border-bottom: 2px solid #dee2e6;">🧬 Ethics Approval & Compliance</th></tr>';
    echo '<tr><th><label for="sjm_ethics_approval">Ethics Approval Required</label></th>';
    echo '<td><select id="sjm_ethics_approval" name="sjm_ethics_approval" style="width:100%">';
    echo '<option value="not_required"' . selected($ethics_approval, 'not_required', false) . '>Not required</option>';
    echo '<option value="obtained"' . selected($ethics_approval, 'obtained', false) . '>Obtained</option>';
    echo '<option value="pending"' . selected($ethics_approval, 'pending', false) . '>Pending</option>';
    echo '<option value="not_applicable"' . selected($ethics_approval, 'not_applicable', false) . '>Not applicable</option>';
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_ethics_approval_number">Ethics Approval Number</label></th>';
    echo '<td><input type="text" id="sjm_ethics_approval_number" name="sjm_ethics_approval_number" value="' . esc_attr($ethics_approval_number) . '" style="width:100%" placeholder="e.g., IRB-2024-001" /></td></tr>';
    
    echo '<tr><th><label for="sjm_ethics_committee">Ethics Committee/IRB</label></th>';
    echo '<td><input type="text" id="sjm_ethics_committee" name="sjm_ethics_committee" value="' . esc_attr($ethics_committee) . '" style="width:100%" placeholder="e.g., University Ethics Committee" /></td></tr>';
    
    echo '<tr><th><label for="sjm_human_subjects">Human Subjects</label></th>';
    echo '<td><input type="checkbox" id="sjm_human_subjects" name="sjm_human_subjects" value="1" ' . checked($human_subjects, '1', false) . ' /> <label for="sjm_human_subjects">This research involves human subjects</label></td></tr>';
    
    echo '<tr><th><label for="sjm_animal_subjects">Animal Subjects</label></th>';
    echo '<td><input type="checkbox" id="sjm_animal_subjects" name="sjm_animal_subjects" value="1" ' . checked($animal_subjects, '1', false) . ' /> <label for="sjm_animal_subjects">This research involves animal subjects</label></td></tr>';
    
    // Data Availability
    echo '<tr><th colspan="2" style="background: #f8f9fa; padding: 10px; font-weight: bold; border-bottom: 2px solid #dee2e6;">📊 Data Availability Statement</th></tr>';
    echo '<tr><th><label for="sjm_data_availability">Data Availability</label></th>';
    echo '<td><select id="sjm_data_availability" name="sjm_data_availability" style="width:100%">';
    echo '<option value="available"' . selected($data_availability, 'available', false) . '>Data available</option>';
    echo '<option value="available_on_request"' . selected($data_availability, 'available_on_request', false) . '>Available on request</option>';
    echo '<option value="restricted"' . selected($data_availability, 'restricted', false) . '>Restricted access</option>';
    echo '<option value="not_applicable"' . selected($data_availability, 'not_applicable', false) . '>Not applicable</option>';
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_data_availability_statement">Data Statement</label></th>';
    echo '<td><textarea id="sjm_data_availability_statement" name="sjm_data_availability_statement" style="width:100%; height:60px" placeholder="Describe data availability, repositories, access conditions...">' . esc_textarea($data_availability_statement) . '</textarea></td></tr>';
    
    // Structured Funding
    echo '<tr><th colspan="2" style="background: #f8f9fa; padding: 10px; font-weight: bold; border-bottom: 2px solid #dee2e6;">💰 Structured Funding Information</th></tr>';
    echo '<tr><th><label>Funding Sources</label></th>';
    echo '<td>';
    echo '<div id="sjm-funding-container">';
    
    if (!empty($funding_structured)) {
        foreach ($funding_structured as $index => $funding) {
            echo '<div class="sjm-funding-item" style="border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px; background: #fafafa;">';
            echo '<table style="width: 100%;">';
            echo '<tr><td style="width: 25%;"><input type="text" name="sjm_funding_structured[' . $index . '][agency]" value="' . esc_attr($funding['agency']) . '" placeholder="Funding Agency" style="width: 100%;" /></td>';
            echo '<td style="width: 25%; padding-left: 5px;"><input type="text" name="sjm_funding_structured[' . $index . '][grant_number]" value="' . esc_attr($funding['grant_number']) . '" placeholder="Grant Number" style="width: 100%;" /></td>';
            echo '<td style="width: 25%; padding-left: 5px;"><input type="text" name="sjm_funding_structured[' . $index . '][amount]" value="' . esc_attr($funding['amount']) . '" placeholder="Amount" style="width: 100%;" /></td>';
            echo '<td style="width: 20%; padding-left: 5px;"><input type="text" name="sjm_funding_structured[' . $index . '][recipient]" value="' . esc_attr($funding['recipient']) . '" placeholder="Recipient" style="width: 100%;" /></td>';
            echo '<td style="width: 5%; padding-left: 5px;"><button type="button" class="sjm-remove-funding button" style="background: #dc3232; border-color: #dc3232; color: white;">×</button></td></tr>';
            echo '</table>';
            echo '</div>';
        }
    }
    
    echo '</div>';
    echo '<button type="button" id="sjm-add-funding" class="button">Add Funding Source</button>';
    echo '<p class="description">Add structured funding information for better discoverability and compliance.</p>';
    echo '</td></tr>';
    
    echo '</table>';
    
    echo '<script>
    jQuery(document).ready(function($) {
        var fundingIndex = ' . count($funding_structured) . ';
        
        $("#sjm-add-funding").click(function() {
            var fundingItem = "<div class=\"sjm-funding-item\" style=\"border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px; background: #fafafa;\">" +
                "<table style=\"width: 100%;\"><tr>" +
                "<td style=\"width: 25%;\"><input type=\"text\" name=\"sjm_funding_structured[" + fundingIndex + "][agency]\" placeholder=\"Funding Agency\" style=\"width: 100%;\" /></td>" +
                "<td style=\"width: 25%; padding-left: 5px;\"><input type=\"text\" name=\"sjm_funding_structured[" + fundingIndex + "][grant_number]\" placeholder=\"Grant Number\" style=\"width: 100%;\" /></td>" +
                "<td style=\"width: 25%; padding-left: 5px;\"><input type=\"text\" name=\"sjm_funding_structured[" + fundingIndex + "][amount]\" placeholder=\"Amount\" style=\"width: 100%;\" /></td>" +
                "<td style=\"width: 20%; padding-left: 5px;\"><input type=\"text\" name=\"sjm_funding_structured[" + fundingIndex + "][recipient]\" placeholder=\"Recipient\" style=\"width: 100%;\" /></td>" +
                "<td style=\"width: 5%; padding-left: 5px;\"><button type=\"button\" class=\"sjm-remove-funding button\" style=\"background: #dc3232; border-color: #dc3232; color: white;\">×</button></td>" +
                "</tr></table></div>";
            $("#sjm-funding-container").append(fundingItem);
            fundingIndex++;
        });
        
        $(document).on("click", ".sjm-remove-funding", function() {
            $(this).closest(".sjm-funding-item").remove();
        });
    });
    </script>';
}

// Copyright Management Meta Box
function sjm_copyright_management_meta_box($post) {
    // Security: Add nonce field for copyright form
    wp_nonce_field('sjm_copyright_meta_nonce', 'sjm_copyright_meta_nonce');
    
    $copyright_holder = get_post_meta($post->ID, '_sjm_copyright_holder', true);
    $copyright_year = get_post_meta($post->ID, '_sjm_copyright_year', true);
    $license_type = get_post_meta($post->ID, '_sjm_license_type', true);
    $license_url = get_post_meta($post->ID, '_sjm_license_url', true);
    $copyright_transfer = get_post_meta($post->ID, '_sjm_copyright_transfer', true);
    $copyright_transfer_date = get_post_meta($post->ID, '_sjm_copyright_transfer_date', true);
    $reuse_permissions = get_post_meta($post->ID, '_sjm_reuse_permissions', true);
    
    echo '<div style="background: #e8f5e8; border: 1px solid #4caf50; padding: 10px; border-radius: 5px; margin-bottom: 15px;">';
    echo '<h4 style="margin: 0 0 5px 0; color: #2e7d32;">📄 Copyright & Licensing</h4>';
    echo '<p style="margin: 0; font-size: 12px; color: #2e7d32;">Manage copyright and licensing for this publication.</p>';
    echo '</div>';
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_copyright_holder">Copyright Holder</label></th>';
    echo '<td><input type="text" id="sjm_copyright_holder" name="sjm_copyright_holder" value="' . esc_attr($copyright_holder) . '" style="width:100%" placeholder="e.g., Authors, Journal, Publisher" /></td></tr>';
    
    echo '<tr><th><label for="sjm_copyright_year">Copyright Year</label></th>';
    echo '<td><input type="number" id="sjm_copyright_year" name="sjm_copyright_year" value="' . esc_attr($copyright_year ?: date('Y')) . '" style="width:100%" min="1900" max="' . (date('Y') + 10) . '" /></td></tr>';
    
    echo '<tr><th><label for="sjm_license_type">License Type</label></th>';
    echo '<td><select id="sjm_license_type" name="sjm_license_type" style="width:100%">';
    echo '<option value="">Select License</option>';
    echo '<option value="cc_by"' . selected($license_type, 'cc_by', false) . '>CC BY 4.0 (Attribution)</option>';
    echo '<option value="cc_by_sa"' . selected($license_type, 'cc_by_sa', false) . '>CC BY-SA 4.0 (Attribution-ShareAlike)</option>';
    echo '<option value="cc_by_nc"' . selected($license_type, 'cc_by_nc', false) . '>CC BY-NC 4.0 (Attribution-NonCommercial)</option>';
    echo '<option value="cc_by_nc_sa"' . selected($license_type, 'cc_by_nc_sa', false) . '>CC BY-NC-SA 4.0 (Attribution-NonCommercial-ShareAlike)</option>';
    echo '<option value="cc_by_nd"' . selected($license_type, 'cc_by_nd', false) . '>CC BY-ND 4.0 (Attribution-NoDerivatives)</option>';
    echo '<option value="cc_by_nc_nd"' . selected($license_type, 'cc_by_nc_nd', false) . '>CC BY-NC-ND 4.0 (Attribution-NonCommercial-NoDerivatives)</option>';
    echo '<option value="all_rights_reserved"' . selected($license_type, 'all_rights_reserved', false) . '>All Rights Reserved</option>';
    echo '<option value="public_domain"' . selected($license_type, 'public_domain', false) . '>Public Domain</option>';
    echo '<option value="custom"' . selected($license_type, 'custom', false) . '>Custom License</option>';
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_license_url">License URL</label></th>';
    echo '<td><input type="url" id="sjm_license_url" name="sjm_license_url" value="' . esc_attr($license_url) . '" style="width:100%" placeholder="https://creativecommons.org/licenses/by/4.0/" /></td></tr>';
    
    echo '<tr><th><label for="sjm_copyright_transfer">Copyright Transfer</label></th>';
    echo '<td><select id="sjm_copyright_transfer" name="sjm_copyright_transfer" style="width:100%">';
    echo '<option value="not_transferred"' . selected($copyright_transfer, 'not_transferred', false) . '>Not transferred</option>';
    echo '<option value="transferred"' . selected($copyright_transfer, 'transferred', false) . '>Transferred to publisher</option>';
    echo '<option value="license_to_publish"' . selected($copyright_transfer, 'license_to_publish', false) . '>License to publish granted</option>';
    echo '<option value="retained_by_authors"' . selected($copyright_transfer, 'retained_by_authors', false) . '>Retained by authors</option>';
    echo '</select></td></tr>';
    
    echo '<tr><th><label for="sjm_copyright_transfer_date">Transfer Date</label></th>';
    echo '<td><input type="date" id="sjm_copyright_transfer_date" name="sjm_copyright_transfer_date" value="' . esc_attr($copyright_transfer_date) . '" style="width:100%" /></td></tr>';
    
    echo '<tr><th><label for="sjm_reuse_permissions">Reuse Permissions</label></th>';
    echo '<td><textarea id="sjm_reuse_permissions" name="sjm_reuse_permissions" style="width:100%; height:60px" placeholder="Describe reuse permissions and restrictions...">' . esc_textarea($reuse_permissions) . '</textarea></td></tr>';
    
    echo '</table>';
    
    echo '<div style="margin-top: 15px; padding: 10px; background: #f0f0f0; border-radius: 5px;">';
    echo '<h5 style="margin: 0 0 10px 0;">📋 Quick License Templates</h5>';
    echo '<button type="button" class="button" onclick="sjm_apply_license_template(\'cc_by\')">Apply CC BY 4.0</button> ';
    echo '<button type="button" class="button" onclick="sjm_apply_license_template(\'all_rights\')">Apply All Rights Reserved</button>';
    echo '</div>';
    
    echo '<script>
    function sjm_apply_license_template(type) {
        if (type === "cc_by") {
            document.getElementById("sjm_license_type").value = "cc_by";
            document.getElementById("sjm_license_url").value = "https://creativecommons.org/licenses/by/4.0/";
            document.getElementById("sjm_reuse_permissions").value = "This work is licensed under a Creative Commons Attribution 4.0 International License. You are free to share and adapt this work with proper attribution.";
        } else if (type === "all_rights") {
            document.getElementById("sjm_license_type").value = "all_rights_reserved";
            document.getElementById("sjm_license_url").value = "";
            document.getElementById("sjm_reuse_permissions").value = "All rights reserved. No part of this publication may be reproduced without written permission from the copyright holder.";
        }
    }
    </script>';
}

// Generate unique manuscript tracking ID
function sjm_generate_manuscript_id($post_id) {
    $journal_id = get_post_meta($post_id, '_sjm_paper_journal', true);
    $journal_code = 'JNL';
    
    if ($journal_id) {
        $journal = get_post($journal_id);
        if ($journal) {
            // Create journal code from title
            $words = explode(' ', $journal->post_title);
            $journal_code = '';
            foreach ($words as $word) {
                if (strlen($word) > 2) {
                    $journal_code .= strtoupper(substr($word, 0, 1));
                }
            }
            if (strlen($journal_code) < 2) {
                $journal_code = 'JNL';
            }
        }
    }
    
    $year = date('Y');
    $month = date('m');
    
    // Get next sequential number for this journal/year
    global $wpdb;
    $sequence = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) + 1 FROM {$wpdb->postmeta} 
         WHERE meta_key = '_sjm_manuscript_id' 
         AND meta_value LIKE %s",
        $journal_code . '-' . $year . '-%'
    ));
    
    return $journal_code . '-' . $year . '-' . str_pad($sequence, 4, '0', STR_PAD_LEFT);
}

function sjm_save_paper_meta($post_id) {
    // SECURITY CHECKS
    
    // Prevent auto-save from processing
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
    
    // Check if this is a paper post type
    if (get_post_type($post_id) !== 'paper') return;
    
    // Verify nonce for security
    if (!isset($_POST['sjm_paper_meta_nonce']) || !wp_verify_nonce($_POST['sjm_paper_meta_nonce'], 'sjm_paper_meta_nonce')) {
        return;
    }
    
    // Check user permissions
    if (!current_user_can('edit_post', $post_id)) {
        return;
    }
    
    // Additional capability check for journal management
    if (!current_user_can('edit_posts') && !sjm_user_has_journal_roles(wp_get_current_user())) {
        return;
    }
    
    // Rate limiting check
    if (!sjm_check_rate_limit('paper_save', get_current_user_id(), 10, 60)) {
        wp_die('Too many save attempts. Please wait before trying again.');
    }
    
    // Get the selected journal with validation
    $selected_journal = isset($_POST['sjm_paper_journal']) ? intval($_POST['sjm_paper_journal']) : 0;
    $selected_issue = isset($_POST['sjm_paper_issue']) ? intval($_POST['sjm_paper_issue']) : 0;
    if (!$selected_journal || !$selected_issue) {
        set_transient('sjm_paper_required_notice_' . $post_id, array(
            'type' => 'error',
            'message' => 'Both Journal and Issue selection are required.'
        ), 45);
        return;
    }
    
    if ($selected_journal) {
        // Check if the journal is open access
        $journal_open_access = get_post_meta($selected_journal, '_sjm_open_access', true);
        
        // If journal is not open access, force paper to not be open access
        if ($journal_open_access != '1') {
            // Remove the open access meta if it exists
            delete_post_meta($post_id, '_sjm_paper_open_access');
            
            // Add admin notice
            set_transient('sjm_paper_open_access_notice', array(
                'type' => 'warning',
                'message' => 'Paper open access status was automatically disabled because the selected journal is not open access.'
            ), 45);
        }
    }
    
    // Handle paper authors data
    if (array_key_exists('sjm_paper_authors_data', $_POST) && is_array($_POST['sjm_paper_authors_data'])) {
        $authors_data = array();
        foreach ($_POST['sjm_paper_authors_data'] as $author_data) {
            if (!empty($author_data['author_id'])) {
                $authors_data[] = array(
                    'author_id' => intval($author_data['author_id']),
                    'order' => intval($author_data['order']),
                    'contributions' => sanitize_textarea_field($author_data['contributions']),
                    'is_corresponding' => isset($author_data['is_corresponding']) ? '1' : '0'
                );
            }
        }
        update_post_meta($post_id, '_sjm_paper_authors_data', $authors_data);
        
        // Also save a simple string version for backward compatibility
        $author_names = array();
        foreach ($authors_data as $author_data) {
            $author = sjm_get_author_by_id($author_data['author_id']);
            if ($author) {
                $author_names[] = $author->first_name . ' ' . $author->last_name;
            }
        }
        update_post_meta($post_id, '_sjm_paper_authors', implode(', ', $author_names));
    }
    
    // No required fields, treat all as optional
    $fields = array('sjm_paper_journal', 'sjm_paper_issue', 'sjm_paper_authors', 'sjm_paper_abstract', 'sjm_paper_type', 'sjm_submission_date', 'sjm_acceptance_date', 'sjm_paper_version', 'sjm_version_number', 'sjm_version_date', 'sjm_version_notes');
    foreach ($fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_paper_journal' || $field == 'sjm_paper_issue') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } elseif ($field == 'sjm_submission_date' || $field == 'sjm_acceptance_date' || $field == 'sjm_paper_version') {
                update_post_meta($post_id, '_' . $field, sanitize_text_field($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, sanitize_textarea_field($_POST[$field]));
            }
        }
    }
    
    // Optional fields
    $optional_fields = array('sjm_paper_doi', 'sjm_paper_keywords', 'sjm_paper_pages', 'sjm_corresponding_author_id', 'sjm_author_affiliations', 'sjm_paper_funding', 'sjm_conflicts_of_interest', 'sjm_paper_pdf_url', 'sjm_citation_count', 'sjm_views_count', 'sjm_manuscript_file', 'sjm_version_number', 'sjm_version_date', 'sjm_version_notes');
    foreach ($optional_fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_paper_pdf_url' || $field == 'sjm_manuscript_file') {
                update_post_meta($post_id, '_' . $field, esc_url_raw($_POST[$field]));
            } elseif ($field == 'sjm_citation_count' || $field == 'sjm_views_count' || $field == 'sjm_version_number') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } elseif ($field == 'sjm_corresponding_author_id') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } elseif ($field == 'sjm_version_date') {
                update_post_meta($post_id, '_' . $field, sanitize_text_field($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, sanitize_textarea_field($_POST[$field]));
            }
        }
    }
    
    // Manuscript tracking fields
    if (array_key_exists('sjm_submission_status', $_POST)) {
        update_post_meta($post_id, '_sjm_submission_status', sanitize_text_field($_POST['sjm_submission_status']));
    }
    
    // Handle tracking history
    if (array_key_exists('sjm_tracking_history', $_POST) && is_array($_POST['sjm_tracking_history'])) {
        $existing_history = get_post_meta($post_id, '_sjm_tracking_history', true);
        if (!is_array($existing_history)) $existing_history = array();
        
        foreach ($_POST['sjm_tracking_history'] as $history_json) {
            $history_data = json_decode(html_entity_decode($history_json), true);
            if ($history_data) {
                $existing_history[] = array(
                    'status' => sanitize_text_field($history_data['status']),
                    'date' => sanitize_text_field($history_data['date']),
                    'notes' => sanitize_textarea_field($history_data['notes'])
                );
            }
        }
        update_post_meta($post_id, '_sjm_tracking_history', $existing_history);
    }
    
    // Academic compliance fields
    $compliance_fields = array(
        'sjm_coi_declaration', 'sjm_coi_details', 'sjm_ethics_approval', 
        'sjm_ethics_approval_number', 'sjm_ethics_committee', 'sjm_data_availability',
        'sjm_data_availability_statement'
    );
    foreach ($compliance_fields as $field) {
        if (array_key_exists($field, $_POST)) {
            update_post_meta($post_id, '_' . $field, sanitize_textarea_field($_POST[$field]));
        }
    }
    
    // Handle compliance checkboxes
    $compliance_checkboxes = array('sjm_human_subjects', 'sjm_animal_subjects');
    foreach ($compliance_checkboxes as $field) {
        $value = array_key_exists($field, $_POST) ? '1' : '0';
        update_post_meta($post_id, '_' . $field, $value);
    }
    
    // Handle structured funding
    if (array_key_exists('sjm_funding_structured', $_POST) && is_array($_POST['sjm_funding_structured'])) {
        $funding_data = array();
        foreach ($_POST['sjm_funding_structured'] as $funding) {
            if (!empty($funding['agency']) || !empty($funding['grant_number'])) {
                $funding_data[] = array(
                    'agency' => sanitize_text_field($funding['agency']),
                    'grant_number' => sanitize_text_field($funding['grant_number']),
                    'amount' => sanitize_text_field($funding['amount']),
                    'recipient' => sanitize_text_field($funding['recipient'])
                );
            }
        }
        update_post_meta($post_id, '_sjm_funding_structured', $funding_data);
    }
    
    // Copyright management fields
    $copyright_fields = array(
        'sjm_copyright_holder', 'sjm_copyright_year', 'sjm_license_type', 
        'sjm_license_url', 'sjm_copyright_transfer', 'sjm_copyright_transfer_date',
        'sjm_reuse_permissions'
    );
    foreach ($copyright_fields as $field) {
        if (array_key_exists($field, $_POST)) {
            if ($field == 'sjm_copyright_year') {
                update_post_meta($post_id, '_' . $field, intval($_POST[$field]));
            } elseif ($field == 'sjm_license_url') {
                update_post_meta($post_id, '_' . $field, esc_url_raw($_POST[$field]));
            } elseif ($field == 'sjm_copyright_transfer_date') {
                update_post_meta($post_id, '_' . $field, sanitize_text_field($_POST[$field]));
            } else {
                update_post_meta($post_id, '_' . $field, sanitize_textarea_field($_POST[$field]));
            }
        }
    }
    
    // Version History
    if (array_key_exists('sjm_version_history', $_POST) && is_array($_POST['sjm_version_history'])) {
        $version_history = array();
        foreach ($_POST['sjm_version_history'] as $version) {
            if (!empty($version['type']) && !empty($version['file'])) {
                // Check if journal allows open access for version-specific access
                $version_open_access = '0';
                if (isset($version['open_access']) && $selected_journal) {
                    $journal_open_access = get_post_meta($selected_journal, '_sjm_open_access', true);
                    if ($journal_open_access == '1') {
                        $version_open_access = '1';
                    }
                }
                
                $version_data = array(
                    'type' => sanitize_text_field($version['type']),
                    'file' => esc_url_raw($version['file']),
                    'date' => sanitize_text_field($version['date']),
                    'description' => sanitize_textarea_field($version['description']),
                    'doi' => isset($version['doi']) ? sanitize_text_field($version['doi']) : '',
                    'open_access' => $version_open_access
                );
                
                // Handle version-specific authors
                if (isset($version['authors']) && is_array($version['authors'])) {
                    $version_authors = array();
                    foreach ($version['authors'] as $version_author) {
                        if (!empty($version_author['author_id'])) {
                            $version_authors[] = array(
                                'author_id' => intval($version_author['author_id']),
                                'role' => sanitize_text_field($version_author['role']),
                                'contribution' => sanitize_text_field($version_author['contribution'])
                            );
                        }
                    }
                    $version_data['authors'] = $version_authors;
                }
                
                $version_history[] = $version_data;
            }
        }
        update_post_meta($post_id, '_sjm_version_history', $version_history);
    }
    
    // Handle open access checkbox (only if journal allows it)
    if ($selected_journal) {
        $journal_open_access = get_post_meta($selected_journal, '_sjm_open_access', true);
        if ($journal_open_access == '1') {
            $paper_open_access = array_key_exists('sjm_paper_open_access', $_POST) ? '1' : '0';
            update_post_meta($post_id, '_sjm_paper_open_access', $paper_open_access);
        }
    }
    
    // Handle other checkbox fields
    $checkbox_fields = array('sjm_paper_peer_reviewed');
    foreach ($checkbox_fields as $field) {
        $value = array_key_exists($field, $_POST) ? '1' : '0';
        update_post_meta($post_id, '_' . $field, $value);
    }
}
add_action('save_post', 'sjm_save_paper_meta');

// SECURITY FUNCTIONS

// Rate limiting function
function sjm_check_rate_limit($action, $user_id, $limit, $time_window) {
    $transient_key = 'sjm_rate_limit_' . $action . '_' . $user_id;
    $attempts = get_transient($transient_key);
    
    if ($attempts === false) {
        // First attempt
        set_transient($transient_key, 1, $time_window);
        return true;
    } elseif ($attempts < $limit) {
        // Increment attempts
        set_transient($transient_key, $attempts + 1, $time_window);
        return true;
    } else {
        // Rate limit exceeded
        return false;
    }
}

// Enhanced input sanitization
function sjm_sanitize_input($input, $type = 'text') {
    if (is_array($input)) {
        return array_map(function($item) use ($type) {
            return sjm_sanitize_input($item, $type);
        }, $input);
    }
    
    switch ($type) {
        case 'email':
            return sanitize_email($input);
        case 'url':
            return esc_url_raw($input);
        case 'int':
            return intval($input);
        case 'float':
            return floatval($input);
        case 'textarea':
            return sanitize_textarea_field($input);
        case 'html':
            return wp_kses_post($input);
        case 'filename':
            return sanitize_file_name($input);
        case 'key':
            return sanitize_key($input);
        case 'title':
            return sanitize_title($input);
        default:
            return sanitize_text_field($input);
    }
}

// SQL injection protection wrapper
function sjm_safe_query($query, $args = array()) {
    global $wpdb;
    
    if (!empty($args)) {
        return $wpdb->get_results($wpdb->prepare($query, ...$args));
    } else {
        // For queries without parameters, ensure they're safe
        return $wpdb->get_results($query);
    }
}

// XSS protection for output
function sjm_safe_output($content, $allow_html = false) {
    if ($allow_html) {
        return wp_kses_post($content);
    } else {
        return esc_html($content);
    }
}

// Validate file uploads
function sjm_validate_file_upload($file) {
    $allowed_types = array(
        'pdf' => 'application/pdf',
        'doc' => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt' => 'text/plain',
        'rtf' => 'application/rtf'
    );
    
    $file_type = wp_check_filetype($file['name']);
    $file_mime = $file['type'];
    
    // Check file extension
    if (!in_array($file_type['ext'], array_keys($allowed_types))) {
        return new WP_Error('invalid_file_type', 'File type not allowed.');
    }
    
    // Check MIME type
    if (!in_array($file_mime, array_values($allowed_types))) {
        return new WP_Error('invalid_mime_type', 'File MIME type not allowed.');
    }
    
    // Check file size (10MB limit)
    if ($file['size'] > 10 * 1024 * 1024) {
        return new WP_Error('file_too_large', 'File size exceeds 10MB limit.');
    }
    
    // Additional security: scan file content for malicious patterns
    $file_content = file_get_contents($file['tmp_name']);
    $malicious_patterns = array(
        '/<script/i',
        '/javascript:/i',
        '/vbscript:/i',
        '/onload=/i',
        '/onerror=/i'
    );
    
    foreach ($malicious_patterns as $pattern) {
        if (preg_match($pattern, $file_content)) {
            return new WP_Error('malicious_content', 'File contains potentially malicious content.');
        }
    }
    
    return true;
}

// Enhanced capability checking
function sjm_check_user_capability($action, $post_id = null) {
    $user = wp_get_current_user();
    
    // Basic logged-in check
    if (!is_user_logged_in()) {
        return false;
    }
    
    switch ($action) {
        case 'edit_paper':
            return current_user_can('edit_post', $post_id) || 
                   current_user_can('edit_papers') ||
                   sjm_user_has_journal_roles($user);
                   
        case 'publish_paper':
            return current_user_can('publish_posts') ||
                   in_array('journal_editor_in_chief', $user->roles) ||
                   in_array('journal_managing_editor', $user->roles);
                   
        case 'manage_authors':
            return current_user_can('manage_options') ||
                   sjm_user_has_journal_roles($user);
                   
        case 'import_export':
            return current_user_can('manage_options') ||
                   in_array('journal_editor_in_chief', $user->roles);
                   
        case 'email_settings':
            return current_user_can('manage_options');
            
        default:
            return current_user_can('edit_posts');
    }
}

// CSRF token generation and validation
function sjm_generate_csrf_token($action) {
    $user_id = get_current_user_id();
    $token = wp_create_nonce($action . '_' . $user_id);
    return $token;
}

function sjm_validate_csrf_token($token, $action) {
    $user_id = get_current_user_id();
    return wp_verify_nonce($token, $action . '_' . $user_id);
}

// Secure session management
function sjm_start_secure_session() {
    if (!session_id()) {
        // Set secure session parameters
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', is_ssl());
        ini_set('session.use_strict_mode', 1);
        session_start();
    }
}

// Log security events
function sjm_log_security_event($event, $details = array()) {
    $log_entry = array(
        'timestamp' => current_time('mysql'),
        'user_id' => get_current_user_id(),
        'user_ip' => $_SERVER['REMOTE_ADDR'],
        'event' => $event,
        'details' => $details,
        'user_agent' => $_SERVER['HTTP_USER_AGENT']
    );
    
    $security_log = get_option('sjm_security_log', array());
    $security_log[] = $log_entry;
    
    // Keep only last 1000 entries
    if (count($security_log) > 1000) {
        $security_log = array_slice($security_log, -1000);
    }
    
    update_option('sjm_security_log', $security_log);
}

// Post-Publication Correction and Retraction System
function sjm_add_retraction_meta_box() {
    add_meta_box(
        'sjm_retraction_system',
        'Post-Publication Actions',
        'sjm_retraction_system_meta_box',
        'paper',
        'side',
        'default'
    );
}
add_action('add_meta_boxes', 'sjm_add_retraction_meta_box');

function sjm_retraction_system_meta_box($post) {
    $publication_status = get_post_meta($post->ID, '_sjm_publication_status', true);
    $retraction_status = get_post_meta($post->ID, '_sjm_retraction_status', true);
    $retraction_reason = get_post_meta($post->ID, '_sjm_retraction_reason', true);
    $retraction_date = get_post_meta($post->ID, '_sjm_retraction_date', true);
    $correction_history = get_post_meta($post->ID, '_sjm_correction_history', true);
    if (!is_array($correction_history)) $correction_history = array();
    
    echo '<div style="padding: 10px; background: #fff2e6; border: 1px solid #ff9800; border-radius: 5px; margin-bottom: 15px;">';
    echo '<h4 style="margin: 0 0 5px 0; color: #e65100;">🔄 Post-Publication Management</h4>';
    echo '<p style="margin: 0; font-size: 12px; color: #e65100;">Manage corrections, retractions, and updates after publication.</p>';
    echo '</div>';
    
    echo '<table class="form-table">';
    echo '<tr><th><label for="sjm_publication_status">Publication Status</label></th>';
    echo '<td><select id="sjm_publication_status" name="sjm_publication_status" style="width:100%">';
    echo '<option value="draft"' . selected($publication_status, 'draft', false) . '>Draft</option>';
    echo '<option value="published"' . selected($publication_status, 'published', false) . '>Published</option>';
    echo '<option value="corrected"' . selected($publication_status, 'corrected', false) . '>Corrected</option>';
    echo '<option value="retracted"' . selected($publication_status, 'retracted', false) . '>Retracted</option>';
    echo '<option value="withdrawn"' . selected($publication_status, 'withdrawn', false) . '>Withdrawn</option>';
    echo '</select></td></tr>';
    
    // Show retraction fields if status is retracted
    echo '<tr id="sjm_retraction_fields" style="' . ($publication_status == 'retracted' ? '' : 'display:none;') . '">';
    echo '<th><label for="sjm_retraction_reason">Retraction Reason</label></th>';
    echo '<td><select id="sjm_retraction_reason" name="sjm_retraction_reason" style="width:100%">';
    echo '<option value="">Select Reason</option>';
    echo '<option value="research_misconduct"' . selected($retraction_reason, 'research_misconduct', false) . '>Research Misconduct</option>';
    echo '<option value="data_fabrication"' . selected($retraction_reason, 'data_fabrication', false) . '>Data Fabrication</option>';
    echo '<option value="plagiarism"' . selected($retraction_reason, 'plagiarism', false) . '>Plagiarism</option>';
    echo '<option value="duplicate_publication"' . selected($retraction_reason, 'duplicate_publication', false) . '>Duplicate Publication</option>';
    echo '<option value="honest_error"' . selected($retraction_reason, 'honest_error', false) . '>Honest Error</option>';
    echo '<option value="author_request"' . selected($retraction_reason, 'author_request', false) . '>Author Request</option>';
    echo '<option value="legal_issues"' . selected($retraction_reason, 'legal_issues', false) . '>Legal Issues</option>';
    echo '<option value="other"' . selected($retraction_reason, 'other', false) . '>Other</option>';
    echo '</select></td></tr>';
    
    echo '<tr id="sjm_retraction_date_field" style="' . ($publication_status == 'retracted' ? '' : 'display:none;') . '">';
    echo '<th><label for="sjm_retraction_date">Retraction Date</label></th>';
    echo '<td><input type="date" id="sjm_retraction_date" name="sjm_retraction_date" value="' . esc_attr($retraction_date) . '" style="width:100%" /></td></tr>';
    
    echo '</table>';
    
    // Correction History
    echo '<h5 style="margin: 15px 0 10px 0; color: #666;">📝 Correction History</h5>';
    echo '<div id="sjm-correction-history" style="max-height: 150px; overflow-y: auto; border: 1px solid #ddd; padding: 8px; background: #fafafa;">';
    if (!empty($correction_history)) {
        foreach ($correction_history as $correction) {
            echo '<div style="margin-bottom: 8px; padding: 6px; background: #fff; border-left: 3px solid #ff9800; border-radius: 3px;">';
            echo '<strong>' . esc_html($correction['type']) . '</strong> - ' . esc_html($correction['date']) . '<br>';
            echo '<small style="color: #666;">' . esc_html($correction['description']) . '</small>';
            echo '</div>';
        }
    } else {
        echo '<p style="margin: 0; color: #666; font-style: italic;">No corrections recorded.</p>';
    }
    echo '</div>';
    
    echo '<div style="margin-top: 10px;">';
    echo '<select id="sjm_correction_type" style="width: 40%; margin-right: 5px;">';
    echo '<option value="minor_correction">Minor Correction</option>';
    echo '<option value="major_correction">Major Correction</option>';
    echo '<option value="erratum">Erratum</option>';
    echo '<option value="corrigendum">Corrigendum</option>';
    echo '<option value="addendum">Addendum</option>';
    echo '</select>';
    echo '<input type="text" id="sjm_correction_description" placeholder="Description..." style="width: 40%; margin-right: 5px;">';
    echo '<button type="button" id="sjm_add_correction" class="button">Add</button>';
    echo '</div>';
    
    echo '<script>
    jQuery(document).ready(function($) {
        $("#sjm_publication_status").change(function() {
            if ($(this).val() === "retracted") {
                $("#sjm_retraction_fields, #sjm_retraction_date_field").show();
            } else {
                $("#sjm_retraction_fields, #sjm_retraction_date_field").hide();
            }
        });
        
        $("#sjm_add_correction").click(function() {
            var type = $("#sjm_correction_type").val();
            var description = $("#sjm_correction_description").val();
            if (description.trim()) {
                var date = new Date().toISOString().split("T")[0];
                var entry = "<div style=\"margin-bottom: 8px; padding: 6px; background: #fff; border-left: 3px solid #ff9800; border-radius: 3px;\">" +
                           "<strong>" + type + "</strong> - " + date + "<br>" +
                           "<small style=\"color: #666;\">" + description + "</small></div>";
                $("#sjm-correction-history").prepend(entry);
                $("#sjm_correction_description").val("");
                
                // Add to hidden field for saving
                var correctionField = $("<input type=\"hidden\" name=\"sjm_correction_history[]\" value=\"" + 
                                      JSON.stringify({type: type, date: date, description: description}).replace(/"/g, "&quot;") + "\">");
                $("form").append(correctionField);
            }
        });
    });
    </script>';
}

// Save retraction and correction data
function sjm_save_retraction_meta($post_id) {
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
    if (get_post_type($post_id) !== 'paper') return;
    
    // Publication status
    if (array_key_exists('sjm_publication_status', $_POST)) {
        update_post_meta($post_id, '_sjm_publication_status', sanitize_text_field($_POST['sjm_publication_status']));
    }
    
    // Retraction fields
    $retraction_fields = array('sjm_retraction_reason', 'sjm_retraction_date');
    foreach ($retraction_fields as $field) {
        if (array_key_exists($field, $_POST)) {
            update_post_meta($post_id, '_' . $field, sanitize_text_field($_POST[$field]));
        }
    }
    
    // Handle correction history
    if (array_key_exists('sjm_correction_history', $_POST) && is_array($_POST['sjm_correction_history'])) {
        $existing_corrections = get_post_meta($post_id, '_sjm_correction_history', true);
        if (!is_array($existing_corrections)) $existing_corrections = array();
        
        foreach ($_POST['sjm_correction_history'] as $correction_json) {
            $correction_data = json_decode(html_entity_decode($correction_json), true);
            if ($correction_data) {
                $existing_corrections[] = array(
                    'type' => sanitize_text_field($correction_data['type']),
                    'date' => sanitize_text_field($correction_data['date']),
                    'description' => sanitize_textarea_field($correction_data['description'])
                );
            }
        }
        update_post_meta($post_id, '_sjm_correction_history', $existing_corrections);
    }
}
add_action('save_post', 'sjm_save_retraction_meta');

// AJAX handler to get issues for a selected journal
function sjm_get_issues_for_journal() {
    $journal_id = intval($_POST['journal_id']);
    $issues = get_posts(array(
        'post_type' => 'journal_issue',
        'posts_per_page' => -1,
        'meta_query' => array(
            array(
                'key' => '_sjm_issue_journal',
                'value' => $journal_id,
                'compare' => '='
            )
        )
    ));
    
    $response = array();
    foreach ($issues as $issue) {
        $response[] = array(
            'id' => $issue->ID,
            'title' => $issue->post_title
        );
    }
    
    wp_send_json($response);
}
add_action('wp_ajax_sjm_get_issues', 'sjm_get_issues_for_journal');
add_action('wp_ajax_nopriv_sjm_get_issues', 'sjm_get_issues_for_journal');

// Add JavaScript for dynamic issue filtering
function sjm_admin_scripts() {
    global $post_type;
    // Ensure $version_history is always an array for use in JS
    global $post;
    // Safely capture current paper ID for inline JS without assuming $post exists
    $sjm_current_paper_id = 0;
    if (is_object($post) && isset($post->ID) && (!isset($post_type) || $post->post_type === 'paper')) {
        $sjm_current_paper_id = (int) $post->ID;
    }
    $version_history = array();
    if ($post && $post->post_type === 'paper') {
        $version_history = get_post_meta($post->ID, '_sjm_version_history', true);
        if (!is_array($version_history)) $version_history = array();
    }
    
    if ($post_type === 'paper') {
        wp_enqueue_script('jquery');
        wp_add_inline_script('jquery', '
            jQuery(document).ready(function($) {
                var journalSelect = $("select[name=\'sjm_paper_journal\']");
                var issueSelect = $("select[name=\'sjm_paper_issue\']");
                
                // Frontend validation for required fields
                function validateRequiredFields() {
                    var isValid = true;
                    var errorMessage = "";
                    
                    if (!journalSelect.val()) {
                        isValid = false;
                        errorMessage += "Journal selection is required. ";
                    }
                    
                    if (!issueSelect.val()) {
                        isValid = false;
                        errorMessage += "Issue selection is required. ";
                    }
                    
                    if (!isValid) {
                        alert("Validation Error: " + errorMessage);
                        return false;
                    }
                    
                    return true;
                }
                
                // Add validation to form submission
                $("form#post").on("submit", function(e) {
                    if (!validateRequiredFields()) {
                        e.preventDefault();
                        return false;
                    }
                });
                
                journalSelect.on("change", function() {
                    var journalId = $(this).val();
                    issueSelect.html("<option value=\'\'>Loading issues...</option>");
                    
                    if (journalId) {
                        $.ajax({
                            url: ajaxurl,
                            type: "POST",
                            data: {
                                action: "sjm_get_issues",
                                journal_id: journalId
                            },
                            success: function(response) {
                                issueSelect.html("<option value=\'\'>Select Issue</option>");
                                $.each(response, function(index, issue) {
                                    issueSelect.append("<option value=\'" + issue.id + "\'>" + issue.title + "</option>");
                                });
                            },
                            error: function() {
                                issueSelect.html("<option value=\'\'>Error loading issues</option>");
                            }
                        });
                    } else {
                        issueSelect.html("<option value=\'\'>Select Issue</option>");
                    }
                });
            });
        ');
    }
    
    // Add validation for journal_issue post type
    if ($post_type === 'journal_issue') {
        wp_enqueue_script('jquery');
        wp_add_inline_script('jquery', '
            jQuery(document).ready(function($) {
                var journalSelect = $("select[name=\'sjm_issue_journal\']");
                
                // Frontend validation for required fields
                function validateRequiredFields() {
                    var isValid = true;
                    var errorMessage = "";
                    
                    if (!journalSelect.val()) {
                        isValid = false;
                        errorMessage += "Journal selection is required for an Issue. ";
                    }
                    
                    if (!isValid) {
                        alert("Validation Error: " + errorMessage);
                        return false;
                    }
                    
                    return true;
                }
                
                // Add validation to form submission
                $("form#post").on("submit", function(e) {
                    if (!validateRequiredFields()) {
                        e.preventDefault();
                        return false;
                    }
                });
            });
        ');
    }
    
    // Add media uploader for journal, issue, and paper post types
    if ($post_type === 'journal' || $post_type === 'journal_issue' || $post_type === 'paper') {
        wp_enqueue_media();
        wp_add_inline_script('jquery', '
            jQuery(document).ready(function($) {
                // Journal logo upload
                $("#sjm_upload_logo").click(function(e) {
                    e.preventDefault();
                    var image = wp.media({
                        title: "Upload Journal Logo",
                        multiple: false
                    }).open().on("select", function() {
                        var uploaded_image = image.state().get("selection").first();
                        var image_url = uploaded_image.toJSON().url;
                        $("#sjm_journal_logo").val(image_url);
                        $("#sjm_logo_preview").html("<img src=\'" + image_url + "\' style=\'max-width: 150px; max-height: 100px; margin-top: 10px;\' />");
                    });
                });
                
                // Journal cover upload
                $("#sjm_upload_cover").click(function(e) {
                    e.preventDefault();
                    var image = wp.media({
                        title: "Upload Journal Cover",
                        multiple: false
                    }).open().on("select", function() {
                        var uploaded_image = image.state().get("selection").first();
                        var image_url = uploaded_image.toJSON().url;
                        $("#sjm_journal_cover").val(image_url);
                        $("#sjm_cover_preview").html("<img src=\'" + image_url + "\' style=\'max-width: 150px; max-height: 100px; margin-top: 10px;\' />");
                    });
                });
                
                // Issue cover upload
                $("#sjm_upload_issue_cover").click(function(e) {
                    e.preventDefault();
                    var image = wp.media({
                        title: "Upload Issue Cover",
                        multiple: false
                    }).open().on("select", function() {
                        var uploaded_image = image.state().get("selection").first();
                        var image_url = uploaded_image.toJSON().url;
                        $("#sjm_cover_image").val(image_url);
                        $("#sjm_issue_cover_preview").html("<img src=\'" + image_url + "\' style=\'max-width: 150px; max-height: 100px; margin-top: 10px;\' />");
                    });
                });
                
                // Paper manuscript upload
                $("#sjm_upload_manuscript").click(function(e) {
                    e.preventDefault();
                    var file = wp.media({
                        title: "Upload Manuscript",
                        multiple: false,
                        library: {
                            type: ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]
                        }
                    }).open().on("select", function() {
                        var uploaded_file = file.state().get("selection").first();
                        var file_url = uploaded_file.toJSON().url;
                        var file_name = uploaded_file.toJSON().filename;
                        $("#sjm_manuscript_file").val(file_url);
                        $("#sjm_manuscript_preview").html("<div style=\'margin-top: 10px; padding: 10px; background: #f0f0f0; border-radius: 3px;\'><strong>File:</strong> " + file_name + "<br><a href=\'" + file_url + "\' target=\'_blank\' style=\'color: #0073aa;\'>View File</a></div>");
                    });
                });
                
                // Handle adding editorial roles (unified system for issues)
                $(document).on("click", ".sjm-add-editor", function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log("Add editor button clicked");
                    
                    var button = $(this);
                    var role = button.attr("data-role");
                    var container = button.attr("data-container");
                    var fieldName = button.attr("data-name");
                    var placeholder = button.attr("data-placeholder");
                    
                    console.log("Role:", role, "Container:", container, "Field:", fieldName);
                    
                    if (!role || !container || !fieldName || !placeholder) {
                        console.error("Missing data attributes");
                        return;
                    }
                    
                    var editorHtml = "<div class=\"sjm-editor-item\" style=\"margin-bottom: 10px;\">" +
                        "<select name=\"" + fieldName + "\" style=\"width: 300px;\">" +
                        "<option value=\"\">Loading...</option>" +
                        "</select>" +
                        "<button type=\"button\" class=\"button sjm-remove-editor\" style=\"margin-left: 10px;\">Remove</button>" +
                        "</div>";
                    
                    var containerElement = $("#" + container);
                    if (containerElement.length === 0) {
                        console.error("Container not found:", container);
                        return;
                    }
                    
                    containerElement.append(editorHtml);
                    
                    // Get the newly added select element
                    var newSelect = containerElement.find(".sjm-editor-item:last select");
                    
                    // Populate with users via AJAX
                    $.ajax({
                        url: ajaxurl,
                        type: "POST",
                        data: {
                            action: "sjm_get_users_by_role",
                            role: role,
                            nonce: "' . wp_create_nonce("sjm_get_users_nonce") . '"
                        },
                        success: function(response) {
                            console.log("AJAX Success:", response);
                            if (response.success) {
                                newSelect.empty();
                                newSelect.append("<option value=\"\">" + placeholder + "</option>");
                                $.each(response.data, function(index, user) {
                                    newSelect.append("<option value=\"" + user.id + "\">" + user.name + "</option>");
                                });
                            } else {
                                newSelect.html("<option value=\"\">Error loading users</option>");
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log("AJAX Error:", error);
                            newSelect.html("<option value=\"\">Error loading users</option>");
                        }
                    });
                });
                
                // Handle removing editorial roles (unified system for issues)
                $(document).on("click", ".sjm-remove-editor", function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log("Remove editor button clicked");
                    
                    var itemToRemove = $(this).closest(".sjm-editor-item");
                    var container = itemToRemove.parent();
                    
                    itemToRemove.remove();
                    
                    // If no items left, add one empty item
                    if (container.find(".sjm-editor-item").length === 0) {
                        var containerType = container.attr("id");
                        var fieldName = "";
                        var placeholder = "";
                        
                        // Determine field details based on container
                        switch(containerType) {
                            case "sjm-guest-editors-container":
                                fieldName = "sjm_guest_editors[]";
                                placeholder = "Select Guest Editor";
                                break;
                            case "sjm-issue-editors-container":
                                fieldName = "sjm_issue_editors[]";
                                placeholder = "Select Issue Editor";
                                break;
                            case "sjm-issue-reviewers-container":
                                fieldName = "sjm_issue_reviewers[]";
                                placeholder = "Select Reviewer";
                                break;
                            case "sjm-copyeditors-container":
                                fieldName = "sjm_copyeditors[]";
                                placeholder = "Select Copyeditor";
                                break;
                            case "sjm-layout-editors-container":
                                fieldName = "sjm_layout_editors[]";
                                placeholder = "Select Layout Editor";
                                break;
                        }
                        
                        if (fieldName && placeholder) {
                            var emptyHtml = "<div class=\"sjm-editor-item\" style=\"margin-bottom: 10px;\">" +
                                "<select name=\"" + fieldName + "\" style=\"width: 300px;\">" +
                                "<option value=\"\">" + placeholder + "</option>" +
                                "</select>" +
                                "<button type=\"button\" class=\"button sjm-remove-editor\" style=\"margin-left: 10px;\">Remove</button>" +
                                "</div>";
                            
                            container.append(emptyHtml);
                        }
                    }
                });
                
                // Enhanced Version Management System functionality
                var versionIndex = ' . count($version_history) . ';
                
                // Auto-update citations and views
                $("#sjm-auto-update-citations").click(function() {
                    var button = $(this);
                    var status = $("#sjm-citation-update-status");
                     var paperId = ' . $sjm_current_paper_id . ';
                    
                    button.prop("disabled", true).text("Updating...");
                    status.text("Fetching citations...");
                    
                    $.post(ajaxurl, {
                        action: "sjm_update_single_paper",
                        paper_id: paperId,
                        nonce: "' . wp_create_nonce('sjm_update_single_paper') . '"
                    }, function(response) {
                        if (response.success) {
                            status.html("<span style=\"color: green;\">✓ Updated</span>");
                            setTimeout(function() {
                                location.reload();
                            }, 1000);
                        } else {
                            status.html("<span style=\"color: red;\">✗ " + response.data + "</span>");
                        }
                        button.prop("disabled", false).text("Auto Update");
                    });
                });
                
                // Handle new version type selection
                $("#sjm-new-version-type").change(function() {
                    var selectedType = $(this).val();
                    if (selectedType) {
                        $("#sjm-version-type-name").text(selectedType);
                    } else {
                        $("#sjm-version-type-name").text("Version");
                    }
                });
                
                // Add first version of a new type
                $("#sjm-add-new-version-type-btn").click(function() {
                    var selectedType = $("#sjm-new-version-type").val();
                    if (!selectedType) {
                        alert("Please select a version type first.");
                        return;
                    }
                    
                    // Check if this type already exists
                    var existingGroup = $(".sjm-version-type-group h5:contains(\'" + selectedType + " Versions\')").closest(".sjm-version-type-group");
                    if (existingGroup.length > 0) {
                        alert("This version type already exists. Use the \'Add Another\' button in that section.");
                        return;
                    }
                    
                    addNewVersionType(selectedType);
                    $("#sjm-new-version-type").val("");
                    $("#sjm-version-type-name").text("Version");
                });
                
                // Add another version of existing type
                $(document).on("click", ".sjm-add-version-of-type", function() {
                    var versionType = $(this).data("type");
                    addVersionToExistingType(versionType, $(this).closest(".sjm-version-type-group"));
                });
                
                function addNewVersionType(versionType) {
                    var groupHtml = \'<div class="sjm-version-type-group" style="margin-bottom: 25px; border: 2px solid #e1e5e9; border-radius: 8px; padding: 15px; background: #fafbfc;">\' +
                        \'<h5 style="margin-top: 0; color: #0073aa; font-size: 16px; font-weight: 600;">\' + versionType + \' Versions (1)</h5>\' +
                        createVersionHtml(versionType, 1, versionIndex) +
                        \'<button type="button" class="sjm-add-version-of-type button" data-type="\' + versionType + \'" style="background: #2271b1; border-color: #2271b1; color: white; margin-top: 10px;">Add Another \' + versionType + \'</button>\' +
                        \'</div>\';
                    
                    $(".sjm-add-new-version-type").before(groupHtml);
                    
                    // Check journal open access status for the new version
                    var journalId = $("#sjm_paper_journal").val();
                    if (journalId) {
                        $.ajax({
                            url: ajaxurl,
                            method: "POST",
                            data: { action: "sjm_check_journal_open_access", journal_id: journalId },
                            success: function(resp) {
                                if (resp.success && resp.data.open_access) {
                                    $(".sjm-version-type-group").last().find(".sjm-version-open-access").prop("disabled", false);
                                    $(".sjm-version-type-group").last().find(".sjm-version-access-warning").hide();
                                } else {
                                    $(".sjm-version-type-group").last().find(".sjm-version-open-access").prop("checked", false).prop("disabled", true);
                                    $(".sjm-version-type-group").last().find(".sjm-version-access-warning").show();
                                }
                            },
                            error: function() {
                                $(".sjm-version-type-group").last().find(".sjm-version-open-access").prop("checked", false).prop("disabled", true);
                                $(".sjm-version-type-group").last().find(".sjm-version-access-warning").show();
                            }
                        });
                    } else {
                        $(".sjm-version-type-group").last().find(".sjm-version-open-access").prop("checked", false).prop("disabled", true);
                        $(".sjm-version-type-group").last().find(".sjm-version-access-warning").show();
                    }
                    
                    versionIndex++;
                }
                
                function addVersionToExistingType(versionType, groupElement) {
                    var currentCount = groupElement.find(".sjm-version-item").length;
                    var newVersionNumber = currentCount + 1;
                    
                    var versionHtml = createVersionHtml(versionType, newVersionNumber, versionIndex);
                    groupElement.find(".sjm-add-version-of-type").before(versionHtml);
                    
                    // Update count in header
                    groupElement.find("h5").text(versionType + " Versions (" + newVersionNumber + ")");
                    
                    // Check journal open access status for the new version
                    var journalId = $("#sjm_paper_journal").val();
                    if (journalId) {
                        $.ajax({
                            url: ajaxurl,
                            method: "POST",
                            data: { action: "sjm_check_journal_open_access", journal_id: journalId },
                            success: function(resp) {
                                if (resp.success && resp.data.open_access) {
                                    groupElement.find(".sjm-version-open-access").last().prop("disabled", false);
                                    groupElement.find(".sjm-version-access-warning").last().hide();
                                } else {
                                    groupElement.find(".sjm-version-open-access").last().prop("checked", false).prop("disabled", true);
                                    groupElement.find(".sjm-version-access-warning").last().show();
                                }
                            },
                            error: function() {
                                groupElement.find(".sjm-version-open-access").last().prop("checked", false).prop("disabled", true);
                                groupElement.find(".sjm-version-access-warning").last().show();
                            }
                        });
                    } else {
                        groupElement.find(".sjm-version-open-access").last().prop("checked", false).prop("disabled", true);
                        groupElement.find(".sjm-version-access-warning").last().show();
                    }
                    
                    versionIndex++;
                }
                
                function createVersionHtml(versionType, versionNumber, index) {
                    var versionLabel = versionType + " v" + versionNumber;
                    var isLatest = true; // New versions are always latest initially
                    
                    return \'<div class="sjm-version-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #ffffff; position: relative;">\' +
                        \'<div style="position: absolute; top: 10px; right: 10px;">\' +
                        (isLatest ? \'<span style="background: #00a32a; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">LATEST</span>\' : \'\') +
                        \'</div>\' +
                        \'<h6 style="margin-top: 0; color: #2271b1; font-size: 14px; font-weight: 600;">\' + versionLabel + \'</h6>\' +
                        \'<table class="form-table" style="margin: 0;">\' +
                        \'<tr><th style="width: 140px;"><label>Version File</label></th>\' +
                        \'<td><input type="text" name="sjm_version_history[\' + index + \'][file]" style="width:65%" placeholder="File URL or DOI" />\' +
                        \'<button type="button" class="sjm-upload-version button" data-index="\' + index + \'" style="margin-left: 10px;">Upload File</button></td></tr>\' +
                        \'<tr><th><label>Version Date</label></th>\' +
                        \'<td><input type="date" name="sjm_version_history[\' + index + \'][date]" style="width:100%" /></td></tr>\' +
                        \'<tr><th><label>DOI/Identifier</label></th>\' +
                        \'<td><input type="text" name="sjm_version_history[\' + index + \'][doi]" style="width:100%" placeholder="e.g., 10.48550/arXiv.2024.12345v\' + versionNumber + \'" /></td></tr>\' +
                        \'<tr><th><label>Changes Made</label></th>\' +
                        \'<td><textarea name="sjm_version_history[\' + index + \'][description]" style="width:100%; height:60px" placeholder="What changed in this version? (e.g., Fixed methodology section, Added new data analysis)"></textarea></td></tr>\' +
                        \'<tr><th><label>Version Access</label></th>\' +
                        \'<td><input type="checkbox" class="sjm-version-open-access" name="sjm_version_history[\' + index + \'][open_access]" value="1" /> <label>This \' + versionType.toLowerCase() + \' version is open access</label>\' +
                        \'<div class="sjm-version-access-warning" style="color:#b91c1c;font-size:11px;margin-top:2px;display:none;">Only available if journal supports open access</div>\' +
                        \'<div style="color:#6b7280;font-size:10px;margin-top:4px;font-style:italic;">Independent access control: This \' + versionType.toLowerCase() + \' can be open while other versions are closed</div></td></tr>\' +
                        \'<input type="hidden" name="sjm_version_history[\' + index + \'][type]" value="\' + versionType + \'" />\' +
                        \'<tr><th><label>Version Contributors</label></th>\' +
                        \'<td><div class="sjm-version-authors-container" id="sjm-version-authors-\' + index + \'"></div>\' +
                        \'<button type="button" class="sjm-add-version-author button" data-version="\' + index + \'" style="margin-top: 5px;">Add Contributor to This Version</button>\' +
                        \'<p style="font-size: 12px; color: #666; margin-top: 5px;"><em>Track who contributed to this specific version (original authors, reviewers, editors, collaborators).</em></p></td></tr>\' +
                        \'</table>\' +
                        \'<button type="button" class="sjm-remove-version button" data-index="\' + index + \'" style="background: #dc3232; border-color: #dc3232; color: white; margin-top: 10px;">Remove This Version</button>\' +
                        \'</div>\';
                }
                
                $(document).on("click", ".sjm-remove-version", function() {
                    var versionItem = $(this).closest(".sjm-version-item");
                    var groupElement = versionItem.closest(".sjm-version-type-group");
                    versionItem.remove();
                    
                    // Update count in header
                    var remainingCount = groupElement.find(".sjm-version-item").length;
                    if (remainingCount === 0) {
                        groupElement.remove();
                    } else {
                        var versionType = groupElement.find(".sjm-add-version-of-type").data("type");
                        groupElement.find("h5").text(versionType + " Versions (" + remainingCount + ")");
                    }
                });
                
                $(document).on("click", ".sjm-upload-version", function() {
                    var button = $(this);
                    var index = button.data("index");
                    var file = wp.media({
                        title: "Upload Version File",
                        multiple: false,
                        library: {
                            type: ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]
                        }
                    }).open().on("select", function() {
                        var uploaded_file = file.state().get("selection").first();
                        var file_url = uploaded_file.toJSON().url;
                        button.siblings("input[type=text]").val(file_url);
                    });
                });
                
                // Version-specific author management
                $(document).on("click", ".sjm-add-version-author", function() {
                    var versionIndex = $(this).data("version");
                    var container = $("#sjm-version-authors-" + versionIndex);
                    var authorIndex = container.find(".sjm-version-author-item").length;
                    var versionAuthorSelectId = "sjm_version_author_" + versionIndex + "_" + authorIndex;
                    
                    var authorHtml = \'<div class="sjm-version-author-item" style="border: 1px solid #ccc; padding: 10px; margin: 5px 0; background: #fff; border-radius: 3px;">\' +
                        \'<select id="\' + versionAuthorSelectId + \'" name="sjm_version_history[\' + versionIndex + \'][authors][\' + authorIndex + \'][author_id]" style="width:30%">\' +
                        \'<option value="">Loading authors...</option>\' +
                        \'</select>\' +
                        \'<select name="sjm_version_history[\' + versionIndex + \'][authors][\' + authorIndex + \'][role]" style="width:20%; margin-left:5px;">\' +
                        \'<option value="author">Author</option>\' +
                        \'<option value="contributor">Contributor</option>\' +
                        \'<option value="reviewer">Reviewer</option>\' +
                        \'<option value="editor">Editor</option>\' +
                        \'<option value="collaborator">Collaborator</option>\' +
                        \'</select>\' +
                        \'<input type="text" name="sjm_version_history[\' + versionIndex + \'][authors][\' + authorIndex + \'][contribution]" placeholder="Contribution" style="width:35%; margin-left:5px;" />\' +
                        \'<button type="button" class="sjm-remove-version-author button" style="margin-left:5px; background: #dc3232; border-color: #dc3232; color: white; padding: 2px 8px;">Remove</button>\' +
                        \'</div>\';
                    
                    container.append(authorHtml);
                    
                    // Populate the new dropdown with authors
                    $.post(ajaxurl, {
                        action: "sjm_get_all_authors"
                    }, function(authors) {
                        var selectElement = $("#" + versionAuthorSelectId);
                        selectElement.html(\'<option value="">Select Author</option>\');
                        $.each(authors, function(index, author) {
                            selectElement.append(\'<option value="\' + author.id + \'">\' + author.name + \'</option>\');
                        });
                    }).fail(function() {
                        $("#" + versionAuthorSelectId).html(\'<option value="">Error loading authors</option>\');
                    });
                });
                
                $(document).on("click", ".sjm-remove-version-author", function() {
                    $(this).closest(".sjm-version-author-item").remove();
                });
                
                // Author Management functionality - full implementation
                var authorIndex = $("#sjm-authors-container .sjm-author-item").length;
                
                $("#sjm-add-author").click(function() {
                    var authorSelectId = "sjm_paper_authors_data_" + authorIndex + "_author_id";
                    var authorHtml = \'<div class="sjm-author-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #f9f9f9;">\' +
                        \'<h5 style="margin-top: 0;">Author \' + (authorIndex + 1) + \'</h5>\' +
                        \'<table class="form-table" style="margin: 0;">\' +
                        \'<tr><th style="width: 150px;"><label>Select Author</label></th>\' +
                        \'<td><select id="\' + authorSelectId + \'" name="sjm_paper_authors_data[\' + authorIndex + \'][author_id]" style="width:100%">\' +
                        \'<option value="">Loading authors...</option>\' +
                        \'</select></td></tr>\' +
                        \'<tr><th><label>Author Order</label></th>\' +
                        \'<td><input type="number" name="sjm_paper_authors_data[\' + authorIndex + \'][order]" value="\' + (authorIndex + 1) + \'" min="1" style="width:100px;" /></td></tr>\' +
                        \'<tr><th><label>Contributions</label></th>\' +
                        \'<td><textarea name="sjm_paper_authors_data[\' + authorIndex + \'][contributions]" style="width:100%; height:60px" placeholder="e.g., Conceptualization, Data analysis, Writing - original draft"></textarea></td></tr>\' +
                        \'<tr><th><label>Corresponding Author</label></th>\' +
                        \'<td><input type="checkbox" name="sjm_paper_authors_data[\' + authorIndex + \'][is_corresponding]" value="1" /> <label>Yes, this is a corresponding author</label></td></tr>\' +
                        \'</table>\' +
                        \'<button type="button" class="sjm-remove-author button" style="background: #dc3232; border-color: #dc3232; color: white;">Remove Author</button>\' +
                        \'</div>\';
                    $("#sjm-authors-container").append(authorHtml);
                    
                    // Populate the new dropdown with authors
                    $.post(ajaxurl, {
                        action: "sjm_get_all_authors"
                    }, function(authors) {
                        var selectElement = $("#" + authorSelectId);
                        selectElement.html(\'<option value="">Select Author</option>\');
                        $.each(authors, function(index, author) {
                            var orcidText = author.orcid ? \' (ORCID: \' + author.orcid + \')\' : \'\';
                            selectElement.append(\'<option value="\' + author.id + \'">\' + author.name + orcidText + \'</option>\');
                        });
                    }).fail(function() {
                        $("#" + authorSelectId).html(\'<option value="">Error loading authors</option>\');
                    });
                    
                    authorIndex++;
                });
                
                $(document).on("click", ".sjm-remove-author", function() {
                    $(this).closest(".sjm-author-item").remove();
                });
                
                // Add Author/Contributor for Journal
                try {
                    var journalAuthorIndex = $("#sjm-journal-authors-container .sjm-journal-author-item").length;
                    console.log(\'SJM: Add Author/Contributor JS loaded. Current index:\', journalAuthorIndex);
                    $("#sjm-add-journal-author").off(\'click\').on(\'click\', function() {
                        var authorHtml = \'<div class="sjm-journal-author-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #f9f9f9;">\' +
                            \'<h5 style="margin-top: 0;">Author/Contributor \' + (journalAuthorIndex + 1) + \'</h5>\' +
                            \'<table class="form-table" style="margin: 0;">\' +
                            \'<tr><th style="width: 150px;"><label>Select Author</label></th>\' +
                            \'<td><select name="sjm_journal_authors_data[\' + journalAuthorIndex + \'][author_id]" style="width:100%"><option value="">Loading authors...</option></select></td></tr>\' +
                            \'<tr><th><label>Role in Journal</label></th>\' +
                            \'<td><select name="sjm_journal_authors_data[\' + journalAuthorIndex + \'][role]" style="width:100%">\' +
                            \'<option value="">Select Role</option>\' +
                            \'<option value="Contributing Author">Contributing Author</option>\' +
                            \'<option value="Regular Contributor">Regular Contributor</option>\' +
                            \'<option value="Guest Author">Guest Author</option>\' +
                            \'<option value="Special Issue Author">Special Issue Author</option>\' +
                            \'<option value="Board Member">Board Member</option>\' +
                            \'<option value="Reviewer">Reviewer</option>\' +
                            \'<option value="Editorial Board">Editorial Board</option>\' +
                            \'</select></td></tr>\' +
                            \'<tr><th><label>Contributions</label></th>\' +
                            \'<td><textarea name="sjm_journal_authors_data[\' + journalAuthorIndex + \'][contributions]" style="width:100%; height:60px" placeholder="e.g., Editorial oversight, Peer review, Special issue editing"></textarea></td></tr>\' +
                            \'<tr><th><label>Publication Versions</label></th>\' +
                            \'<td><textarea name="sjm_journal_authors_data[\' + journalAuthorIndex + \'][versions]" style="width:100%; height:60px" placeholder="e.g., Volume 1-5, Special Issue 2023, Editorial Board 2020-2024"></textarea></td></tr>\' +
                            \'<tr><th><label>Active Period</label></th>\' +
                            \'<td><input type="text" name="sjm_journal_authors_data[\' + journalAuthorIndex + \'][period]" style="width:100%" placeholder="e.g., 2020-2024, 2023-Present" /></td></tr>\' +
                            \'</table>\' +
                            \'<button type="button" class="sjm-remove-journal-author button" style="background: #dc3232; border-color: #dc3232; color: white;">Remove Author</button>\' +
                            \'</div>\';
                        $("#sjm-journal-authors-container").append(authorHtml);
                        // Populate the new dropdown with authors
                        var selectElement = $("#sjm-journal-authors-container .sjm-journal-author-item:last select[name^=\'sjm_journal_authors_data\'][name$=\'[author_id]\']");
                        $.post(ajaxurl, {
                            action: "sjm_get_all_authors"
                        }, function(authors) {
                            selectElement.html(\'<option value="">Select Author</option>\');
                            $.each(authors, function(index, author) {
                                var orcidText = author.orcid ? \' (ORCID: \' + author.orcid + \')\' : \'\';
                                selectElement.append(\'<option value="\' + author.id + \'">\' + author.name + orcidText + \'</option>\');
                            });
                        }).fail(function() {
                            selectElement.html(\'<option value="">Error loading authors</option>\');
                        });
                        journalAuthorIndex++;
                    });
                    $(document).on("click", ".sjm-remove-journal-author", function() {
                        $(this).closest(".sjm-journal-author-item").remove();
                    });
                } catch (e) { console.error(\'SJM: Error in Add Author/Contributor JS\', e); }
            });
        ');
    }
}
add_action('admin_enqueue_scripts', 'sjm_admin_scripts');

// Shortcode to List Journals
function sjm_journals_shortcode($atts = array()) {
    $atts = shortcode_atts(array(
        'layout' => 'grid', // 'grid' or 'list'
        'publisher' => '',
        'subject_area' => '',
        'language' => '',
        'open_access' => '',
        'peer_reviewed' => '',
        'year' => '',
        'per_page' => 12
    ), $atts);
    
    // Build query args
    $args = array(
        'post_type' => 'journal',
        'posts_per_page' => intval($atts['per_page']),
        'meta_query' => array('relation' => 'AND')
    );
    
    // Add filters
    if (!empty($atts['publisher'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_publisher',
            'value' => $atts['publisher'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['subject_area'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_subject_areas',
            'value' => $atts['subject_area'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['language'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_language',
            'value' => $atts['language'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['open_access'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_open_access',
            'value' => '1',
            'compare' => '='
        );
    }
    
    if (!empty($atts['peer_reviewed'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_peer_reviewed',
            'value' => '1',
            'compare' => '='
        );
    }
    
    if (!empty($atts['year'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_founding_year',
            'value' => $atts['year'],
            'compare' => '='
        );
    }
    
    $journals = get_posts($args);
    
    // Get unique values for filters
    $all_journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    $publishers = array();
    $languages = array();
    $subject_areas = array();
    
    foreach ($all_journals as $journal) {
        $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
        $language = get_post_meta($journal->ID, '_sjm_language', true);
        $subjects = get_post_meta($journal->ID, '_sjm_subject_areas', true);
        
        if ($publisher && !in_array($publisher, $publishers)) {
            $publishers[] = $publisher;
        }
        if ($language && !in_array($language, $languages)) {
            $languages[] = $language;
        }
        if ($subjects) {
            $subject_list = array_map('trim', explode(',', $subjects));
            foreach ($subject_list as $subject) {
                if ($subject && !in_array($subject, $subject_areas)) {
                    $subject_areas[] = $subject;
                }
            }
        }
    }
    
    sort($publishers);
    sort($languages);
    sort($subject_areas);
    
    if (!$journals && empty($_GET['sjm_journal_filter'])) {
        return '<div class="sjm-empty-state"><p>No journals found.</p></div>';
    }
    
    // Enqueue the new CSS file
    wp_enqueue_style('sjm-academic-shortcodes', plugin_dir_url(__FILE__) . 'academic-shortcodes.css', array(), '1.0.0');
    
    $output = '<div class="sjm-container">';
    
    // Search filters for journals
    $output .= '<form method="get" class="sjm-filters">';
    $output .= '<input type="hidden" name="sjm_journal_filter" value="1">';
    
    $output .= '<div class="sjm-filters-grid">';
    
    // Publisher filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Publisher</label>';
    $output .= '<select name="publisher" class="sjm-filter-select">';
    $output .= '<option value="">All Publishers</option>';
    foreach ($publishers as $publisher) {
        $selected = (isset($_GET['publisher']) && $_GET['publisher'] == $publisher) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($publisher) . '" ' . $selected . '>' . esc_html($publisher) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Subject Area filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Subject Area</label>';
    $output .= '<select name="subject_area" class="sjm-filter-select">';
    $output .= '<option value="">All Subject Areas</option>';
    foreach ($subject_areas as $subject) {
        $selected = (isset($_GET['subject_area']) && $_GET['subject_area'] == $subject) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($subject) . '" ' . $selected . '>' . esc_html($subject) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Language filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Language</label>';
    $output .= '<select name="language" class="sjm-filter-select">';
    $output .= '<option value="">All Languages</option>';
    foreach ($languages as $language) {
        $selected = (isset($_GET['language']) && $_GET['language'] == $language) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($language) . '" ' . $selected . '>' . esc_html($language) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Open Access filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Access Type</label>';
    $output .= '<select name="open_access" class="sjm-filter-select">';
    $output .= '<option value="">All Access Types</option>';
    $selected = (isset($_GET['open_access']) && $_GET['open_access'] == '1') ? 'selected' : '';
    $output .= '<option value="1" ' . $selected . '>Open Access Only</option>';
    $output .= '</select>';
    $output .= '</div>';
    
    // Peer Reviewed filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Review Status</label>';
    $output .= '<select name="peer_reviewed" class="sjm-filter-select">';
    $output .= '<option value="">All Review Types</option>';
    $selected = (isset($_GET['peer_reviewed']) && $_GET['peer_reviewed'] == '1') ? 'selected' : '';
    $output .= '<option value="1" ' . $selected . '>Peer Reviewed Only</option>';
    $output .= '</select>';
    $output .= '</div>';
    
    $output .= '</div>'; // Close filters-grid
    
    // Filter buttons
    $output .= '<div class="sjm-filter-buttons">';
    $output .= '<a href="' . get_permalink() . '" class="sjm-filter-button">Clear Filters</a>';
    $output .= '<button type="submit" class="sjm-filter-button sjm-filter-button-primary">Apply Filters</button>';
    $output .= '</div>';
    
    $output .= '</form>';
    
    // Handle URL parameters for filtering
    if (isset($_GET['sjm_journal_filter'])) {
        $filter_args = array(
            'post_type' => 'journal',
            'posts_per_page' => intval($atts['per_page']),
            'meta_query' => array('relation' => 'AND')
        );
        
        if (!empty($_GET['publisher'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_publisher',
                'value' => $_GET['publisher'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['subject_area'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_subject_areas',
                'value' => $_GET['subject_area'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['language'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_language',
                'value' => $_GET['language'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['open_access'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_open_access',
                'value' => '1',
                'compare' => '='
            );
        }
        
        if (!empty($_GET['peer_reviewed'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_peer_reviewed',
                'value' => '1',
                'compare' => '='
            );
        }
        
        $journals = get_posts($filter_args);
    }
    
    if (!$journals) {
        $output .= '<div class="sjm-empty-state"><p>No journals found matching your criteria.</p></div>';
        $output .= '</div>';
        return $output;
    }
    
    if ($atts['layout'] === 'list') {
        $output .= '<div class="sjm-journals-list">';
        
        foreach ($journals as $journal) {
            $journal_cover = get_post_meta($journal->ID, '_sjm_journal_cover', true);
            $issn = get_post_meta($journal->ID, '_sjm_issn', true);
            $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
            $impact_factor = get_post_meta($journal->ID, '_sjm_impact_factor', true);
            $open_access = get_post_meta($journal->ID, '_sjm_open_access', true);
            $peer_reviewed = get_post_meta($journal->ID, '_sjm_peer_reviewed', true);
            $permalink = get_permalink($journal->ID);
            
            $output .= '<div class="sjm-journal-card-list">';
            
            // Cover image
            $output .= '<div class="sjm-journal-cover-list">';
            if ($journal_cover) {
                $output .= '<img src="' . esc_url($journal_cover) . '" alt="' . esc_attr($journal->post_title) . ' Cover">';
            } else {
                $output .= '<div class="sjm-journal-cover-placeholder"></div>';
            }
            $output .= '</div>';
            
            // Journal info
            $output .= '<div class="sjm-journal-info-list">';
            $output .= '<h3 class="sjm-journal-title">' . esc_html($journal->post_title) . '</h3>';
            
            // Create badges for key information
            $output .= '<div class="sjm-journal-badges-list">';
            if ($issn) {
                $output .= '<span class="sjm-badge">ISSN ' . esc_html($issn) . '</span>';
            }
            if ($impact_factor) {
                $output .= '<span class="sjm-badge">IF ' . esc_html($impact_factor) . '</span>';
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge">Open Access</span>';
            } else {
                $output .= '<span class="sjm-badge" style="background:transparent;color:#b91c1c;border:1px solid #b91c1c;font-style:italic;">Not Open Access</span>';
                $output .= '<div style="color:#6b7280;font-size:13px;margin-top:4px;font-style:italic;max-width:400px;">This journal is not open access. Access to full articles may be restricted according to publisher policy.</div>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge">Peer Reviewed</span>';
            }
            if ($publisher) {
                $output .= '<span class="sjm-badge">' . esc_html($publisher) . '</span>';
            }
            $output .= '</div>';
            $output .= '</div>';
            
            // View Journal button with arrow
            $output .= '<div class="sjm-journal-actions-list">';
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-view-button">';
            $output .= 'View Journal';
            $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            $output .= '</div>';
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
    } else {
        // Grid layout (default)
        $output .= '<div class="sjm-journals-grid">';
        
        foreach ($journals as $journal) {
            $journal_cover = get_post_meta($journal->ID, '_sjm_journal_cover', true);
            $issn = get_post_meta($journal->ID, '_sjm_issn', true);
            $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
            $impact_factor = get_post_meta($journal->ID, '_sjm_impact_factor', true);
            $open_access = get_post_meta($journal->ID, '_sjm_open_access', true);
            $peer_reviewed = get_post_meta($journal->ID, '_sjm_peer_reviewed', true);
            $permalink = get_permalink($journal->ID);
            
            $output .= '<div class="sjm-journal-card">';
            $output .= '<div class="sjm-journal-cover">';
            
            if ($journal_cover) {
                $output .= '<img src="' . esc_url($journal_cover) . '" alt="' . esc_attr($journal->post_title) . ' Cover">';
            } else {
                $output .= '<div class="sjm-journal-cover-placeholder"></div>';
            }
            
            $output .= '</div>';
            $output .= '<div class="sjm-journal-info">';
            $output .= '<h3 class="sjm-journal-title">' . esc_html($journal->post_title) . '</h3>';
            
            // Create badges for key information
            $output .= '<div class="sjm-journal-badges">';
            if ($issn) {
                $output .= '<span class="sjm-badge">ISSN ' . esc_html($issn) . '</span>';
            }
            if ($impact_factor) {
                $output .= '<span class="sjm-badge">IF ' . esc_html($impact_factor) . '</span>';
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge">Open Access</span>';
            } else {
                $output .= '<span class="sjm-badge" style="background:transparent;color:#b91c1c;border:1px solid #b91c1c;font-style:italic;">Not Open Access</span>';
                $output .= '<div style="color:#6b7280;font-size:13px;margin-top:4px;font-style:italic;max-width:400px;">This journal is not open access. Access to full articles may be restricted according to publisher policy.</div>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge">Peer Reviewed</span>';
            }
            if ($publisher) {
                $output .= '<span class="sjm-badge">' . esc_html($publisher) . '</span>';
            }
            $output .= '</div>';
            
            // View Journal button with arrow
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-view-button">';
            $output .= 'View Journal';
            $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            
            $output .= '</div>';
            $output .= '</div>';
        }
        
        $output .= '</div>';
    }
    
    $output .= '</div>';
    
    return $output;
}
// Use the new improved shortcode
add_shortcode('journals', 'sjm_journals_shortcode_new');

// Legacy function kept for compatibility (but not used)
function sjm_journals_shortcode_legacy($atts = array()) {
    $atts = shortcode_atts(array(
        'layout' => 'grid', // 'grid' or 'list'
        'journal_id' => '',
        'issue_id' => '',
        'paper_type' => '',
        'author' => '',
        'keyword' => '',
        'year' => '',
        'per_page' => 12
    ), $atts);
    
    // Build query args
    $args = array(
        'post_type' => 'paper',
        'posts_per_page' => intval($atts['per_page']),
        'meta_query' => array('relation' => 'AND')
    );
    
    // Add filters
    if (!empty($atts['journal_id'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_journal',
            'value' => $atts['journal_id'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['issue_id'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_issue',
            'value' => $atts['issue_id'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['paper_type'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_type',
            'value' => $atts['paper_type'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['author'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_authors',
            'value' => $atts['author'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['keyword'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_keywords',
            'value' => $atts['keyword'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['year'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_acceptance_date',
            'value' => $atts['year'],
            'compare' => 'LIKE'
        );
    }
    
    $papers = get_posts($args);
    
    // Get all journals and paper types for filters
    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    $paper_types = array('Research Article', 'Review Article', 'Case Study', 'Short Communication', 'Editorial', 'Letter', 'Manuscript');
    
    if (!$papers && empty($_GET['sjm_filter'])) {
        return '<div class="sjm-empty-state"><p>No papers found.</p></div>';
    }
    
    // Steve Jobs inspired minimal design for papers
    $output = '<style>
    /* Papers search filters */
    .sjm-papers-filters {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 32px;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
        align-items: end;
    }
    
    .sjm-filter-group {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    
    .sjm-filter-label {
        font-size: 13px;
        font-weight: 500;
        color: #374151;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    .sjm-filter-input,
    .sjm-filter-select {
        padding: 8px 12px;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        font-size: 14px;
        color: #374151;
        background: #ffffff;
        transition: border-color 0.2s ease;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    .sjm-filter-input:focus,
    .sjm-filter-select:focus {
        outline: none;
        border-color: #3b82f6;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    
    .sjm-filter-buttons {
        display: flex;
        gap: 8px;
        grid-column: 1 / -1;
        justify-content: flex-end;
        margin-top: 8px;
    }
    
    .sjm-filter-button {
        padding: 8px 16px;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        color: #374151;
        background: #ffffff;
        cursor: pointer;
        transition: all 0.15s ease;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    
    .sjm-filter-button:hover {
        background: #f3f4f6;
        border-color: #d1d5db;
        text-decoration: none;
    }
    
    .sjm-filter-button-primary {
        background: #3b82f6;
        border-color: #3b82f6;
        color: #ffffff;
    }
    
    .sjm-filter-button-primary:hover {
        background: #2563eb;
        border-color: #2563eb;
        color: #ffffff;
    }
    
    /* Papers grid/list - reuse journal styles */
    .sjm-papers-container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 0 20px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    .sjm-papers-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
        gap: 32px;
        margin: 32px 0;
    }
    
    .sjm-papers-list {
        display: flex;
        flex-direction: column;
        gap: 16px;
        margin: 32px 0;
    }
    
    .sjm-paper-card {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        overflow: hidden;
        transition: border-color 0.2s ease;
        text-decoration: none;
        display: block;
        position: relative;
    }
    
    .sjm-paper-card:hover {
        border-color: #d1d5db;
        text-decoration: none;
    }
    
    .sjm-paper-card-list {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        overflow: hidden;
        transition: border-color 0.2s ease;
        text-decoration: none;
        display: flex;
        align-items: flex-start;
        gap: 20px;
        padding: 20px;
    }
    
    .sjm-paper-card-list:hover {
        border-color: #d1d5db;
        text-decoration: none;
    }
    
    .sjm-paper-info {
        padding: 20px;
    }
    
    .sjm-paper-info-list {
        flex: 1;
        min-width: 0;
    }
    
    .sjm-paper-title {
        font-size: 16px;
        font-weight: 600;
        color: #111827;
        margin: 0 0 8px 0;
        line-height: 1.4;
        letter-spacing: -0.01em;
    }
    
    .sjm-paper-authors {
        font-size: 14px;
        color: #6b7280;
        margin: 0 0 12px 0;
        font-weight: 500;
    }
    
    .sjm-paper-abstract {
        font-size: 13px;
        color: #6b7280;
        margin: 0 0 12px 0;
        line-height: 1.5;
        display: -webkit-box;
        -webkit-line-clamp: 3;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }
    
    .sjm-paper-badges {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 16px;
    }
    
    .sjm-paper-badges-list {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin: 8px 0 12px 0;
    }
    
    .sjm-paper-actions-list {
        flex-shrink: 0;
        margin-left: auto;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
        .sjm-papers-container {
            padding: 0 16px;
        }
        
        .sjm-papers-filters {
            grid-template-columns: 1fr;
            padding: 16px;
            margin-bottom: 20px;
        }
        
        .sjm-papers-grid {
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .sjm-papers-list {
            gap: 12px;
            margin: 20px 0;
        }
        
        .sjm-paper-card-list {
            flex-direction: column;
            text-align: left;
            gap: 16px;
            padding: 16px;
        }
        
        .sjm-paper-actions-list {
            margin-left: 0;
        }
    }
    
    @media (max-width: 480px) {
        .sjm-papers-grid {
            grid-template-columns: 1fr;
            gap: 16px;
        }
        
        .sjm-filter-buttons {
            flex-direction: column;
        }
    }
    </style>';
    
    $output .= '<div class="sjm-papers-container">';
    
    // Search filters
    $output .= '<form method="get" class="sjm-papers-filters">';
    $output .= '<input type="hidden" name="sjm_filter" value="1">';
    
    // Journal filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Journal</label>';
    $output .= '<select name="journal_id" class="sjm-filter-select">';
    $output .= '<option value="">All Journals</option>';
    foreach ($journals as $journal) {
        $selected = (isset($_GET['journal_id']) && $_GET['journal_id'] == $journal->ID) ? 'selected' : '';
        $output .= '<option value="' . $journal->ID . '" ' . $selected . '>' . esc_html($journal->post_title) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Paper type filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Paper Type</label>';
    $output .= '<select name="paper_type" class="sjm-filter-select">';
    $output .= '<option value="">All Types</option>';
    foreach ($paper_types as $type) {
        $selected = (isset($_GET['paper_type']) && $_GET['paper_type'] == $type) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($type) . '" ' . $selected . '>' . esc_html($type) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Author filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Author</label>';
    $output .= '<input type="text" name="author" class="sjm-filter-input" placeholder="Search by author..." value="' . esc_attr(isset($_GET['author']) ? $_GET['author'] : '') . '">';
    $output .= '</div>';
    
    // Keyword filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Keywords</label>';
    $output .= '<input type="text" name="keyword" class="sjm-filter-input" placeholder="Search keywords..." value="' . esc_attr(isset($_GET['keyword']) ? $_GET['keyword'] : '') . '">';
    $output .= '</div>';
    
    // Year filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Year</label>';
    $output .= '<input type="number" name="year" class="sjm-filter-input" placeholder="2024" min="1900" max="2030" value="' . esc_attr(isset($_GET['year']) ? $_GET['year'] : '') . '">';
    $output .= '</div>';
    
    // Filter buttons
    $output .= '<div class="sjm-filter-buttons">';
    $output .= '<a href="' . get_permalink() . '" class="sjm-filter-button">Clear</a>';
    $output .= '<button type="submit" class="sjm-filter-button sjm-filter-button-primary">Search</button>';
    $output .= '</div>';
    
    $output .= '</form>';
    
    // Handle URL parameters for filtering
    if (isset($_GET['sjm_filter'])) {
        $filter_args = array(
            'post_type' => 'paper',
            'posts_per_page' => intval($atts['per_page']),
            'meta_query' => array('relation' => 'AND')
        );
        
        if (!empty($_GET['journal_id'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_journal',
                'value' => $_GET['journal_id'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['paper_type'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_type',
                'value' => $_GET['paper_type'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['author'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_authors',
                'value' => $_GET['author'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['keyword'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_keywords',
                'value' => $_GET['keyword'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['year'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_acceptance_date',
                'value' => $_GET['year'],
                'compare' => 'LIKE'
            );
        }
        
        $papers = get_posts($filter_args);
    }
    
    if (!$papers) {
        $output .= '<div class="sjm-empty-state"><p>No papers found matching your criteria.</p></div>';
        $output .= '</div>';
        return $output;
    }
    
    // Display papers
    if ($atts['layout'] === 'list') {
        $output .= '<div class="sjm-papers-list">';
        
        foreach ($papers as $paper) {
            $paper_journal_id = get_post_meta($paper->ID, '_sjm_paper_journal', true);
            $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
            $paper_authors = get_post_meta($paper->ID, '_sjm_paper_authors', true);
            $paper_authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
            if (!is_array($paper_authors_data)) $paper_authors_data = array();
            $paper_abstract = get_post_meta($paper->ID, '_sjm_paper_abstract', true);
            $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
            $paper_keywords = get_post_meta($paper->ID, '_sjm_paper_keywords', true);
            $paper_doi = get_post_meta($paper->ID, '_sjm_paper_doi', true);
            $open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
            $peer_reviewed = get_post_meta($paper->ID, '_sjm_paper_peer_reviewed', true);
            $acceptance_date = get_post_meta($paper->ID, '_sjm_acceptance_date', true);
            $permalink = get_permalink($paper->ID);
            
            $output .= '<div class="sjm-paper-card-list">';
            
            // Paper info
            $output .= '<div class="sjm-paper-info-list">';
            $output .= '<h3 class="sjm-paper-title">' . esc_html($paper->post_title) . '</h3>';
            
            // Display enhanced author information with links
            if (!empty($paper_authors_data)) {
                // Sort authors by order
                usort($paper_authors_data, function($a, $b) {
                    return intval($a['order']) - intval($b['order']);
                });
                
                $author_displays = array();
                foreach ($paper_authors_data as $author_data) {
                    $author = sjm_get_author_by_id($author_data['author_id']);
                    if ($author) {
                        $author_displays[] = sjm_format_author_display($author, $author_data, true, false);
                    }
                }
                if (!empty($author_displays)) {
                    $output .= '<p class="sjm-paper-authors">' . implode(', ', $author_displays) . '</p>';
                }
            } elseif ($paper_authors) {
                $output .= '<p class="sjm-paper-authors">' . esc_html($paper_authors) . '</p>';
            }
            
            if ($paper_abstract) {
                $output .= '<p class="sjm-paper-abstract">' . esc_html($paper_abstract) . '</p>';
            }
            
            // Create badges for key information
            $output .= '<div class="sjm-paper-badges-list">';
            if ($paper_type) {
                $output .= '<span class="sjm-badge">' . esc_html($paper_type) . '</span>';
            }
            if ($paper_journal) {
                $output .= '<span class="sjm-badge">' . esc_html($paper_journal->post_title) . '</span>';
            }
            if ($acceptance_date) {
                $year = date('Y', strtotime($acceptance_date));
                $output .= '<span class="sjm-badge">' . esc_html($year) . '</span>';
            }
            if ($paper_doi) {
                $output .= '<span class="sjm-badge">DOI</span>';
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge">Open Access</span>';
            } else {
                $output .= '<span class="sjm-badge" style="background:transparent;color:#b91c1c;border:1px solid #b91c1c;font-style:italic;">Not Open Access</span>';
                $output .= '<div style="color:#6b7280;font-size:13px;margin-top:4px;font-style:italic;max-width:400px;">This journal is not open access. Access to full articles may be restricted according to publisher policy.</div>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge">Peer Reviewed</span>';
            }
            $output .= '</div>';
            $output .= '</div>';
            
            // View Paper button with arrow
            $output .= '<div class="sjm-paper-actions-list">';
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-view-button">';
            $output .= 'View Paper';
            $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            $output .= '</div>';
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
    } else {
        // Grid layout (default)
        $output .= '<div class="sjm-papers-grid">';
        
        foreach ($papers as $paper) {
            $paper_journal_id = get_post_meta($paper->ID, '_sjm_paper_journal', true);
            $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
            $paper_authors = get_post_meta($paper->ID, '_sjm_paper_authors', true);
            $paper_authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
            if (!is_array($paper_authors_data)) $paper_authors_data = array();
            $paper_abstract = get_post_meta($paper->ID, '_sjm_paper_abstract', true);
            $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
            $paper_keywords = get_post_meta($paper->ID, '_sjm_paper_keywords', true);
            $paper_doi = get_post_meta($paper->ID, '_sjm_paper_doi', true);
            $open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
            $peer_reviewed = get_post_meta($paper->ID, '_sjm_paper_peer_reviewed', true);
            $acceptance_date = get_post_meta($paper->ID, '_sjm_acceptance_date', true);
            $permalink = get_permalink($paper->ID);
            
            $output .= '<div class="sjm-paper-card">';
            $output .= '<div class="sjm-paper-info">';
            $output .= '<h3 class="sjm-paper-title">' . esc_html($paper->post_title) . '</h3>';
            
            // Display enhanced author information with links
            if (!empty($paper_authors_data)) {
                // Sort authors by order
                usort($paper_authors_data, function($a, $b) {
                    return intval($a['order']) - intval($b['order']);
                });
                
                $author_displays = array();
                foreach ($paper_authors_data as $author_data) {
                    $author = sjm_get_author_by_id($author_data['author_id']);
                    if ($author) {
                        $author_displays[] = sjm_format_author_display($author, $author_data, true, false);
                    }
                }
                if (!empty($author_displays)) {
                    $output .= '<p class="sjm-paper-authors">' . implode(', ', $author_displays) . '</p>';
                }
            } elseif ($paper_authors) {
                $output .= '<p class="sjm-paper-authors">' . esc_html($paper_authors) . '</p>';
            }
            
            if ($paper_abstract) {
                $output .= '<p class="sjm-paper-abstract">' . esc_html($paper_abstract) . '</p>';
            }
            
            // Create badges for key information
            $output .= '<div class="sjm-paper-badges">';
            if ($paper_type) {
                $output .= '<span class="sjm-badge">' . esc_html($paper_type) . '</span>';
            }
            if ($paper_journal) {
                $output .= '<span class="sjm-badge">' . esc_html($paper_journal->post_title) . '</span>';
            }
            if ($acceptance_date) {
                $year = date('Y', strtotime($acceptance_date));
                $output .= '<span class="sjm-badge">' . esc_html($year) . '</span>';
            }
            if ($paper_doi) {
                $output .= '<span class="sjm-badge">DOI</span>';
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge">Open Access</span>';
            } else {
                $output .= '<span class="sjm-badge" style="background:transparent;color:#b91c1c;border:1px solid #b91c1c;font-style:italic;">Not Open Access</span>';
                $output .= '<div style="color:#6b7280;font-size:13px;margin-top:4px;font-style:italic;max-width:400px;">This journal is not open access. Access to full articles may be restricted according to publisher policy.</div>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge">Peer Reviewed</span>';
            }
            $output .= '</div>';
            
            // View Paper button with arrow
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-view-button">';
            $output .= 'View Paper';
            $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            
            $output .= '</div>';
            $output .= '</div>';
        }
        
        $output .= '</div>';
    }
    
    $output .= '</div>';
    
    return $output;
}
add_shortcode('papers', 'sjm_papers_shortcode_new');

// Shortcode to List Issues with Filters
function sjm_issues_shortcode($atts = array()) {
    $atts = shortcode_atts(array(
        'layout' => 'grid', // 'grid' or 'list'
        'journal_id' => '',
        'volume' => '',
        'year' => '',
        'special_issue' => '',
        'per_page' => 12
    ), $atts);
    
    // Build query args
    $args = array(
        'post_type' => 'journal_issue',
        'posts_per_page' => intval($atts['per_page']),
        'meta_query' => array('relation' => 'AND'),
        'orderby' => 'meta_value_num',
        'meta_key' => '_sjm_issue_year',
        'order' => 'DESC'
    );
    
    // Add filters
    if (!empty($atts['journal_id'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_issue_journal',
            'value' => $atts['journal_id'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['volume'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_issue_volume',
            'value' => $atts['volume'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['year'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_issue_year',
            'value' => $atts['year'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['special_issue'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_special_issue',
            'value' => '1',
            'compare' => '='
        );
    }
    
    $issues = get_posts($args);
    
    // Get all journals for filters
    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    
    // Get unique years and volumes
    $all_issues = get_posts(array('post_type' => 'journal_issue', 'posts_per_page' => -1));
    $years = array();
    $volumes = array();
    
    foreach ($all_issues as $issue) {
        $year = get_post_meta($issue->ID, '_sjm_issue_year', true);
        $volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
        
        if ($year && !in_array($year, $years)) {
            $years[] = $year;
        }
        if ($volume && !in_array($volume, $volumes)) {
            $volumes[] = $volume;
        }
    }
    
    rsort($years);
    sort($volumes);
    
    if (!$issues && empty($_GET['sjm_issue_filter'])) {
        return '<div class="sjm-empty-state"><p>No issues found.</p></div>';
    }
    
    // Use same CSS as papers (already defined)
    $output = '<div class="sjm-papers-container">';
    
    // Search filters for issues
    $output .= '<form method="get" class="sjm-papers-filters">';
    $output .= '<input type="hidden" name="sjm_issue_filter" value="1">';
    
    // Journal filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Journal</label>';
    $output .= '<select name="journal_id" class="sjm-filter-select">';
    $output .= '<option value="">All Journals</option>';
    foreach ($journals as $journal) {
        $selected = (isset($_GET['journal_id']) && $_GET['journal_id'] == $journal->ID) ? 'selected' : '';
        $output .= '<option value="' . $journal->ID . '" ' . $selected . '>' . esc_html($journal->post_title) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Volume filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Volume</label>';
    $output .= '<select name="volume" class="sjm-filter-select">';
    $output .= '<option value="">All Volumes</option>';
    foreach ($volumes as $volume) {
        $selected = (isset($_GET['volume']) && $_GET['volume'] == $volume) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($volume) . '" ' . $selected . '>Volume ' . esc_html($volume) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Year filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Year</label>';
    $output .= '<select name="year" class="sjm-filter-select">';
    $output .= '<option value="">All Years</option>';
    foreach ($years as $year) {
        $selected = (isset($_GET['year']) && $_GET['year'] == $year) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($year) . '" ' . $selected . '>' . esc_html($year) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Special Issue filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Issue Type</label>';
    $output .= '<select name="special_issue" class="sjm-filter-select">';
    $output .= '<option value="">All Issues</option>';
    $selected = (isset($_GET['special_issue']) && $_GET['special_issue'] == '1') ? 'selected' : '';
    $output .= '<option value="1" ' . $selected . '>Special Issues Only</option>';
    $output .= '</select>';
    $output .= '</div>';
    
    // Filter buttons
    $output .= '<div class="sjm-filter-buttons">';
    $output .= '<a href="' . get_permalink() . '" class="sjm-filter-button">Clear</a>';
    $output .= '<button type="submit" class="sjm-filter-button sjm-filter-button-primary">Search</button>';
    $output .= '</div>';
    
    $output .= '</form>';
    
    // Handle URL parameters for filtering
    if (isset($_GET['sjm_issue_filter'])) {
        $filter_args = array(
            'post_type' => 'journal_issue',
            'posts_per_page' => intval($atts['per_page']),
            'meta_query' => array('relation' => 'AND'),
            'orderby' => 'meta_value_num',
            'meta_key' => '_sjm_issue_year',
            'order' => 'DESC'
        );
        
        if (!empty($_GET['journal_id'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_issue_journal',
                'value' => $_GET['journal_id'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['volume'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_issue_volume',
                'value' => $_GET['volume'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['year'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_issue_year',
                'value' => $_GET['year'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['special_issue'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_special_issue',
                'value' => '1',
                'compare' => '='
            );
        }
        
        $issues = get_posts($filter_args);
    }
    
    if (!$issues) {
        $output .= '<div class="sjm-empty-state"><p>No issues found matching your criteria.</p></div>';
        $output .= '</div>';
        return $output;
    }
    
    // Display issues
    if ($atts['layout'] === 'list') {
        $output .= '<div class="sjm-papers-list">';
        
        foreach ($issues as $issue) {
            $issue_journal_id = get_post_meta($issue->ID, '_sjm_issue_journal', true);
            $issue_journal = $issue_journal_id ? get_post($issue_journal_id) : null;
            $issue_number = get_post_meta($issue->ID, '_sjm_issue_number', true);
            $issue_volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
            $issue_year = get_post_meta($issue->ID, '_sjm_issue_year', true);
            $publication_date = get_post_meta($issue->ID, '_sjm_publication_date', true);
            $special_issue = get_post_meta($issue->ID, '_sjm_special_issue', true);
            $special_issue_title = get_post_meta($issue->ID, '_sjm_special_issue_title', true);
            $total_papers = get_post_meta($issue->ID, '_sjm_total_papers', true);
            $cover_image = get_post_meta($issue->ID, '_sjm_cover_image', true);
            $permalink = get_permalink($issue->ID);
            
            $output .= '<div class="sjm-paper-card-list">';
            
            // Issue cover (if available)
            if ($cover_image) {
                $output .= '<div class="sjm-journal-cover-list">';
                $output .= '<img src="' . esc_url($cover_image) . '" alt="' . esc_attr($issue->post_title) . ' Cover">';
                $output .= '</div>';
            }
            
            // Issue info
            $output .= '<div class="sjm-paper-info-list">';
            $output .= '<h3 class="sjm-paper-title">' . esc_html($issue->post_title) . '</h3>';
            
            if ($issue_journal) {
                $output .= '<p class="sjm-paper-authors">' . esc_html($issue_journal->post_title) . '</p>';
            }
            
            // Create badges for key information
            $output .= '<div class="sjm-paper-badges-list">';
            if ($issue_volume && $issue_number) {
                $output .= '<span class="sjm-badge">Vol. ' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</span>';
            }
            if ($issue_year) {
                $output .= '<span class="sjm-badge">' . esc_html($issue_year) . '</span>';
            }
            if ($special_issue) {
                $output .= '<span class="sjm-badge">Special Issue</span>';
            }
            if ($total_papers) {
                $output .= '<span class="sjm-badge">' . esc_html($total_papers) . ' Papers</span>';
            }
            if ($publication_date) {
                $formatted_date = date('M Y', strtotime($publication_date));
                $output .= '<span class="sjm-badge">' . esc_html($formatted_date) . '</span>';
            }
            $output .= '</div>';
            $output .= '</div>';
            
            // View Issue button with arrow
            $output .= '<div class="sjm-paper-actions-list">';
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-view-button">';
            $output .= 'View Issue';
            $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            $output .= '</div>';
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
    } else {
        // Grid layout (default)
        $output .= '<div class="sjm-papers-grid">';
        
        foreach ($issues as $issue) {
            $issue_journal_id = get_post_meta($issue->ID, '_sjm_issue_journal', true);
            $issue_journal = $issue_journal_id ? get_post($issue_journal_id) : null;
            $issue_number = get_post_meta($issue->ID, '_sjm_issue_number', true);
            $issue_volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
            $issue_year = get_post_meta($issue->ID, '_sjm_issue_year', true);
            $publication_date = get_post_meta($issue->ID, '_sjm_publication_date', true);
            $special_issue = get_post_meta($issue->ID, '_sjm_special_issue', true);
            $special_issue_title = get_post_meta($issue->ID, '_sjm_special_issue_title', true);
            $total_papers = get_post_meta($issue->ID, '_sjm_total_papers', true);
            $cover_image = get_post_meta($issue->ID, '_sjm_cover_image', true);
            $permalink = get_permalink($issue->ID);
            
            $output .= '<div class="sjm-paper-card">';
            
            // Issue cover
            if ($cover_image) {
                $output .= '<div class="sjm-journal-cover">';
                $output .= '<img src="' . esc_url($cover_image) . '" alt="' . esc_attr($issue->post_title) . ' Cover">';
                $output .= '</div>';
            }
            
            $output .= '<div class="sjm-paper-info">';
            $output .= '<h3 class="sjm-paper-title">' . esc_html($issue->post_title) . '</h3>';
            
            if ($issue_journal) {
                $output .= '<p class="sjm-paper-authors">' . esc_html($issue_journal->post_title) . '</p>';
            }
            
            // Create badges for key information
            $output .= '<div class="sjm-paper-badges">';
            if ($issue_volume && $issue_number) {
                $output .= '<span class="sjm-badge">Vol. ' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</span>';
            }
            if ($issue_year) {
                $output .= '<span class="sjm-badge">' . esc_html($issue_year) . '</span>';
            }
            if ($special_issue) {
                $output .= '<span class="sjm-badge">Special Issue</span>';
            }
            if ($total_papers) {
                $output .= '<span class="sjm-badge">' . esc_html($total_papers) . ' Papers</span>';
            }
            if ($publication_date) {
                $formatted_date = date('M Y', strtotime($publication_date));
                $output .= '<span class="sjm-badge">' . esc_html($formatted_date) . '</span>';
            }
            $output .= '</div>';
            
            // View Issue button with arrow
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-view-button">';
            $output .= 'View Issue';
            $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            
            $output .= '</div>';
            $output .= '</div>';
        }
        
        $output .= '</div>';
    }
    
    $output .= '</div>';
    
    return $output;
}
add_shortcode('issues', 'sjm_issues_shortcode_new');

// Single Journal Page Template
function sjm_single_journal_template($content) {
    global $post;
    if (is_singular('journal')) {
        // Clear the default content to replace it completely
        $content = '';
        $journal_id = $post->ID;
        
        // Get all journal meta
        $issn = get_post_meta($journal_id, '_sjm_issn', true);
        $publisher = get_post_meta($journal_id, '_sjm_publisher', true);
        $editor_in_chief_id = get_post_meta($journal_id, '_sjm_editor_in_chief_id', true);
        $editor_in_chief = sjm_get_user_display_info($editor_in_chief_id);
        $managing_editor_id = get_post_meta($journal_id, '_sjm_managing_editor_id', true);
        $managing_editor = sjm_get_user_display_info($managing_editor_id);
        $founding_year = get_post_meta($journal_id, '_sjm_founding_year', true);
        $doi_prefix = get_post_meta($journal_id, '_sjm_doi_prefix', true);
        $frequency = get_post_meta($journal_id, '_sjm_frequency', true);
        $language = get_post_meta($journal_id, '_sjm_language', true);
        $subject_areas = get_post_meta($journal_id, '_sjm_subject_areas', true);
        $impact_factor = get_post_meta($journal_id, '_sjm_impact_factor', true);
        $website = get_post_meta($journal_id, '_sjm_website', true);
        $email = get_post_meta($journal_id, '_sjm_email', true);
        $peer_reviewed = get_post_meta($journal_id, '_sjm_peer_reviewed', true);
        $open_access = get_post_meta($journal_id, '_sjm_open_access', true);
        $indexed_in = get_post_meta($journal_id, '_sjm_indexed_in', true);
        $journal_logo = get_post_meta($journal_id, '_sjm_journal_logo', true);
        $journal_cover = get_post_meta($journal_id, '_sjm_journal_cover', true);
        
        // Get journal authors
        $journal_authors_data = get_post_meta($journal_id, '_sjm_journal_authors_data', true);
        if (!is_array($journal_authors_data)) $journal_authors_data = array();
        
        // Get related issues
        $issues = get_posts(array(
            'post_type' => 'journal_issue',
            'posts_per_page' => -1,
            'meta_query' => array(
                array(
                    'key' => '_sjm_issue_journal',
                    'value' => $journal_id,
                    'compare' => '='
                )
            ),
            'orderby' => 'meta_value_num',
            'meta_key' => '_sjm_issue_year',
            'order' => 'DESC'
        ));
        
        $output = '<style>
        /* World-Class Design System - Perfect Single Views */
        :root {
            /* Typography Scale (1.25 ratio) */
            --font-size-xs: 0.75rem;    /* 12px */
            --font-size-sm: 0.875rem;   /* 14px */
            --font-size-base: 1rem;     /* 16px */
            --font-size-lg: 1.125rem;   /* 18px */
            --font-size-xl: 1.25rem;    /* 20px */
            --font-size-2xl: 1.5rem;    /* 24px */
            --font-size-3xl: 1.875rem;  /* 30px */
            --font-size-4xl: 2.25rem;   /* 36px */
            
            /* Spacing Scale (8px base) */
            --space-1: 0.25rem;   /* 4px */
            --space-2: 0.5rem;    /* 8px */
            --space-3: 0.75rem;   /* 12px */
            --space-4: 1rem;      /* 16px */
            --space-5: 1.25rem;   /* 20px */
            --space-6: 1.5rem;    /* 24px */
            --space-8: 2rem;      /* 32px */
            --space-10: 2.5rem;   /* 40px */
            --space-12: 3rem;     /* 48px */
            --space-16: 4rem;     /* 64px */
            
            /* Color System */
            --color-primary: #2563eb;
            --color-primary-hover: #1d4ed8;
            --color-secondary: #64748b;
            --color-success: #059669;
            --color-warning: #d97706;
            --color-error: #dc2626;
            
            --color-gray-50: #f8fafc;
            --color-gray-100: #f1f5f9;
            --color-gray-200: #e2e8f0;
            --color-gray-300: #cbd5e1;
            --color-gray-400: #94a3b8;
            --color-gray-500: #64748b;
            --color-gray-600: #475569;
            --color-gray-700: #334155;
            --color-gray-800: #1e293b;
            --color-gray-900: #0f172a;
            
            /* Shadows */
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            
            /* Border Radius */
            --radius-sm: 0.25rem;   /* 4px */
            --radius-md: 0.375rem;  /* 6px */
            --radius-lg: 0.5rem;    /* 8px */
            --radius-xl: 0.75rem;   /* 12px */
            --radius-2xl: 1rem;     /* 16px */
        }
        
        /* Base Container */
        .sjm-single-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2.5rem 1.25rem;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background: #ffffff;
        }
        
        /* Header Section */
        .sjm-single-header {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 2.5rem;
            margin-bottom: 2.5rem;
            padding: 2rem;
            background: #ffffff;
            border-radius: 1rem;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            border: 1px solid #e2e8f0;
        }
        
        .sjm-single-cover {
            width: 200px;
            height: 260px;
            background: #f8fafc;
            border-radius: 0.75rem;
            border: 1px solid #e2e8f0;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            transition: all 0.2s ease;
            position: relative;
        }
        
        .sjm-single-cover:hover {
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            transform: translateY(-2px);
        }
        
        .sjm-single-cover img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            border-radius: 0.75rem;
        }
        
        .sjm-single-info h1 {
            font-size: 2.25rem;
            font-weight: 700;
            color: #0f172a;
            margin: 0 0 1rem 0;
            line-height: 1.2;
            letter-spacing: -0.025em;
        }
        
        .sjm-single-info h2 {
            font-size: 1.5rem;
            font-weight: 600;
            color: #1e293b;
            margin: 0 0 1rem 0;
            line-height: 1.3;
        }
        
        .sjm-single-info h3 {
            font-size: 1.25rem;
            font-weight: 600;
            color: #334155;
            margin: 0 0 0.75rem 0;
            line-height: 1.4;
        }
        
        /* Meta Grid System */
        .sjm-single-meta, .sjm-meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        
        .sjm-meta-group, .sjm-meta-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 1rem;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            transition: all 0.2s ease;
            position: relative;
        }
        
        .sjm-meta-group:hover, .sjm-meta-card:hover {
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            border-color: #cbd5e1;
            transform: translateY(-1px);
        }
        
        .sjm-meta-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 1.25rem;
            letter-spacing: -0.01em;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        .sjm-meta-title::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 2rem;
            height: 2px;
            background: #2563eb;
            border-radius: 1px;
        }
        
        .sjm-meta-item {
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            align-items: flex-start;
            padding: 0.75rem 0;
            font-size: 1rem;
            border-bottom: 1px solid #f1f5f9;
        }
        
        .sjm-meta-item:last-child { 
            border-bottom: none; 
        }
        
        .sjm-meta-label { 
            color: #64748b; 
            font-weight: 500; 
            margin-bottom: 0.25rem; 
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .sjm-meta-value { 
            color: #0f172a; 
            font-weight: 500; 
            margin-bottom: 0.25rem; 
        }
        
        .sjm-meta-value a { 
            color: #2563eb; 
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .sjm-meta-value a:hover { 
            color: #1d4ed8;
            text-decoration: underline; 
        }
        
        /* Section Titles */
        .sjm-section-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #0f172a;
            margin: 2.5rem 0 1.5rem 0;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        .sjm-section-title::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 3rem;
            height: 2px;
            background: #2563eb;
            border-radius: 1px;
        }
        
        /* Download Button */
        .sjm-download-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            background: #2563eb;
            color: #ffffff;
            text-decoration: none;
            border-radius: 0.5rem;
            font-weight: 500;
            font-size: 0.875rem;
            transition: all 0.2s ease;
            border: none;
            cursor: pointer;
        }
        
        .sjm-download-btn:hover {
            background: #1d4ed8;
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            text-decoration: none;
            color: #ffffff;
        }
        
        .sjm-download-btn:focus {
            outline: 2px solid #2563eb;
            outline-offset: 2px;
        }
        
        .sjm-download-btn svg {
            width: 16px;
            height: 16px;
        }
        
        /* Badges */
        .sjm-journal-badges {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1.25rem;
        }
        
        .sjm-badge {
            display: inline-flex;
            align-items: center;
            background: #f1f5f9;
            color: #334155;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 0.375rem;
            padding: 0.25rem 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border: 1px solid #e2e8f0;
            transition: all 0.2s ease;
        }
        
        .sjm-badge:hover {
            background: #e2e8f0;
            border-color: #cbd5e1;
        }
        
        .sjm-badge a {
            color: inherit;
            text-decoration: none;
        }
        
        .sjm-badge a:hover {
            text-decoration: underline;
        }
    </style>';
    
    $output .= '<div class="sjm-single-container">';
        $output .= '<div class="sjm-single-sections" style="display: flex; gap: 40px; align-items: flex-start;">';
        $output .= '<div class="sjm-single-main" style="flex: 1 1 0; min-width: 0;">';
        
        // Header section
        $output .= '<div class="sjm-single-header" style="grid-template-columns: 1fr;">';
    $output .= '<div class="sjm-single-info">';
    $output .= '<h1>' . esc_html($post->post_title) . '</h1>';
    
    // Quick badges
    $output .= '<div class="sjm-journal-badges" style="margin-bottom: 20px;">';
    if ($issn) $output .= '<span class="sjm-badge">ISSN ' . esc_html($issn) . '</span>';
    if ($impact_factor) $output .= '<span class="sjm-badge">IF ' . esc_html($impact_factor) . '</span>';
    if ($open_access) {
        $output .= '<span class="sjm-badge">Supports Open Access</span>';
    } else {
        $output .= '<span class="sjm-badge" style="background:transparent;color:#b91c1c;border:1px solid #b91c1c;font-style:italic;">Traditional Subscription</span>';
        $output .= '<div style="color:#6b7280;font-size:13px;margin-top:4px;font-style:italic;max-width:400px;">This journal follows a traditional subscription model. Individual articles may still be accessible through author self-archiving or institutional access.</div>';
    }
    if ($peer_reviewed) $output .= '<span class="sjm-badge">Peer Reviewed</span>';
    $output .= '</div>';
    
    // Download options
    if ($website) {
        $output .= '<a href="' . esc_url($website) . '" target="_blank" class="sjm-download-btn" style="margin-right: 12px;">';
        $output .= '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
        $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>';
        $output .= '</svg>';
        $output .= 'Visit Website';
        $output .= '</a>';
    }
    
    $output .= '</div>';
    $output .= '</div>';
    
        // Journal details
    $output .= '<div class="sjm-single-meta">';
    
    // Basic Information
        $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Basic Information</h2>';
        $output .= '<div class="sjm-meta-grid">';
    if ($publisher) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Publisher</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($publisher) . '</span>';
        $output .= '</div>';
    }
    if ($editor_in_chief) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Editor-in-Chief</span>';
        $output .= '<span class="sjm-meta-value"><a href="' . esc_url($editor_in_chief['url']) . '">' . esc_html($editor_in_chief['name']) . '</a></span>';
        $output .= '</div>';
    }
    if ($managing_editor) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Managing Editor</span>';
        $output .= '<span class="sjm-meta-value"><a href="' . esc_url($managing_editor['url']) . '">' . esc_html($managing_editor['name']) . '</a></span>';
        $output .= '</div>';
    }
    if ($founding_year) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Founded</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($founding_year) . '</span>';
        $output .= '</div>';
    }
    if ($frequency) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Frequency</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($frequency) . '</span>';
        $output .= '</div>';
    }
    if ($language) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Language</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($language) . '</span>';
        $output .= '</div>';
    }
        $output .= '</div>';
    $output .= '</div>';
    
    // Academic Information
        $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Academic Information</h2>';
        $output .= '<div class="sjm-meta-grid">';
    if ($subject_areas) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Subject Areas</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($subject_areas) . '</span>';
        $output .= '</div>';
    }
    if ($impact_factor) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Impact Factor</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($impact_factor) . '</span>';
        $output .= '</div>';
    }
    if ($indexed_in) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">Indexed In</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($indexed_in) . '</span>';
        $output .= '</div>';
    }
    if ($doi_prefix) {
        $output .= '<div class="sjm-meta-item">';
        $output .= '<span class="sjm-meta-label">DOI Prefix</span>';
        $output .= '<span class="sjm-meta-value">' . esc_html($doi_prefix) . '</span>';
        $output .= '</div>';
    }
        $output .= '</div>';
    $output .= '</div>';
    
    // Contact Information
    if ($email || $website) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Contact Information</h2>';
            $output .= '<div class="sjm-meta-grid">';
        if ($email) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Email</span>';
            $output .= '<span class="sjm-meta-value"><a href="mailto:' . esc_attr($email) . '" style="color: #2563eb; text-decoration: none;">' . esc_html($email) . '</a></span>';
            $output .= '</div>';
        }
        if ($website) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Website</span>';
            $output .= '<span class="sjm-meta-value"><a href="' . esc_url($website) . '" target="_blank" style="color: #2563eb; text-decoration: none;">' . esc_html($website) . '</a></span>';
            $output .= '</div>';
        }
        $output .= '</div>';
            $output .= '</div>';
    }
    
    $output .= '</div>';
    
    // Display journal authors/contributors
    if (!empty($journal_authors_data)) {
            $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Authors & Contributors (' . count($journal_authors_data) . ')</h2>';
            $output .= '<div class="sjm-meta-grid">';
        
        foreach ($journal_authors_data as $journal_author) {
            $author = sjm_get_author_by_id($journal_author['author_id']);
            if ($author) {
                $profile_url = sjm_get_author_profile_url($author->id);
                    $output .= '<div class="sjm-author-card">';
                    $output .= '<div class="sjm-author-name">';
                $output .= '<a href="' . esc_url($profile_url) . '" style="color: #1e40af; text-decoration: none;">' . esc_html($author->first_name . ' ' . $author->last_name) . '</a>';
                if ($author->orcid) {
                    $output .= ' <a href="https://orcid.org/' . esc_attr($author->orcid) . '" target="_blank" style="color: #16a085; text-decoration: none; font-size: 14px;">(ORCID)</a>';
                }
                    $output .= '</div>';
                
                    $output .= '<div class="sjm-author-info">';
                if ($journal_author['role']) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Role:</strong> ' . esc_html($journal_author['role']);
                        $output .= '</div>';
                }
                
                if ($author->affiliation) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Affiliation:</strong> ' . esc_html($author->affiliation);
                        $output .= '</div>';
                }
                
                if ($author->email) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Email:</strong> <a href="mailto:' . esc_attr($author->email) . '" style="color: #2563eb; text-decoration: none;">' . esc_html($author->email) . '</a>';
                        $output .= '</div>';
                    }
                    
                if ($journal_author['period']) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Period:</strong> ' . esc_html($journal_author['period']);
            $output .= '</div>';
                    }
                
                if ($journal_author['contributions']) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Contributions:</strong> ' . esc_html($journal_author['contributions']);
                        $output .= '</div>';
                }
                
                if ($journal_author['versions']) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Versions:</strong> ' . esc_html($journal_author['versions']);
                        $output .= '</div>';
                }
        $output .= '</div>';
                
        $output .= '</div>';
            }
        }
        
            $output .= '</div>';
            $output .= '</div>';
        }
        
        // Related Issues
        if ($issues) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Recent Issues (' . count($issues) . ')</h2>';
            $output .= '<div class="sjm-meta-grid">';
            
            foreach (array_slice($issues, 0, 6) as $issue) {
                $issue_number = get_post_meta($issue->ID, '_sjm_issue_number', true);
                $issue_volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
                $issue_year = get_post_meta($issue->ID, '_sjm_issue_year', true);
                $publication_date = get_post_meta($issue->ID, '_sjm_publication_date', true);
                $total_papers = get_post_meta($issue->ID, '_sjm_total_papers', true);
                
                $output .= '<div class="sjm-meta-card">';
                $output .= '<h4 style="margin: 0 0 12px 0; font-size: 16px; font-weight: 600;">' . esc_html($issue->post_title) . '</h4>';
                $output .= '<div class="sjm-journal-badges">';
                if ($issue_volume && $issue_number) {
                    $output .= '<span class="sjm-badge">Vol. ' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</span>';
                }
                if ($issue_year) {
                    $output .= '<span class="sjm-badge">' . esc_html($issue_year) . '</span>';
                }
                if ($total_papers) {
                    $output .= '<span class="sjm-badge">' . esc_html($total_papers) . ' Papers</span>';
                }
                $output .= '</div>';
                $output .= '<a href="' . get_permalink($issue->ID) . '" class="sjm-view-button" style="margin-top: 12px;">';
                $output .= 'View Issue';
                $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 14px; height: 14px; margin-left: 4px; vertical-align: middle;">';
                $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
                $output .= '</svg>';
                $output .= '</a>';
                $output .= '</div>';
            }
            
            $output .= '</div>';
            $output .= '</div>';
        }
        
        $output .= '</div>'; // Close sjm-single-main
        $output .= '</div>'; // Close sjm-single-sections
        
        $output .= '</div>'; // Close sjm-single-container
        
        return $output;
    }
    return $content;
}
add_filter('the_content', 'sjm_single_journal_template');

// Single Issue Page Template
function sjm_single_issue_template($content) {
    global $post;
    if (is_singular('journal_issue')) {
        $content = '';
        $issue_id = $post->ID;
        // Get all issue meta
        $issue_journal_id = get_post_meta($issue_id, '_sjm_issue_journal', true);
        $issue_journal = $issue_journal_id ? get_post($issue_journal_id) : null;
        $issue_number = get_post_meta($issue_id, '_sjm_issue_number', true);
        $issue_volume = get_post_meta($issue_id, '_sjm_issue_volume', true);
        $issue_year = get_post_meta($issue_id, '_sjm_issue_year', true);
        $publication_date = get_post_meta($issue_id, '_sjm_publication_date', true);
        $issue_doi = get_post_meta($issue_id, '_sjm_issue_doi', true);
        $issue_page_range = get_post_meta($issue_id, '_sjm_issue_page_range', true);
        $special_issue = get_post_meta($issue_id, '_sjm_special_issue', true);
        $special_issue_title = get_post_meta($issue_id, '_sjm_special_issue_title', true);
        $guest_editors = get_post_meta($issue_id, '_sjm_guest_editors', true);
        if (!is_array($guest_editors)) $guest_editors = array();
        $issue_editors = get_post_meta($issue_id, '_sjm_issue_editors', true);
        if (!is_array($issue_editors)) $issue_editors = array();
        $copyeditors = get_post_meta($issue_id, '_sjm_copyeditors', true);
        if (!is_array($copyeditors)) $copyeditors = array();
        $layout_editors = get_post_meta($issue_id, '_sjm_layout_editors', true);
        if (!is_array($layout_editors)) $layout_editors = array();
        $issue_reviewers = get_post_meta($issue_id, '_sjm_issue_reviewers', true);
        if (!is_array($issue_reviewers)) $issue_reviewers = array();
        $issue_keywords = get_post_meta($issue_id, '_sjm_issue_keywords', true);
        $issue_abstract = get_post_meta($issue_id, '_sjm_issue_abstract', true);
        $total_papers = get_post_meta($issue_id, '_sjm_total_papers', true);
        $cover_image = get_post_meta($issue_id, '_sjm_cover_image', true);
        $pdf_url = get_post_meta($issue_id, '_sjm_pdf_url', true);
        // Get papers in this issue
        $papers = get_posts(array(
            'post_type' => 'paper',
            'posts_per_page' => -1,
            'meta_query' => array(
                array(
                    'key' => '_sjm_paper_issue',
                    'value' => $issue_id,
                    'compare' => '='
                )
            ),
            'orderby' => 'date',
            'order' => 'ASC'
        ));
        $output = '<style>
        /* World-Class Design System - Perfect Single Views */
        :root {
            /* Typography Scale (1.25 ratio) */
            --font-size-xs: 0.75rem;    /* 12px */
            --font-size-sm: 0.875rem;   /* 14px */
            --font-size-base: 1rem;     /* 16px */
            --font-size-lg: 1.125rem;   /* 18px */
            --font-size-xl: 1.25rem;    /* 20px */
            --font-size-2xl: 1.5rem;    /* 24px */
            --font-size-3xl: 1.875rem;  /* 30px */
            --font-size-4xl: 2.25rem;   /* 36px */
            
            /* Spacing Scale (8px base) */
            --space-1: 0.25rem;   /* 4px */
            --space-2: 0.5rem;    /* 8px */
            --space-3: 0.75rem;   /* 12px */
            --space-4: 1rem;      /* 16px */
            --space-5: 1.25rem;   /* 20px */
            --space-6: 1.5rem;    /* 24px */
            --space-8: 2rem;      /* 32px */
            --space-10: 2.5rem;   /* 40px */
            --space-12: 3rem;     /* 48px */
            --space-16: 4rem;     /* 64px */
            
            /* Color System */
            --color-primary: #2563eb;
            --color-primary-hover: #1d4ed8;
            --color-secondary: #64748b;
            --color-success: #059669;
            --color-warning: #d97706;
            --color-error: #dc2626;
            
            --color-gray-50: #f8fafc;
            --color-gray-100: #f1f5f9;
            --color-gray-200: #e2e8f0;
            --color-gray-300: #cbd5e1;
            --color-gray-400: #94a3b8;
            --color-gray-500: #64748b;
            --color-gray-600: #475569;
            --color-gray-700: #334155;
            --color-gray-800: #1e293b;
            --color-gray-900: #0f172a;
            
            /* Shadows */
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            
            /* Border Radius */
            --radius-sm: 0.25rem;   /* 4px */
            --radius-md: 0.375rem;  /* 6px */
            --radius-lg: 0.5rem;    /* 8px */
            --radius-xl: 0.75rem;   /* 12px */
            --radius-2xl: 1rem;     /* 16px */
        }
        
        /* Base Container */
        .sjm-single-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2.5rem 1.25rem;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background: #ffffff;
        }
        
        /* Header Section */
        .sjm-single-header {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 2.5rem;
            margin-bottom: 2.5rem;
            padding: 2rem;
            background: #ffffff;
            border-radius: 1rem;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            border: 1px solid #e2e8f0;
        }
        
        .sjm-single-cover {
            width: 200px;
            height: 260px;
            background: #f8fafc;
            border-radius: 0.75rem;
            border: 1px solid #e2e8f0;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            transition: all 0.2s ease;
            position: relative;
        }
        
        .sjm-single-cover:hover {
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            transform: translateY(-2px);
        }
        
        .sjm-single-cover img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            border-radius: 0.75rem;
        }
        
        .sjm-single-info h1 {
            font-size: 2.25rem;
            font-weight: 700;
            color: #0f172a;
            margin: 0 0 1rem 0;
            line-height: 1.2;
            letter-spacing: -0.025em;
        }
        
        /* Meta Grid System */
            .sjm-single-meta, .sjm-meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
            }
        
            .sjm-meta-group, .sjm-meta-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 1rem;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            transition: all 0.2s ease;
            position: relative;
        }
        
        .sjm-meta-group:hover, .sjm-meta-card:hover {
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            border-color: #cbd5e1;
            transform: translateY(-1px);
        }
        
        .sjm-meta-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 1.25rem;
            letter-spacing: -0.01em;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        .sjm-meta-title::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 2rem;
            height: 2px;
            background: #2563eb;
            border-radius: 1px;
        }
        
        .sjm-meta-item {
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            align-items: flex-start;
            padding: 0.75rem 0;
            font-size: 1rem;
            border-bottom: 1px solid #f1f5f9;
        }
        
        .sjm-meta-item:last-child { 
            border-bottom: none; 
        }
        
        .sjm-meta-label { 
            color: #64748b; 
            font-weight: 500; 
            margin-bottom: 0.25rem; 
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .sjm-meta-value { 
            color: #0f172a; 
            font-weight: 500; 
            margin-bottom: 0.25rem; 
        }
        
        .sjm-meta-value a { 
            color: #2563eb; 
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .sjm-meta-value a:hover { 
            color: #1d4ed8;
            text-decoration: underline; 
        }
    </style>';
    $output .= '<div class="sjm-single-container">';
        $output .= '<div class="sjm-single-sections" style="display: flex; gap: 40px; align-items: flex-start;">';
        $output .= '<div class="sjm-single-main" style="flex: 1 1 0; min-width: 0;">';
        
        // Header section
        $output .= '<div class="sjm-single-header" style="grid-template-columns: 1fr;">';
        $output .= '<div class="sjm-single-info">';
        $output .= '<h1>' . esc_html($post->post_title) . '</h1>';
        if ($issue_journal) {
            $output .= '<p style="font-size: 18px; color: #6b7280; margin: 0 0 16px 0;"><a href="' . esc_url(get_permalink($issue_journal->ID)) . '" style="color: #2563eb; text-decoration: none; font-size: inherit; font-weight: 500; transition: text-decoration 0.2s;" onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">' . esc_html($issue_journal->post_title) . '</a></p>';
        }
        $output .= '<div class="sjm-journal-badges">';
        if ($issue_volume && $issue_number) $output .= '<span class="sjm-badge">Vol. ' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</span>';
        if ($issue_year) $output .= '<span class="sjm-badge">' . esc_html($issue_year) . '</span>';
        if ($special_issue) $output .= '<span class="sjm-badge">Special Issue</span>';
        if ($total_papers) $output .= '<span class="sjm-badge">' . esc_html($total_papers) . ' Papers</span>';
    $output .= '</div>';
    
        $output .= '</div>';
        $output .= '</div>';
        // Issue details
        $output .= '<div class="sjm-single-meta">';
        
        // Publication Information
        $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Publication Information</h2>';
        $output .= '<div class="sjm-meta-grid">';
        if ($publication_date) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Publication Date</span>';
            $output .= '<span class="sjm-meta-value">' . date('F j, Y', strtotime($publication_date)) . '</span>';
            $output .= '</div>';
        }
        if ($issue_page_range) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Page Range</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($issue_page_range) . '</span>';
            $output .= '</div>';
        }
        if ($issue_doi) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">DOI</span>';
            $output .= '<span class="sjm-meta-value"><a href="https://doi.org/' . esc_attr($issue_doi) . '" class="sjm-doi-link" target="_blank">' . esc_html($issue_doi) . '</a></span>';
            $output .= '</div>';
        }
        if ($pdf_url) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Full Issue PDF</span>';
            $output .= '<span class="sjm-meta-value"><a href="' . esc_url($pdf_url) . '" target="_blank" class="sjm-download-btn" style="display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; background: #2563eb; border: 1px solid #2563eb; border-radius: 6px; font-size: 13px; font-weight: 500; color: white; text-decoration: none; transition: all 0.15s ease;"><svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>Download PDF</a></span>';
            $output .= '</div>';
        }
        $output .= '</div>';
        $output .= '</div>';
        // Editorial Team
        $editorial_team = array();
        
        // Add Guest Editors
        foreach ($guest_editors as $editor_id) {
            $editor_info = sjm_get_user_display_info($editor_id);
            if ($editor_info) {
                $editorial_team[] = array('role' => 'Guest Editor', 'info' => $editor_info);
            }
        }
        
        // Add Issue Editors
        foreach ($issue_editors as $editor_id) {
            $editor_info = sjm_get_user_display_info($editor_id);
            if ($editor_info) {
                $editorial_team[] = array('role' => 'Issue Editor', 'info' => $editor_info);
            }
        }
        
        // Add Copyeditors
        foreach ($copyeditors as $editor_id) {
            $editor_info = sjm_get_user_display_info($editor_id);
            if ($editor_info) {
                $editorial_team[] = array('role' => 'Copyeditor', 'info' => $editor_info);
            }
        }
        
        // Add Layout Editors
        foreach ($layout_editors as $editor_id) {
            $editor_info = sjm_get_user_display_info($editor_id);
            if ($editor_info) {
                $editorial_team[] = array('role' => 'Layout Editor', 'info' => $editor_info);
            }
        }
        
        // Add Reviewers
        foreach ($issue_reviewers as $reviewer_id) {
            $reviewer_info = sjm_get_user_display_info($reviewer_id);
            if ($reviewer_info) {
                $editorial_team[] = array('role' => 'Reviewer', 'info' => $reviewer_info);
            }
        }
        
        if ($special_issue || $special_issue_title || !empty($editorial_team)) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Editorial Team</h2>';
            $output .= '<div class="sjm-meta-grid">';
            if ($special_issue_title) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Special Issue Title</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($special_issue_title) . '</span>';
                $output .= '</div>';
            }
            
            // Display editorial team members
            foreach ($editorial_team as $member) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">' . esc_html($member['role']) . '</span>';
                $output .= '<span class="sjm-meta-value">';
                $output .= '<a href="' . esc_url($member['info']['url']) . '" style="color: #1e40af; text-decoration: none; font-weight: 500;">' . esc_html($member['info']['name']) . '</a>';
                if (!empty($member['info']['email'])) {
                    $output .= ' | <a href="mailto:' . esc_attr($member['info']['email']) . '" style="color: #2563eb; text-decoration: none; font-size: 0.9em;">' . esc_html($member['info']['email']) . '</a>';
                }
                $output .= '</span>';
                $output .= '</div>';
            }
            $output .= '</div>';
            $output .= '</div>';
        }
        // Additional Information
        if ($issue_keywords || $issue_abstract) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Additional Information</h2>';
            $output .= '<div class="sjm-meta-grid">';
            if ($issue_keywords) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Keywords</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($issue_keywords) . '</span>';
                $output .= '</div>';
            }
            $output .= '</div>';
            if ($issue_abstract) {
                $output .= '<div style="margin-top: 16px; padding: 16px; background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;">';
                $output .= '<h4 style="font-size: 16px; font-weight: 600; color: #374151; margin: 0 0 12px 0;">Abstract</h4>';
                $output .= '<p style="font-size: 14px; color: #111827; line-height: 1.6; margin: 0;">' . esc_html($issue_abstract) . '</p>';
                $output .= '</div>';
            }
            $output .= '</div>';
        }
        $output .= '</div>';
        // Papers in this issue
        if ($papers) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Papers in this Issue (' . count($papers) . ')</h2>';
            $output .= '<div class="sjm-meta-grid">';
            foreach ($papers as $paper) {
                $paper_authors = get_post_meta($paper->ID, '_sjm_paper_authors', true);
                $paper_authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
                if (!is_array($paper_authors_data)) $paper_authors_data = array();
                $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
                $paper_pages = get_post_meta($paper->ID, '_sjm_paper_pages', true);
                $paper_doi = get_post_meta($paper->ID, '_sjm_paper_doi', true);
                $paper_pdf_url = get_post_meta($paper->ID, '_sjm_paper_pdf_url', true);
                $paper_open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
                $paper_peer_reviewed = get_post_meta($paper->ID, '_sjm_paper_peer_reviewed', true);
                $output .= '<div class="sjm-meta-card">';
                $output .= '<h4 style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600;">' . esc_html($paper->post_title) . '</h4>';
                
                // Display enhanced author information with links
                if (!empty($paper_authors_data)) {
                    // Sort authors by order
                    usort($paper_authors_data, function($a, $b) {
                        return intval($a['order']) - intval($b['order']);
                    });
                    
                    $author_displays = array();
                    foreach ($paper_authors_data as $author_data) {
                        $author = sjm_get_author_by_id($author_data['author_id']);
                        if ($author) {
                            $author_displays[] = sjm_format_author_display($author, $author_data, true, false);
                        }
                    }
                    if (!empty($author_displays)) {
                        $output .= '<p style="font-size: 14px; color: #6b7280; margin: 0 0 12px 0; font-weight: 500;">' . implode(', ', $author_displays) . '</p>';
                    }
                } elseif ($paper_authors) {
                    $output .= '<p style="font-size: 14px; color: #6b7280; margin: 0 0 12px 0; font-weight: 500;">' . esc_html($paper_authors) . '</p>';
                }
                $output .= '<div class="sjm-journal-badges" style="margin-bottom: 12px;">';
                if ($paper_type) $output .= '<span class="sjm-badge">' . esc_html($paper_type) . '</span>';
                if ($paper_pages) $output .= '<span class="sjm-badge">Pages ' . esc_html($paper_pages) . '</span>';
                if ($paper_doi) $output .= '<span class="sjm-badge"><a href="https://doi.org/' . esc_attr($paper_doi) . '" class="sjm-doi-link" target="_blank">DOI</a></span>';
                if ($paper_open_access) $output .= '<span class="sjm-badge">Open Access</span>';
                if ($paper_peer_reviewed) $output .= '<span class="sjm-badge">Peer Reviewed</span>';
                $output .= '</div>';
                $output .= '<div style="display: flex; gap: 8px; margin-top: 12px; align-items: center;">';
                if ($paper_pdf_url) {
                    $output .= '<a href="' . esc_url($paper_pdf_url) . '" target="_blank" class="sjm-view-button" style="font-size: 13px; padding: 8px 12px;">';
                    $output .= '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="margin-right:4px; vertical-align:middle;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>PDF</a>';
                }
                $output .= '<a href="' . get_permalink($paper->ID) . '" class="sjm-view-button" style="font-size: 13px; padding: 8px 12px;">View Paper <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14" style="margin-left:4px; vertical-align:middle;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg></a>';
                $output .= '</div>';
                $output .= '</div>';
            }
            $output .= '</div>';
            $output .= '</div>';
        }
        $output .= '</div>'; // Close sjm-single-main
        $output .= '</div>'; // Close sjm-single-container
        return $output;
    }
    return $content;
}
add_filter('the_content', 'sjm_single_issue_template');

// Single Paper Page Template
function sjm_single_paper_template($content) {
    if (!isset($content)) $content = '';
    global $post;
    if (is_singular('paper')) {
        // Real-time view tracking: increment views count
        $paper_id = $post->ID;
        $views_count = (int) get_post_meta($paper_id, '_sjm_views_count', true);
        $views_count++;
        update_post_meta($paper_id, '_sjm_views_count', $views_count);

        // Clear the default content to replace it completely
        $content = '';
        $paper_id = $post->ID;
        
        // Get all paper meta
        $paper_journal_id = get_post_meta($paper_id, '_sjm_paper_journal', true);
        $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
        $paper_issue_id = get_post_meta($paper_id, '_sjm_paper_issue', true);
        $paper_issue = $paper_issue_id ? get_post($paper_issue_id) : null;
        $paper_authors = get_post_meta($paper_id, '_sjm_paper_authors', true);
        $paper_authors_data = get_post_meta($paper_id, '_sjm_paper_authors_data', true);
        if (!is_array($paper_authors_data)) $paper_authors_data = array();
        $paper_abstract = get_post_meta($paper_id, '_sjm_paper_abstract', true);
        $paper_type = get_post_meta($paper_id, '_sjm_paper_type', true);
        $submission_date = get_post_meta($paper_id, '_sjm_submission_date', true);
        $acceptance_date = get_post_meta($paper_id, '_sjm_acceptance_date', true);
        $paper_version = get_post_meta($paper_id, '_sjm_paper_version', true);
        $paper_doi = get_post_meta($paper_id, '_sjm_paper_doi', true);
        $paper_keywords = get_post_meta($paper_id, '_sjm_paper_keywords', true);
        $paper_pages = get_post_meta($paper_id, '_sjm_paper_pages', true);
        $paper_pdf_url = get_post_meta($paper_id, '_sjm_paper_pdf_url', true);
        $corresponding_author_id = get_post_meta($paper_id, '_sjm_corresponding_author_id', true);
        $corresponding_author = sjm_get_user_display_info($corresponding_author_id);
        $author_affiliations = get_post_meta($paper_id, '_sjm_author_affiliations', true);
        $paper_funding = get_post_meta($paper_id, '_sjm_paper_funding', true);
        $conflicts_of_interest = get_post_meta($paper_id, '_sjm_conflicts_of_interest', true);
        $paper_peer_reviewed = get_post_meta($paper_id, '_sjm_paper_peer_reviewed', true);
        $paper_open_access = get_post_meta($paper_id, '_sjm_paper_open_access', true);
        $citation_count = get_post_meta($paper_id, '_sjm_citation_count', true);
        $views_count = get_post_meta($paper_id, '_sjm_views_count', true);
        $manuscript_file = get_post_meta($paper_id, '_sjm_manuscript_file', true);
        $version_notes = get_post_meta($paper_id, '_sjm_version_notes', true);
        $version_history = get_post_meta($paper_id, '_sjm_version_history', true);
        
        $output = '<style>
        /* World-Class Design System - Perfect Single Views */
        :root {
            /* Typography Scale (1.25 ratio) */
            --font-size-xs: 0.75rem;    /* 12px */
            --font-size-sm: 0.875rem;   /* 14px */
            --font-size-base: 1rem;     /* 16px */
            --font-size-lg: 1.125rem;   /* 18px */
            --font-size-xl: 1.25rem;    /* 20px */
            --font-size-2xl: 1.5rem;    /* 24px */
            --font-size-3xl: 1.875rem;  /* 30px */
            --font-size-4xl: 2.25rem;   /* 36px */
            
            /* Spacing Scale (8px base) */
            --space-1: 0.25rem;   /* 4px */
            --space-2: 0.5rem;    /* 8px */
            --space-3: 0.75rem;   /* 12px */
            --space-4: 1rem;      /* 16px */
            --space-5: 1.25rem;   /* 20px */
            --space-6: 1.5rem;    /* 24px */
            --space-8: 2rem;      /* 32px */
            --space-10: 2.5rem;   /* 40px */
            --space-12: 3rem;     /* 48px */
            --space-16: 4rem;     /* 64px */
            
            /* Color System */
            --color-primary: #2563eb;
            --color-primary-hover: #1d4ed8;
            --color-secondary: #64748b;
            --color-success: #059669;
            --color-warning: #d97706;
            --color-error: #dc2626;
            
            --color-gray-50: #f8fafc;
            --color-gray-100: #f1f5f9;
            --color-gray-200: #e2e8f0;
            --color-gray-300: #cbd5e1;
            --color-gray-400: #94a3b8;
            --color-gray-500: #64748b;
            --color-gray-600: #475569;
            --color-gray-700: #334155;
            --color-gray-800: #1e293b;
            --color-gray-900: #0f172a;
            
            /* Shadows */
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            
            /* Border Radius */
            --radius-sm: 0.25rem;   /* 4px */
            --radius-md: 0.375rem;  /* 6px */
            --radius-lg: 0.5rem;    /* 8px */
            --radius-xl: 0.75rem;   /* 12px */
            --radius-2xl: 1rem;     /* 16px */
        }
        
        /* Base Container */
        .sjm-single-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2.5rem 1.25rem;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background: #ffffff;
        }
        
        /* Header Section */
        .sjm-single-header {
            display: grid;
            grid-template-columns: 1fr;
            gap: 2.5rem;
            margin-bottom: 2.5rem;
            padding: 2rem;
            background: #ffffff;
            border-radius: 1rem;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            border: 1px solid #e2e8f0;
        }
        
        .sjm-single-info h1 {
            font-size: 2.25rem;
            font-weight: 700;
            color: #0f172a;
            margin: 0 0 1rem 0;
            line-height: 1.2;
            letter-spacing: -0.025em;
        }
        
        /* Meta Grid System */
        .sjm-single-meta, .sjm-meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        
        .sjm-meta-group, .sjm-meta-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 1rem;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1);
            transition: all 0.2s ease;
        }
        
        .sjm-meta-group:hover, .sjm-meta-card:hover {
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            border-color: #cbd5e1;
            transform: translateY(-1px);
        }
        
        .sjm-meta-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 1.25rem;
            letter-spacing: -0.01em;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        .sjm-meta-title::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 2rem;
            height: 2px;
            background: #2563eb;
            border-radius: 1px;
        }
        
        .sjm-meta-item {
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            align-items: flex-start;
            padding: var(--space-3) 0;
            font-size: var(--font-size-base);
            border-bottom: 1px solid var(--color-gray-100);
        }
        
        .sjm-meta-item:last-child { 
            border-bottom: none; 
        }
        
        .sjm-meta-label { 
            color: var(--color-gray-600); 
            font-weight: 500; 
            margin-bottom: var(--space-1); 
            font-size: var(--font-size-sm);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .sjm-meta-value { 
            color: var(--color-gray-900); 
            font-weight: 500; 
            margin-bottom: var(--space-1); 
        }
        
        .sjm-meta-value a { 
            color: var(--color-primary); 
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .sjm-meta-value a:hover { 
            color: var(--color-primary-hover);
            text-decoration: underline; 
        }
        
        /* Buttons */
        .sjm-download-btn {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: var(--space-3) var(--space-4);
            background: var(--color-primary);
            border: 1px solid var(--color-primary);
            border-radius: var(--radius-lg);
            color: #ffffff;
            text-decoration: none;
            font-size: var(--font-size-sm);
            font-weight: 500;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .sjm-download-btn:hover {
            background: var(--color-primary-hover);
            border-color: var(--color-primary-hover);
            text-decoration: none;
            color: #ffffff;
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }
        
        .sjm-download-btn:focus {
            outline: 2px solid var(--color-primary);
            outline-offset: 2px;
        }
        
        /* Badges */
        .sjm-journal-badges {
            display: flex;
            gap: var(--space-2);
            flex-wrap: wrap;
            margin-bottom: var(--space-5);
        }
        
        .sjm-badge {
            display: inline-flex;
            align-items: center;
            background: var(--color-gray-100);
            color: var(--color-gray-700);
            font-size: var(--font-size-xs);
            font-weight: 600;
            border-radius: var(--radius-md);
            padding: var(--space-1) var(--space-3);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border: 1px solid var(--color-gray-200);
        }
        
        .sjm-badge a {
            color: inherit;
            text-decoration: none;
        }
        
        .sjm-badge a:hover {
            text-decoration: underline;
        }
        
        /* DOI Links */
        .sjm-doi-link {
            color: var(--color-primary);
            text-decoration: none;
            word-break: break-all;
            transition: color 0.2s ease;
        }
        
        .sjm-doi-link:hover {
            color: var(--color-primary-hover);
            text-decoration: underline;
        }
        
        /* Author Cards */
        .sjm-author-card {
            background: #fff;
            border: 1px solid var(--color-gray-200);
            border-radius: var(--radius-xl);
            padding: var(--space-6) var(--space-5);
            margin-bottom: var(--space-6);
            box-shadow: var(--shadow-sm);
            display: flex;
            flex-direction: column;
            gap: var(--space-3);
            transition: all 0.2s ease;
        }
        
        .sjm-author-card:hover {
            box-shadow: var(--shadow-md);
            border-color: var(--color-gray-300);
        }
        
        .sjm-author-info {
            display: flex;
            flex-direction: column;
            gap: var(--space-2);
        }
        
        .sjm-author-item {
            font-size: var(--font-size-sm);
            color: var(--color-gray-700);
        }
        
        .sjm-author-name {
            font-size: var(--font-size-lg);
            font-weight: 600;
            color: var(--color-gray-900);
        }
        
        .sjm-author-name a {
            color: var(--color-primary);
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .sjm-author-name a:hover {
            color: var(--color-primary-hover);
            text-decoration: underline;
        }
        
        .sjm-corresponding-badge {
            background: var(--color-success);
            color: white;
            font-size: var(--font-size-xs);
            padding: var(--space-1) var(--space-2);
            border-radius: var(--radius-sm);
            margin-left: var(--space-2);
        }
        
        /* Abstract Section */
        .sjm-abstract-section {
            margin: var(--space-8) 0;
            padding: var(--space-6);
            background: var(--color-gray-50);
            border-radius: var(--radius-xl);
            border: 1px solid var(--color-gray-200);
        }
        
        .sjm-abstract-title {
            font-size: var(--font-size-lg);
            font-weight: 600;
            color: var(--color-gray-900);
            margin: 0 0 var(--space-4) 0;
        }
        
        .sjm-abstract-content {
            font-size: var(--font-size-sm);
            color: var(--color-gray-700);
            line-height: 1.7;
            margin: 0;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .sjm-single-container {
                padding: 1.25rem 1rem;
            }
            
            .sjm-single-header {
                grid-template-columns: 1fr !important;
                padding: 1.5rem;
            }
            
            .sjm-single-info h1 {
                font-size: 1.875rem;
                line-height: 1.3;
            }
            
            .sjm-single-meta, .sjm-meta-grid {
                grid-template-columns: 1fr;
                gap: 1.5rem;
            }
            
            .sjm-meta-group, .sjm-meta-card {
                padding: 1.5rem 1rem;
            }
            
            .sjm-abstract-section {
                padding: 1.5rem;
                margin: 1.5rem 0;
            }
        }
        
        @media (max-width: 480px) {
            .sjm-single-container {
                padding: 1rem 0.75rem;
            }
            
            .sjm-single-header {
                padding: 1rem;
            }
            
            .sjm-single-info h1 {
                font-size: 1.5rem;
                line-height: 1.4;
            }
            
            .sjm-meta-group, .sjm-meta-card {
                padding: 1rem 0.75rem;
            }
            
            .sjm-abstract-section {
                padding: 1rem;
            }
            
            .sjm-journal-badges {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
        }
        </style>';
        
        $output .= '<div class="sjm-single-container">';
        $output .= '<div class="sjm-single-main" style="width: 100%;">';
        
        // Header section
        $output .= '<div class="sjm-single-header" style="grid-template-columns: 1fr;">';
    $output .= '<div class="sjm-single-info">';
    $output .= '<h1>' . esc_html($post->post_title) . '</h1>';
        
        // Display enhanced author information with links
        if (!empty($paper_authors_data)) {
            // Sort authors by order
            usort($paper_authors_data, function($a, $b) {
                return intval($a['order']) - intval($b['order']);
            });
            
            $author_displays = array();
            foreach ($paper_authors_data as $author_data) {
                $author = sjm_get_author_by_id($author_data['author_id']);
                if ($author) {
                    $author_displays[] = sjm_format_author_display($author, $author_data, true, false);
                }
            }
            if (!empty($author_displays)) {
                $output .= '<p style="font-size: 18px; color: #6b7280; margin: 0 0 8px 0; font-weight: 500;">' . implode(', ', $author_displays) . '</p>';
            }
        } elseif ($paper_authors) {
            $output .= '<p style="font-size: 18px; color: #6b7280; margin: 0 0 8px 0; font-weight: 500;">' . esc_html($paper_authors) . '</p>';
        }
        
        if ($paper_journal || $paper_issue) {
            $output .= '<p style="font-size: 16px; color: #9ca3af; margin: 0 0 16px 0;">';
            if ($paper_journal) {
                $output .= '<a href="' . esc_url(get_permalink($paper_journal->ID)) . '" style="color: #2563eb; text-decoration: none; font-size: inherit; font-weight: 500; transition: text-decoration 0.2s;" onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">' . esc_html($paper_journal->post_title) . '</a>';
            }
            if ($paper_issue) {
                $issue_volume = get_post_meta($paper_issue->ID, '_sjm_issue_volume', true);
                $issue_number = get_post_meta($paper_issue->ID, '_sjm_issue_number', true);
                if ($issue_volume && $issue_number) {
                    $output .= ' • <a href="' . esc_url(get_permalink($paper_issue->ID)) . '" style="color: #2563eb; text-decoration: none; font-size: inherit; font-weight: 500; transition: text-decoration 0.2s;" onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">Vol. ' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</a>';
                }
            }
            $output .= '</p>';
        }
    
    // Quick badges
    $output .= '<div class="sjm-journal-badges" style="margin-bottom: 20px;">';
        if ($paper_type) {
            $output .= '<span class="sjm-badge">' . esc_html($paper_type) . '</span>';
        }
        if ($acceptance_date) {
            $year = date('Y', strtotime($acceptance_date));
            $output .= '<span class="sjm-badge">' . esc_html($year) . '</span>';
        }
        if ($paper_doi) {
            $output .= '<span class="sjm-badge"><a href="https://doi.org/' . esc_attr($paper_doi) . '" class="sjm-doi-link" target="_blank">DOI</a></span>';
        }
        if ($paper_open_access) {
            $output .= '<span class="sjm-badge">Open Access</span>';
        }
        if ($paper_peer_reviewed) {
            $output .= '<span class="sjm-badge">Peer Reviewed</span>';
        }
    $output .= '</div>';
    
    // Download options
        if ($paper_pdf_url || $manuscript_file) {
            if ($paper_pdf_url) {
                $output .= '<a href="' . esc_url($paper_pdf_url) . '" target="_blank" class="sjm-download-btn" style="margin-right: 12px;">';
        $output .= '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
                $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';
        $output .= '</svg>';
                $output .= 'Download PDF';
        $output .= '</a>';
            }
            if ($manuscript_file) {
                $output .= '<a href="' . esc_url($manuscript_file) . '" target="_blank" class="sjm-download-btn">';
                $output .= '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
                $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';
                $output .= '</svg>';
                $output .= 'Download Manuscript';
                $output .= '</a>';
            }
    }
    
    $output .= '</div>';
    $output .= '</div>';
    
        // Abstract
        if ($paper_abstract) {
            $output .= '<div class="sjm-abstract-section">';
            $output .= '<h3 class="sjm-abstract-title">Abstract</h3>';
            $output .= '<p class="sjm-abstract-content">' . nl2br(esc_html($paper_abstract)) . '</p>';
            $output .= '</div>';
        }
        
        // Paper details
    $output .= '<div class="sjm-single-meta">';
    
        // Publication Information
        $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Publication Information</h2>';
        $output .= '<div class="sjm-meta-grid">';
        if ($submission_date) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Submitted</span>';
            $output .= '<span class="sjm-meta-value">' . date('F j, Y', strtotime($submission_date)) . '</span>';
        $output .= '</div>';
    }
        if ($acceptance_date) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Accepted</span>';
            $output .= '<span class="sjm-meta-value">' . date('F j, Y', strtotime($acceptance_date)) . '</span>';
        $output .= '</div>';
    }
        if ($paper_version) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Version</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($paper_version) . '</span>';
        $output .= '</div>';
    }
        if ($paper_pages) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Pages</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($paper_pages) . '</span>';
        $output .= '</div>';
    }
        if ($paper_doi) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">DOI</span>';
            $output .= '<span class="sjm-meta-value"><a href="https://doi.org/' . esc_attr($paper_doi) . '" class="sjm-doi-link" target="_blank">' . esc_html($paper_doi) . '</a></span>';
        $output .= '</div>';
    }
        $output .= '</div>';
        $output .= '</div>';
        
        // Author Information
        $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Author Information</h2>';
        $output .= '<div class="sjm-meta-grid">';
        // Display detailed author information with profile links
        if (!empty($paper_authors_data)) {
            foreach ($paper_authors_data as $author_data) {
                $author = sjm_get_author_by_id($author_data['author_id']);
                if ($author) {
                    $output .= '<div class="sjm-author-card">';
                    $profile_url = sjm_get_author_profile_url($author->id);
                    $output .= '<div class="sjm-author-name">';
                    $output .= '<a href="' . esc_url($profile_url) . '" style="color: #1e40af; text-decoration: none;">' . esc_html($author->first_name . ' ' . $author->last_name) . '</a>';
                    if ($author_data['is_corresponding'] == '1') {
                        $output .= ' <span class="sjm-badge sjm-corresponding-badge">Corresponding Author</span>';
                    }
                    $output .= '</div>';
                    $output .= '<div class="sjm-author-info">';
                    if ($author->orcid) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>ORCID:</strong> <a href="https://orcid.org/' . esc_attr($author->orcid) . '" target="_blank" style="color: #059669; text-decoration: none;">' . esc_html($author->orcid) . '</a>';
                        $output .= '</div>';
                    }
                    if ($author->affiliation) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Affiliation:</strong> ' . esc_html($author->affiliation);
                        $output .= '</div>';
                    }
                    if ($author->email) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Email:</strong> <a href="mailto:' . esc_attr($author->email) . '" style="color: #2563eb; text-decoration: none;">' . esc_html($author->email) . '</a>';
                        $output .= '</div>';
                    }
                    if ($author->website) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Website:</strong> <a href="' . esc_url($author->website) . '" target="_blank" style="color: #2563eb; text-decoration: none;">' . esc_html($author->website) . '</a>';
                        $output .= '</div>';
                    }
                    if (!empty($author_data['contributions'])) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Contributions:</strong> ' . esc_html($author_data['contributions']);
                        $output .= '</div>';
                    }
                    $output .= '</div>';
                    $output .= '</div>';
                }
            }
        } elseif ($corresponding_author) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Corresponding Author</span>';
            $output .= '<span class="sjm-meta-value"><a href="' . esc_url($corresponding_author['url']) . '">' . esc_html($corresponding_author['name']) . '</a></span>';
        $output .= '</div>';
    }
        if ($author_affiliations) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Affiliations</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($author_affiliations) . '</span>';
            $output .= '</div>';
        }
        if ($paper_keywords) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Keywords</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($paper_keywords) . '</span>';
            $output .= '</div>';
        }
        $output .= '</div>';
    $output .= '</div>';
    
        // Manuscript Tracking
        $manuscript_id = get_post_meta($paper_id, '_sjm_manuscript_id', true);
        if ($manuscript_id) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Manuscript Tracking</h2>';
            $output .= '<div class="sjm-meta-grid">';
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Manuscript ID</span>';
            $output .= '<span class="sjm-meta-value" style="font-family: monospace; background: #f3f4f6; padding: 4px 8px; border-radius: 4px; font-weight: 600;">' . esc_html($manuscript_id) . '</span>';
                $output .= '</div>';
                $output .= '</div>';
        $output .= '</div>';
    }
        
        // Additional Information
        $output .= '<div class="sjm-section">';
        $output .= '<h2 class="sjm-section-title">Additional Information</h2>';
        $output .= '<div class="sjm-meta-grid">';
                if ($paper_funding) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Funding</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($paper_funding) . '</span>';
        $output .= '</div>';
    }
        
        // Structured Funding Information
        $funding_sources = get_post_meta($paper_id, '_sjm_funding_sources', true);
        if ($funding_sources && is_array($funding_sources) && !empty($funding_sources)) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Structured Funding Sources</span>';
            $output .= '<span class="sjm-meta-value">';
            foreach ($funding_sources as $index => $funding) {
                if ($index > 0) $output .= '<br>';
                $output .= '<strong>' . esc_html($funding['source']) . '</strong>';
                if (!empty($funding['grant_number'])) {
                    $output .= ' (Grant: ' . esc_html($funding['grant_number']) . ')';
                }
                if (!empty($funding['amount'])) {
                    $output .= ' - ' . esc_html($funding['amount']);
                }
            }
            $output .= '</span>';
        $output .= '</div>';
    }
        if ($conflicts_of_interest) {
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Conflicts of Interest</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($conflicts_of_interest) . '</span>';
        $output .= '</div>';
    }
        if ($citation_count) {
                $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Citations</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($citation_count) . '</span>';
                $output .= '</div>';
            }
        if ($views_count) {
                $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Views</span>';
            $output .= '<span class="sjm-meta-value">' . esc_html($views_count) . '</span>';
                $output .= '</div>';
            }
            $output .= '</div>';
    $output .= '</div>';
    
        $output .= '</div>';
        
        // Academic Compliance & Ethics
        $ethics_approval_required = get_post_meta($paper_id, '_sjm_ethics_approval_required', true);
        $ethics_approval_number = get_post_meta($paper_id, '_sjm_ethics_approval_number', true);
        $ethics_committee = get_post_meta($paper_id, '_sjm_ethics_committee', true);
        $human_subjects = get_post_meta($paper_id, '_sjm_human_subjects', true);
        $animal_subjects = get_post_meta($paper_id, '_sjm_animal_subjects', true);
        $data_availability = get_post_meta($paper_id, '_sjm_data_availability', true);
        $data_statement = get_post_meta($paper_id, '_sjm_data_statement', true);
        
        if ($ethics_approval_required || $ethics_approval_number || $ethics_committee || $human_subjects || $animal_subjects || $data_availability || $data_statement) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Academic Compliance & Ethics</h2>';
            $output .= '<div class="sjm-meta-grid">';
            if ($ethics_approval_required) {
            $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Ethics Approval Required</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($ethics_approval_required) . '</span>';
            $output .= '</div>';
        }
            if ($ethics_approval_number) {
            $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Ethics Approval Number</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($ethics_approval_number) . '</span>';
            $output .= '</div>';
        }
            if ($ethics_committee) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Ethics Committee/IRB</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($ethics_committee) . '</span>';
                $output .= '</div>';
            }
            if ($human_subjects) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Human Subjects Research</span>';
                $output .= '<span class="sjm-meta-value">Yes</span>';
                $output .= '</div>';
            }
            if ($animal_subjects) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Animal Subjects Research</span>';
                $output .= '<span class="sjm-meta-value">Yes</span>';
                $output .= '</div>';
            }
            if ($data_availability) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Data Availability</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($data_availability) . '</span>';
                $output .= '</div>';
            }
            if ($data_statement) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Data Statement</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($data_statement) . '</span>';
                $output .= '</div>';
            }
            $output .= '</div>';
        $output .= '</div>';
    }
    
        // Copyright & Licensing
        $copyright_holder = get_post_meta($paper_id, '_sjm_copyright_holder', true);
        $copyright_year = get_post_meta($paper_id, '_sjm_copyright_year', true);
        $license_type = get_post_meta($paper_id, '_sjm_license_type', true);
        $license_url = get_post_meta($paper_id, '_sjm_license_url', true);
        $copyright_transfer = get_post_meta($paper_id, '_sjm_copyright_transfer', true);
        $transfer_date = get_post_meta($paper_id, '_sjm_transfer_date', true);
        $reuse_permissions = get_post_meta($paper_id, '_sjm_reuse_permissions', true);
        
        if ($copyright_holder || $copyright_year || $license_type || $license_url || $copyright_transfer || $transfer_date || $reuse_permissions) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Copyright & Licensing</h2>';
            $output .= '<div class="sjm-meta-grid">';
            if ($copyright_holder) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Copyright Holder</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($copyright_holder) . '</span>';
    $output .= '</div>';
            }
            if ($copyright_year) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Copyright Year</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($copyright_year) . '</span>';
                $output .= '</div>';
            }
            if ($license_type) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">License Type</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($license_type) . '</span>';
                $output .= '</div>';
            }
            if ($license_url) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">License URL</span>';
                $output .= '<span class="sjm-meta-value"><a href="' . esc_url($license_url) . '" target="_blank" style="color: #2563eb; text-decoration: none;">' . esc_html($license_url) . '</a></span>';
                $output .= '</div>';
            }
            if ($copyright_transfer) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Copyright Transfer</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($copyright_transfer) . '</span>';
                $output .= '</div>';
            }
            if ($transfer_date) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Transfer Date</span>';
                $output .= '<span class="sjm-meta-value">' . date('F j, Y', strtotime($transfer_date)) . '</span>';
                $output .= '</div>';
            }
            if ($reuse_permissions) {
                $output .= '<div class="sjm-meta-item">';
                $output .= '<span class="sjm-meta-label">Reuse Permissions</span>';
                $output .= '<span class="sjm-meta-value">' . esc_html($reuse_permissions) . '</span>';
                $output .= '</div>';
            }
            $output .= '</div>';
            $output .= '</div>';
        }
        
        // Enhanced Version Management Display
        if ($version_history && is_array($version_history) && !empty($version_history)) {
            // Group versions by type for better display
            $versions_by_type = array();
            foreach ($version_history as $version) {
                $type = $version['type'];
                if (!isset($versions_by_type[$type])) {
                    $versions_by_type[$type] = array();
                }
                $versions_by_type[$type][] = $version;
            }
            
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Version Management (' . count($version_history) . ' total versions)</h2>';
            
            foreach ($versions_by_type as $type => $type_versions) {
                $output .= '<div class="sjm-version-type-section" style="margin-bottom: 24px; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">';
                $output .= '<div style="background: #f9fafb; padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">';
                $output .= '<h3 style="margin: 0; font-size: 16px; font-weight: 600; color: #374151;">' . esc_html($type) . ' Versions (' . count($type_versions) . ')</h3>';
                $output .= '</div>';
                
                $output .= '<div style="padding: 16px;">';
                foreach ($type_versions as $version_num => $version) {
                    $version_label = $type . ' v' . ($version_num + 1);
                    $is_latest = ($version_num === count($type_versions) - 1);
                    
                    $output .= '<div class="sjm-version-card" style="' . ($version_num > 0 ? 'margin-top: 16px; padding-top: 16px; border-top: 1px solid #f3f4f6;' : '') . '">';
                    $output .= '<div style="display: flex; align-items: flex-start; gap: 16px;">';
                    
                    $output .= '<div style="flex: 1;">';
                    $output .= '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">';
                    $output .= '<h4 style="margin: 0; font-size: 16px; font-weight: 600; color: #2563eb;">' . esc_html($version_label) . '</h4>';
                    if ($is_latest) {
                        $output .= '<span style="background: #10b981; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">LATEST</span>';
                    }
                    if (!empty($version['open_access']) && $version['open_access'] == '1') {
                        $output .= '<span style="background: #059669; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">OPEN ACCESS</span>';
                    }
                $output .= '</div>';
                    
                    if (!empty($version['description'])) {
                        $output .= '<p style="font-size: 14px; color: #6b7280; margin: 0 0 8px 0; line-height: 1.5;"><strong>Version Notes:</strong> ' . esc_html($version['description']) . '</p>';
                    }
                    
                    // Display DOI if available
                    if (!empty($version['doi'])) {
                        $output .= '<p style="font-size: 13px; color: #6b7280; margin: 0 0 8px 0;"><strong>DOI:</strong> <a href="https://doi.org/' . esc_attr($version['doi']) . '" target="_blank" style="color: #2563eb; text-decoration: none;">' . esc_html($version['doi']) . '</a></p>';
                    }
                    
                    // Display version-specific authors/contributors with profile links
                    if (!empty($version['authors'])) {
                        $version_contributors = array();
                        foreach ($version['authors'] as $version_author) {
                            $author = sjm_get_author_by_id($version_author['author_id']);
            if ($author) {
                $profile_url = sjm_get_author_profile_url($author->id);
                                $contributor_text = '<a href="' . esc_url($profile_url) . '" style="color: #1e40af; text-decoration: none;">' . esc_html($author->first_name . ' ' . $author->last_name) . '</a>';
                                if (!empty($version_author['role'])) {
                                    $contributor_text .= ' (' . esc_html($version_author['role']) . ')';
                                }
                                if (!empty($version_author['contribution'])) {
                                    $contributor_text .= ' - ' . esc_html($version_author['contribution']);
                                }
                                $version_contributors[] = $contributor_text;
                            }
                        }
                        if (!empty($version_contributors)) {
                            $output .= '<p style="font-size: 13px; color: #6b7280; margin: 0 0 8px 0;"><strong>Contributors:</strong> ' . implode('; ', $version_contributors) . '</p>';
                        }
                    }
                    
                    $output .= '<div class="sjm-version-badges">';
                    if (!empty($version['date'])) {
                        $output .= '<span class="sjm-badge" style="background: #f3f4f6; color: #6b7280; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 500;">' . date('M j, Y', strtotime($version['date'])) . '</span>';
                    }
                    $output .= '</div>';
                    $output .= '</div>';
                    
                    if (!empty($version['file'])) {
                        $output .= '<div class="sjm-version-actions" style="flex-shrink: 0;">';
                        $output .= '<a href="' . esc_url($version['file']) . '" target="_blank" class="sjm-download-btn" style="display: inline-flex; align-items: center; gap: 6px; padding: 8px 12px; background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 8px; font-size: 13px; font-weight: 500; color: #374151; text-decoration: none; transition: all 0.15s ease;">';
                        $output .= '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
                        $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';
                        $output .= '</svg>';
                        $output .= 'Download';
                        $output .= '</a>';
                $output .= '</div>';
            }
                    
                    $output .= '</div>';
                $output .= '</div>';
            }
                $output .= '</div>';
                $output .= '</div>';
            }
            
                $output .= '</div>';
            }
        
                $output .= '</div>';
        
        // Request by Email for non-open-access papers
        if (!$paper_open_access && !empty($corresponding_author['email'])) {
            $subject = rawurlencode('Request for Full Text: ' . $post->post_title);
            $body = rawurlencode('Dear ' . $corresponding_author['name'] . ',%0D%0A%0D%0AI would like to request access to the full text of the paper titled: ' . $post->post_title . '.%0D%0A%0D%0AThank you!');
            $mailto = 'mailto:' . $corresponding_author['email'] . '?subject=' . $subject . '&body=' . $body;
            $output .= '<a href="' . esc_url($mailto) . '" class="sjm-download-btn" style="background:#f8d7da;color:#842029;margin-bottom:16px;">Request Full Text by Email</a>';
        } elseif (!$paper_open_access) {
            $output .= '<div style="color:#842029;font-size:13px;margin-bottom:16px;">This paper is not open access. Please contact the corresponding author to request the full text.</div>';
        }
        
            $output .= '</div>';
        
        return $output;
    }
    return $content;
}
add_filter('the_content', 'sjm_single_paper_template');

// Force table creation immediately when plugin loads
add_action('plugins_loaded', 'sjm_force_create_authors_table');

function sjm_force_create_authors_table() {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'sjm_authors';
    
    // Check if table exists, create if it doesn't
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
        sjm_create_authors_table();
    }
}

// Also run on init to ensure table exists
add_action('init', 'sjm_ensure_authors_table_exists', 5); // Early priority

function sjm_ensure_authors_table_exists() {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'sjm_authors';
    
    // Check if table exists
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
        sjm_create_authors_table();
    }
}

// Also run table creation on admin_init to catch any missed cases
add_action('admin_init', 'sjm_ensure_authors_table_exists_admin');

function sjm_ensure_authors_table_exists_admin() {
    global $wpdb;
    
    // Only run this on journal-related admin pages
    if (isset($_GET['post_type']) && $_GET['post_type'] === 'journal') {
        $table_name = $wpdb->prefix . 'sjm_authors';
        
        // Check if table exists
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            sjm_create_authors_table();
        }
    }
}

// Function to fetch author data from ORCID API
function sjm_fetch_orcid_data($orcid) {
    $orcid = sanitize_text_field($orcid);
    
    // Remove any formatting and validate ORCID format
    $orcid = preg_replace('/[^0-9X-]/', '', $orcid);
    if (!preg_match('/^\d{4}-\d{4}-\d{4}-\d{3}[0-9X]$/', $orcid)) {
        return false;
    }
    
    $api_url = "https://pub.orcid.org/v3.0/$orcid/person";
    
    $response = wp_remote_get($api_url, array(
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'timeout' => 15
    ));
    
    if (is_wp_error($response)) {
        return false;
    }
    
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);
    
    if (!$data) {
        return false;
    }
    
    // Extract author information
    $author_data = array();
    
    if (isset($data['name'])) {
        $author_data['first_name'] = isset($data['name']['given-names']['value']) ? $data['name']['given-names']['value'] : '';
        $author_data['last_name'] = isset($data['name']['family-name']['value']) ? $data['name']['family-name']['value'] : '';
    }
    
    if (isset($data['emails']['email'][0]['email'])) {
        $author_data['email'] = $data['emails']['email'][0]['email'];
    }
    
    if (isset($data['biography']['content'])) {
        $author_data['bio'] = wp_trim_words($data['biography']['content'], 50);
    }
    
    // Get affiliation from employment or education
    $affiliations = array();
    if (isset($data['activities-summary']['employments']['employment-summary'])) {
        foreach ($data['activities-summary']['employments']['employment-summary'] as $employment) {
            if (isset($employment['organization']['name'])) {
                $affiliations[] = $employment['organization']['name'];
            }
        }
    }
    
    if (!empty($affiliations)) {
        $author_data['affiliation'] = implode(', ', array_unique($affiliations));
    }
    
    $author_data['orcid'] = $orcid;
    
    return $author_data;
}

// Create authors table if it doesn't exist
function sjm_create_authors_table() {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'sjm_authors';
    
    // Check if table already exists
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
        return true; // Table already exists
    }
    
    // Create the authors table
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        first_name varchar(100) NOT NULL,
        last_name varchar(100) NOT NULL,
        email varchar(255) DEFAULT NULL,
        affiliation text DEFAULT NULL,
        bio text DEFAULT NULL,
        website varchar(255) DEFAULT NULL,
        orcid varchar(50) DEFAULT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY orcid (orcid),
        KEY email (email),
        KEY name_index (last_name, first_name)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
    
    // Log the table creation
    WJM_Security_Manager::log_security_event('authors_table_created', array(
        'table_name' => $table_name,
        'status' => 'success'
    ), 'info');
    
    return true;
}

// Function to save or update author
function sjm_save_author($author_data) {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'sjm_authors';
    
    // Handle empty ORCID - set to NULL to avoid unique constraint issues
    $orcid_value = !empty($author_data['orcid']) ? sanitize_text_field($author_data['orcid']) : null;
    
    // Check if author already exists by ORCID or email
    $existing_author = null;
    if (!empty($author_data['orcid'])) {
        $existing_author = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name WHERE orcid = %s",
            $author_data['orcid']
        ));
    } elseif (!empty($author_data['email'])) {
        $existing_author = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name WHERE email = %s",
            $author_data['email']
        ));
    }
    
    $data_to_save = array(
        'first_name' => sanitize_text_field($author_data['first_name']),
        'last_name' => sanitize_text_field($author_data['last_name']),
        'email' => sanitize_email($author_data['email']),
        'affiliation' => sanitize_textarea_field($author_data['affiliation']),
        'bio' => sanitize_textarea_field($author_data['bio']),
        'website' => esc_url_raw($author_data['website']),
        'orcid' => $orcid_value
    );
    
    if ($existing_author) {
        // Update existing author
        $wpdb->update(
            $table_name,
            $data_to_save,
            array('id' => $existing_author->id),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s'),
            array('%d')
        );
        return $existing_author->id;
    } else {
        // Insert new author
        $result = $wpdb->insert(
            $table_name,
            $data_to_save,
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s')
        );
        
        if ($result === false) {
            // Log the error for debugging
            error_log('SJM Author Insert Error: ' . $wpdb->last_error);
            return false;
        }
        
        return $wpdb->insert_id;
    }
}

// Function to get all authors
function sjm_get_all_authors() {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'sjm_authors';
    
    // Check if table exists first, create if it doesn't
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
        sjm_create_authors_table();
    }
    
    $results = $wpdb->get_results("SELECT * FROM $table_name ORDER BY last_name, first_name");
    
    // Return empty array if query fails
    return $results ? $results : array();
}

// Function to get author by ID
function sjm_get_author_by_id($author_id) {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'sjm_authors';
    
    // Check if table exists first, create if it doesn't
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
        sjm_create_authors_table();
        // If table was just created, there are no authors yet
        return null;
    }
    
    return $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE id = %d",
        $author_id
    ));
}

// AJAX handler for ORCID lookup
function sjm_orcid_lookup() {
    // Simple security check - just verify it's an admin user
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Permission denied.');
        return;
    }
    
    $orcid = sanitize_text_field($_POST['orcid']);
    
    $author_data = sjm_fetch_orcid_data($orcid);
    
    if ($author_data) {
        wp_send_json_success($author_data);
    } else {
        wp_send_json_error('Could not fetch ORCID data. Please check the ORCID ID.');
    }
}
add_action('wp_ajax_sjm_orcid_lookup', 'sjm_orcid_lookup');

// AJAX handler for saving author
function sjm_save_author_ajax() {
    // Simple security check - just verify it's an admin user
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Permission denied.');
        return;
    }
    
    // Ensure the authors table exists
    sjm_create_authors_table();
    
    $author_data = array(
        'first_name' => sanitize_text_field($_POST['first_name']),
        'last_name' => sanitize_text_field($_POST['last_name']),
        'email' => sanitize_email($_POST['email']),
        'affiliation' => sanitize_textarea_field($_POST['affiliation']),
        'bio' => sanitize_textarea_field($_POST['bio']),
        'website' => esc_url_raw($_POST['website']),
        'orcid' => sanitize_text_field($_POST['orcid'])
    );
    
    $author_id = sjm_save_author($author_data);
    
    if ($author_id) {
        $author = sjm_get_author_by_id($author_id);
        wp_send_json_success(array(
            'author_id' => $author_id,
            'author' => $author,
            'message' => 'Author added successfully!'
        ));
    } else {
        wp_send_json_error('Could not save author. Database error occurred.');
    }
}
add_action('wp_ajax_sjm_save_author', 'sjm_save_author_ajax');

// Admin page for author management
function sjm_add_authors_management_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Author Management',
        'Authors',
        'manage_options',
        'sjm-authors',
        'sjm_authors_page'
    );
}
add_action('admin_menu', 'sjm_add_authors_management_page');

function sjm_authors_page() {
    global $wpdb;
    
    // Ensure table exists
    $table_name = $wpdb->prefix . 'sjm_authors';
    sjm_create_authors_table();
    
    // Handle form submission for adding new author
    if (isset($_POST['add_author']) && wp_verify_nonce($_POST['sjm_author_nonce'], 'sjm_add_author')) {
        $first_name = sanitize_text_field($_POST['first_name']);
        $last_name = sanitize_text_field($_POST['last_name']);
        
        if (!empty($first_name) && !empty($last_name)) {
            $author_data = array(
                'first_name' => $first_name,
                'last_name' => $last_name,
                'email' => sanitize_email($_POST['email']),
                'affiliation' => sanitize_textarea_field($_POST['affiliation']),
                'bio' => sanitize_textarea_field($_POST['bio']),
                'website' => esc_url_raw($_POST['website']),
                'orcid' => sanitize_text_field($_POST['orcid'])
            );
            
            $author_id = sjm_save_author($author_data);
            
            if ($author_id) {
                echo '<div class="notice notice-success"><p><strong>Success!</strong> Author "' . esc_html($first_name . ' ' . $last_name) . '" has been added successfully!</p></div>';
            } else {
                echo '<div class="notice notice-error"><p><strong>Error:</strong> Could not save author. Please try again.</p></div>';
            }
        } else {
            echo '<div class="notice notice-error"><p><strong>Error:</strong> First Name and Last Name are required fields.</p></div>';
        }
    }
    
    // Handle author deletion
    if (isset($_POST['delete_author']) && wp_verify_nonce($_POST['sjm_author_nonce'], 'sjm_delete_author')) {
        $author_id = intval($_POST['author_id']);
        
        $deleted = $wpdb->delete($table_name, array('id' => $author_id), array('%d'));
        if ($deleted) {
            echo '<div class="notice notice-success"><p><strong>Success!</strong> Author deleted successfully!</p></div>';
        } else {
            echo '<div class="notice notice-error"><p><strong>Error:</strong> Could not delete author.</p></div>';
        }
    }
    
    // Fix any existing empty ORCID values
    $wpdb->query("UPDATE $table_name SET orcid = NULL WHERE orcid = ''");
    
    // Show current table status
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");
    if (!$table_exists) {
        echo '<div class="notice notice-warning"><p><strong>WARNING: Authors table does not exist!</strong> <a href="' . admin_url('edit.php?post_type=journal&page=sjm-authors&force_create_table=1') . '" class="button">Force Create Table</a></p></div>';
    } else {
        echo '<div class="notice notice-success"><p><strong>Authors table exists.</strong> Table name: ' . $table_name . '</p></div>';
    }
    
    $authors = sjm_get_all_authors();
    ?>
    <div class="wrap">
        <h1>Author Management</h1>
        
        <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-top: 20px;">
            <!-- Add New Author Section -->
            <div class="postbox">
                <h2 class="hndle">Add New Author</h2>
                <div class="inside">
                    <form method="post" action="">
                        <?php wp_nonce_field('sjm_add_author', 'sjm_author_nonce'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="orcid">ORCID ID</label></th>
                                <td style="position:relative;">
                                    <input type="text" id="orcid" name="orcid" placeholder="0000-0000-0000-0000" class="regular-text" style="max-width:220px;">
                                    <button type="button" id="sjm-fetch-orcid" class="button" style="margin-left:8px;vertical-align:top;">Fetch from ORCID</button>
                                    <span id="sjm-orcid-loading" style="display:none;margin-left:8px;vertical-align:middle;">Loading...</span>
                                    <span id="sjm-orcid-message" style="display:none;margin-left:8px;"></span>
                                    <p class="description">Optional: Enter ORCID ID for author identification</p>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="first_name">First Name</label></th>
                                <td><input type="text" id="first_name" name="first_name" class="regular-text"></td>
                            </tr>
                            <tr>
                                <th><label for="last_name">Last Name</label></th>
                                <td><input type="text" id="last_name" name="last_name" class="regular-text"></td>
                            </tr>
                            <tr>
                                <th><label for="email">Email</label></th>
                                <td><input type="email" id="email" name="email" class="regular-text"></td>
                            </tr>
                            <tr>
                                <th><label for="affiliation">Affiliation</label></th>
                                <td>
                                    <textarea id="affiliation" name="affiliation" rows="3" class="large-text" placeholder="University, Institution, or Organization"></textarea>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="bio">Bio</label></th>
                                <td>
                                    <textarea id="bio" name="bio" rows="4" class="large-text" placeholder="Brief biography or description"></textarea>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="website">Website</label></th>
                                <td><input type="url" id="website" name="website" class="regular-text" placeholder="https://"></td>
                            </tr>
                        </table>
                        <p class="submit">
                            <input type="submit" name="add_author" class="button-primary" value="Add Author">
                        </p>
                    </form>
                </div>
            </div>
            
            <!-- Existing Authors Section -->
            <div class="postbox">
                <h2 class="hndle">Existing Authors (<?php echo count($authors); ?>)</h2>
                <div class="inside">
                    <?php if ($authors): ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>ORCID</th>
                                    <th>Email</th>
                                    <th>Affiliation</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($authors as $author): ?>
                                    <tr>
                                        <td>
                                            <strong><?php echo esc_html($author->first_name . ' ' . $author->last_name); ?></strong>
                                        </td>
                                        <td>
                                            <?php if ($author->orcid): ?>
                                                <a href="https://orcid.org/<?php echo esc_attr($author->orcid); ?>" target="_blank">
                                                    <?php echo esc_html($author->orcid); ?>
                                                </a>
                                            <?php else: ?>
                                                <span style="color: #666;">—</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo esc_html($author->email ?: '—'); ?></td>
                                        <td><?php echo esc_html(wp_trim_words($author->affiliation ?: '—', 8)); ?></td>
                                        <td>
                                            <a href="<?php echo esc_url(sjm_get_author_profile_url($author->id)); ?>" 
                                               class="button button-small" 
                                               target="_blank" 
                                               style="margin-right: 5px;">
                                                View Profile
                                            </a>
                                            <form method="post" style="display: inline-block;">
                                                <?php wp_nonce_field('sjm_delete_author', 'sjm_author_nonce'); ?>
                                                <input type="hidden" name="author_id" value="<?php echo esc_attr($author->id); ?>">
                                                <input type="submit" name="delete_author" class="button button-small" value="Delete" onclick="return confirm('Are you sure?');">
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p>No authors found. Add your first author above.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    
    <script>
    jQuery(document).ready(function($) {
        // Simple form validation - only for the add author form
        $('form').submit(function() {
            // Only validate if this form has the add_author submit button
            if ($(this).find('input[name="add_author"]').length > 0) {
                var firstName = $('#first_name').val().trim();
                var lastName = $('#last_name').val().trim();
                
                if (!firstName || !lastName) {
                    alert('First Name and Last Name are required fields.');
                    return false;
                }
            }
            
            return true;
        });

        // Fetch from ORCID button logic
        $('#sjm-fetch-orcid').on('click', function() {
            var orcid = $('#orcid').val().trim();
            var $loading = $('#sjm-orcid-loading');
            var $msg = $('#sjm-orcid-message');
            $msg.hide().text('');
            if (!orcid) {
                $msg.text('Please enter an ORCID ID.').css('color', '#dc2626').show();
                return;
            }
            $loading.show();
            $.post(ajaxurl, { action: 'sjm_orcid_lookup', orcid: orcid }, function(response) {
                $loading.hide();
                if (response.success && response.data) {
                    var d = response.data;
                    if (d.first_name) $('#first_name').val(d.first_name);
                    if (d.last_name) $('#last_name').val(d.last_name);
                    if (d.email) $('#email').val(d.email);
                    if (d.affiliation) $('#affiliation').val(d.affiliation);
                    if (d.bio) $('#bio').val(d.bio);
                    $msg.text('ORCID data loaded!').css('color', '#059669').show();
                } else {
                    $msg.text(response.data || 'Could not fetch ORCID data.').css('color', '#dc2626').show();
                }
            }).fail(function() {
                $loading.hide();
                $msg.text('Error contacting ORCID.').css('color', '#dc2626').show();
            });
        });
    });
    </script>
    <?php
}

// Function to get author profile URL
function sjm_get_author_profile_url($author_id) {
    $author = sjm_get_author_by_id($author_id);
    if (!$author) return '#';
    
    // Create a slug from the author's name
    $slug = sanitize_title($author->first_name . '-' . $author->last_name);
    return home_url("/author/{$slug}-{$author_id}/");
}

// Function to get user profile URL
function sjm_get_user_profile_url($user_id) {
    $user = get_user_by('ID', $user_id);
    if (!$user || !sjm_user_has_journal_roles($user)) return '#';
    
    // Create a slug from the user's display name
    $slug = sanitize_title($user->display_name);
    return home_url("/user/{$slug}-{$user_id}/");
}

// Function to format author display with links
function sjm_format_author_display($author, $author_data = array(), $show_links = true, $show_details = false) {
    if (!$author) return '';
    
    $output = '';
    $author_name = esc_html($author->first_name . ' ' . $author->last_name);
    
    if ($show_links) {
        $profile_url = sjm_get_author_profile_url($author->id);
        $output .= '<a href="' . esc_url($profile_url) . '" style="color: #1e40af; text-decoration: none; font-weight: 500;">' . $author_name . '</a>';
    } else {
        $output .= '<span style="font-weight: 500;">' . $author_name . '</span>';
    }
    
    // Add corresponding author indicator
    if (!empty($author_data['is_corresponding']) && $author_data['is_corresponding'] == '1') {
        $output .= '<sup style="color: #dc2626;">*</sup>';
    }
    
    if ($show_details) {
        $details = array();
        
                if ($author->orcid) {
            $details[] = '<a href="https://orcid.org/' . esc_attr($author->orcid) . '" target="_blank" style="color: #059669; text-decoration: none; font-size: 0.9em;">ORCID: ' . esc_html($author->orcid) . '</a>';
                }
                
        if ($author->email) {
            $details[] = '<a href="mailto:' . esc_attr($author->email) . '" style="color: #2563eb; text-decoration: none; font-size: 0.9em;">' . esc_html($author->email) . '</a>';
                }
                
                if ($author->affiliation) {
            $details[] = '<span style="color: #6b7280; font-size: 0.9em;">' . esc_html($author->affiliation) . '</span>';
        }
        
        if (!empty($author_data['contributions'])) {
            $details[] = '<span style="color: #6b7280; font-size: 0.9em; font-style: italic;">Contributions: ' . esc_html($author_data['contributions']) . '</span>';
        }
        
        if (!empty($details)) {
            $output .= '<br><small>' . implode(' | ', $details) . '</small>';
        }
    }
    
    return $output;
}

// AJAX handler to get all authors for dropdowns
add_action('wp_ajax_sjm_get_all_authors', 'sjm_get_all_authors_ajax');
function sjm_get_all_authors_ajax() {
    $authors = sjm_get_all_authors();
    $result = array();
    foreach ($authors as $author) {
        $result[] = array(
            'id' => $author->id,
            'name' => $author->first_name . ' ' . $author->last_name,
            'orcid' => $author->orcid,
            'affiliation' => $author->affiliation
        );
    }
    wp_send_json($result);
}

// AJAX handler to get users by role for dropdowns
add_action('wp_ajax_sjm_get_users_by_role', 'sjm_get_users_by_role_ajax');
function sjm_get_users_by_role_ajax() {
    // Verify nonce
    if (!wp_verify_nonce($_POST['nonce'], 'sjm_get_users_nonce')) {
        wp_send_json_error('Invalid nonce');
        return;
    }
    
    $role = sanitize_text_field($_POST['role']);
    $users = sjm_get_users_by_journal_role($role);
    
    $formatted_users = array();
    foreach ($users as $user) {
        $formatted_users[] = array(
            'id' => $user->ID,
            'name' => $user->display_name . ' (' . $user->user_email . ')'
        );
    }
    
    wp_send_json_success($formatted_users);
}

// AJAX handler to check journal open access status
function sjm_check_journal_open_access() {
    // Security checks
    if (!is_user_logged_in()) {
        wp_send_json_error('Not logged in');
        return;
    }
    
    // Rate limiting
    if (!sjm_check_rate_limit('ajax_check_journal', get_current_user_id(), 30, 60)) {
        wp_send_json_error('Too many requests');
        return;
    }
    
    if (!isset($_POST['journal_id']) || empty($_POST['journal_id'])) {
        wp_send_json_error('Journal ID is required');
        return;
    }
    
    $journal_id = sjm_sanitize_input($_POST['journal_id'], 'int');
    
    // Validate journal exists
    $journal = get_post($journal_id);
    if (!$journal || $journal->post_type !== 'journal') {
        wp_send_json_error('Invalid journal');
        return;
    }
    
    $open_access = get_post_meta($journal_id, '_sjm_open_access', true);
    
    wp_send_json_success(array(
        'open_access' => $open_access == '1',
        'journal_title' => sjm_safe_output(get_the_title($journal_id))
    ));
}
add_action('wp_ajax_sjm_check_journal_open_access', 'sjm_check_journal_open_access');

// Function to get papers that would be affected by journal open access change
function sjm_get_papers_affected_by_journal_change($journal_id, $new_open_access_status) {
    $papers = get_posts(array(
                'post_type' => 'paper',
                'posts_per_page' => -1,
                'meta_query' => array(
                    array(
                'key' => '_sjm_paper_journal',
                'value' => $journal_id,
                'compare' => '='
            )
        )
    ));
    
    $affected_papers = array();
    foreach ($papers as $paper) {
        $paper_open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
        
        // If journal is becoming closed and paper is open access, it will be affected
        if ($new_open_access_status == '0' && $paper_open_access == '1') {
            $affected_papers[] = array(
                'id' => $paper->ID,
                'title' => $paper->post_title,
                'current_status' => 'open_access'
            );
        }
    }
    
    return $affected_papers;
}

// AJAX handler to get affected papers when journal open access changes
function sjm_get_affected_papers() {
    // Security checks
    if (!sjm_check_user_capability('edit_paper')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }
    
    // Verify nonce
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'sjm_ajax_nonce')) {
        wp_send_json_error('Security check failed');
        return;
    }
    
    // Rate limiting
    if (!sjm_check_rate_limit('ajax_affected_papers', get_current_user_id(), 20, 60)) {
        wp_send_json_error('Too many requests');
        return;
    }
    
    if (!isset($_POST['journal_id']) || !isset($_POST['new_status'])) {
        wp_send_json_error('Journal ID and new status are required');
        return;
    }
    
    $journal_id = sjm_sanitize_input($_POST['journal_id'], 'int');
    $new_status = $_POST['new_status'] === 'true' ? '1' : '0';
    
    // Validate journal exists and user can edit it
    $journal = get_post($journal_id);
    if (!$journal || $journal->post_type !== 'journal') {
        wp_send_json_error('Invalid journal');
        return;
    }
    
    if (!current_user_can('edit_post', $journal_id)) {
        wp_send_json_error('Cannot edit this journal');
        return;
    }
    
    $affected_papers = sjm_get_papers_affected_by_journal_change($journal_id, $new_status);
    
    // Log security event
    sjm_log_security_event('ajax_affected_papers', array(
        'journal_id' => $journal_id,
        'new_status' => $new_status,
        'affected_count' => count($affected_papers)
    ));
    
    wp_send_json_success(array(
        'affected_papers' => $affected_papers,
        'count' => count($affected_papers)
    ));
}
add_action('wp_ajax_sjm_get_affected_papers', 'sjm_get_affected_papers');

// AJAX handler to bulk update papers when journal open access changes
function sjm_bulk_update_papers_open_access() {
    // Security checks
    if (!sjm_check_user_capability('edit_paper')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }
    
    // Verify nonce
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'sjm_ajax_nonce')) {
        wp_send_json_error('Security check failed');
        return;
    }
    
    // Rate limiting
    if (!sjm_check_rate_limit('ajax_bulk_update', get_current_user_id(), 5, 300)) {
        wp_send_json_error('Too many bulk update requests');
        return;
    }
    
    if (!isset($_POST['journal_id']) || !isset($_POST['new_status'])) {
        wp_send_json_error('Journal ID and new status are required');
        return;
    }
    
    $journal_id = sjm_sanitize_input($_POST['journal_id'], 'int');
    $new_status = $_POST['new_status'] === 'true' ? '1' : '0';
    
    // Validate journal exists and user can edit it
    $journal = get_post($journal_id);
    if (!$journal || $journal->post_type !== 'journal') {
        wp_send_json_error('Invalid journal');
        return;
    }
    
    if (!current_user_can('edit_post', $journal_id)) {
        wp_send_json_error('Cannot edit this journal');
        return;
    }
    
    $affected_papers = sjm_get_papers_affected_by_journal_change($journal_id, $new_status);
    $updated_count = 0;
    
    foreach ($affected_papers as $paper) {
        // Check if user can edit each paper
        if (current_user_can('edit_post', $paper['id'])) {
            update_post_meta($paper['id'], '_sjm_paper_open_access', '0');
            $updated_count++;
        }
    }
    
    // Log security event
    sjm_log_security_event('bulk_update_papers', array(
        'journal_id' => $journal_id,
        'new_status' => $new_status,
        'updated_count' => $updated_count
    ));
    
    wp_send_json_success(array(
        'updated_count' => $updated_count,
        'message' => sprintf('Updated %d papers to match journal open access status.', $updated_count)
    ));
}
add_action('wp_ajax_sjm_bulk_update_papers_open_access', 'sjm_bulk_update_papers_open_access');



// Add admin notices for paper open access changes
function sjm_admin_notices() {
    // Handle paper open access notice
    $notice = get_transient('sjm_paper_open_access_notice');
    if ($notice) {
        $class = $notice['type'] === 'warning' ? 'notice-warning' : 'notice-info';
        echo '<div class="notice ' . $class . ' is-dismissible"><p>' . esc_html($notice['message']) . '</p></div>';
        delete_transient('sjm_paper_open_access_notice');
    }
    
    // Handle paper required field validation notices
    global $post;
    if ($post && $post->post_type === 'paper') {
        $paper_notice = get_transient('sjm_paper_required_notice_' . $post->ID);
        if ($paper_notice) {
            $class = $paper_notice['type'] === 'error' ? 'notice-error' : 'notice-warning';
            echo '<div class="notice ' . $class . ' is-dismissible"><p>' . esc_html($paper_notice['message']) . '</p></div>';
            delete_transient('sjm_paper_required_notice_' . $post->ID);
        }
    }
    
    // Handle issue required field validation notices
    if ($post && $post->post_type === 'journal_issue') {
        $issue_notice = get_transient('sjm_issue_required_notice_' . $post->ID);
        if ($issue_notice) {
            $class = $issue_notice['type'] === 'error' ? 'notice-error' : 'notice-warning';
            echo '<div class="notice ' . $class . ' is-dismissible"><p>' . esc_html($issue_notice['message']) . '</p></div>';
            delete_transient('sjm_issue_required_notice_' . $post->ID);
        }
    }
}
add_action('admin_notices', 'sjm_admin_notices');

// Enhanced JavaScript for journal open access change handling
function sjm_enhanced_admin_scripts() {
    global $post_type;
    
    // Only load on journal and paper edit screens
    if (!in_array($post_type, array('journal', 'paper'))) {
        return;
    }
    
    // Localize script with security nonce
    wp_localize_script('jquery', 'sjm_ajax_object', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('sjm_ajax_nonce'),
        'user_id' => get_current_user_id()
    ));
    
    ?>
    <script type="text/javascript">
    jQuery(document).ready(function($) {
        // Enhanced paper open access logic
        function updatePaperOpenAccessCheckbox() {
            var journalId = $("#sjm_paper_journal").val();
            if (!journalId) {
                $("#sjm_paper_open_access").prop("checked", false).prop("disabled", true);
                $("#sjm_paper_open_access_msg").show();
                return;
            }
            
            $.ajax({
                url: ajaxurl,
                method: "POST",
                data: { 
                    action: "sjm_check_journal_open_access", 
                    journal_id: journalId,
                    nonce: sjm_ajax_object.nonce
                },
                success: function(resp) {
                    if (resp.success && resp.data.open_access) {
                        $("#sjm_paper_open_access").prop("disabled", false);
                        $("#sjm_paper_open_access_msg").hide();
                    } else {
                        $("#sjm_paper_open_access").prop("checked", false).prop("disabled", true);
                        $("#sjm_paper_open_access_msg").show();
                    }
                },
                error: function() {
                    $("#sjm_paper_open_access").prop("checked", false).prop("disabled", true);
                    $("#sjm_paper_open_access_msg").show();
                }
            });
        }
        
        // Journal open access change handler
        function handleJournalOpenAccessChange() {
            var journalId = $("input[name='post_ID']").val();
            var isOpenAccess = $("#sjm_open_access").is(":checked");
            
            if (!journalId) return;
            
            $.ajax({
                url: ajaxurl,
                method: "POST",
                data: { 
                    action: "sjm_get_affected_papers", 
                    journal_id: journalId,
                    new_status: isOpenAccess,
                    nonce: sjm_ajax_object.nonce
                },
                success: function(resp) {
                    if (resp.success && resp.data.count > 0) {
                        showAffectedPapersDialog(resp.data.affected_papers, isOpenAccess);
                    }
                }
            });
        }
        
        function showAffectedPapersDialog(affectedPapers, isOpenAccess) {
            var message = isOpenAccess ? 
                "This journal is being marked as open access. All papers will now be eligible for open access status." :
                "This journal is being marked as closed access. " + affectedPapers.length + " paper(s) currently marked as open access will be affected.";
            
            var dialogContent = '<div id="sjm-affected-papers-dialog" style="display:none;">' +
                '<h3>Academic Workflow Notice</h3>' +
                '<p>' + message + '</p>';
            
            if (!isOpenAccess && affectedPapers.length > 0) {
                dialogContent += '<h4>Affected Papers:</h4><ul>';
                affectedPapers.forEach(function(paper) {
                    dialogContent += '<li>' + paper.title + '</li>';
                });
                dialogContent += '</ul>';
                dialogContent += '<p><strong>Would you like to automatically update these papers to match the journal\'s new status?</strong></p>';
                dialogContent += '<button type="button" id="sjm-update-papers" class="button button-primary">Yes, Update Papers</button> ';
                dialogContent += '<button type="button" id="sjm-keep-papers" class="button">No, Keep Papers As-Is</button>';
            }
            
            dialogContent += '</div>';
            
            if ($("#sjm-affected-papers-dialog").length === 0) {
                $("body").append(dialogContent);
            }
            
            $("#sjm-affected-papers-dialog").dialog({
                modal: true,
                width: 500,
                close: function() {
                    $(this).dialog("destroy");
                }
            });
        }
        
        // Event handlers
        if ($("#sjm_paper_journal").length) {
            $("#sjm_paper_journal").on("change", updatePaperOpenAccessCheckbox);
            updatePaperOpenAccessCheckbox();
        }
        
        if ($("#sjm_open_access").length) {
            $("#sjm_open_access").on("change", handleJournalOpenAccessChange);
        }
        
        // Handle bulk update button
        $(document).on("click", "#sjm-update-papers", function() {
            var journalId = $("input[name='post_ID']").val();
            var isOpenAccess = $("#sjm_open_access").is(":checked");
            
            $.ajax({
                url: ajaxurl,
                method: "POST",
                data: { 
                    action: "sjm_bulk_update_papers_open_access", 
                    journal_id: journalId,
                    new_status: isOpenAccess,
                    nonce: sjm_ajax_object.nonce
                },
                success: function(resp) {
                    if (resp.success) {
                        $("#sjm-affected-papers-dialog").dialog("close");
                        alert(resp.data.message);
                    }
                }
            });
        });
        
        $(document).on("click", "#sjm-keep-papers", function() {
            $("#sjm-affected-papers-dialog").dialog("close");
        });
    });
    </script>
    <?php
}
add_action('admin_footer', 'sjm_enhanced_admin_scripts');

// Add jQuery UI for dialogs
function sjm_admin_enqueue_scripts() {
    global $post_type;
    
    if (in_array($post_type, array('journal', 'paper'))) {
        wp_enqueue_script('jquery-ui-dialog');
        wp_enqueue_style('wp-jquery-ui-dialog');
    }
}
add_action('admin_enqueue_scripts', 'sjm_admin_enqueue_scripts');

// Import/Export functionality
function sjm_add_import_export_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Import/Export',
        'Import/Export',
        'manage_options',
        'sjm-import-export',
        'sjm_import_export_page'
    );
}
add_action('admin_menu', 'sjm_add_import_export_page');

function sjm_import_export_page() {
    $message = '';
    $error = '';
    
    // Handle import
    if (isset($_POST['sjm_import']) && wp_verify_nonce($_POST['sjm_import_nonce'], 'sjm_import_data')) {
        $result = sjm_handle_import();
        if (is_wp_error($result)) {
            $error = $result->get_error_message();
        } else {
            $message = 'Import completed successfully! ' . $result['imported'] . ' items imported.';
        }
    }
    
    // Handle export
    if (isset($_POST['sjm_export']) && wp_verify_nonce($_POST['sjm_export_nonce'], 'sjm_export_data')) {
        sjm_handle_export();
        exit;
    }
    
    ?>
    <div class="wrap">
        <h1>Import/Export Journal Data</h1>
        
        <?php if ($message): ?>
            <div class="notice notice-success is-dismissible">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="notice notice-error is-dismissible">
                <p><?php echo esc_html($error); ?></p>
            </div>
        <?php endif; ?>
        
        <div class="postbox">
            <h2 class="hndle">Import Data</h2>
            <div class="inside">
                <form method="post" enctype="multipart/form-data">
                    <?php wp_nonce_field('sjm_import_data', 'sjm_import_nonce'); ?>
                    
                    <table class="form-table">
                        <tr>
                            <th><label for="import_type">Content Type</label></th>
                            <td>
                                <select name="import_type" id="import_type">
                                    <option value="">Select content type</option>
                                    <option value="journals">Journals</option>
                                    <option value="issues">Issues</option>
                                    <option value="papers">Papers</option>
                                    <option value="authors">Authors</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="import_file">CSV File</label></th>
                            <td>
                                <input type="file" name="import_file" id="import_file" accept=".csv" />
                                <p class="description">Upload a CSV file with your data. <a href="#" id="download_template">Download template</a></p>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="import_options">Options</label></th>
                            <td>
                                <label><input type="checkbox" name="import_options[]" value="skip_duplicates" /> Skip duplicates</label><br>
                                <label><input type="checkbox" name="import_options[]" value="update_existing" /> Update existing items</label>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <input type="submit" name="sjm_import" class="button-primary" value="Import Data" />
                    </p>
                </form>
            </div>
        </div>
        
        <div class="postbox">
            <h2 class="hndle">Export Data</h2>
            <div class="inside">
                <form method="post">
                    <?php wp_nonce_field('sjm_export_data', 'sjm_export_nonce'); ?>
                    
                    <table class="form-table">
                        <tr>
                            <th><label for="export_type">Content Type</label></th>
                            <td>
                                <select name="export_type" id="export_type">
                                    <option value="">Select content type</option>
                                    <option value="journals">Journals</option>
                                    <option value="issues">Issues</option>
                                    <option value="papers">Papers</option>
                                    <option value="authors">Authors</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="export_format">Format</label></th>
                            <td>
                                <select name="export_format" id="export_format">
                                    <option value="csv">CSV</option>
                                    <option value="json">JSON</option>
                                    <option value="xml">XML</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="export_filters">Filters</label></th>
                            <td>
                                <label>Date Range:</label><br>
                                <input type="date" name="export_date_from" placeholder="From" />
                                <input type="date" name="export_date_to" placeholder="To" /><br><br>
                                
                                <label>Journal:</label><br>
                                <select name="export_journal">
                                    <option value="">All journals</option>
                                    <?php
                                    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
                                    foreach ($journals as $journal) {
                                        echo '<option value="' . $journal->ID . '">' . esc_html($journal->post_title) . '</option>';
                                    }
                                    ?>
                                </select><br><br>
                                
                                <label>Open Access:</label><br>
                                <select name="export_open_access">
                                    <option value="">All</option>
                                    <option value="1">Open Access only</option>
                                    <option value="0">Closed Access only</option>
                                </select>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <input type="submit" name="sjm_export" class="button-primary" value="Export Data" />
                    </p>
                </form>
            </div>
        </div>
    </div>
    
    <script>
    jQuery(document).ready(function($) {
        $('#download_template').click(function(e) {
            e.preventDefault();
            var importType = $('#import_type').val();
            if (!importType) {
                alert('Please select a content type first.');
                return;
            }
            
            // Generate template based on type
            var template = sjm_generate_template(importType);
            sjm_download_csv(template, importType + '_template.csv');
        });
        
        function sjm_generate_template(type) {
            var headers = [];
            switch(type) {
                case 'journals':
                    headers = ['Title', 'Content', 'ISSN', 'Publisher', 'Editor in Chief ID', 'Founding Year', 'Open Access', 'Peer Reviewed', 'Frequency', 'Subject Areas'];
                    break;
                case 'issues':
                    headers = ['Title', 'Content', 'Journal ID', 'Issue Number', 'Volume', 'Year', 'Publication Date', 'Special Issue', 'Special Issue Title'];
                    break;
                case 'papers':
                    headers = ['Title', 'Content', 'Journal ID', 'Issue ID', 'Abstract', 'Paper Type', 'Submission Date', 'Acceptance Date', 'Open Access', 'DOI'];
                    break;
                case 'authors':
                    headers = ['First Name', 'Last Name', 'Email', 'ORCID', 'Affiliation', 'Bio', 'Website'];
                    break;
            }
            return headers.join(',');
        }
        
        function sjm_download_csv(content, filename) {
            var blob = new Blob([content], { type: 'text/csv' });
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            window.URL.revokeObjectURL(url);
        }
    });
    </script>
    <?php
}

function sjm_handle_import() {
    if (!isset($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK) {
        return new WP_Error('upload_error', 'File upload failed.');
    }
    
    $import_type = sanitize_text_field($_POST['import_type']);
    $import_options = isset($_POST['import_options']) ? $_POST['import_options'] : array();
    
    $file = $_FILES['import_file']['tmp_name'];
    $handle = fopen($file, 'r');
    
    if (!$handle) {
        return new WP_Error('file_error', 'Could not open file.');
    }
    
    $headers = fgetcsv($handle);
    if (!$headers) {
        fclose($handle);
        return new WP_Error('format_error', 'Invalid CSV format.');
    }
    
    $imported = 0;
    $row = 1;
    
    while (($data = fgetcsv($handle)) !== false) {
        $row++;
        
        if (count($data) !== count($headers)) {
            continue; // Skip malformed rows
        }
        
        $item_data = array_combine($headers, $data);
        
        switch ($import_type) {
            case 'journals':
                $result = sjm_import_journal($item_data, $import_options);
                break;
            case 'issues':
                $result = sjm_import_issue($item_data, $import_options);
                break;
            case 'papers':
                $result = sjm_import_paper($item_data, $import_options);
                break;
            case 'authors':
                $result = sjm_import_author($item_data, $import_options);
                break;
            default:
                continue 2;
        }
        
        if ($result) {
            $imported++;
        }
    }
    
    fclose($handle);
    
    return array('imported' => $imported);
}

function sjm_import_journal($data, $options) {
    $post_data = array(
        'post_title' => sanitize_text_field($data['Title']),
        'post_content' => wp_kses_post($data['Content']),
        'post_type' => 'journal',
        'post_status' => 'publish'
    );
    
    // Check for duplicates
    if (in_array('skip_duplicates', $options)) {
        $existing = get_posts(array(
            'post_type' => 'journal',
            'meta_query' => array(
                array('key' => '_sjm_issn', 'value' => $data['ISSN'])
            ),
            'posts_per_page' => 1
        ));
        
        if (!empty($existing)) {
            return false;
        }
    }
    
    $journal_id = wp_insert_post($post_data);
    
    if ($journal_id) {
        update_post_meta($journal_id, '_sjm_issn', sanitize_text_field($data['ISSN']));
        update_post_meta($journal_id, '_sjm_publisher', sanitize_text_field($data['Publisher']));
        update_post_meta($journal_id, '_sjm_editor_in_chief_id', intval($data['Editor in Chief ID']));
        update_post_meta($journal_id, '_sjm_founding_year', sanitize_text_field($data['Founding Year']));
        update_post_meta($journal_id, '_sjm_open_access', $data['Open Access'] == '1' ? '1' : '0');
        update_post_meta($journal_id, '_sjm_peer_reviewed', $data['Peer Reviewed'] == '1' ? '1' : '0');
        update_post_meta($journal_id, '_sjm_frequency', sanitize_text_field($data['Frequency']));
        update_post_meta($journal_id, '_sjm_subject_areas', sanitize_textarea_field($data['Subject Areas']));
        
        return $journal_id;
    }
    
    return false;
}

function sjm_import_issue($data, $options) {
    $post_data = array(
        'post_title' => sanitize_text_field($data['Title']),
        'post_content' => wp_kses_post($data['Content']),
        'post_type' => 'journal_issue',
        'post_status' => 'publish'
    );
    
    $issue_id = wp_insert_post($post_data);
    
    if ($issue_id) {
        update_post_meta($issue_id, '_sjm_issue_journal', intval($data['Journal ID']));
        update_post_meta($issue_id, '_sjm_issue_number', sanitize_text_field($data['Issue Number']));
        update_post_meta($issue_id, '_sjm_issue_volume', sanitize_text_field($data['Volume']));
        update_post_meta($issue_id, '_sjm_issue_year', sanitize_text_field($data['Year']));
        update_post_meta($issue_id, '_sjm_publication_date', sanitize_text_field($data['Publication Date']));
        update_post_meta($issue_id, '_sjm_special_issue', $data['Special Issue'] == '1' ? '1' : '0');
        update_post_meta($issue_id, '_sjm_special_issue_title', sanitize_text_field($data['Special Issue Title']));
        
        return $issue_id;
    }
    
    return false;
}

function sjm_import_paper($data, $options) {
    $post_data = array(
        'post_title' => sanitize_text_field($data['Title']),
        'post_content' => wp_kses_post($data['Content']),
        'post_type' => 'paper',
        'post_status' => 'publish'
    );
    
    $paper_id = wp_insert_post($post_data);
    
    if ($paper_id) {
        update_post_meta($paper_id, '_sjm_paper_journal', intval($data['Journal ID']));
        update_post_meta($paper_id, '_sjm_paper_issue', intval($data['Issue ID']));
        update_post_meta($paper_id, '_sjm_paper_abstract', sanitize_textarea_field($data['Abstract']));
        update_post_meta($paper_id, '_sjm_paper_type', sanitize_text_field($data['Paper Type']));
        update_post_meta($paper_id, '_sjm_submission_date', sanitize_text_field($data['Submission Date']));
        update_post_meta($paper_id, '_sjm_acceptance_date', sanitize_text_field($data['Acceptance Date']));
        update_post_meta($paper_id, '_sjm_paper_open_access', $data['Open Access'] == '1' ? '1' : '0');
        update_post_meta($paper_id, '_sjm_paper_doi', sanitize_text_field($data['DOI']));
        
        return $paper_id;
    }
    
    return false;
}

function sjm_import_author($data, $options) {
    $author_data = array(
        'first_name' => sanitize_text_field($data['First Name']),
        'last_name' => sanitize_text_field($data['Last Name']),
        'email' => sanitize_email($data['Email']),
        'orcid' => sanitize_text_field($data['ORCID']),
        'affiliation' => sanitize_text_field($data['Affiliation']),
        'bio' => sanitize_textarea_field($data['Bio']),
        'website' => esc_url_raw($data['Website'])
    );
    
    return sjm_save_author($author_data);
}

function sjm_handle_export() {
    $export_type = sanitize_text_field($_POST['export_type']);
    $export_format = sanitize_text_field($_POST['export_format']);
    $export_date_from = sanitize_text_field($_POST['export_date_from']);
    $export_date_to = sanitize_text_field($_POST['export_date_to']);
    $export_journal = intval($_POST['export_journal']);
    $export_open_access = $_POST['export_open_access'];
    
    $data = sjm_get_export_data($export_type, $export_date_from, $export_date_to, $export_journal, $export_open_access);
    
    switch ($export_format) {
        case 'json':
            sjm_export_json($data, $export_type);
            break;
        case 'xml':
            sjm_export_xml($data, $export_type);
            break;
        default:
            sjm_export_csv($data, $export_type);
            break;
    }
}

function sjm_get_export_data($type, $date_from, $date_to, $journal_id, $open_access) {
    $args = array(
        'post_type' => $type,
        'posts_per_page' => -1,
        'post_status' => 'publish'
    );
    
    if ($date_from || $date_to) {
        $args['date_query'] = array();
        if ($date_from) $args['date_query']['after'] = $date_from;
        if ($date_to) $args['date_query']['before'] = $date_to;
    }
    
    if ($journal_id) {
        $args['meta_query'] = array(
            array('key' => '_sjm_paper_journal', 'value' => $journal_id)
        );
    }
    
    if ($open_access !== '') {
        if (!isset($args['meta_query'])) $args['meta_query'] = array();
        $args['meta_query'][] = array('key' => '_sjm_open_access', 'value' => $open_access);
    }
    
    $posts = get_posts($args);
    $data = array();
    
    foreach ($posts as $post) {
        $item = array(
            'ID' => $post->ID,
            'Title' => $post->post_title,
            'Content' => $post->post_content,
            'Date' => $post->post_date
        );
        
        // Add meta data
        $meta = get_post_meta($post->ID);
        foreach ($meta as $key => $values) {
            if (strpos($key, '_sjm_') === 0) {
                $item[str_replace('_sjm_', '', $key)] = $values[0];
            }
        }
        
        $data[] = $item;
    }
    
    return $data;
}

function sjm_export_csv($data, $type) {
    if (empty($data)) {
        wp_die('No data to export.');
    }
    
    $filename = $type . '_export_' . date('Y-m-d') . '.csv';
    
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    
    // Headers
    fputcsv($output, array_keys($data[0]));
    
    // Data
    foreach ($data as $row) {
        fputcsv($output, $row);
    }
    
    fclose($output);
    exit;
}

function sjm_export_json($data, $type) {
    $filename = $type . '_export_' . date('Y-m-d') . '.json';
    
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    echo json_encode($data, JSON_PRETTY_PRINT);
    exit;
}

function sjm_export_xml($data, $type) {
    $filename = $type . '_export_' . date('Y-m-d') . '.xml';
    
    header('Content-Type: application/xml');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><data></data>');
    
    foreach ($data as $item) {
        $record = $xml->addChild('record');
        foreach ($item as $key => $value) {
            $record->addChild($key, htmlspecialchars($value));
        }
    }
    
    echo $xml->asXML();
    exit;
}

// Email Notifications System
function sjm_add_email_settings_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Email Settings',
        'Email Settings',
        'manage_options',
        'sjm-email-settings',
        'sjm_email_settings_page'
    );
}
add_action('admin_menu', 'sjm_add_email_settings_page');

function sjm_email_settings_page() {
    if (isset($_POST['sjm_save_email_settings']) && wp_verify_nonce($_POST['sjm_email_nonce'], 'sjm_email_settings')) {
        $settings = array(
            'paper_submission_editors' => isset($_POST['paper_submission_editors']),
            'paper_submission_authors' => isset($_POST['paper_submission_authors']),
            'paper_published_authors' => isset($_POST['paper_published_authors']),
            'paper_published_subscribers' => isset($_POST['paper_published_subscribers']),
            'issue_published_subscribers' => isset($_POST['issue_published_subscribers']),
            'review_assignment_reviewers' => isset($_POST['review_assignment_reviewers']),
            'from_email' => sanitize_email($_POST['from_email']),
            'from_name' => sanitize_text_field($_POST['from_name']),
            'email_template_header' => wp_kses_post($_POST['email_template_header']),
            'email_template_footer' => wp_kses_post($_POST['email_template_footer'])
        );
        
        update_option('sjm_email_settings', $settings);
        echo '<div class="notice notice-success"><p>Email settings saved successfully!</p></div>';
    }
    
    $settings = get_option('sjm_email_settings', array());
    ?>
    <div class="wrap">
        <h1>Email Notification Settings</h1>
        
        <form method="post">
            <?php wp_nonce_field('sjm_email_settings', 'sjm_email_nonce'); ?>
            
            <table class="form-table">
                <tr>
                    <th>Email Notifications</th>
                    <td>
                        <label><input type="checkbox" name="paper_submission_editors" <?php checked(isset($settings['paper_submission_editors']) ? $settings['paper_submission_editors'] : true); ?> /> Notify editors when paper is submitted</label><br>
                        <label><input type="checkbox" name="paper_submission_authors" <?php checked(isset($settings['paper_submission_authors']) ? $settings['paper_submission_authors'] : true); ?> /> Notify authors of submission confirmation</label><br>
                        <label><input type="checkbox" name="paper_published_authors" <?php checked(isset($settings['paper_published_authors']) ? $settings['paper_published_authors'] : true); ?> /> Notify authors when paper is published</label><br>
                        <label><input type="checkbox" name="paper_published_subscribers" <?php checked(isset($settings['paper_published_subscribers']) ? $settings['paper_published_subscribers'] : false); ?> /> Notify subscribers when paper is published</label><br>
                        <label><input type="checkbox" name="issue_published_subscribers" <?php checked(isset($settings['issue_published_subscribers']) ? $settings['issue_published_subscribers'] : false); ?> /> Notify subscribers when issue is published</label><br>
                        <label><input type="checkbox" name="review_assignment_reviewers" <?php checked(isset($settings['review_assignment_reviewers']) ? $settings['review_assignment_reviewers'] : true); ?> /> Notify reviewers when assigned</label>
                    </td>
                </tr>
                <tr>
                    <th><label for="from_email">From Email</label></th>
                    <td>
                        <input type="email" name="from_email" id="from_email" value="<?php echo esc_attr(isset($settings['from_email']) ? $settings['from_email'] : get_option('admin_email')); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label for="from_name">From Name</label></th>
                    <td>
                        <input type="text" name="from_name" id="from_name" value="<?php echo esc_attr(isset($settings['from_name']) ? $settings['from_name'] : get_bloginfo('name')); ?>" class="regular-text" />
                    </td>
                </tr>
                <tr>
                    <th><label for="email_template_header">Email Header Template</label></th>
                    <td>
                        <textarea name="email_template_header" id="email_template_header" rows="5" class="large-text"><?php echo esc_textarea(isset($settings['email_template_header']) ? $settings['email_template_header'] : 'Dear {recipient_name},'); ?></textarea>
                        <p class="description">Available placeholders: {recipient_name}, {site_name}, {site_url}</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="email_template_footer">Email Footer Template</label></th>
                    <td>
                        <textarea name="email_template_footer" id="email_template_footer" rows="5" class="large-text"><?php echo esc_textarea(isset($settings['email_template_footer']) ? $settings['email_template_footer'] : 'Best regards,<br>{site_name} Team'); ?></textarea>
                        <p class="description">Available placeholders: {site_name}, {site_url}, {unsubscribe_link}</p>
                    </td>
                </tr>
            </table>
            
            <p class="submit">
                <input type="submit" name="sjm_save_email_settings" class="button-primary" value="Save Settings" />
            </p>
        </form>
        
        <div class="postbox">
            <h2 class="hndle">Test Email</h2>
            <div class="inside">
                <p>Send a test email to verify your settings:</p>
                <form method="post">
                    <?php wp_nonce_field('sjm_test_email', 'sjm_test_email_nonce'); ?>
                    <input type="email" name="test_email" placeholder="Enter email address" required />
                    <input type="submit" name="sjm_test_email" class="button-secondary" value="Send Test Email" />
                </form>
            </div>
        </div>
    </div>
    <?php
    
    // Handle test email
    if (isset($_POST['sjm_test_email']) && wp_verify_nonce($_POST['sjm_test_email_nonce'], 'sjm_test_email')) {
        $test_email = sanitize_email($_POST['test_email']);
        $result = sjm_send_test_email($test_email);
        if ($result) {
            echo '<div class="notice notice-success"><p>Test email sent successfully!</p></div>';
        } else {
            echo '<div class="notice notice-error"><p>Failed to send test email.</p></div>';
        }
    }
}

function sjm_send_test_email($email) {
    $settings = get_option('sjm_email_settings', array());
    $from_email = isset($settings['from_email']) ? $settings['from_email'] : get_option('admin_email');
    $from_name = isset($settings['from_name']) ? $settings['from_name'] : get_bloginfo('name');
    
    $subject = 'Test Email - ' . get_bloginfo('name');
    $message = sjm_get_email_template('test', array(
        'recipient_name' => 'Test User',
        'site_name' => get_bloginfo('name'),
        'site_url' => get_bloginfo('url')
    ));
    
    $headers = array(
        'Content-Type: text/html; charset=UTF-8',
        'From: ' . $from_name . ' <' . $from_email . '>'
    );
    
    return wp_mail($email, $subject, $message, $headers);
}

function sjm_get_email_template($type, $data) {
    $settings = get_option('sjm_email_settings', array());
    $header = isset($settings['email_template_header']) ? $settings['email_template_header'] : 'Dear {recipient_name},';
    $footer = isset($settings['email_template_footer']) ? $settings['email_template_footer'] : 'Best regards,<br>{site_name} Team';
    
        $content = '';
    switch ($type) {
        case 'paper_submission_editor':
            $content = 'A new paper has been submitted to your journal.<br><br>';
            $content .= '<strong>Paper:</strong> ' . $data['paper_title'] . '<br>';
            $content .= '<strong>Authors:</strong> ' . $data['authors'] . '<br>';
            $content .= '<strong>Journal:</strong> ' . $data['journal_title'] . '<br>';
            $content .= '<strong>Submission Date:</strong> ' . $data['submission_date'] . '<br><br>';
            $content .= 'Please review the submission at: <a href="' . $data['admin_url'] . '">' . $data['admin_url'] . '</a>';
            break;
            
        case 'paper_submission_author':
            $content = 'Your paper has been successfully submitted.<br><br>';
            $content .= '<strong>Paper:</strong> ' . $data['paper_title'] . '<br>';
            $content .= '<strong>Journal:</strong> ' . $data['journal_title'] . '<br>';
            $content .= '<strong>Submission Date:</strong> ' . $data['submission_date'] . '<br><br>';
            $content .= 'You will be notified of the review status.';
            break;
            
        case 'paper_published_author':
            $content = 'Your paper has been published!<br><br>';
            $content .= '<strong>Paper:</strong> ' . $data['paper_title'] . '<br>';
            $content .= '<strong>Journal:</strong> ' . $data['journal_title'] . '<br>';
            $content .= '<strong>Publication Date:</strong> ' . $data['publication_date'] . '<br><br>';
            $content .= 'View your paper at: <a href="' . $data['paper_url'] . '">' . $data['paper_url'] . '</a>';
            break;
            
        case 'paper_published_subscriber':
            $content = 'A new paper has been published in ' . $data['journal_title'] . '.<br><br>';
            $content .= '<strong>Paper:</strong> ' . $data['paper_title'] . '<br>';
            $content .= '<strong>Authors:</strong> ' . $data['authors'] . '<br>';
            $content .= '<strong>Abstract:</strong> ' . $data['abstract'] . '<br><br>';
            $content .= 'Read the full paper at: <a href="' . $data['paper_url'] . '">' . $data['paper_url'] . '</a>';
            break;
            
        case 'issue_published_subscriber':
            $content = 'A new issue has been published in ' . $data['journal_title'] . '.<br><br>';
            $content .= '<strong>Issue:</strong> ' . $data['issue_title'] . '<br>';
            $content .= '<strong>Publication Date:</strong> ' . $data['publication_date'] . '<br>';
            $content .= '<strong>Papers:</strong> ' . $data['paper_count'] . ' papers<br><br>';
            $content .= 'View the issue at: <a href="' . $data['issue_url'] . '">' . $data['issue_url'] . '</a>';
            break;
            
        case 'review_assignment':
            $content = 'You have been assigned to review a paper.<br><br>';
            $content .= '<strong>Paper:</strong> ' . $data['paper_title'] . '<br>';
            $content .= '<strong>Journal:</strong> ' . $data['journal_title'] . '<br>';
            $content .= '<strong>Due Date:</strong> ' . $data['due_date'] . '<br><br>';
            $content .= 'Access the review at: <a href="' . $data['review_url'] . '">' . $data['review_url'] . '</a>';
            break;
            
        case 'test':
            $content = 'This is a test email from the Simple Journal Manager plugin.<br><br>';
            $content .= 'If you received this email, your email settings are working correctly.';
            break;
    }
    
    // Replace placeholders
    $header = str_replace(
        array('{recipient_name}', '{site_name}', '{site_url}'),
        array($data['recipient_name'], $data['site_name'], $data['site_url']),
        $header
    );
    
    $footer = str_replace(
        array('{site_name}', '{site_url}', '{unsubscribe_link}'),
        array($data['site_name'], $data['site_url'], $data['unsubscribe_link'] ?? ''),
        $footer
    );
    
    return $header . '<br><br>' . $content . '<br><br>' . $footer;
}

// Hook into paper submission
function sjm_notify_paper_submission($paper_id) {
    $settings = get_option('sjm_email_settings', array());
    
    if (!isset($settings['paper_submission_editors']) || !$settings['paper_submission_editors']) {
        return;
    }
    
    $paper = get_post($paper_id);
    $journal_id = get_post_meta($paper_id, '_sjm_paper_journal', true);
    $journal = get_post($journal_id);
    
    // Get editor email
    $editor_id = get_post_meta($journal_id, '_sjm_editor_in_chief_id', true);
    $editor = get_user_by('id', $editor_id);
    
    if ($editor) {
        $data = array(
            'recipient_name' => $editor->display_name,
            'site_name' => get_bloginfo('name'),
            'site_url' => get_bloginfo('url'),
            'paper_title' => $paper->post_title,
            'authors' => sjm_get_paper_authors_string($paper_id),
            'journal_title' => $journal->post_title,
            'submission_date' => $paper->post_date,
            'admin_url' => admin_url('post.php?post=' . $paper_id . '&action=edit')
        );
        
        sjm_send_email_enhanced($editor->user_email, 'New Paper Submission', 'paper_submission_editor', $data);
    }
}

// Hook into paper publication
function sjm_notify_paper_published($paper_id) {
    $settings = get_option('sjm_email_settings', array());
    
    $paper = get_post($paper_id);
    $journal_id = get_post_meta($paper_id, '_sjm_paper_journal', true);
    $journal = get_post($journal_id);
    
    // Notify authors
    if (isset($settings['paper_published_authors']) && $settings['paper_published_authors']) {
        $authors = sjm_get_paper_authors($paper_id);
        foreach ($authors as $author) {
            $data = array(
                'recipient_name' => $author['first_name'] . ' ' . $author['last_name'],
                'site_name' => get_bloginfo('name'),
                'site_url' => get_bloginfo('url'),
                'paper_title' => $paper->post_title,
                'journal_title' => $journal->post_title,
                'publication_date' => $paper->post_date,
                'paper_url' => get_permalink($paper_id)
            );
            
            sjm_send_email_enhanced($author['email'], 'Your Paper Has Been Published', 'paper_published_author', $data);
        }
    }
    
    // Notify subscribers
    if (isset($settings['paper_published_subscribers']) && $settings['paper_published_subscribers']) {
        $subscribers = sjm_get_journal_subscribers($journal_id);
        foreach ($subscribers as $subscriber) {
            $data = array(
                'recipient_name' => $subscriber['name'],
                'site_name' => get_bloginfo('name'),
                'site_url' => get_bloginfo('url'),
                'paper_title' => $paper->post_title,
                'journal_title' => $journal->post_title,
                'authors' => sjm_get_paper_authors_string($paper_id),
                'abstract' => get_post_meta($paper_id, '_sjm_paper_abstract', true),
                'paper_url' => get_permalink($paper_id),
                'unsubscribe_link' => sjm_get_unsubscribe_link($subscriber['email'], $journal_id)
            );
            
            sjm_send_email_enhanced($subscriber['email'], 'New Paper Published', 'paper_published_subscriber', $data);
        }
    }
}

function sjm_send_email($to, $subject, $template, $data) {
    $settings = get_option('sjm_email_settings', array());
    $from_email = isset($settings['from_email']) ? $settings['from_email'] : get_option('admin_email');
    $from_name = isset($settings['from_name']) ? $settings['from_name'] : get_bloginfo('name');
    
    $message = sjm_get_email_template($template, $data);
    
    $headers = array(
        'Content-Type: text/html; charset=UTF-8',
        'From: ' . $from_name . ' <' . $from_email . '>'
    );
    
    return wp_mail($to, $subject, $message, $headers);
}

// Helper functions
function sjm_get_paper_authors($paper_id) {
    global $wpdb;
    
    $paper_authors_data = get_post_meta($paper_id, '_sjm_paper_authors_data', true);
    if (!is_array($paper_authors_data)) {
        return array();
    }
    
    $authors = array();
    foreach ($paper_authors_data as $author_data) {
        if (!empty($author_data['author_id'])) {
            $author = sjm_get_author_by_id($author_data['author_id']);
            if ($author) {
                $authors[] = array(
                    'id' => $author->id,
                    'first_name' => $author->first_name,
                    'last_name' => $author->last_name,
                    'email' => $author->email,
                    'orcid' => $author->orcid,
                    'affiliation' => $author->affiliation,
                    'order' => $author_data['order'] ?? 1,
                    'contributions' => $author_data['contributions'] ?? '',
                    'is_corresponding' => $author_data['is_corresponding'] ?? false
                );
            }
        }
    }
    
    // Sort by order
    usort($authors, function($a, $b) {
        return ($a['order'] ?? 1) - ($b['order'] ?? 1);
    });
    
    return $authors;
}

function sjm_get_paper_authors_string($paper_id) {
    $authors = sjm_get_paper_authors($paper_id);
    $names = array();
    foreach ($authors as $author) {
        $names[] = $author['first_name'] . ' ' . $author['last_name'];
    }
    return implode(', ', $names);
}

function sjm_get_journal_subscribers($journal_id) {
    // This would integrate with your subscription system
    // For now, return empty array
    return array();
}

function sjm_get_unsubscribe_link($email, $journal_id) {
    // This would generate an unsubscribe link
    return add_query_arg(array(
        'action' => 'unsubscribe',
        'email' => $email,
        'journal' => $journal_id
    ), home_url());
}

// Add email debugging and logging
function sjm_log_email($to, $subject, $template, $success, $error = '') {
    $log_entry = array(
        'timestamp' => current_time('mysql'),
        'to' => $to,
        'subject' => $subject,
        'template' => $template,
        'success' => $success,
        'error' => $error
    );
    
    $email_log = get_option('sjm_email_log', array());
    $email_log[] = $log_entry;
    
    // Keep only last 100 entries
    if (count($email_log) > 100) {
        $email_log = array_slice($email_log, -100);
    }
    
    update_option('sjm_email_log', $email_log);
}

// Enhanced email sending with logging
function sjm_send_email_enhanced($to, $subject, $template, $data) {
    $result = sjm_send_email($to, $subject, $template, $data);
    
    if ($result) {
        sjm_log_email($to, $subject, $template, true);
    } else {
        sjm_log_email($to, $subject, $template, false, 'wp_mail failed');
    }
    
    return $result;
}

// Add email log viewer to admin
function sjm_add_email_log_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Email Log',
        'Email Log',
        'manage_options',
        'sjm-email-log',
        'sjm_email_log_page'
    );
}
add_action('admin_menu', 'sjm_add_email_log_page');

// Add Workflow Guide page
function sjm_add_workflow_guide_page() {
    add_submenu_page(
        'sjm-dashboard',
        'Plugin Guide',
        'Plugin Guide',
        'manage_options',
        'sjm-plugin-guide',
        'sjm_plugin_guide_page'
    );
}
add_action('admin_menu', 'sjm_add_workflow_guide_page');

function sjm_plugin_guide_page() {
    // Include the plugin guide template
    include plugin_dir_path(__FILE__) . 'templates/plugin-guide.php';
}

// Security Dashboard
function sjm_add_security_dashboard() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Security Log',
        'Security Log',
        'manage_options',
        'sjm-security-log',
        'sjm_security_log_page'
    );
}
add_action('admin_menu', 'sjm_add_security_dashboard');

// Rate Limit Dashboard
function sjm_add_rate_limit_dashboard() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Rate Limits',
        'Rate Limits',
        'manage_options',
        'sjm-rate-limits',
        'sjm_rate_limit_dashboard_page'
    );
}
add_action('admin_menu', 'sjm_add_rate_limit_dashboard');

// Plugin Cleanup Page
function sjm_add_cleanup_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Plugin Cleanup',
        'Plugin Cleanup',
        'manage_options',
        'sjm-cleanup',
        'sjm_cleanup_page'
    );
}
add_action('admin_menu', 'sjm_add_cleanup_page');

function sjm_cleanup_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Insufficient permissions');
    }
    
    if (isset($_POST['run_cleanup']) && wp_verify_nonce($_POST['cleanup_nonce'], 'sjm_cleanup')) {
        // Run cleanup operations
        global $wpdb;
        
        // Clear expired transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%' AND option_value < " . time());
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' AND option_name NOT LIKE '_transient_timeout_%' AND option_name NOT IN (SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%')");
        
        // Clean up old rate limiting data
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'sjm_rate_limit_%' AND option_value < " . (time() - 86400));
        
        // Clean up logs
        $security_log = get_option('wjm_security_log', array());
        if (count($security_log) > 1000) {
            $security_log = array_slice($security_log, -1000);
            update_option('wjm_security_log', $security_log);
        }
        
        echo '<div class="notice notice-success"><p>Plugin cleanup completed successfully!</p></div>';
    }
    
    ?>
    <div class="wrap">
        <h1>🧹 Plugin Cleanup & Optimization</h1>
        <p>This tool performs comprehensive cleanup and optimization of the Wisdom Journal Manager plugin.</p>
        
        <form method="post">
            <?php wp_nonce_field('sjm_cleanup', 'cleanup_nonce'); ?>
            <p><input type="submit" name="run_cleanup" class="button button-primary" value="Run Cleanup & Optimization"></p>
        </form>
        
        <div style="background: #fff; padding: 20px; border: 1px solid #ccc; border-radius: 5px; margin-top: 20px;">
            <h3>What gets cleaned up:</h3>
            <ul>
                <li>Expired transients and cached data</li>
                <li>Old rate limiting data (older than 24 hours)</li>
                <li>Security logs (keeps last 1000 entries)</li>
                <li>Database optimization</li>
            </ul>
        </div>
    </div>
    <?php
}

// Plugin Verification Page
function sjm_add_verification_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Plugin Verification',
        'Plugin Verification',
        'manage_options',
        'sjm-verification',
        'sjm_verification_page'
    );
}
add_action('admin_menu', 'sjm_add_verification_page');

function sjm_verification_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Insufficient permissions');
    }
    
    // Run verification tests
    $tests = array();
    
    // Test 1: Security Manager exists
    $tests['security_manager'] = class_exists('WJM_Security_Manager');
    
    // Test 2: Authors table exists
    global $wpdb;
    $table_name = $wpdb->prefix . 'sjm_authors';
    $tests['authors_table'] = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name;
    
    // Test 3: Custom post types registered
    $post_types = get_post_types(array(), 'names');
    $tests['post_types'] = in_array('journal', $post_types) && in_array('journal_issue', $post_types) && in_array('paper', $post_types);
    
    // Test 4: Essential functions exist
    $tests['essential_functions'] = function_exists('sjm_create_authors_table') && function_exists('sjm_save_author');
    
    $passed = count(array_filter($tests));
    $total = count($tests);
    $percentage = round(($passed / $total) * 100, 2);
    
    ?>
    <div class="wrap">
        <h1>🔍 Plugin Verification Results</h1>
        
        <div class="notice notice-<?php echo $percentage == 100 ? 'success' : ($percentage >= 80 ? 'warning' : 'error'); ?>">
            <h3>Overall Status: <?php echo $percentage; ?>%</h3>
            <p>Passed: <?php echo $passed; ?>/<?php echo $total; ?> tests</p>
        </div>
        
        <div style="background: #fff; padding: 20px; border: 1px solid #ccc; border-radius: 5px; margin-top: 20px;">
            <h3>Test Results:</h3>
            <ul>
                <?php foreach ($tests as $test => $result): ?>
                <li><?php echo $result ? '✅' : '❌'; ?> <?php echo esc_html(ucwords(str_replace('_', ' ', $test))); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <?php
}

function sjm_rate_limit_dashboard_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Insufficient permissions');
    }
    
    $user_id = get_current_user_id();
    $user = wp_get_current_user();
    $user_role = $user->roles[0] ?? 'subscriber';
    
    // Get rate limit info for different actions
    $actions = array('api_call', 'data_fetch', 'file_upload', 'login_attempt');
    
    ?>
    <div class="wrap">
        <h1>📊 Rate Limit Dashboard</h1>
        <p>Monitor your current rate limit usage and remaining quota.</p>
        
        <div style="background: #fff; padding: 20px; border: 1px solid #ccc; border-radius: 5px; margin-bottom: 20px;">
            <h3>Your Usage Summary</h3>
            <p><strong>User:</strong> <?php echo esc_html($user->user_login); ?> (<?php echo esc_html(ucfirst($user_role)); ?>)</p>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 20px;">
                <?php foreach ($actions as $action): 
                    $rate_info = WJM_Security_Manager::get_rate_limit_info($action, $user_id);
                    $percentage = ($rate_info['current_usage'] / $rate_info['limit']) * 100;
                    $status_color = $percentage > 80 ? '#dc2626' : ($percentage > 60 ? '#f59e0b' : '#10b981');
                ?>
                <div style="padding: 15px; background: #f9f9f9; border-left: 4px solid <?php echo $status_color; ?>; border-radius: 3px;">
                    <h4><?php echo esc_html(ucwords(str_replace('_', ' ', $action))); ?></h4>
                    <p><strong>Used:</strong> <?php echo $rate_info['current_usage']; ?> / <?php echo $rate_info['limit']; ?></p>
                    <p><strong>Remaining:</strong> <?php echo $rate_info['remaining']; ?></p>
                    <p><strong>Reset:</strong> <?php echo date('H:i', $rate_info['reset_time']); ?></p>
                    <div style="background: #e5e7eb; height: 8px; border-radius: 4px; margin-top: 8px;">
                        <div style="background: <?php echo $status_color; ?>; height: 8px; border-radius: 4px; width: <?php echo min(100, $percentage); ?>%;"></div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div style="background: #fff; padding: 20px; border: 1px solid #ccc; border-radius: 5px;">
            <h3>Rate Limit Information</h3>
            <p>Rate limits help prevent abuse and manage API costs. Your limits are based on your user role:</p>
            <ul>
                <li><strong>Student:</strong> 50 API calls/hour, 30 data fetches/hour</li>
                <li><strong>Researcher:</strong> 100 API calls/hour, 60 data fetches/hour</li>
                <li><strong>Editor:</strong> 200 API calls/hour, 120 data fetches/hour</li>
                <li><strong>Administrator:</strong> 500 API calls/hour, 300 data fetches/hour</li>
            </ul>
            <p>If you need higher limits, contact your administrator.</p>
        </div>
    </div>
    <?php
}

function sjm_security_log_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Insufficient permissions');
    }
    
    $security_log = get_option('sjm_security_log', array());
    $security_log = array_reverse($security_log); // Show newest first
    
    // Handle log clearing
    if (isset($_POST['clear_log']) && wp_verify_nonce($_POST['security_nonce'], 'sjm_clear_security_log')) {
        update_option('sjm_security_log', array());
        echo '<div class="notice notice-success"><p>Security log cleared successfully!</p></div>';
        $security_log = array();
    }
    
    ?>
    <div class="wrap">
        <h1>🔒 Security Log</h1>
        
        <div style="background: #fff; padding: 20px; border: 1px solid #ccc; border-radius: 5px; margin-bottom: 20px;">
            <h3>Security Overview</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div style="padding: 15px; background: #f0f6ff; border-left: 4px solid #0073aa; border-radius: 3px;">
                    <strong>Total Events</strong><br>
                    <span style="font-size: 24px; color: #0073aa;"><?php echo count($security_log); ?></span>
                </div>
                <div style="padding: 15px; background: #f0fff4; border-left: 4px solid #00a32a; border-radius: 3px;">
                    <strong>Active Users</strong><br>
                    <span style="font-size: 24px; color: #00a32a;"><?php echo count(array_unique(array_column($security_log, 'user_id'))); ?></span>
                </div>
                <div style="padding: 15px; background: #fff8e1; border-left: 4px solid #ff9800; border-radius: 3px;">
                    <strong>Last 24h Events</strong><br>
                    <span style="font-size: 24px; color: #ff9800;">
                        <?php 
                        $last_24h = array_filter($security_log, function($event) {
                            return strtotime($event['timestamp']) > (time() - 86400);
                        });
                        echo count($last_24h);
                        ?>
                    </span>
                </div>
            </div>
        </div>
        
        <form method="post" style="margin-bottom: 20px;">
            <?php wp_nonce_field('sjm_clear_security_log', 'security_nonce'); ?>
            <input type="submit" name="clear_log" class="button-secondary" value="Clear Security Log" 
                   onclick="return confirm('Are you sure you want to clear the security log?')" />
        </form>
        
        <?php if (empty($security_log)): ?>
            <div style="text-align: center; padding: 40px; background: #f9f9f9; border-radius: 5px;">
                <p style="font-size: 18px; color: #666;">No security events logged yet.</p>
            </div>
        <?php else: ?>
            <div style="background: #fff; border: 1px solid #ccc; border-radius: 5px;">
                <table class="widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 150px;">Timestamp</th>
                            <th style="width: 100px;">User</th>
                            <th style="width: 120px;">IP Address</th>
                            <th style="width: 150px;">Event</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_slice($security_log, 0, 100) as $event): ?>
                            <tr>
                                <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($event['timestamp']))); ?></td>
                                <td>
                                    <?php 
                                    if ($event['user_id']) {
                                        $user = get_user_by('id', $event['user_id']);
                                        echo $user ? esc_html($user->user_login) : 'Unknown';
                                    } else {
                                        echo 'Guest';
                                    }
                                    ?>
                                </td>
                                <td><?php echo esc_html($event['user_ip']); ?></td>
                                <td>
                                    <span style="padding: 3px 8px; background: #f0f6ff; border-radius: 12px; font-size: 12px;">
                                        <?php echo esc_html($event['event']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if (!empty($event['details'])): ?>
                                        <details>
                                            <summary style="cursor: pointer;">View Details</summary>
                                            <pre style="margin-top: 10px; padding: 10px; background: #f5f5f5; border-radius: 3px; font-size: 12px; overflow-x: auto;"><?php echo esc_html(print_r($event['details'], true)); ?></pre>
                                        </details>
                                    <?php else: ?>
                                        <em>No details</em>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <?php if (count($security_log) > 100): ?>
                    <div style="padding: 15px; text-align: center; background: #f9f9f9; border-top: 1px solid #ddd;">
                        <em>Showing latest 100 events. Total events: <?php echo count($security_log); ?></em>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

function sjm_email_log_page() {
    $email_log = get_option('sjm_email_log', array());
    
    if (isset($_POST['sjm_clear_log']) && wp_verify_nonce($_POST['sjm_clear_log_nonce'], 'sjm_clear_log')) {
        update_option('sjm_email_log', array());
        echo '<div class="notice notice-success"><p>Email log cleared successfully!</p></div>';
        $email_log = array();
    }
    
    ?>
    <div class="wrap">
        <h1>Email Notification Log</h1>
        
        <form method="post" style="margin-bottom: 20px;">
            <?php wp_nonce_field('sjm_clear_log', 'sjm_clear_log_nonce'); ?>
            <input type="submit" name="sjm_clear_log" class="button-secondary" value="Clear Log" onclick="return confirm('Are you sure you want to clear the email log?')" />
        </form>
        
        <?php if (empty($email_log)): ?>
            <p>No email log entries found.</p>
        <?php else: ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Date/Time</th>
                        <th>To</th>
                        <th>Subject</th>
                        <th>Template</th>
                        <th>Status</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (array_reverse($email_log) as $entry): ?>
                        <tr>
                            <td><?php echo esc_html($entry['timestamp']); ?></td>
                            <td><?php echo esc_html($entry['to']); ?></td>
                            <td><?php echo esc_html($entry['subject']); ?></td>
                            <td><?php echo esc_html($entry['template']); ?></td>
                            <td>
                                <?php if ($entry['success']): ?>
                                    <span style="color: green;">✓ Sent</span>
                                <?php else: ?>
                                    <span style="color: red;">✗ Failed</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($entry['error']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    <?php
}

// Hook into WordPress actions
add_action('publish_paper', 'sjm_notify_paper_published');
add_action('draft_to_publish', 'sjm_notify_paper_published');
add_action('wp_insert_post', 'sjm_enhanced_paper_submission_notification', 10, 2);

// Enhanced paper submission notification
function sjm_enhanced_paper_submission_notification($post_id, $post) {
    // Only handle papers
    if ($post->post_type !== 'paper') {
        return;
    }
    
    // Only notify on new submissions (not updates)
    if ($post->post_status === 'publish') {
        return; // This will be handled by the publish hook
    }
    
    $settings = get_option('sjm_email_settings', array());
    
    // Notify editors when paper is submitted
    if (isset($settings['paper_submission_editors']) && $settings['paper_submission_editors']) {
        $journal_id = get_post_meta($post_id, '_sjm_paper_journal', true);
        if ($journal_id) {
            $journal = get_post($journal_id);
            $editor_id = get_post_meta($journal_id, '_sjm_editor_in_chief_id', true);
            $editor = get_user_by('id', $editor_id);
            
            if ($editor && $journal) {
                $data = array(
                    'recipient_name' => $editor->display_name,
                    'site_name' => get_bloginfo('name'),
                    'site_url' => get_bloginfo('url'),
                    'paper_title' => $post->post_title,
                    'authors' => sjm_get_paper_authors_string($post_id),
                    'journal_title' => $journal->post_title,
                    'submission_date' => $post->post_date,
                    'admin_url' => admin_url('post.php?post=' . $post_id . '&action=edit')
                );
                
                sjm_send_email_enhanced($editor->user_email, 'New Paper Submission', 'paper_submission_editor', $data);
            }
        }
    }
    
    // Notify authors of submission confirmation
    if (isset($settings['paper_submission_authors']) && $settings['paper_submission_authors']) {
        $authors = sjm_get_paper_authors($post_id);
        $journal_id = get_post_meta($post_id, '_sjm_paper_journal', true);
        $journal = get_post($journal_id);
        
        foreach ($authors as $author) {
            if (!empty($author['email'])) {
                $data = array(
                    'recipient_name' => $author['first_name'] . ' ' . $author['last_name'],
                    'site_name' => get_bloginfo('name'),
                    'site_url' => get_bloginfo('url'),
                    'paper_title' => $post->post_title,
                    'journal_title' => $journal ? $journal->post_title : 'Unknown Journal',
                    'submission_date' => $post->post_date
                );
                
                sjm_send_email_enhanced($author['email'], 'Paper Submission Confirmation', 'paper_submission_author', $data);
            }
        }
    }
}

// Include automation system
require_once plugin_dir_path(__FILE__) . 'automation-system.php';

// REST API Endpoints
function sjm_register_rest_routes() {
    register_rest_route('sjm/v1', '/journals', array(
                array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_journals',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => 'sjm_create_journal',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/journals/(?P<id>\d+)', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_journal',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::EDITABLE,
            'callback' => 'sjm_update_journal',
            'permission_callback' => 'sjm_check_edit_permissions'
        ),
        array(
            'methods' => WP_REST_Server::DELETABLE,
            'callback' => 'sjm_delete_journal',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/journals/(?P<id>\d+)/issues', array(
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'sjm_get_journal_issues',
        'permission_callback' => '__return_true'
    ));
    
    register_rest_route('sjm/v1', '/journals/(?P<id>\d+)/papers', array(
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'sjm_get_journal_papers',
        'permission_callback' => '__return_true'
    ));
    
    register_rest_route('sjm/v1', '/issues', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_issues',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => 'sjm_create_issue',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/issues/(?P<id>\d+)', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_issue',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::EDITABLE,
            'callback' => 'sjm_update_issue',
            'permission_callback' => 'sjm_check_edit_permissions'
        ),
        array(
            'methods' => WP_REST_Server::DELETABLE,
            'callback' => 'sjm_delete_issue',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/papers', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_papers',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => 'sjm_create_paper',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/papers/(?P<id>\d+)', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_paper',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::EDITABLE,
            'callback' => 'sjm_update_paper',
            'permission_callback' => 'sjm_check_edit_permissions'
        ),
        array(
            'methods' => WP_REST_Server::DELETABLE,
            'callback' => 'sjm_delete_paper',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/authors', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_authors',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => 'sjm_create_author',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
    
    register_rest_route('sjm/v1', '/authors/(?P<id>\d+)', array(
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'sjm_get_author',
            'permission_callback' => '__return_true'
        ),
        array(
            'methods' => WP_REST_Server::EDITABLE,
            'callback' => 'sjm_update_author',
            'permission_callback' => 'sjm_check_edit_permissions'
        ),
        array(
            'methods' => WP_REST_Server::DELETABLE,
            'callback' => 'sjm_delete_author',
            'permission_callback' => 'sjm_check_edit_permissions'
        )
    ));
}
add_action('rest_api_init', 'sjm_register_rest_routes');

// Permission callback
function sjm_check_edit_permissions() {
    return current_user_can('edit_posts');
}

// Journal endpoints
function sjm_get_journals($request) {
    $args = array(
        'post_type' => 'journal',
        'posts_per_page' => $request->get_param('per_page') ?: 10,
        'paged' => $request->get_param('page') ?: 1,
        'post_status' => 'publish'
    );
    
    if ($request->get_param('open_access') !== null) {
        $args['meta_query'] = array(
            array('key' => '_sjm_open_access', 'value' => $request->get_param('open_access'))
        );
    }
    
    $journals = get_posts($args);
    $data = array();
    
    foreach ($journals as $journal) {
        $data[] = sjm_prepare_journal_data($journal);
    }
    
    return new WP_REST_Response($data, 200);
}

function sjm_get_journal($request) {
    $journal_id = $request->get_param('id');
    $journal = get_post($journal_id);
    
    if (!$journal || $journal->post_type !== 'journal') {
        return new WP_Error('not_found', 'Journal not found', array('status' => 404));
    }
    
    return new WP_REST_Response(sjm_prepare_journal_data($journal), 200);
}

function sjm_create_journal($request) {
    $params = $request->get_params();
    
    $post_data = array(
        'post_title' => sanitize_text_field($params['title']),
        'post_content' => wp_kses_post($params['content']),
        'post_type' => 'journal',
        'post_status' => 'publish'
    );
    
    $journal_id = wp_insert_post($post_data);
    
    if (is_wp_error($journal_id)) {
        return $journal_id;
    }
    
    // Save meta data
    if (isset($params['issn'])) {
        update_post_meta($journal_id, '_sjm_issn', sanitize_text_field($params['issn']));
    }
    if (isset($params['publisher'])) {
        update_post_meta($journal_id, '_sjm_publisher', sanitize_text_field($params['publisher']));
    }
    if (isset($params['editor_in_chief_id'])) {
        update_post_meta($journal_id, '_sjm_editor_in_chief_id', intval($params['editor_in_chief_id']));
    }
    if (isset($params['founding_year'])) {
        update_post_meta($journal_id, '_sjm_founding_year', sanitize_text_field($params['founding_year']));
    }
    if (isset($params['open_access'])) {
        update_post_meta($journal_id, '_sjm_open_access', $params['open_access'] ? '1' : '0');
    }
    if (isset($params['peer_reviewed'])) {
        update_post_meta($journal_id, '_sjm_peer_reviewed', $params['peer_reviewed'] ? '1' : '0');
    }
    if (isset($params['frequency'])) {
        update_post_meta($journal_id, '_sjm_frequency', sanitize_text_field($params['frequency']));
    }
    if (isset($params['subject_areas'])) {
        update_post_meta($journal_id, '_sjm_subject_areas', sanitize_textarea_field($params['subject_areas']));
    }
    
    $journal = get_post($journal_id);
    return new WP_REST_Response(sjm_prepare_journal_data($journal), 201);
}

function sjm_update_journal($request) {
    $journal_id = $request->get_param('id');
    $params = $request->get_params();
    
    $post_data = array('ID' => $journal_id);
    
    if (isset($params['title'])) {
        $post_data['post_title'] = sanitize_text_field($params['title']);
    }
    if (isset($params['content'])) {
        $post_data['post_content'] = wp_kses_post($params['content']);
    }
    
    $result = wp_update_post($post_data);
    
    if (is_wp_error($result)) {
        return $result;
    }
    
    // Update meta data
    if (isset($params['issn'])) {
        update_post_meta($journal_id, '_sjm_issn', sanitize_text_field($params['issn']));
    }
    if (isset($params['publisher'])) {
        update_post_meta($journal_id, '_sjm_publisher', sanitize_text_field($params['publisher']));
    }
    if (isset($params['editor_in_chief_id'])) {
        update_post_meta($journal_id, '_sjm_editor_in_chief_id', intval($params['editor_in_chief_id']));
    }
    if (isset($params['founding_year'])) {
        update_post_meta($journal_id, '_sjm_founding_year', sanitize_text_field($params['founding_year']));
    }
    if (isset($params['open_access'])) {
        update_post_meta($journal_id, '_sjm_open_access', $params['open_access'] ? '1' : '0');
    }
    if (isset($params['peer_reviewed'])) {
        update_post_meta($journal_id, '_sjm_peer_reviewed', $params['peer_reviewed'] ? '1' : '0');
    }
    if (isset($params['frequency'])) {
        update_post_meta($journal_id, '_sjm_frequency', sanitize_text_field($params['frequency']));
    }
    if (isset($params['subject_areas'])) {
        update_post_meta($journal_id, '_sjm_subject_areas', sanitize_textarea_field($params['subject_areas']));
    }
    
    $journal = get_post($journal_id);
    return new WP_REST_Response(sjm_prepare_journal_data($journal), 200);
}

function sjm_delete_journal($request) {
    $journal_id = $request->get_param('id');
    $result = wp_delete_post($journal_id, true);
    
    if (!$result) {
        return new WP_Error('delete_failed', 'Failed to delete journal', array('status' => 500));
    }
    
    return new WP_REST_Response(array('message' => 'Journal deleted successfully'), 200);
}

function sjm_get_journal_issues($request) {
    $journal_id = $request->get_param('id');
    
    $args = array(
        'post_type' => 'journal_issue',
        'posts_per_page' => -1,
        'meta_query' => array(
            array('key' => '_sjm_issue_journal', 'value' => $journal_id)
        ),
        'post_status' => 'publish'
    );
    
    $issues = get_posts($args);
    $data = array();
    
    foreach ($issues as $issue) {
        $data[] = sjm_prepare_issue_data($issue);
    }
    
    return new WP_REST_Response($data, 200);
}

function sjm_get_journal_papers($request) {
    $journal_id = $request->get_param('id');
    
    $args = array(
        'post_type' => 'paper',
        'posts_per_page' => $request->get_param('per_page') ?: 10,
        'paged' => $request->get_param('page') ?: 1,
        'meta_query' => array(
            array('key' => '_sjm_paper_journal', 'value' => $journal_id)
        ),
        'post_status' => 'publish'
    );
    
    $papers = get_posts($args);
    $data = array();
    
    foreach ($papers as $paper) {
        $data[] = sjm_prepare_paper_data($paper);
    }
    
    return new WP_REST_Response($data, 200);
}

// Issue endpoints
function sjm_get_issues($request) {
    $args = array(
        'post_type' => 'journal_issue',
        'posts_per_page' => $request->get_param('per_page') ?: 10,
        'paged' => $request->get_param('page') ?: 1,
        'post_status' => 'publish'
    );
    
    if ($request->get_param('journal_id')) {
        $args['meta_query'] = array(
            array('key' => '_sjm_issue_journal', 'value' => $request->get_param('journal_id'))
        );
    }
    
    $issues = get_posts($args);
    $data = array();
    
    foreach ($issues as $issue) {
        $data[] = sjm_prepare_issue_data($issue);
    }
    
    return new WP_REST_Response($data, 200);
}

function sjm_get_issue($request) {
    $issue_id = $request->get_param('id');
    $issue = get_post($issue_id);
    
    if (!$issue || $issue->post_type !== 'journal_issue') {
        return new WP_Error('not_found', 'Issue not found', array('status' => 404));
    }
    
    return new WP_REST_Response(sjm_prepare_issue_data($issue), 200);
}

function sjm_create_issue($request) {
    $params = $request->get_params();
    
    $post_data = array(
        'post_title' => sanitize_text_field($params['title']),
        'post_content' => wp_kses_post($params['content']),
        'post_type' => 'journal_issue',
        'post_status' => 'publish'
    );
    
    $issue_id = wp_insert_post($post_data);
    
    if (is_wp_error($issue_id)) {
        return $issue_id;
    }
    
    // Save meta data
    if (isset($params['journal_id'])) {
        update_post_meta($issue_id, '_sjm_issue_journal', intval($params['journal_id']));
    }
    if (isset($params['issue_number'])) {
        update_post_meta($issue_id, '_sjm_issue_number', sanitize_text_field($params['issue_number']));
    }
    if (isset($params['volume'])) {
        update_post_meta($issue_id, '_sjm_issue_volume', sanitize_text_field($params['volume']));
    }
    if (isset($params['year'])) {
        update_post_meta($issue_id, '_sjm_issue_year', sanitize_text_field($params['year']));
    }
    if (isset($params['publication_date'])) {
        update_post_meta($issue_id, '_sjm_publication_date', sanitize_text_field($params['publication_date']));
    }
    if (isset($params['special_issue'])) {
        update_post_meta($issue_id, '_sjm_special_issue', $params['special_issue'] ? '1' : '0');
    }
    if (isset($params['special_issue_title'])) {
        update_post_meta($issue_id, '_sjm_special_issue_title', sanitize_text_field($params['special_issue_title']));
    }
    
    $issue = get_post($issue_id);
    return new WP_REST_Response(sjm_prepare_issue_data($issue), 201);
}

function sjm_update_issue($request) {
    $issue_id = $request->get_param('id');
    $params = $request->get_params();
    
    $post_data = array('ID' => $issue_id);
    
    if (isset($params['title'])) {
        $post_data['post_title'] = sanitize_text_field($params['title']);
    }
    if (isset($params['content'])) {
        $post_data['post_content'] = wp_kses_post($params['content']);
    }
    
    $result = wp_update_post($post_data);
    
    if (is_wp_error($result)) {
        return $result;
    }
    
    // Update meta data
    if (isset($params['journal_id'])) {
        update_post_meta($issue_id, '_sjm_issue_journal', intval($params['journal_id']));
    }
    if (isset($params['issue_number'])) {
        update_post_meta($issue_id, '_sjm_issue_number', sanitize_text_field($params['issue_number']));
    }
    if (isset($params['volume'])) {
        update_post_meta($issue_id, '_sjm_issue_volume', sanitize_text_field($params['volume']));
    }
    if (isset($params['year'])) {
        update_post_meta($issue_id, '_sjm_issue_year', sanitize_text_field($params['year']));
    }
    if (isset($params['publication_date'])) {
        update_post_meta($issue_id, '_sjm_publication_date', sanitize_text_field($params['publication_date']));
    }
    if (isset($params['special_issue'])) {
        update_post_meta($issue_id, '_sjm_special_issue', $params['special_issue'] ? '1' : '0');
    }
    if (isset($params['special_issue_title'])) {
        update_post_meta($issue_id, '_sjm_special_issue_title', sanitize_text_field($params['special_issue_title']));
    }
    
    $issue = get_post($issue_id);
    return new WP_REST_Response(sjm_prepare_issue_data($issue), 200);
}

function sjm_delete_issue($request) {
    $issue_id = $request->get_param('id');
    $result = wp_delete_post($issue_id, true);
    
    if (!$result) {
        return new WP_Error('delete_failed', 'Failed to delete issue', array('status' => 500));
    }
    
    return new WP_REST_Response(array('message' => 'Issue deleted successfully'), 200);
}

// Paper endpoints
function sjm_get_papers($request) {
    $args = array(
        'post_type' => 'paper',
        'posts_per_page' => $request->get_param('per_page') ?: 10,
        'paged' => $request->get_param('page') ?: 1,
        'post_status' => 'publish'
    );
    
    if ($request->get_param('journal_id')) {
        $args['meta_query'] = array(
            array('key' => '_sjm_paper_journal', 'value' => $request->get_param('journal_id'))
        );
    }
    
    if ($request->get_param('issue_id')) {
        if (!isset($args['meta_query'])) $args['meta_query'] = array();
        $args['meta_query'][] = array('key' => '_sjm_paper_issue', 'value' => $request->get_param('issue_id'));
    }
    
    if ($request->get_param('open_access') !== null) {
        if (!isset($args['meta_query'])) $args['meta_query'] = array();
        $args['meta_query'][] = array('key' => '_sjm_paper_open_access', 'value' => $request->get_param('open_access'));
    }
    
    $papers = get_posts($args);
    $data = array();
    
    foreach ($papers as $paper) {
        $data[] = sjm_prepare_paper_data($paper);
    }
    
    return new WP_REST_Response($data, 200);
}

function sjm_get_paper($request) {
    $paper_id = $request->get_param('id');
    $paper = get_post($paper_id);
    
    if (!$paper || $paper->post_type !== 'paper') {
        return new WP_Error('not_found', 'Paper not found', array('status' => 404));
    }
    
    return new WP_REST_Response(sjm_prepare_paper_data($paper), 200);
}

function sjm_create_paper($request) {
    $params = $request->get_params();
    
    $post_data = array(
        'post_title' => sanitize_text_field($params['title']),
        'post_content' => wp_kses_post($params['content']),
        'post_type' => 'paper',
        'post_status' => 'publish'
    );
    
    $paper_id = wp_insert_post($post_data);
    
    if (is_wp_error($paper_id)) {
        return $paper_id;
    }
    
    // Save meta data
    if (isset($params['journal_id'])) {
        update_post_meta($paper_id, '_sjm_paper_journal', intval($params['journal_id']));
    }
    if (isset($params['issue_id'])) {
        update_post_meta($paper_id, '_sjm_paper_issue', intval($params['issue_id']));
    }
    if (isset($params['abstract'])) {
        update_post_meta($paper_id, '_sjm_paper_abstract', sanitize_textarea_field($params['abstract']));
    }
    if (isset($params['paper_type'])) {
        update_post_meta($paper_id, '_sjm_paper_type', sanitize_text_field($params['paper_type']));
    }
    if (isset($params['submission_date'])) {
        update_post_meta($paper_id, '_sjm_submission_date', sanitize_text_field($params['submission_date']));
    }
    if (isset($params['acceptance_date'])) {
        update_post_meta($paper_id, '_sjm_acceptance_date', sanitize_text_field($params['acceptance_date']));
    }
    if (isset($params['open_access'])) {
        update_post_meta($paper_id, '_sjm_paper_open_access', $params['open_access'] ? '1' : '0');
    }
    if (isset($params['doi'])) {
        update_post_meta($paper_id, '_sjm_paper_doi', sanitize_text_field($params['doi']));
    }
    
    $paper = get_post($paper_id);
    return new WP_REST_Response(sjm_prepare_paper_data($paper), 201);
}

function sjm_update_paper($request) {
    $paper_id = $request->get_param('id');
    $params = $request->get_params();
    
    $post_data = array('ID' => $paper_id);
    
    if (isset($params['title'])) {
        $post_data['post_title'] = sanitize_text_field($params['title']);
    }
    if (isset($params['content'])) {
        $post_data['post_content'] = wp_kses_post($params['content']);
    }
    
    $result = wp_update_post($post_data);
    
    if (is_wp_error($result)) {
        return $result;
    }
    
    // Update meta data
    if (isset($params['journal_id'])) {
        update_post_meta($paper_id, '_sjm_paper_journal', intval($params['journal_id']));
    }
    if (isset($params['issue_id'])) {
        update_post_meta($paper_id, '_sjm_paper_issue', intval($params['issue_id']));
    }
    if (isset($params['abstract'])) {
        update_post_meta($paper_id, '_sjm_paper_abstract', sanitize_textarea_field($params['abstract']));
    }
    if (isset($params['paper_type'])) {
        update_post_meta($paper_id, '_sjm_paper_type', sanitize_text_field($params['paper_type']));
    }
    if (isset($params['submission_date'])) {
        update_post_meta($paper_id, '_sjm_submission_date', sanitize_text_field($params['submission_date']));
    }
    if (isset($params['acceptance_date'])) {
        update_post_meta($paper_id, '_sjm_acceptance_date', sanitize_text_field($params['acceptance_date']));
    }
    if (isset($params['open_access'])) {
        update_post_meta($paper_id, '_sjm_paper_open_access', $params['open_access'] ? '1' : '0');
    }
    if (isset($params['doi'])) {
        update_post_meta($paper_id, '_sjm_paper_doi', sanitize_text_field($params['doi']));
    }
    
    $paper = get_post($paper_id);
    return new WP_REST_Response(sjm_prepare_paper_data($paper), 200);
}

function sjm_delete_paper($request) {
    $paper_id = $request->get_param('id');
    $result = wp_delete_post($paper_id, true);
    
    if (!$result) {
        return new WP_Error('delete_failed', 'Failed to delete paper', array('status' => 500));
    }
    
    return new WP_REST_Response(array('message' => 'Paper deleted successfully'), 200);
}

// Author endpoints
function sjm_get_authors($request) {
    global $wpdb;
    
    $authors = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}sjm_authors ORDER BY last_name, first_name");
    $data = array();
    
    foreach ($authors as $author) {
        $data[] = sjm_prepare_author_data($author);
    }
    
    return new WP_REST_Response($data, 200);
}

function sjm_get_author($request) {
    global $wpdb;
    
    $author_id = $request->get_param('id');
    $author = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}sjm_authors WHERE id = %d", $author_id));
    
    if (!$author) {
        return new WP_Error('not_found', 'Author not found', array('status' => 404));
    }
    
    return new WP_REST_Response(sjm_prepare_author_data($author), 200);
}

function sjm_create_author($request) {
    $params = $request->get_params();
    
    $author_data = array(
        'first_name' => sanitize_text_field($params['first_name']),
        'last_name' => sanitize_text_field($params['last_name']),
        'email' => sanitize_email($params['email']),
        'orcid' => sanitize_text_field($params['orcid'] ?? ''),
        'affiliation' => sanitize_text_field($params['affiliation'] ?? ''),
        'bio' => sanitize_textarea_field($params['bio'] ?? ''),
        'website' => esc_url_raw($params['website'] ?? '')
    );
    
    $author_id = sjm_save_author($author_data);
    
    if (is_wp_error($author_id)) {
        return $author_id;
    }
    
    global $wpdb;
    $author = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}sjm_authors WHERE id = %d", $author_id));
    
    return new WP_REST_Response(sjm_prepare_author_data($author), 201);
}

function sjm_update_author($request) {
    global $wpdb;
    
    $author_id = $request->get_param('id');
    $params = $request->get_params();
    
    $update_data = array();
    
    if (isset($params['first_name'])) {
        $update_data['first_name'] = sanitize_text_field($params['first_name']);
    }
    if (isset($params['last_name'])) {
        $update_data['last_name'] = sanitize_text_field($params['last_name']);
    }
    if (isset($params['email'])) {
        $update_data['email'] = sanitize_email($params['email']);
    }
    if (isset($params['orcid'])) {
        $update_data['orcid'] = sanitize_text_field($params['orcid']);
    }
    if (isset($params['affiliation'])) {
        $update_data['affiliation'] = sanitize_text_field($params['affiliation']);
    }
    if (isset($params['bio'])) {
        $update_data['bio'] = sanitize_textarea_field($params['bio']);
    }
    if (isset($params['website'])) {
        $update_data['website'] = esc_url_raw($params['website']);
    }
    
    if (!empty($update_data)) {
        $wpdb->update(
            $wpdb->prefix . 'sjm_authors',
            $update_data,
            array('id' => $author_id),
            null,
            array('%d')
        );
    }
    
    $author = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}sjm_authors WHERE id = %d", $author_id));
    
    if (!$author) {
        return new WP_Error('not_found', 'Author not found', array('status' => 404));
    }
    
    return new WP_REST_Response(sjm_prepare_author_data($author), 200);
}

function sjm_delete_author($request) {
    global $wpdb;
    
    $author_id = $request->get_param('id');
    $result = $wpdb->delete($wpdb->prefix . 'sjm_authors', array('id' => $author_id), array('%d'));
    
    if (!$result) {
        return new WP_Error('delete_failed', 'Failed to delete author', array('status' => 500));
    }
    
    return new WP_REST_Response(array('message' => 'Author deleted successfully'), 200);
}

// Data preparation functions
function sjm_prepare_journal_data($journal) {
    return array(
        'id' => $journal->ID,
        'title' => $journal->post_title,
        'content' => $journal->post_content,
        'date' => $journal->post_date,
        'modified' => $journal->post_modified,
        'issn' => get_post_meta($journal->ID, '_sjm_issn', true),
        'publisher' => get_post_meta($journal->ID, '_sjm_publisher', true),
        'editor_in_chief_id' => get_post_meta($journal->ID, '_sjm_editor_in_chief_id', true),
        'founding_year' => get_post_meta($journal->ID, '_sjm_founding_year', true),
        'open_access' => get_post_meta($journal->ID, '_sjm_open_access', true) === '1',
        'peer_reviewed' => get_post_meta($journal->ID, '_sjm_peer_reviewed', true) === '1',
        'frequency' => get_post_meta($journal->ID, '_sjm_frequency', true),
        'subject_areas' => get_post_meta($journal->ID, '_sjm_subject_areas', true),
        'link' => get_permalink($journal->ID)
    );
}

function sjm_prepare_issue_data($issue) {
    return array(
        'id' => $issue->ID,
        'title' => $issue->post_title,
        'content' => $issue->post_content,
        'date' => $issue->post_date,
        'modified' => $issue->post_modified,
        'journal_id' => get_post_meta($issue->ID, '_sjm_issue_journal', true),
        'issue_number' => get_post_meta($issue->ID, '_sjm_issue_number', true),
        'volume' => get_post_meta($issue->ID, '_sjm_issue_volume', true),
        'year' => get_post_meta($issue->ID, '_sjm_issue_year', true),
        'publication_date' => get_post_meta($issue->ID, '_sjm_publication_date', true),
        'special_issue' => get_post_meta($issue->ID, '_sjm_special_issue', true) === '1',
        'special_issue_title' => get_post_meta($issue->ID, '_sjm_special_issue_title', true),
        'link' => get_permalink($issue->ID)
    );
}

function sjm_prepare_paper_data($paper) {
    return array(
        'id' => $paper->ID,
        'title' => $paper->post_title,
        'content' => $paper->post_content,
        'date' => $paper->post_date,
        'modified' => $paper->post_modified,
        'journal_id' => get_post_meta($paper->ID, '_sjm_paper_journal', true),
        'issue_id' => get_post_meta($paper->ID, '_sjm_paper_issue', true),
        'abstract' => get_post_meta($paper->ID, '_sjm_paper_abstract', true),
        'paper_type' => get_post_meta($paper->ID, '_sjm_paper_type', true),
        'submission_date' => get_post_meta($paper->ID, '_sjm_submission_date', true),
        'acceptance_date' => get_post_meta($paper->ID, '_sjm_acceptance_date', true),
        'open_access' => get_post_meta($paper->ID, '_sjm_paper_open_access', true) === '1',
        'doi' => get_post_meta($paper->ID, '_sjm_paper_doi', true),
        'authors' => sjm_get_paper_authors($paper->ID),
        'link' => get_permalink($paper->ID)
    );
}

function sjm_prepare_author_data($author) {
    return array(
        'id' => $author->id,
        'first_name' => $author->first_name,
        'last_name' => $author->last_name,
        'email' => $author->email,
        'orcid' => $author->orcid,
        'affiliation' => $author->affiliation,
        'bio' => $author->bio,
        'website' => $author->website,
        'created_at' => $author->created_at,
        'updated_at' => $author->updated_at
    );
}

// Analytics Dashboard System
function sjm_add_analytics_dashboard() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Analytics Dashboard',
        'Analytics',
        'manage_options',
        'sjm-analytics',
        'sjm_analytics_dashboard_page'
    );
}
add_action('admin_menu', 'sjm_add_analytics_dashboard');

function sjm_analytics_dashboard_page() {
    // Check user capabilities
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'wisdom-journal-manager'));
    }
    
    // Get date range from request
    $date_range = isset($_GET['range']) ? sanitize_text_field($_GET['range']) : '30';
    $start_date = isset($_GET['start_date']) ? sanitize_text_field($_GET['start_date']) : date('Y-m-d', strtotime("-{$date_range} days"));
    $end_date = isset($_GET['end_date']) ? sanitize_text_field($_GET['end_date']) : date('Y-m-d');
    
    // Get analytics data
    $analytics_data = sjm_get_analytics_data($start_date, $end_date);
    
    ?>
    <div class="wrap">
        <h1>Journal Analytics Dashboard</h1>
        
        <!-- Date Range Filter -->
        <div class="sjm-analytics-filters" style="margin: 20px 0; padding: 15px; background: #fff; border: 1px solid #ccd0d4; border-radius: 4px;">
            <form method="get" style="display: flex; gap: 15px; align-items: center;">
                <input type="hidden" name="page" value="sjm-analytics">
                <input type="hidden" name="post_type" value="journal">
                
                <label for="range">Quick Range:</label>
                <select name="range" id="range" onchange="this.form.submit()">
                    <option value="7" <?php selected($date_range, '7'); ?>>Last 7 days</option>
                    <option value="30" <?php selected($date_range, '30'); ?>>Last 30 days</option>
                    <option value="90" <?php selected($date_range, '90'); ?>>Last 90 days</option>
                    <option value="365" <?php selected($date_range, '365'); ?>>Last year</option>
                </select>
                
                <label for="start_date">Start Date:</label>
                <input type="date" name="start_date" id="start_date" value="<?php echo esc_attr($start_date); ?>">
                
                <label for="end_date">End Date:</label>
                <input type="date" name="end_date" id="end_date" value="<?php echo esc_attr($end_date); ?>">
                
                <button type="submit" class="button button-primary">Apply Filter</button>
            </form>
        </div>
        
        <!-- Key Metrics Cards -->
        <div class="sjm-analytics-metrics" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <div class="sjm-metric-card" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 10px 0; color: #374151; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Total Journals</h3>
                <div style="font-size: 32px; font-weight: 700; color: #1f2937;"><?php echo esc_html($analytics_data['total_journals']); ?></div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 5px;">
                    <?php echo esc_html($analytics_data['journals_change']); ?>% from previous period
                </div>
            </div>
            
            <div class="sjm-metric-card" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 10px 0; color: #374151; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Total Issues</h3>
                <div style="font-size: 32px; font-weight: 700; color: #1f2937;"><?php echo esc_html($analytics_data['total_issues']); ?></div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 5px;">
                    <?php echo esc_html($analytics_data['issues_change']); ?>% from previous period
                </div>
            </div>
            
            <div class="sjm-metric-card" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 10px 0; color: #374151; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Total Papers</h3>
                <div style="font-size: 32px; font-weight: 700; color: #1f2937;"><?php echo esc_html($analytics_data['total_papers']); ?></div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 5px;">
                    <?php echo esc_html($analytics_data['papers_change']); ?>% from previous period
                </div>
            </div>
            
            <div class="sjm-metric-card" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 10px 0; color: #374151; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Total Authors</h3>
                <div style="font-size: 32px; font-weight: 700; color: #1f2937;"><?php echo esc_html($analytics_data['total_authors']); ?></div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 5px;">
                    <?php echo esc_html($analytics_data['authors_change']); ?>% from previous period
                </div>
            </div>
        </div>
        
        <!-- Charts and Detailed Analytics -->
        <div class="sjm-analytics-charts" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
            <!-- Content Growth Chart -->
            <div class="sjm-chart-container" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); max-width: 600px; height: 350px; margin: 0 auto; overflow-x: auto;">
                <h3 style="margin: 0 0 20px 0; color: #374151;">Content Growth</h3>
                <canvas id="contentGrowthChart" style="width:100%;height:100%;min-width:400px;min-height:200px;"></canvas>
            </div>
            
            <!-- Publication Activity Chart -->
            <div class="sjm-chart-container" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); max-width: 600px; height: 350px; margin: 0 auto; overflow-x: auto;">
                <h3 style="margin: 0 0 20px 0; color: #374151;">Publication Activity</h3>
                <canvas id="publicationActivityChart" style="width:100%;height:100%;min-width:400px;min-height:200px;"></canvas>
            </div>
        </div>
        
        <!-- Detailed Tables -->
        <div class="sjm-analytics-tables" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <!-- Top Performing Journals -->
            <div class="sjm-table-container" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #374151;">Top Performing Journals</h3>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Journal</th>
                            <th>Papers</th>
                            <th>Issues</th>
                            <th>Views</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($analytics_data['top_journals'] as $journal): ?>
                        <tr>
                            <td><a href="<?php echo esc_url(get_edit_post_link($journal['id'])); ?>"><?php echo esc_html($journal['title']); ?></a></td>
                            <td><?php echo esc_html($journal['papers']); ?></td>
                            <td><?php echo esc_html($journal['issues']); ?></td>
                            <td><?php echo esc_html($journal['views']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Recent Activity -->
            <div class="sjm-table-container" style="background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #374151;">Recent Activity</h3>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Item</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($analytics_data['recent_activity'] as $activity): ?>
                        <tr>
                            <td><?php echo esc_html($activity['action']); ?></td>
                            <td><a href="<?php echo esc_url($activity['link']); ?>"><?php echo esc_html($activity['title']); ?></a></td>
                            <td><?php echo esc_html($activity['date']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Export Options -->
        <div class="sjm-analytics-export" style="margin-top: 30px; padding: 20px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;">
            <h3 style="margin: 0 0 15px 0; color: #374151;">Export Analytics Data</h3>
            <div style="display: flex; gap: 10px;">
                <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=sjm_export_analytics&format=csv&start_date=' . $start_date . '&end_date=' . $end_date)); ?>" class="button">Export as CSV</a>
                <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=sjm_export_analytics&format=json&start_date=' . $start_date . '&end_date=' . $end_date)); ?>" class="button">Export as JSON</a>
                <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=sjm_export_analytics&format=pdf&start_date=' . $start_date . '&end_date=' . $end_date)); ?>" class="button">Export as PDF</a>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    // Content Growth Chart
    const contentGrowthCtx = document.getElementById('contentGrowthChart').getContext('2d');
    new Chart(contentGrowthCtx, {
        type: 'line',
        data: {
            labels: <?php echo json_encode($analytics_data['chart_labels']); ?>,
            datasets: [{
                label: 'Journals',
                data: <?php echo json_encode($analytics_data['journals_data']); ?>,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4
            }, {
                label: 'Issues',
                data: <?php echo json_encode($analytics_data['issues_data']); ?>,
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.4
            }, {
                label: 'Papers',
                data: <?php echo json_encode($analytics_data['papers_data']); ?>,
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'top',
                }
            },
            scales: {
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 12
                    }
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Publication Activity Chart
    const publicationActivityCtx = document.getElementById('publicationActivityChart').getContext('2d');
    new Chart(publicationActivityCtx, {
        type: 'bar',
        data: {
            labels: <?php echo json_encode($analytics_data['activity_labels']); ?>,
            datasets: [{
                label: 'Publications',
                data: <?php echo json_encode($analytics_data['activity_data']); ?>,
                backgroundColor: 'rgba(59, 130, 246, 0.8)',
                borderColor: '#3b82f6',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'top',
                }
            },
            scales: {
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 7
                    }
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    </script>
    <?php
}

function sjm_get_analytics_data($start_date, $end_date) {
    global $wpdb;
    
    $data = array();
    
    // Calculate previous period for comparison
    $period_days = (strtotime($end_date) - strtotime($start_date)) / (24 * 60 * 60);
    $prev_start_date = date('Y-m-d', strtotime($start_date . " -{$period_days} days"));
    $prev_end_date = date('Y-m-d', strtotime($start_date . ' -1 day'));
    
    // Total counts for current period
    $data['total_journals'] = wp_count_posts('journal')->publish;
    $data['total_issues'] = wp_count_posts('journal_issue')->publish;
    $data['total_papers'] = wp_count_posts('paper')->publish;
    $data['total_authors'] = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}sjm_authors");
    
    // Previous period counts
    $prev_journals = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'journal' AND post_status = 'publish' AND post_date BETWEEN %s AND %s",
        $prev_start_date,
        $prev_end_date
    ));
    $prev_issues = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'journal_issue' AND post_status = 'publish' AND post_date BETWEEN %s AND %s",
        $prev_start_date,
        $prev_end_date
    ));
    $prev_papers = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'paper' AND post_status = 'publish' AND post_date BETWEEN %s AND %s",
        $prev_start_date,
        $prev_end_date
    ));
    
    // Calculate percentage changes
    $data['journals_change'] = $prev_journals > 0 ? round((($data['total_journals'] - $prev_journals) / $prev_journals) * 100, 1) : 0;
    $data['issues_change'] = $prev_issues > 0 ? round((($data['total_issues'] - $prev_issues) / $prev_issues) * 100, 1) : 0;
    $data['papers_change'] = $prev_papers > 0 ? round((($data['total_papers'] - $prev_papers) / $prev_papers) * 100, 1) : 0;
    $data['authors_change'] = 0; // Placeholder for author change calculation
    
    // Chart data
    $data['chart_labels'] = array();
    $data['journals_data'] = array();
    $data['issues_data'] = array();
    $data['papers_data'] = array();
    
    // Generate chart data for the last 12 months
    for ($i = 11; $i >= 0; $i--) {
        $month_start = date('Y-m-01', strtotime("-{$i} months"));
        $month_end = date('Y-m-t', strtotime("-{$i} months"));
        
        $data['chart_labels'][] = date('M Y', strtotime($month_start));
        
        $data['journals_data'][] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'journal' AND post_status = 'publish' AND post_date BETWEEN %s AND %s",
            $month_start,
            $month_end
        ));
        
        $data['issues_data'][] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'journal_issue' AND post_status = 'publish' AND post_date BETWEEN %s AND %s",
            $month_start,
            $month_end
        ));
        
        $data['papers_data'][] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'paper' AND post_status = 'publish' AND post_date BETWEEN %s AND %s",
            $month_start,
            $month_end
        ));
    }
    
    // Publication activity data (last 7 days)
    $data['activity_labels'] = array();
    $data['activity_data'] = array();
    
    for ($i = 6; $i >= 0; $i--) {
        $day = date('Y-m-d', strtotime("-{$i} days"));
        $data['activity_labels'][] = date('M j', strtotime($day));
        
        $data['activity_data'][] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('journal', 'journal_issue', 'paper') AND post_status = 'publish' AND DATE(post_date) = %s",
            $day
        ));
    }
    
    // Top performing journals
    $data['top_journals'] = $wpdb->get_results(
        "SELECT 
            j.ID as id,
            j.post_title as title,
            COUNT(DISTINCT p.ID) as papers,
            COUNT(DISTINCT i.ID) as issues,
            COALESCE(SUM(pm.meta_value), 0) as views
        FROM {$wpdb->posts} j
        LEFT JOIN {$wpdb->posts} i ON i.post_type = 'journal_issue' AND i.post_status = 'publish'
        LEFT JOIN {$wpdb->postmeta} im ON im.post_id = i.ID AND im.meta_key = '_sjm_issue_journal'
        LEFT JOIN {$wpdb->posts} p ON p.post_type = 'paper' AND p.post_status = 'publish'
        LEFT JOIN {$wpdb->postmeta} pm ON pm.post_id = p.ID AND pm.meta_key = '_sjm_paper_journal'
        LEFT JOIN {$wpdb->postmeta} pv ON pv.post_id = p.ID AND pv.meta_key = '_sjm_views_count'
        WHERE j.post_type = 'journal' AND j.post_status = 'publish'
        AND (im.meta_value = j.ID OR pm.meta_value = j.ID)
        GROUP BY j.ID
        ORDER BY papers DESC, views DESC
        LIMIT 10",
        ARRAY_A
    );
    
    // Recent activity
    $data['recent_activity'] = $wpdb->get_results($wpdb->prepare(
        "SELECT 
            'Published' as action,
            post_title as title,
            post_date as date,
            CONCAT('post.php?post=', ID, '&action=edit') as link
        FROM {$wpdb->posts} 
        WHERE post_type IN ('journal', 'journal_issue', 'paper') 
        AND post_status = 'publish'
        AND post_date BETWEEN %s AND %s
        ORDER BY post_date DESC
        LIMIT 10",
        $start_date,
        $end_date
    ), ARRAY_A);
    
    return $data;
}

// Export analytics data
function sjm_export_analytics() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'wisdom-journal-manager'));
    }
    
    $format = isset($_GET['format']) ? sanitize_text_field($_GET['format']) : 'csv';
    $start_date = isset($_GET['start_date']) ? sanitize_text_field($_GET['start_date']) : date('Y-m-d', strtotime('-30 days'));
    $end_date = isset($_GET['end_date']) ? sanitize_text_field($_GET['end_date']) : date('Y-m-d');
    
    $analytics_data = sjm_get_analytics_data($start_date, $end_date);
    
    switch ($format) {
        case 'csv':
            sjm_export_analytics_csv($analytics_data, $start_date, $end_date);
            break;
        case 'json':
            sjm_export_analytics_json($analytics_data, $start_date, $end_date);
            break;
        case 'pdf':
            sjm_export_analytics_pdf($analytics_data, $start_date, $end_date);
            break;
    }
}
add_action('wp_ajax_sjm_export_analytics', 'sjm_export_analytics');

function sjm_export_analytics_csv($data, $start_date, $end_date) {
    $filename = "journal-analytics-{$start_date}-to-{$end_date}.csv";
    
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    
    // Write headers
    fputcsv($output, array('Metric', 'Value', 'Change %'));
    fputcsv($output, array('Total Journals', $data['total_journals'], $data['journals_change']));
    fputcsv($output, array('Total Issues', $data['total_issues'], $data['issues_change']));
    fputcsv($output, array('Total Papers', $data['total_papers'], $data['papers_change']));
    fputcsv($output, array('Total Authors', $data['total_authors'], $data['authors_change']));
    
    fclose($output);
    exit;
}

function sjm_export_analytics_json($data, $start_date, $end_date) {
    $filename = "journal-analytics-{$start_date}-to-{$end_date}.json";
    
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    echo json_encode($data, JSON_PRETTY_PRINT);
    exit;
}

function sjm_export_analytics_pdf($data, $start_date, $end_date) {
    // This would require a PDF library like TCPDF or mPDF
    // For now, we'll create a simple HTML report
    $filename = "journal-analytics-{$start_date}-to-{$end_date}.html";
    
    header('Content-Type: text/html');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Journal Analytics Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { text-align: center; margin-bottom: 30px; }
            .metric { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f5f5f5; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Journal Analytics Report</h1>
            <p>Period: <?php echo esc_html($start_date); ?> to <?php echo esc_html($end_date); ?></p>
        </div>
        
        <h2>Key Metrics</h2>
        <div class="metric">
            <strong>Total Journals:</strong> <?php echo esc_html($data['total_journals']); ?> 
            (<?php echo esc_html($data['journals_change']); ?>% change)
        </div>
        <div class="metric">
            <strong>Total Issues:</strong> <?php echo esc_html($data['total_issues']); ?> 
            (<?php echo esc_html($data['issues_change']); ?>% change)
        </div>
        <div class="metric">
            <strong>Total Papers:</strong> <?php echo esc_html($data['total_papers']); ?> 
            (<?php echo esc_html($data['papers_change']); ?>% change)
        </div>
        <div class="metric">
            <strong>Total Authors:</strong> <?php echo esc_html($data['total_authors']); ?> 
            (<?php echo esc_html($data['authors_change']); ?>% change)
        </div>
        
        <h2>Top Performing Journals</h2>
        <table>
            <tr>
                <th>Journal</th>
                <th>Papers</th>
                <th>Issues</th>
                <th>Views</th>
            </tr>
            <?php foreach ($data['top_journals'] as $journal): ?>
            <tr>
                <td><?php echo esc_html($journal['title']); ?></td>
                <td><?php echo esc_html($journal['papers']); ?></td>
                <td><?php echo esc_html($journal['issues']); ?></td>
                <td><?php echo esc_html($journal['views']); ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </body>
    </html>
    <?php
    exit;
}

// Enhanced analytics functions
function sjm_get_journal_performance_metrics($journal_id, $start_date = null, $end_date = null) {
    global $wpdb;
    
    if (!$start_date) $start_date = date('Y-m-d', strtotime('-30 days'));
    if (!$end_date) $end_date = date('Y-m-d');
    
    $metrics = array();
    
    // Get papers count
    $metrics['papers_count'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        WHERE p.post_type = 'paper' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_paper_journal' AND pm.meta_value = %d",
        $journal_id
    ));
    
    // Get issues count
    $metrics['issues_count'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        WHERE p.post_type = 'journal_issue' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_issue_journal' AND pm.meta_value = %d",
        $journal_id
    ));
    
    // Get total views
    $metrics['total_views'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COALESCE(SUM(pm.meta_value), 0) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        JOIN {$wpdb->postmeta} pj ON p.ID = pj.post_id 
        WHERE p.post_type = 'paper' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_views_count' 
        AND pj.meta_key = '_sjm_paper_journal' AND pj.meta_value = %d",
        $journal_id
    ));
    
    // Get average citations
    $metrics['avg_citations'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COALESCE(AVG(pm.meta_value), 0) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        JOIN {$wpdb->postmeta} pj ON p.ID = pj.post_id 
        WHERE p.post_type = 'paper' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_citation_count' 
        AND pj.meta_key = '_sjm_paper_journal' AND pj.meta_value = %d",
        $journal_id
    ));
    
    return $metrics;
}

function sjm_get_author_analytics($author_id, $start_date = null, $end_date = null) {
    global $wpdb;
    
    if (!$start_date) $start_date = date('Y-m-d', strtotime('-30 days'));
    if (!$end_date) $end_date = date('Y-m-d');
    
    $analytics = array();
    
    // Get papers by this author
    $analytics['papers_count'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(DISTINCT p.ID) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        WHERE p.post_type = 'paper' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_paper_authors_data' 
        AND pm.meta_value LIKE %s",
        '%"author_id":"' . $author_id . '"%'
    ));
    
    // Get total citations
    $analytics['total_citations'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COALESCE(SUM(pm.meta_value), 0) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        JOIN {$wpdb->postmeta} pa ON p.ID = pa.post_id 
        WHERE p.post_type = 'paper' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_citation_count' 
        AND pa.meta_key = '_sjm_paper_authors_data' 
        AND pa.meta_value LIKE %s",
        '%"author_id":"' . $author_id . '"%'
    ));
    
    // Get total views
    $analytics['total_views'] = $wpdb->get_var($wpdb->prepare(
        "SELECT COALESCE(SUM(pm.meta_value), 0) FROM {$wpdb->posts} p 
        JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
        JOIN {$wpdb->postmeta} pa ON p.ID = pa.post_id 
        WHERE p.post_type = 'paper' AND p.post_status = 'publish' 
        AND pm.meta_key = '_sjm_views_count' 
        AND pa.meta_key = '_sjm_paper_authors_data' 
        AND pa.meta_value LIKE %s",
        '%"author_id":"' . $author_id . '"%'
    ));
    
    return $analytics;
}

// Add analytics widget to dashboard
function sjm_add_analytics_dashboard_widget() {
    wp_add_dashboard_widget(
        'sjm_analytics_widget',
        'Journal Analytics Overview',
        'sjm_analytics_dashboard_widget_content'
    );
}
add_action('wp_dashboard_setup', 'sjm_add_analytics_dashboard_widget');

function sjm_analytics_dashboard_widget_content() {
    $analytics_data = sjm_get_analytics_data(date('Y-m-d', strtotime('-30 days')), date('Y-m-d'));
    
    ?>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
        <div>
            <strong>Journals:</strong> <?php echo esc_html($analytics_data['total_journals']); ?>
        </div>
        <div>
            <strong>Issues:</strong> <?php echo esc_html($analytics_data['total_issues']); ?>
        </div>
        <div>
            <strong>Papers:</strong> <?php echo esc_html($analytics_data['total_papers']); ?>
        </div>
        <div>
            <strong>Authors:</strong> <?php echo esc_html($analytics_data['total_authors']); ?>
        </div>
    </div>
    <p style="margin-top: 15px;">
        <a href="<?php echo esc_url(admin_url('edit.php?post_type=journal&page=sjm-analytics')); ?>" class="button button-primary">
            View Full Analytics
        </a>
    </p>
    <?php
}

