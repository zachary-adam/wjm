<?php
/*
Plugin Name: Wisdom Journal Manager
Plugin URI: http://aethexweb.com
Description: World's First Affordable Journal Manager — a full-stack WordPress solution for managing academic journals, issues, papers, and authors with automated citation tracking and enterprise-grade security.
Version: 1.0.0
Author: Zachary Adam
Author URI: http://aethexweb.com
Company: Aethex
Text Domain: wisdom-journal-manager
Domain Path: /languages
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('WJM_VERSION', '1.0.3');
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
            case 'doi':
                // DOI format validation: 10.xxxx/xxxxx
                $clean = sanitize_text_field($input);
                if (preg_match('/^10\.\d{4,}\/[^\s]+$/i', $clean)) {
                    return $clean;
                }
                return ''; // Invalid DOI format
            case 'issn':
                // ISSN format validation: XXXX-XXXX (8 digits with hyphen)
                $clean = sanitize_text_field($input);
                $clean = strtoupper(str_replace([' ', '-'], '', $clean));
                if (preg_match('/^[0-9]{7}[0-9X]$/', $clean)) {
                    // Format as XXXX-XXXX
                    return substr($clean, 0, 4) . '-' . substr($clean, 4);
                }
                return ''; // Invalid ISSN format
            case 'orcid':
                // ORCID format validation: 0000-0000-0000-0000
                $clean = sanitize_text_field($input);
                $clean = str_replace([' ', '-'], '', $clean);
                if (preg_match('/^[0-9]{15}[0-9X]$/i', $clean)) {
                    // Format as 0000-0000-0000-0000
                    return substr($clean, 0, 4) . '-' . substr($clean, 4, 4) . '-' . substr($clean, 8, 4) . '-' . substr($clean, 12);
                }
                return ''; // Invalid ORCID format
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
     * Enhanced file upload validation with improved security
     * Fixed: Check size BEFORE reading content, validate real MIME type
     */
    public static function validate_file_upload($file, $allowed_types = null) {
        // Security improvement: Check if file was actually uploaded
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            return new WP_Error('invalid_upload', 'Invalid file upload.');
        }

        // Security improvement: Check file size FIRST before reading content
        $max_size = 10 * 1024 * 1024; // 10MB
        if ($file['size'] > $max_size || filesize($file['tmp_name']) > $max_size) {
            return new WP_Error('file_too_large', 'File size exceeds 10MB limit.');
        }

        // Security improvement: Check if file is empty
        if ($file['size'] == 0 || filesize($file['tmp_name']) == 0) {
            return new WP_Error('empty_file', 'Uploaded file is empty.');
        }

        $allowed_types = $allowed_types ?: array(
            'pdf' => 'application/pdf',
            'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'txt' => 'text/plain',
            'rtf' => 'application/rtf'
        );

        $file_type = wp_check_filetype($file['name']);

        // Security improvement: Check file extension
        if (!in_array($file_type['ext'], array_keys($allowed_types))) {
            return new WP_Error('invalid_file_type', 'File type not allowed. Allowed types: ' . implode(', ', array_keys($allowed_types)));
        }

        // Security improvement: Verify MIME type from file content, not user input
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $real_mime = finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);

            if (!in_array($real_mime, array_values($allowed_types))) {
                return new WP_Error('invalid_mime_type', 'File MIME type not allowed. Detected: ' . $real_mime);
            }
        } else {
            // Fallback to user-provided MIME (less secure but better than nothing)
            $file_mime = $file['type'];
            if (!in_array($file_mime, array_values($allowed_types))) {
                return new WP_Error('invalid_mime_type', 'File MIME type not allowed.');
            }
        }

        // Security improvement: Scan only first 1MB of file for malicious patterns
        $scan_size = min(1024 * 1024, filesize($file['tmp_name']));
        $handle = fopen($file['tmp_name'], 'r');
        if (!$handle) {
            return new WP_Error('file_read_error', 'Could not read uploaded file.');
        }

        $file_content = fread($handle, $scan_size);
        fclose($handle);

        $malicious_patterns = array(
            '/<script/i',
            '/<iframe/i',
            '/javascript:/i',
            '/vbscript:/i',
            '/onload\s*=/i',
            '/onerror\s*=/i',
            '/eval\s*\(/i',
            '/<\?php/i',
            '/<?=/i',
            '/<object/i',
            '/<embed/i'
        );

        foreach ($malicious_patterns as $pattern) {
            if (preg_match($pattern, $file_content)) {
                // Log security event
                self::log_security_event('malicious_file_upload_attempt', array(
                    'filename' => $file['name'],
                    'pattern_matched' => $pattern
                ), 'warning');

                return new WP_Error('malicious_content', 'File contains potentially malicious content and has been blocked.');
            }
        }

        // Security improvement: Sanitize filename
        $sanitized_name = sanitize_file_name($file['name']);
        if ($sanitized_name !== $file['name']) {
            $file['name'] = $sanitized_name;
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

// ========================================
// FORMAT VALIDATION HELPERS
// ========================================

/**
 * Validate DOI format
 * DOI format: 10.xxxx/xxxxx
 *
 * @param string $doi The DOI to validate
 * @return array Array with 'valid' (bool) and 'message' (string) keys
 */
function wjm_validate_doi($doi) {
    if (empty($doi)) {
        return array('valid' => false, 'message' => 'DOI cannot be empty');
    }

    $doi = trim($doi);

    // DOI must start with 10. and contain a forward slash
    if (!preg_match('/^10\.\d{4,}\/[^\s]+$/i', $doi)) {
        return array(
            'valid' => false,
            'message' => 'Invalid DOI format. Must be in format: 10.xxxx/xxxxx (e.g., 10.1234/example)'
        );
    }

    return array('valid' => true, 'message' => 'Valid DOI format');
}

/**
 * Validate ISSN format
 * ISSN format: XXXX-XXXX (8 digits with hyphen, last can be X)
 *
 * @param string $issn The ISSN to validate
 * @return array Array with 'valid' (bool) and 'message' (string) keys
 */
function wjm_validate_issn($issn) {
    if (empty($issn)) {
        return array('valid' => false, 'message' => 'ISSN cannot be empty');
    }

    $issn = trim($issn);
    $clean = strtoupper(str_replace([' ', '-'], '', $issn));

    // ISSN must be exactly 8 characters (7 digits + check digit which can be X)
    if (!preg_match('/^[0-9]{7}[0-9X]$/', $clean)) {
        return array(
            'valid' => false,
            'message' => 'Invalid ISSN format. Must be 8 digits in format: XXXX-XXXX (e.g., 1234-5678)'
        );
    }

    // Validate ISSN check digit
    $sum = 0;
    for ($i = 0; $i < 7; $i++) {
        $sum += intval($clean[$i]) * (8 - $i);
    }
    $check_digit = (11 - ($sum % 11)) % 11;
    $expected = ($check_digit == 10) ? 'X' : strval($check_digit);

    if ($clean[7] !== $expected) {
        return array(
            'valid' => false,
            'message' => 'Invalid ISSN check digit. Expected: ' . $expected . ', got: ' . $clean[7]
        );
    }

    return array('valid' => true, 'message' => 'Valid ISSN format');
}

/**
 * Validate ORCID format
 * ORCID format: 0000-0000-0000-0000 (16 digits with hyphens, last can be X)
 *
 * @param string $orcid The ORCID to validate
 * @return array Array with 'valid' (bool) and 'message' (string) keys
 */
function wjm_validate_orcid($orcid) {
    if (empty($orcid)) {
        return array('valid' => false, 'message' => 'ORCID cannot be empty');
    }

    $orcid = trim($orcid);

    // Remove https://orcid.org/ prefix if present
    $orcid = str_replace(['https://orcid.org/', 'http://orcid.org/'], '', $orcid);

    $clean = strtoupper(str_replace([' ', '-'], '', $orcid));

    // ORCID must be exactly 16 characters (15 digits + check digit which can be X)
    if (!preg_match('/^[0-9]{15}[0-9X]$/i', $clean)) {
        return array(
            'valid' => false,
            'message' => 'Invalid ORCID format. Must be 16 digits in format: 0000-0000-0000-0000 (e.g., 0000-0002-1825-0097)'
        );
    }

    // Validate ORCID check digit (MOD 11-2 algorithm)
    $total = 0;
    for ($i = 0; $i < 15; $i++) {
        $digit = intval($clean[$i]);
        $total = ($total + $digit) * 2;
    }
    $remainder = $total % 11;
    $result = (12 - $remainder) % 11;
    $expected = ($result == 10) ? 'X' : strval($result);

    if ($clean[15] !== $expected) {
        return array(
            'valid' => false,
            'message' => 'Invalid ORCID check digit. Expected: ' . $expected . ', got: ' . $clean[15]
        );
    }

    return array('valid' => true, 'message' => 'Valid ORCID format');
}

/**
 * Format DOI for display
 */
function wjm_format_doi($doi) {
    return trim($doi);
}

/**
 * Format ISSN for display (XXXX-XXXX)
 */
function wjm_format_issn($issn) {
    $clean = strtoupper(str_replace([' ', '-'], '', $issn));
    if (strlen($clean) === 8) {
        return substr($clean, 0, 4) . '-' . substr($clean, 4);
    }
    return $issn;
}

/**
 * Format ORCID for display (0000-0000-0000-0000)
 */
function wjm_format_orcid($orcid) {
    // Remove URL prefix if present
    $orcid = str_replace(['https://orcid.org/', 'http://orcid.org/'], '', $orcid);
    $clean = str_replace([' ', '-'], '', $orcid);
    if (strlen($clean) === 16) {
        return substr($clean, 0, 4) . '-' . substr($clean, 4, 4) . '-' . substr($clean, 8, 4) . '-' . substr($clean, 12);
    }
    return $orcid;
}

/**
 * Check if DOI already exists in the database
 *
 * @param string $doi The DOI to check
 * @param int $exclude_post_id Optional post ID to exclude from check (for updates)
 * @return array Array with 'exists' (bool), 'post_id' (int), and 'post_title' (string) keys
 */
function wjm_check_duplicate_doi($doi, $exclude_post_id = 0) {
    if (empty($doi)) {
        return array('exists' => false, 'post_id' => 0, 'post_title' => '');
    }

    // Normalize DOI for comparison
    $doi = trim(strtolower($doi));

    // Query for papers with this DOI
    $args = array(
        'post_type' => 'paper',
        'post_status' => array('publish', 'draft', 'pending', 'private'),
        'posts_per_page' => 1,
        'meta_query' => array(
            array(
                'key' => '_sjm_paper_doi',
                'value' => $doi,
                'compare' => '='
            )
        ),
        'fields' => 'ids'
    );

    // Exclude current post if updating
    if ($exclude_post_id > 0) {
        $args['post__not_in'] = array($exclude_post_id);
    }

    $query = new WP_Query($args);

    if ($query->have_posts()) {
        $post_id = $query->posts[0];
        $post_title = get_the_title($post_id);

        return array(
            'exists' => true,
            'post_id' => $post_id,
            'post_title' => $post_title,
            'edit_link' => admin_url('post.php?post=' . $post_id . '&action=edit')
        );
    }

    return array('exists' => false, 'post_id' => 0, 'post_title' => '');
}

/**
 * Hook to validate DOI before saving paper
 */
function wjm_validate_paper_doi_before_save($post_id, $post, $update) {
    // Only for paper post type
    if ($post->post_type !== 'paper') {
        return;
    }

    // Skip autosave and revisions
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
        return;
    }
    if (wp_is_post_revision($post_id)) {
        return;
    }

    // Check if DOI is being saved
    if (isset($_POST['_sjm_paper_doi'])) {
        $doi = trim($_POST['_sjm_paper_doi']);

        if (!empty($doi)) {
            // Validate DOI format
            $validation = wjm_validate_doi($doi);
            if (!$validation['valid']) {
                // Store error in transient to show on next page load
                set_transient('wjm_doi_validation_error_' . $post_id, $validation['message'], 60);
                return;
            }

            // Check for duplicate DOI
            $duplicate_check = wjm_check_duplicate_doi($doi, $post_id);
            if ($duplicate_check['exists']) {
                $error_msg = sprintf(
                    'Duplicate DOI detected! This DOI is already used by paper: <a href="%s" target="_blank">%s</a>',
                    $duplicate_check['edit_link'],
                    $duplicate_check['post_title']
                );
                set_transient('wjm_doi_duplicate_error_' . $post_id, $error_msg, 60);
            }
        }
    }
}
add_action('save_post', 'wjm_validate_paper_doi_before_save', 10, 3);

/**
 * Display DOI validation errors in admin notices
 */
function wjm_display_doi_validation_errors() {
    global $post;

    if (!$post || $post->post_type !== 'paper') {
        return;
    }

    // Check for validation error
    $validation_error = get_transient('wjm_doi_validation_error_' . $post->ID);
    if ($validation_error) {
        echo '<div class="notice notice-error is-dismissible"><p><strong>DOI Validation Error:</strong> ' . esc_html($validation_error) . '</p></div>';
        delete_transient('wjm_doi_validation_error_' . $post->ID);
    }

    // Check for duplicate error
    $duplicate_error = get_transient('wjm_doi_duplicate_error_' . $post->ID);
    if ($duplicate_error) {
        echo '<div class="notice notice-warning is-dismissible"><p><strong>Warning:</strong> ' . wp_kses_post($duplicate_error) . '</p></div>';
        delete_transient('wjm_doi_duplicate_error_' . $post->ID);
    }
}
add_action('admin_notices', 'wjm_display_doi_validation_errors');

// ========================================
// CITATION EXPORT SYSTEM
// ========================================

/**
 * Get paper metadata for export
 *
 * @param int $post_id The paper post ID
 * @return array Paper metadata
 */
function wjm_get_paper_export_data($post_id) {
    $paper = get_post($post_id);
    if (!$paper || $paper->post_type !== 'paper') {
        return null;
    }

    // Get all paper metadata
    $data = array(
        'title' => get_the_title($post_id),
        'abstract' => get_the_content(null, false, $post_id),
        'doi' => get_post_meta($post_id, '_sjm_paper_doi', true),
        'keywords' => get_post_meta($post_id, '_sjm_paper_keywords', true),
        'pages' => get_post_meta($post_id, '_sjm_paper_pages', true),
        'year' => date('Y', strtotime($paper->post_date)),
        'month' => date('m', strtotime($paper->post_date)),
        'day' => date('d', strtotime($paper->post_date)),
        'url' => get_permalink($post_id),
        'paper_type' => get_post_meta($post_id, '_sjm_paper_type', true),
        'authors' => array(),
        'journal' => '',
        'volume' => '',
        'issue' => '',
        'publisher' => ''
    );

    // Get authors
    $authors_data = get_post_meta($post_id, '_sjm_paper_authors', true);
    if (is_array($authors_data)) {
        foreach ($authors_data as $author) {
            if (is_array($author)) {
                $data['authors'][] = array(
                    'first_name' => $author['first_name'] ?? '',
                    'last_name' => $author['last_name'] ?? '',
                    'full_name' => trim(($author['first_name'] ?? '') . ' ' . ($author['last_name'] ?? ''))
                );
            }
        }
    }

    // Get journal information
    $journal_id = get_post_meta($post_id, '_sjm_paper_journal', true);
    if ($journal_id) {
        $data['journal'] = get_the_title($journal_id);
        $data['publisher'] = get_post_meta($journal_id, '_sjm_publisher', true);
    }

    // Get issue information
    $issue_id = get_post_meta($post_id, '_sjm_paper_issue', true);
    if ($issue_id) {
        $data['volume'] = get_post_meta($issue_id, '_sjm_issue_volume', true);
        $data['issue'] = get_post_meta($issue_id, '_sjm_issue_number', true);
    }

    return $data;
}

/**
 * Export paper to BibTeX format
 *
 * @param int $post_id The paper post ID
 * @return string BibTeX formatted citation
 */
function wjm_export_bibtex($post_id) {
    $data = wjm_get_paper_export_data($post_id);
    if (!$data) {
        return '';
    }

    // Generate citation key (FirstAuthorLastName + Year)
    $citation_key = 'paper' . $post_id;
    if (!empty($data['authors'][0]['last_name'])) {
        $citation_key = preg_replace('/[^a-zA-Z0-9]/', '', $data['authors'][0]['last_name']) . $data['year'];
    }

    $bibtex = "@article{" . $citation_key . ",\n";
    $bibtex .= "  title = {" . addslashes($data['title']) . "},\n";

    // Add authors
    if (!empty($data['authors'])) {
        $author_list = array();
        foreach ($data['authors'] as $author) {
            $author_list[] = $author['last_name'] . ', ' . $author['first_name'];
        }
        $bibtex .= "  author = {" . implode(' and ', $author_list) . "},\n";
    }

    if (!empty($data['journal'])) {
        $bibtex .= "  journal = {" . addslashes($data['journal']) . "},\n";
    }

    if (!empty($data['year'])) {
        $bibtex .= "  year = {" . $data['year'] . "},\n";
    }

    if (!empty($data['volume'])) {
        $bibtex .= "  volume = {" . $data['volume'] . "},\n";
    }

    if (!empty($data['issue'])) {
        $bibtex .= "  number = {" . $data['issue'] . "},\n";
    }

    if (!empty($data['pages'])) {
        $bibtex .= "  pages = {" . $data['pages'] . "},\n";
    }

    if (!empty($data['doi'])) {
        $bibtex .= "  doi = {" . $data['doi'] . "},\n";
    }

    if (!empty($data['url'])) {
        $bibtex .= "  url = {" . $data['url'] . "},\n";
    }

    if (!empty($data['keywords'])) {
        $bibtex .= "  keywords = {" . addslashes($data['keywords']) . "},\n";
    }

    if (!empty($data['abstract'])) {
        $abstract = strip_tags($data['abstract']);
        $bibtex .= "  abstract = {" . addslashes($abstract) . "},\n";
    }

    if (!empty($data['publisher'])) {
        $bibtex .= "  publisher = {" . addslashes($data['publisher']) . "},\n";
    }

    $bibtex = rtrim($bibtex, ",\n") . "\n";
    $bibtex .= "}\n";

    return $bibtex;
}

/**
 * Export paper to RIS format
 *
 * @param int $post_id The paper post ID
 * @return string RIS formatted citation
 */
function wjm_export_ris($post_id) {
    $data = wjm_get_paper_export_data($post_id);
    if (!$data) {
        return '';
    }

    $ris = "TY  - JOUR\n"; // Journal Article

    $ris .= "TI  - " . $data['title'] . "\n";

    // Add authors
    foreach ($data['authors'] as $author) {
        $ris .= "AU  - " . $author['last_name'] . ", " . $author['first_name'] . "\n";
    }

    if (!empty($data['journal'])) {
        $ris .= "JO  - " . $data['journal'] . "\n";
        $ris .= "T2  - " . $data['journal'] . "\n"; // Secondary title
    }

    if (!empty($data['year'])) {
        $ris .= "PY  - " . $data['year'] . "\n";
        $ris .= "Y1  - " . $data['year'] . "/" . $data['month'] . "/" . $data['day'] . "\n";
    }

    if (!empty($data['volume'])) {
        $ris .= "VL  - " . $data['volume'] . "\n";
    }

    if (!empty($data['issue'])) {
        $ris .= "IS  - " . $data['issue'] . "\n";
    }

    if (!empty($data['pages'])) {
        $pages = explode('-', $data['pages']);
        if (count($pages) == 2) {
            $ris .= "SP  - " . trim($pages[0]) . "\n"; // Start page
            $ris .= "EP  - " . trim($pages[1]) . "\n"; // End page
        } else {
            $ris .= "SP  - " . $data['pages'] . "\n";
        }
    }

    if (!empty($data['doi'])) {
        $ris .= "DO  - " . $data['doi'] . "\n";
    }

    if (!empty($data['url'])) {
        $ris .= "UR  - " . $data['url'] . "\n";
    }

    if (!empty($data['keywords'])) {
        $keywords = array_map('trim', explode(',', $data['keywords']));
        foreach ($keywords as $keyword) {
            $ris .= "KW  - " . $keyword . "\n";
        }
    }

    if (!empty($data['abstract'])) {
        $abstract = strip_tags($data['abstract']);
        $ris .= "AB  - " . $abstract . "\n";
    }

    if (!empty($data['publisher'])) {
        $ris .= "PB  - " . $data['publisher'] . "\n";
    }

    $ris .= "ER  - \n\n"; // End of reference

    return $ris;
}

/**
 * Export paper to EndNote (ENW) format
 *
 * @param int $post_id The paper post ID
 * @return string EndNote formatted citation
 */
function wjm_export_endnote($post_id) {
    $data = wjm_get_paper_export_data($post_id);
    if (!$data) {
        return '';
    }

    $endnote = "%0 Journal Article\n"; // Reference type

    $endnote .= "%T " . $data['title'] . "\n";

    // Add authors
    foreach ($data['authors'] as $author) {
        $endnote .= "%A " . $author['full_name'] . "\n";
    }

    if (!empty($data['journal'])) {
        $endnote .= "%J " . $data['journal'] . "\n";
    }

    if (!empty($data['year'])) {
        $endnote .= "%D " . $data['year'] . "\n";
    }

    if (!empty($data['volume'])) {
        $endnote .= "%V " . $data['volume'] . "\n";
    }

    if (!empty($data['issue'])) {
        $endnote .= "%N " . $data['issue'] . "\n";
    }

    if (!empty($data['pages'])) {
        $endnote .= "%P " . $data['pages'] . "\n";
    }

    if (!empty($data['doi'])) {
        $endnote .= "%R " . $data['doi'] . "\n"; // DOI
    }

    if (!empty($data['url'])) {
        $endnote .= "%U " . $data['url'] . "\n";
    }

    if (!empty($data['keywords'])) {
        $endnote .= "%K " . $data['keywords'] . "\n";
    }

    if (!empty($data['abstract'])) {
        $abstract = strip_tags($data['abstract']);
        $endnote .= "%X " . $abstract . "\n";
    }

    if (!empty($data['publisher'])) {
        $endnote .= "%I " . $data['publisher'] . "\n";
    }

    $endnote .= "\n";

    return $endnote;
}

/**
 * Handle citation export download
 */
function wjm_handle_citation_export() {
    if (!isset($_GET['wjm_export']) || !isset($_GET['paper_id']) || !isset($_GET['format'])) {
        return;
    }

    // Verify nonce
    if (!isset($_GET['nonce']) || !wp_verify_nonce($_GET['nonce'], 'wjm_export_citation')) {
        wp_die('Security check failed.');
    }

    $paper_id = intval($_GET['paper_id']);
    $format = sanitize_text_field($_GET['format']);

    // Check if paper exists
    $paper = get_post($paper_id);
    if (!$paper || $paper->post_type !== 'paper') {
        wp_die('Paper not found.');
    }

    // Generate export content
    $content = '';
    $filename = sanitize_file_name(sanitize_title(get_the_title($paper_id)));
    $mime_type = 'text/plain';

    switch ($format) {
        case 'bibtex':
            $content = wjm_export_bibtex($paper_id);
            $filename .= '.bib';
            $mime_type = 'application/x-bibtex';
            break;

        case 'ris':
            $content = wjm_export_ris($paper_id);
            $filename .= '.ris';
            $mime_type = 'application/x-research-info-systems';
            break;

        case 'endnote':
            $content = wjm_export_endnote($paper_id);
            $filename .= '.enw';
            $mime_type = 'application/x-endnote-refer';
            break;

        default:
            wp_die('Invalid export format.');
    }

    // Log export event
    WJM_Security_Manager::log_security_event('citation_export', array(
        'paper_id' => $paper_id,
        'format' => $format
    ), 'info');

    // Send download headers
    header('Content-Type: ' . $mime_type . '; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($content));
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    echo $content;
    exit;
}
add_action('init', 'wjm_handle_citation_export');

/**
 * Add export buttons to paper edit screen
 */
function wjm_add_citation_export_meta_box() {
    add_meta_box(
        'wjm_citation_export',
        'Export Citation',
        'wjm_citation_export_meta_box_callback',
        'paper',
        'side',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_citation_export_meta_box');

/**
 * Display export buttons in meta box
 */
function wjm_citation_export_meta_box_callback($post) {
    $nonce = wp_create_nonce('wjm_export_citation');

    echo '<div style="padding: 10px;">';
    echo '<p><strong>Download citation in:</strong></p>';

    // BibTeX export
    $bibtex_url = add_query_arg(array(
        'wjm_export' => '1',
        'paper_id' => $post->ID,
        'format' => 'bibtex',
        'nonce' => $nonce
    ), home_url());
    echo '<p><a href="' . esc_url($bibtex_url) . '" class="button button-secondary" style="width: 100%; text-align: center; margin-bottom: 8px;">📄 Download BibTeX</a></p>';

    // RIS export
    $ris_url = add_query_arg(array(
        'wjm_export' => '1',
        'paper_id' => $post->ID,
        'format' => 'ris',
        'nonce' => $nonce
    ), home_url());
    echo '<p><a href="' . esc_url($ris_url) . '" class="button button-secondary" style="width: 100%; text-align: center; margin-bottom: 8px;">📋 Download RIS</a></p>';

    // EndNote export
    $endnote_url = add_query_arg(array(
        'wjm_export' => '1',
        'paper_id' => $post->ID,
        'format' => 'endnote',
        'nonce' => $nonce
    ), home_url());
    echo '<p><a href="' . esc_url($endnote_url) . '" class="button button-secondary" style="width: 100%; text-align: center;">📚 Download EndNote</a></p>';

    echo '<p class="description">Compatible with reference managers like Zotero, Mendeley, and EndNote.</p>';
    echo '</div>';
}

// ========================================
// AUDIT LOGGING SYSTEM
// ========================================

/**
 * Log content changes for audit trail
 *
 * @param string $action The action performed (create, update, delete, etc.)
 * @param string $object_type Type of object (paper, journal, issue, author)
 * @param int $object_id ID of the object
 * @param array $changes Array of changes made
 * @param string $notes Optional notes
 */
function wjm_log_audit_event($action, $object_type, $object_id, $changes = array(), $notes = '') {
    global $wpdb;

    $user_id = get_current_user_id();
    $user = wp_get_current_user();
    $user_name = $user->display_name ?: $user->user_login;
    $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    $log_entry = array(
        'timestamp' => current_time('mysql'),
        'user_id' => $user_id,
        'user_name' => $user_name,
        'user_ip' => $user_ip,
        'action' => $action,
        'object_type' => $object_type,
        'object_id' => $object_id,
        'changes' => wp_json_encode($changes),
        'notes' => $notes
    );

    // Store in options (for simplicity - in production, use dedicated table)
    $audit_log = get_option('wjm_audit_log', array());

    // Keep only last 1000 entries to prevent bloat
    if (count($audit_log) >= 1000) {
        $audit_log = array_slice($audit_log, -999);
    }

    $audit_log[] = $log_entry;
    update_option('wjm_audit_log', $audit_log);
}

/**
 * Hook to log paper changes
 */
function wjm_audit_paper_changes($post_id, $post_after, $post_before) {
    if ($post_after->post_type !== 'paper') {
        return;
    }

    // Skip autosaves and revisions
    if (wp_is_post_revision($post_id) || (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE)) {
        return;
    }

    $changes = array();

    // Check if this is a new paper or update
    if ($post_before->post_status === 'auto-draft' && $post_after->post_status !== 'auto-draft') {
        wjm_log_audit_event('create', 'paper', $post_id, array('title' => $post_after->post_title), 'Paper created');
        return;
    }

    // Track title changes
    if ($post_before->post_title !== $post_after->post_title) {
        $changes['title'] = array(
            'from' => $post_before->post_title,
            'to' => $post_after->post_title
        );
    }

    // Track status changes
    if ($post_before->post_status !== $post_after->post_status) {
        $changes['status'] = array(
            'from' => $post_before->post_status,
            'to' => $post_after->post_status
        );
    }

    // Track content changes
    if ($post_before->post_content !== $post_after->post_content) {
        $changes['content'] = 'modified';
    }

    if (!empty($changes)) {
        wjm_log_audit_event('update', 'paper', $post_id, $changes, 'Paper updated');
    }
}
add_action('post_updated', 'wjm_audit_paper_changes', 10, 3);

/**
 * Hook to log paper deletion
 */
function wjm_audit_paper_deletion($post_id) {
    $post = get_post($post_id);
    if ($post && $post->post_type === 'paper') {
        wjm_log_audit_event('delete', 'paper', $post_id, array('title' => $post->post_title), 'Paper deleted');
    }
}
add_action('before_delete_post', 'wjm_audit_paper_deletion');

/**
 * Hook to log metadata changes
 */
function wjm_audit_metadata_changes($meta_id, $object_id, $meta_key, $meta_value) {
    // Only log important metadata for papers
    $post = get_post($object_id);
    if (!$post || $post->post_type !== 'paper') {
        return;
    }

    // Only log specific metadata fields
    $tracked_fields = array(
        '_sjm_paper_doi',
        '_sjm_paper_authors',
        '_sjm_paper_journal',
        '_sjm_paper_issue',
        '_sjm_paper_keywords'
    );

    if (in_array($meta_key, $tracked_fields)) {
        $old_value = get_post_meta($object_id, $meta_key, true);

        wjm_log_audit_event('metadata_update', 'paper', $object_id, array(
            'field' => $meta_key,
            'old_value' => $old_value,
            'new_value' => $meta_value
        ), 'Paper metadata updated');
    }
}
add_action('updated_post_meta', 'wjm_audit_metadata_changes', 10, 4);

/**
 * Add audit log viewer page
 */
function wjm_add_audit_log_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Audit Log',
        'Audit Log',
        'manage_options',
        'wjm-audit-log',
        'wjm_audit_log_page'
    );
}
add_action('admin_menu', 'wjm_add_audit_log_page');

/**
 * Display audit log page
 */
function wjm_audit_log_page() {
    // Handle export
    if (isset($_GET['export']) && wp_verify_nonce($_GET['nonce'], 'wjm_export_audit_log')) {
        $audit_log = get_option('wjm_audit_log', array());

        $filename = 'audit-log-' . date('Y-m-d-H-i-s') . '.csv';
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');

        $output = fopen('php://output', 'w');
        fputcsv($output, array('Timestamp', 'User', 'IP Address', 'Action', 'Object Type', 'Object ID', 'Changes', 'Notes'));

        foreach ($audit_log as $entry) {
            fputcsv($output, array(
                $entry['timestamp'],
                $entry['user_name'],
                $entry['user_ip'],
                $entry['action'],
                $entry['object_type'],
                $entry['object_id'],
                $entry['changes'],
                $entry['notes']
            ));
        }

        fclose($output);
        exit;
    }

    // Handle clear log
    if (isset($_POST['clear_log']) && wp_verify_nonce($_POST['nonce'], 'wjm_clear_audit_log')) {
        update_option('wjm_audit_log', array());
        echo '<div class="notice notice-success"><p>Audit log cleared successfully.</p></div>';
    }

    $audit_log = get_option('wjm_audit_log', array());
    $audit_log = array_reverse($audit_log); // Show newest first

    // Pagination
    $per_page = 50;
    $page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $offset = ($page - 1) * $per_page;
    $total_entries = count($audit_log);
    $total_pages = ceil($total_entries / $per_page);
    $audit_log_page = array_slice($audit_log, $offset, $per_page);

    ?>
    <div class="wrap wjm-modern-wrap">
        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">
                    <span class="dashicons dashicons-list-view"></span>
                    Audit Log
                </h1>
                <p class="wjm-page-description">Track all changes made to papers, journals, and issues</p>
            </div>
            <div class="wjm-page-actions">
                <a href="<?php echo esc_url(add_query_arg(array('export' => '1', 'nonce' => wp_create_nonce('wjm_export_audit_log')))); ?>" class="wjm-btn wjm-btn-secondary">
                    <span class="dashicons dashicons-download"></span> Export to CSV
                </a>
                <form method="post" style="display: inline-block;">
                    <?php wp_nonce_field('wjm_clear_audit_log', 'nonce'); ?>
                    <button type="submit" name="clear_log" class="wjm-btn wjm-btn-danger" onclick="return confirm('Are you sure you want to clear the audit log? This cannot be undone.');">
                        <span class="dashicons dashicons-trash"></span> Clear Log
                    </button>
                </form>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-chart-bar"></span>
                    Audit Statistics
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo esc_html($total_entries); ?></div>
                        <div class="wjm-stat-simple-label">Total Entries</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo esc_html($total_pages); ?></div>
                        <div class="wjm-stat-simple-label">Total Pages</div>
                    </div>
                </div>
            </div>
        </div>

        <?php if (empty($audit_log_page)): ?>
            <div class="wjm-card">
                <div class="wjm-card-body">
                    <div class="wjm-empty-state">
                        <span class="dashicons dashicons-list-view"></span>
                        <p>No audit entries yet</p>
                        <small>Changes will be tracked here automatically</small>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <div class="wjm-card">
                <div class="wjm-card-body" style="padding: 0;">
                    <div class="wjm-table-container">
                        <table class="wjm-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Type</th>
                                    <th>ID</th>
                                    <th>Changes</th>
                                    <th>Notes</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($audit_log_page as $entry): ?>
                                    <tr>
                                        <td><?php echo esc_html(date('M j, Y g:i A', strtotime($entry['timestamp']))); ?></td>
                                        <td>
                                            <strong><?php echo esc_html($entry['user_name']); ?></strong>
                                            <br><small class="wjm-text-muted"><?php echo esc_html($entry['user_ip']); ?></small>
                                        </td>
                                        <td>
                                            <?php
                                            $action_class = 'wjm-badge-info';
                                            if ($entry['action'] === 'create') $action_class = 'wjm-badge-success';
                                            if ($entry['action'] === 'update' || $entry['action'] === 'metadata_update') $action_class = 'wjm-badge-warning';
                                            if ($entry['action'] === 'delete') $action_class = 'wjm-badge-danger';
                                            ?>
                                            <span class="wjm-badge <?php echo esc_attr($action_class); ?>">
                                                <?php echo esc_html(ucfirst(str_replace('_', ' ', $entry['action']))); ?>
                                            </span>
                                        </td>
                                        <td><span class="wjm-badge"><?php echo esc_html(ucfirst($entry['object_type'])); ?></span></td>
                                        <td>
                                            <?php if ($entry['object_type'] === 'paper'): ?>
                                                <a href="<?php echo esc_url(admin_url('post.php?post=' . $entry['object_id'] . '&action=edit')); ?>" class="wjm-link">
                                                    #<?php echo esc_html($entry['object_id']); ?>
                                                </a>
                                            <?php else: ?>
                                                <code>#<?php echo esc_html($entry['object_id']); ?></code>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php
                                            $changes = json_decode($entry['changes'], true);
                                            if ($changes && is_array($changes)) {
                                                echo '<details style="cursor: pointer;"><summary style="color: var(--wjm-primary); font-weight: 500;">View ' . count($changes) . ' changes</summary>';
                                                echo '<pre style="font-size: 11px; max-height: 120px; overflow: auto; background: var(--wjm-gray-50); padding: 8px; border-radius: 4px; margin-top: 8px;">';
                                                echo esc_html(print_r($changes, true));
                                                echo '</pre></details>';
                                            } else {
                                                echo '<em class="wjm-text-muted">No changes</em>';
                                            }
                                            ?>
                                        </td>
                                        <td><?php echo esc_html($entry['notes'] ?: '—'); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <?php if ($total_pages > 1): ?>
                    <div class="wjm-card-footer">
                        <div class="wjm-pagination">
                            <div class="wjm-pagination-info">
                                Showing page <?php echo esc_html($page); ?> of <?php echo esc_html($total_pages); ?> (<?php echo esc_html($total_entries); ?> total entries)
                            </div>
                            <div class="wjm-pagination-buttons">
                                <?php
                                $base_url = remove_query_arg('paged');
                                if ($page > 1): ?>
                                    <a class="wjm-btn wjm-btn-sm wjm-btn-secondary" href="<?php echo esc_url(add_query_arg('paged', $page - 1, $base_url)); ?>">
                                        <span class="dashicons dashicons-arrow-left-alt2"></span> Previous
                                    </a>
                                <?php endif; ?>

                                <?php if ($page < $total_pages): ?>
                                    <a class="wjm-btn wjm-btn-sm wjm-btn-secondary" href="<?php echo esc_url(add_query_arg('paged', $page + 1, $base_url)); ?>">
                                        Next <span class="dashicons dashicons-arrow-right-alt2"></span>
                                    </a>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

// ========================================
// PERFORMANCE OPTIMIZATION & CACHING
// ========================================

/**
 * Get cached query result or execute and cache
 *
 * @param string $cache_key Unique cache key
 * @param callable $callback Function to execute if cache miss
 * @param int $expiration Cache expiration in seconds (default: 1 hour)
 * @return mixed Cached or fresh query result
 */
function wjm_get_cached_query($cache_key, $callback, $expiration = 3600) {
    // Try to get from cache first
    $cached = get_transient('wjm_cache_' . $cache_key);

    if ($cached !== false) {
        return $cached;
    }

    // Cache miss - execute callback
    $result = $callback();

    // Store in cache
    set_transient('wjm_cache_' . $cache_key, $result, $expiration);

    return $result;
}

/**
 * Clear specific cache or all caches
 *
 * @param string $cache_key Specific cache key to clear, or 'all' for everything
 */
function wjm_clear_cache($cache_key = 'all') {
    global $wpdb;

    if ($cache_key === 'all') {
        // Clear all WJM caches
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wjm_cache_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_wjm_cache_%'");
    } else {
        delete_transient('wjm_cache_' . $cache_key);
    }
}

/**
 * Clear cache when papers are modified
 */
function wjm_clear_cache_on_paper_change($post_id, $post) {
    if ($post->post_type === 'paper') {
        wjm_clear_cache('all');
    }
}
add_action('save_post', 'wjm_clear_cache_on_paper_change', 10, 2);
add_action('delete_post', 'wjm_clear_cache_on_paper_change', 10, 2);

/**
 * Get paginated papers with caching
 *
 * @param array $args WP_Query arguments
 * @return array Array with 'posts', 'total', 'pages' keys
 */
function wjm_get_papers_paginated($args = array()) {
    $defaults = array(
        'post_type' => 'paper',
        'post_status' => 'publish',
        'posts_per_page' => 20,
        'paged' => 1,
        'orderby' => 'date',
        'order' => 'DESC'
    );

    $args = wp_parse_args($args, $defaults);

    // Create cache key from args
    $cache_key = 'papers_' . md5(serialize($args));

    $result = wjm_get_cached_query($cache_key, function() use ($args) {
        $query = new WP_Query($args);

        return array(
            'posts' => $query->posts,
            'total' => $query->found_posts,
            'pages' => $query->max_num_pages,
            'current_page' => $args['paged']
        );
    }, 1800); // Cache for 30 minutes

    return $result;
}

/**
 * Get papers count by status with caching
 *
 * @return array Array with counts by status
 */
function wjm_get_papers_count_by_status() {
    return wjm_get_cached_query('papers_count', function() {
        $counts = wp_count_posts('paper');

        return array(
            'publish' => $counts->publish ?? 0,
            'draft' => $counts->draft ?? 0,
            'pending' => $counts->pending ?? 0,
            'total' => ($counts->publish ?? 0) + ($counts->draft ?? 0) + ($counts->pending ?? 0)
        );
    }, 3600);
}

/**
 * Get journals with pagination and caching
 *
 * @param int $per_page Number of journals per page
 * @param int $paged Current page number
 * @return array Array with journals and pagination info
 */
function wjm_get_journals_paginated($per_page = 20, $paged = 1) {
    $cache_key = 'journals_page_' . $per_page . '_' . $paged;

    return wjm_get_cached_query($cache_key, function() use ($per_page, $paged) {
        $args = array(
            'post_type' => 'journal',
            'post_status' => 'publish',
            'posts_per_page' => $per_page,
            'paged' => $paged,
            'orderby' => 'title',
            'order' => 'ASC'
        );

        $query = new WP_Query($args);

        return array(
            'journals' => $query->posts,
            'total' => $query->found_posts,
            'pages' => $query->max_num_pages
        );
    }, 1800);
}

/**
 * Add cache management admin page
 */
function wjm_add_cache_management_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Performance Cache',
        'Performance',
        'manage_options',
        'wjm-performance',
        'wjm_performance_page'
    );
}
add_action('admin_menu', 'wjm_add_cache_management_page');

/**
 * Display performance cache management page
 */
function wjm_performance_page() {
    // Handle cache clear
    if (isset($_POST['clear_cache']) && wp_verify_nonce($_POST['nonce'], 'wjm_clear_cache')) {
        wjm_clear_cache('all');
        echo '<div class="notice notice-success"><p>Performance cache cleared successfully!</p></div>';
    }

    global $wpdb;

    // Get cache statistics
    $cache_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_wjm_cache_%'");
    $cache_size = $wpdb->get_var("SELECT SUM(LENGTH(option_value)) FROM {$wpdb->options} WHERE option_name LIKE '_transient_wjm_cache_%'");
    $cache_size_mb = $cache_size ? round($cache_size / 1024 / 1024, 2) : 0;

    ?>
    <div class="wrap wjm-modern-wrap">
        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">
                    <span class="dashicons dashicons-performance"></span>
                    Performance & Cache Management
                </h1>
                <p class="wjm-page-description">Manage query caching and performance optimization settings</p>
            </div>
            <div class="wjm-page-actions">
                <form method="post" style="display: inline-block;">
                    <?php wp_nonce_field('wjm_clear_cache', 'nonce'); ?>
                    <button type="submit" name="clear_cache" class="wjm-btn wjm-btn-primary">
                        <span class="dashicons dashicons-update"></span> Clear All Caches
                    </button>
                </form>
            </div>
        </div>

        <!-- Cache Statistics -->
        <div class="wjm-stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));">
            <div class="wjm-stat-card">
                <div class="wjm-stat-icon" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                    <span class="dashicons dashicons-database"></span>
                </div>
                <div class="wjm-stat-content">
                    <div class="wjm-stat-value"><?php echo esc_html($cache_count); ?></div>
                    <div class="wjm-stat-label">Cached Queries</div>
                </div>
            </div>

            <div class="wjm-stat-card">
                <div class="wjm-stat-icon" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                    <span class="dashicons dashicons-admin-site"></span>
                </div>
                <div class="wjm-stat-content">
                    <div class="wjm-stat-value"><?php echo esc_html($cache_size_mb); ?> MB</div>
                    <div class="wjm-stat-label">Cache Size</div>
                </div>
            </div>

            <div class="wjm-stat-card">
                <div class="wjm-stat-icon" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                    <span class="dashicons dashicons-yes-alt"></span>
                </div>
                <div class="wjm-stat-content">
                    <div class="wjm-stat-value">Active</div>
                    <div class="wjm-stat-label">Cache Status</div>
                </div>
            </div>
        </div>

        <div class="wjm-grid-2">
            <!-- Performance Optimizations -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-lightbulb"></span>
                        Active Optimizations
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <div class="wjm-list">
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>Query result caching (30 minutes)</span>
                        </div>
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>Pagination for large datasets</span>
                        </div>
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>Automatic cache invalidation on updates</span>
                        </div>
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>Optimized database queries</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Cache Expiration Times -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-clock"></span>
                        Cache Expiration Times
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <div class="wjm-list">
                        <div class="wjm-list-item">
                            <div class="wjm-list-item-content">
                                <div class="wjm-list-item-title">Paper Queries</div>
                                <div class="wjm-list-item-meta">
                                    <span class="wjm-badge wjm-badge-info">30 minutes</span>
                                </div>
                            </div>
                        </div>
                        <div class="wjm-list-item">
                            <div class="wjm-list-item-content">
                                <div class="wjm-list-item-title">Journal Queries</div>
                                <div class="wjm-list-item-meta">
                                    <span class="wjm-badge wjm-badge-info">30 minutes</span>
                                </div>
                            </div>
                        </div>
                        <div class="wjm-list-item">
                            <div class="wjm-list-item-content">
                                <div class="wjm-list-item-title">Statistics</div>
                                <div class="wjm-list-item-meta">
                                    <span class="wjm-badge wjm-badge-info">1 hour</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Cache Management Info -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-info"></span>
                    About Cache Management
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-alert wjm-alert-info">
                    <strong>When to Clear Cache:</strong>
                    <ul style="margin: 8px 0 0 20px;">
                        <li>After bulk operations or data imports</li>
                        <li>If you notice stale or outdated data</li>
                        <li>After making significant configuration changes</li>
                        <li>When troubleshooting performance issues</li>
                    </ul>
                </div>
                <p style="margin-top: 16px; color: var(--wjm-gray-700);">
                    The caching system automatically stores query results to reduce database load and improve page load times.
                    Caches are automatically cleared when data is modified, but you can manually clear them using the button above.
                </p>
            </div>
        </div>
    </div>
    <?php
}

// ========================================
// BACKUP & RESTORE SYSTEM
// ========================================

/**
 * Create backup of all plugin data
 *
 * @return array Backup data
 */
function wjm_create_backup() {
    global $wpdb;

    $backup = array(
        'version' => '1.0.0',
        'timestamp' => current_time('mysql'),
        'site_url' => get_site_url(),
        'data' => array()
    );

    // Backup papers
    $papers = get_posts(array(
        'post_type' => 'paper',
        'post_status' => 'any',
        'posts_per_page' => -1
    ));

    $backup['data']['papers'] = array();
    foreach ($papers as $paper) {
        $backup['data']['papers'][] = array(
            'ID' => $paper->ID,
            'title' => $paper->post_title,
            'content' => $paper->post_content,
            'status' => $paper->post_status,
            'date' => $paper->post_date,
            'meta' => get_post_meta($paper->ID)
        );
    }

    // Backup journals
    $journals = get_posts(array(
        'post_type' => 'journal',
        'post_status' => 'any',
        'posts_per_page' => -1
    ));

    $backup['data']['journals'] = array();
    foreach ($journals as $journal) {
        $backup['data']['journals'][] = array(
            'ID' => $journal->ID,
            'title' => $journal->post_title,
            'content' => $journal->post_content,
            'status' => $journal->post_status,
            'date' => $journal->post_date,
            'meta' => get_post_meta($journal->ID)
        );
    }

    // Backup issues
    $issues = get_posts(array(
        'post_type' => 'journal_issue',
        'post_status' => 'any',
        'posts_per_page' => -1
    ));

    $backup['data']['issues'] = array();
    foreach ($issues as $issue) {
        $backup['data']['issues'][] = array(
            'ID' => $issue->ID,
            'title' => $issue->post_title,
            'content' => $issue->post_content,
            'status' => $issue->post_status,
            'date' => $issue->post_date,
            'meta' => get_post_meta($issue->ID)
        );
    }

    // Backup authors table
    $table_name = $wpdb->prefix . 'sjm_authors';
    $authors = $wpdb->get_results("SELECT * FROM `{$table_name}`", ARRAY_A);
    $backup['data']['authors'] = $authors ?: array();

    // Backup plugin settings
    $backup['data']['settings'] = array(
        'automation' => get_option('sjm_automation_settings', array()),
        'email' => get_option('sjm_email_settings', array()),
        'security' => get_option('wjm_security_settings', array())
    );

    return $backup;
}

/**
 * Restore plugin data from backup
 *
 * @param array $backup_data Backup data array
 * @return bool|WP_Error True on success, WP_Error on failure
 */
function wjm_restore_backup($backup_data) {
    global $wpdb;

    if (!isset($backup_data['version']) || !isset($backup_data['data'])) {
        return new WP_Error('invalid_backup', 'Invalid backup file format.');
    }

    // Start transaction (if supported)
    $wpdb->query('START TRANSACTION');

    try {
        // Restore papers
        if (isset($backup_data['data']['papers'])) {
            foreach ($backup_data['data']['papers'] as $paper_data) {
                // Check if paper exists
                $existing = get_post($paper_data['ID']);

                if (!$existing) {
                    // Create new paper
                    $post_id = wp_insert_post(array(
                        'post_title' => $paper_data['title'],
                        'post_content' => $paper_data['content'],
                        'post_status' => $paper_data['status'],
                        'post_type' => 'paper',
                        'post_date' => $paper_data['date']
                    ));

                    // Restore metadata
                    if ($post_id && isset($paper_data['meta'])) {
                        foreach ($paper_data['meta'] as $key => $values) {
                            foreach ($values as $value) {
                                add_post_meta($post_id, $key, maybe_unserialize($value));
                            }
                        }
                    }
                }
            }
        }

        // Restore journals
        if (isset($backup_data['data']['journals'])) {
            foreach ($backup_data['data']['journals'] as $journal_data) {
                $existing = get_post($journal_data['ID']);

                if (!$existing) {
                    $post_id = wp_insert_post(array(
                        'post_title' => $journal_data['title'],
                        'post_content' => $journal_data['content'],
                        'post_status' => $journal_data['status'],
                        'post_type' => 'journal',
                        'post_date' => $journal_data['date']
                    ));

                    if ($post_id && isset($journal_data['meta'])) {
                        foreach ($journal_data['meta'] as $key => $values) {
                            foreach ($values as $value) {
                                add_post_meta($post_id, $key, maybe_unserialize($value));
                            }
                        }
                    }
                }
            }
        }

        // Restore authors
        if (isset($backup_data['data']['authors'])) {
            $table_name = $wpdb->prefix . 'sjm_authors';
            foreach ($backup_data['data']['authors'] as $author) {
                // Check if author exists
                $existing = $wpdb->get_var($wpdb->prepare(
                    "SELECT id FROM `{$table_name}` WHERE id = %d",
                    $author['id']
                ));

                if (!$existing) {
                    $wpdb->insert($table_name, $author);
                }
            }
        }

        // Commit transaction
        $wpdb->query('COMMIT');

        return true;

    } catch (Exception $e) {
        // Rollback on error
        $wpdb->query('ROLLBACK');
        return new WP_Error('restore_failed', 'Restore failed: ' . $e->getMessage());
    }
}

/**
 * Add backup/restore admin page
 */
function wjm_add_backup_restore_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Backup & Restore',
        'Backup/Restore',
        'manage_options',
        'wjm-backup',
        'wjm_backup_restore_page'
    );
}
add_action('admin_menu', 'wjm_add_backup_restore_page');

/**
 * Display backup/restore page
 */
function wjm_backup_restore_page() {
    // Handle backup creation
    if (isset($_POST['create_backup']) && wp_verify_nonce($_POST['nonce'], 'wjm_create_backup')) {
        $backup = wjm_create_backup();
        $filename = 'wjm-backup-' . date('Y-m-d-H-i-s') . '.json';

        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen(json_encode($backup)));

        echo json_encode($backup, JSON_PRETTY_PRINT);
        exit;
    }

    // Handle restore
    if (isset($_POST['restore_backup']) && wp_verify_nonce($_POST['nonce'], 'wjm_restore_backup')) {
        if (isset($_FILES['backup_file']) && $_FILES['backup_file']['error'] === UPLOAD_ERR_OK) {
            $file_content = file_get_contents($_FILES['backup_file']['tmp_name']);
            $backup_data = json_decode($file_content, true);

            if ($backup_data) {
                $result = wjm_restore_backup($backup_data);

                if (is_wp_error($result)) {
                    echo '<div class="notice notice-error"><p>Restore failed: ' . esc_html($result->get_error_message()) . '</p></div>';
                } else {
                    echo '<div class="notice notice-success"><p>Backup restored successfully!</p></div>';
                }
            } else {
                echo '<div class="notice notice-error"><p>Invalid backup file format.</p></div>';
            }
        }
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'sjm_authors';

    // Get statistics
    $papers_count = wp_count_posts('paper')->publish;
    $journals_count = wp_count_posts('journal')->publish;
    $issues_count = wp_count_posts('journal_issue')->publish;
    $authors_count = $wpdb->get_var("SELECT COUNT(*) FROM `{$table_name}`");

    ?>
    <div class="wrap wjm-modern-wrap">
        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">
                    <span class="dashicons dashicons-backup"></span>
                    Backup & Restore
                </h1>
                <p class="wjm-page-description">Create backups of all plugin data and restore from previous backups</p>
            </div>
        </div>

        <!-- Current Data Statistics -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-chart-bar"></span>
                    Current Data Statistics
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo esc_html($papers_count); ?></div>
                        <div class="wjm-stat-simple-label">Papers</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo esc_html($journals_count); ?></div>
                        <div class="wjm-stat-simple-label">Journals</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo esc_html($issues_count); ?></div>
                        <div class="wjm-stat-simple-label">Issues</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo esc_html($authors_count); ?></div>
                        <div class="wjm-stat-simple-label">Authors</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="wjm-grid-2">
            <!-- Create Backup -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-download"></span>
                        Create Backup
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <p class="wjm-text-muted">Download a complete backup of all papers, journals, issues, and authors as a JSON file.</p>

                    <div class="wjm-list" style="margin: 16px 0;">
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>All papers, journals, issues, and authors</span>
                        </div>
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>Metadata and relationships preserved</span>
                        </div>
                        <div class="wjm-list-item">
                            <span class="wjm-badge wjm-badge-success">✓</span>
                            <span>Plugin settings included</span>
                        </div>
                    </div>

                    <form method="post">
                        <?php wp_nonce_field('wjm_create_backup', 'nonce'); ?>
                        <button type="submit" name="create_backup" class="wjm-btn wjm-btn-primary wjm-btn-block">
                            <span class="dashicons dashicons-download"></span> Download Backup
                        </button>
                    </form>
                </div>
            </div>

            <!-- Restore from Backup -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-upload"></span>
                        Restore from Backup
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <div class="wjm-alert wjm-alert-warning">
                        <strong>⚠️ Warning:</strong> Restoring will add data from the backup. Existing data will NOT be deleted.
                    </div>

                    <form method="post" enctype="multipart/form-data" style="margin-top: 16px;">
                        <?php wp_nonce_field('wjm_restore_backup', 'nonce'); ?>

                        <div class="wjm-form-group">
                            <label class="wjm-form-label">Upload Backup JSON File</label>
                            <input type="file" name="backup_file" accept=".json" required class="wjm-form-control">
                        </div>

                        <button type="submit" name="restore_backup" class="wjm-btn wjm-btn-secondary wjm-btn-block" onclick="return confirm('Are you sure you want to restore from this backup? This will add all data from the backup file.');">
                            <span class="dashicons dashicons-upload"></span> Restore from Backup
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Backup Information -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-info"></span>
                    Backup Information
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-grid-2">
                    <div>
                        <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--wjm-gray-900);">What's Included</h3>
                        <div class="wjm-list">
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-success">✓</span>
                                <span>All papers with complete metadata</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-success">✓</span>
                                <span>All journals and issues</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-success">✓</span>
                                <span>Complete authors database</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-success">✓</span>
                                <span>Plugin configuration settings</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-success">✓</span>
                                <span>Relationships and associations</span>
                            </div>
                        </div>
                    </div>

                    <div>
                        <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--wjm-gray-900);">Best Practices</h3>
                        <div class="wjm-list">
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-info">💡</span>
                                <span>Create backups before major updates</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-info">💡</span>
                                <span>Store backups in a secure location</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-info">💡</span>
                                <span>Test restores in staging first</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-info">💡</span>
                                <span>Create regular backups (weekly)</span>
                            </div>
                            <div class="wjm-list-item">
                                <span class="wjm-badge wjm-badge-info">💡</span>
                                <span>Verify backup files after creation</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php
}

// Load text domain for translations
function wjm_load_textdomain() {
    load_plugin_textdomain('wisdom-journal-manager', false, dirname(plugin_basename(__FILE__)) . '/languages/');
}
add_action('plugins_loaded', 'wjm_load_textdomain');

// Include automated pages system
require_once plugin_dir_path(__FILE__) . 'automated-pages.php';

// Demo content generator disabled for production
// require_once plugin_dir_path(__FILE__) . 'demo-content.php';

// Include updated shortcodes with improved design
require_once plugin_dir_path(__FILE__) . 'updated-shortcodes.php';

// Include Phase 1 database schema (Citations, Metrics, Search)
require_once plugin_dir_path(__FILE__) . 'phase1-database-schema.php';

// Include Citation Tracking System
require_once plugin_dir_path(__FILE__) . 'citation-tracking-system.php';

// Include Metrics Tracking System
require_once plugin_dir_path(__FILE__) . 'metrics-tracking-system.php';

// Include Advanced Search System
require_once plugin_dir_path(__FILE__) . 'advanced-search-system.php';

// Include DOI Crossref Integration
require_once plugin_dir_path(__FILE__) . 'doi-crossref-integration.php';

// Include Analytics Dashboard
require_once plugin_dir_path(__FILE__) . 'analytics-dashboard.php';

// Author Profiles CPT system disabled - plugin uses custom wp_sjm_authors table instead
// require_once plugin_dir_path(__FILE__) . 'author-profiles-system.php';

// Include Advanced Metrics & Altmetrics System
require_once plugin_dir_path(__FILE__) . 'advanced-metrics-system.php';

// Include Collaboration Tools
require_once plugin_dir_path(__FILE__) . 'collaboration-tools.php';


// Include Integration Fixes & Enhancements
require_once plugin_dir_path(__FILE__) . 'integration-fixes.php';


// Author system unification disabled - no longer needed
// require_once plugin_dir_path(__FILE__) . 'author-system-unification.php';

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
register_activation_hook(WJM_PLUGIN_FILE, 'sjm_flush_rewrite_rules');

// Create Phase 1 database tables on activation
register_activation_hook(WJM_PLUGIN_FILE, 'wjm_phase1_create_tables');

// Auto-flush rewrite rules whenever WJM_VERSION changes (catches file uploads/updates)
add_action('init', function() {
    // Manual flush flag
    if (get_option('sjm_flush_rewrite_rules', false)) {
        sjm_add_author_rewrite_rules();
        flush_rewrite_rules();
        delete_option('sjm_flush_rewrite_rules');
    }
    // Version-based auto-flush: runs once automatically after every plugin update
    if (get_option('sjm_version_last_flushed') !== WJM_VERSION) {
        sjm_add_author_rewrite_rules();
        flush_rewrite_rules();
        update_option('sjm_version_last_flushed', WJM_VERSION);
    }
}, 99);

// Admin notice + one-click flush button for 404 issues
add_action('admin_notices', function() {
    // Only show to admins on journal-related screens
    if (!current_user_can('manage_options')) return;
    $screen = get_current_screen();
    if (!$screen) return;
    $show_on = ['journal', 'paper', 'journal_issue', 'edit-journal', 'edit-paper', 'edit-journal_issue'];
    if (!in_array($screen->id, $show_on) && strpos($screen->id, 'sjm') === false && strpos($screen->id, 'wjm') === false) return;

    // Handle flush action
    if (isset($_GET['wjm_flush_permalinks']) && check_admin_referer('wjm_flush_permalinks')) {
        sjm_add_author_rewrite_rules();
        flush_rewrite_rules();
        echo '<div class="notice notice-success is-dismissible"><p><strong>✓ Permalinks flushed.</strong> Journal, issue, and paper pages should now load correctly.</p></div>';
        return;
    }

    // Show notice only if user hasn't dismissed it recently
    if (get_transient('wjm_permalink_notice_dismissed')) return;
    if (isset($_GET['wjm_dismiss_permalink_notice'])) {
        set_transient('wjm_permalink_notice_dismissed', 1, WEEK_IN_SECONDS);
        return;
    }

    $flush_url   = wp_nonce_url(add_query_arg('wjm_flush_permalinks', '1'), 'wjm_flush_permalinks');
    $dismiss_url = add_query_arg('wjm_dismiss_permalink_notice', '1');
    echo '<div class="notice notice-warning" style="display:flex;align-items:center;gap:16px;padding:10px 16px;">';
    echo '<span style="font-size:20px;">⚠️</span>';
    echo '<div style="flex:1;">';
    echo '<strong>Journal pages showing 404?</strong> ';
    echo 'If journal, issue, or paper pages return "Page not found", click the button to fix it instantly.';
    echo '</div>';
    echo '<a href="' . esc_url($flush_url) . '" class="button button-primary" style="white-space:nowrap;">Fix Permalinks Now</a>';
    echo '<a href="' . esc_url($dismiss_url) . '" style="margin-left:8px;color:#999;text-decoration:none;font-size:18px;line-height:1;" title="Dismiss">×</a>';
    echo '</div>';
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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">User Roles</h1>
                <p class="wjm-page-description">Assign and manage journal roles for your team</p>
            </div>
        </div>

        <div class="wjm-grid-2">

            <!-- Assign Role -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Assign Journal Role</h2>
                </div>
                <div class="wjm-card-body">
                    <form method="post">
                        <?php wp_nonce_field('sjm_assign_role', 'sjm_role_nonce'); ?>
                        <table class="wjm-settings-table">
                            <tr>
                                <th><label for="user_id">User</label></th>
                                <td>
                                    <select name="user_id" id="user_id" class="wjm-select" style="width:100%;">
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
                                    <select name="role" id="role" class="wjm-select" style="width:100%;">
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
                        <div style="margin-top:1rem;">
                            <button type="submit" name="assign_role" class="wjm-btn wjm-btn-primary">Assign Role</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Current Journal Users -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Current Journal Users</h2>
                </div>
                <div class="wjm-card-body" style="padding:0;">
                    <?php
                    $journal_users = sjm_get_users_by_journal_role();
                    if ($journal_users) {
                        echo '<table class="wjm-table">';
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
                                echo '<td><strong>' . esc_html($user->display_name) . '</strong><br><span style="font-size:0.75rem;color:var(--wjm-text-secondary);">' . esc_html($user->user_email) . '</span></td>';
                                echo '<td>';
                                foreach ($journal_roles as $role) {
                                    $role_display = ucwords(str_replace('_', ' ', str_replace('journal_', '', $role)));
                                    echo '<span class="wjm-role-badge" style="margin:2px 2px 2px 0;display:inline-block;">' . esc_html($role_display) . '</span>';
                                }
                                echo '</td>';
                                echo '<td>';
                                echo '<a href="' . esc_url(sjm_get_user_profile_url($user->ID)) . '" class="wjm-btn wjm-btn-secondary wjm-btn-sm" target="_blank" style="margin:2px;">Profile</a>';
                                foreach ($journal_roles as $role) {
                                    echo '<form method="post" style="display:inline-block;margin:2px;">';
                                    wp_nonce_field('sjm_remove_role', 'sjm_role_nonce');
                                    echo '<input type="hidden" name="user_id" value="' . esc_attr($user->ID) . '">';
                                    echo '<input type="hidden" name="role" value="' . esc_attr($role) . '">';
                                    echo '<button type="submit" name="remove_role" class="wjm-btn wjm-btn-secondary wjm-btn-sm" onclick="return confirm(\'Remove this role?\');">Remove ' . esc_html(str_replace('journal_', '', $role)) . '</button>';
                                    echo '</form>';
                                }
                                echo '</td>';
                                echo '</tr>';
                            }
                        }

                        echo '</tbody></table>';
                    } else {
                        echo '<div class="wjm-empty-state"><span class="dashicons dashicons-admin-users"></span><p>No users with journal roles found.</p></div>';
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
    wp_nonce_field('sjm_save_journal_meta', 'sjm_journal_meta_nonce');

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
    // Only run for journal post type
    if (get_post_type($post_id) !== 'journal') {
        return;
    }

    // Verify nonce
    if (!isset($_POST['sjm_journal_meta_nonce']) || !wp_verify_nonce($_POST['sjm_journal_meta_nonce'], 'sjm_save_journal_meta')) {
        return;
    }

    // Check autosave
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
        return;
    }

    // Check permissions
    if (!current_user_can('edit_post', $post_id)) {
        return;
    }

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
    wp_nonce_field('sjm_save_issue_meta', 'sjm_issue_meta_nonce');

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
    // Only run for journal_issue post type
    if (get_post_type($post_id) !== 'journal_issue') {
        return;
    }

    // Verify nonce
    if (!isset($_POST['sjm_issue_meta_nonce']) || !wp_verify_nonce($_POST['sjm_issue_meta_nonce'], 'sjm_save_issue_meta')) {
        return;
    }

    // Check autosave
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
        return;
    }

    // Check permissions
    if (!current_user_can('edit_post', $post_id)) {
        return;
    }

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
    wp_nonce_field('sjm_save_retraction_meta', 'sjm_retraction_meta_nonce');

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

    // Verify nonce
    if (!isset($_POST['sjm_retraction_meta_nonce']) || !wp_verify_nonce($_POST['sjm_retraction_meta_nonce'], 'sjm_save_retraction_meta')) {
        return;
    }

    // Check permissions
    if (!current_user_can('edit_post', $post_id)) {
        return;
    }

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
// Use the new improved shortcode
add_shortcode('journals', 'sjm_journals_shortcode_new');
add_shortcode('papers', 'sjm_papers_shortcode_new');
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
        
        $output = '<div class="sjm-single-container">';

        // Breadcrumb
        $output .= '<nav class="sjm-breadcrumb">';
        $output .= '<a href="' . esc_url(home_url('/')) . '">Home</a>';
        $output .= '<span class="sjm-breadcrumb-separator">&rsaquo;</span>';
        $output .= '<span class="sjm-breadcrumb-current">' . esc_html($post->post_title) . '</span>';
        $output .= '</nav>';

        $output .= '<div class="sjm-single-sections">';
        $output .= '<div class="sjm-single-main">';

        // Header section
        $output .= '<div class="sjm-single-header">';
    $output .= '<div class="sjm-single-info">';
    $output .= '<h1>' . esc_html($post->post_title) . '</h1>';

    // Quick badges
    $output .= '<div class="sjm-journal-badges">';
    if ($issn) $output .= '<span class="sjm-badge">ISSN ' . esc_html($issn) . '</span>';
    if ($impact_factor) $output .= '<span class="sjm-badge">IF ' . esc_html($impact_factor) . '</span>';
    if ($open_access) {
        $output .= '<span class="sjm-badge">Supports Open Access</span>';
    } else {
        $output .= '<span class="sjm-badge sjm-badge-subscription">Traditional Subscription</span>';
        $output .= '<div class="sjm-subscription-note">This journal follows a traditional subscription model. Individual articles may still be accessible through author self-archiving or institutional access.</div>';
    }
    if ($peer_reviewed) $output .= '<span class="sjm-badge">Peer Reviewed</span>';
    $output .= '</div>';

    // Download options
    if ($website) {
        $output .= '<a href="' . esc_url($website) . '" target="_blank" class="sjm-download-btn">';
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
            $output .= '<span class="sjm-meta-value"><a href="mailto:' . esc_attr($email) . '">' . esc_html($email) . '</a></span>';
            $output .= '</div>';
        }
        if ($website) {
            $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Website</span>';
            $output .= '<span class="sjm-meta-value"><a href="' . esc_url($website) . '" target="_blank">' . esc_html($website) . '</a></span>';
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
            $output .= '<div class="sjm-authors-grid">';

        foreach ($journal_authors_data as $journal_author) {
            $author = sjm_get_author_by_id($journal_author['author_id']);
            if ($author) {
                $profile_url = sjm_get_author_profile_url($author->id);
                    $output .= '<div class="sjm-author-card">';
                    $output .= '<div class="sjm-author-name">';
                $output .= '<a href="' . esc_url($profile_url) . '">' . esc_html($author->first_name . ' ' . $author->last_name) . '</a>';
                if ($author->orcid) {
                    $output .= ' <a href="https://orcid.org/' . esc_attr($author->orcid) . '" target="_blank" class="sjm-orcid-link">(ORCID)</a>';
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
                        $output .= '<strong>Email:</strong> <a href="mailto:' . esc_attr($author->email) . '">' . esc_html($author->email) . '</a>';
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
            $output .= '<div class="sjm-cards-grid">';

            foreach (array_slice($issues, 0, 6) as $issue) {
                $issue_number = get_post_meta($issue->ID, '_sjm_issue_number', true);
                $issue_volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
                $issue_year = get_post_meta($issue->ID, '_sjm_issue_year', true);
                $publication_date = get_post_meta($issue->ID, '_sjm_publication_date', true);
                $total_papers = get_post_meta($issue->ID, '_sjm_total_papers', true);

                $output .= '<div class="sjm-meta-card">';
                $output .= '<h4>' . esc_html($issue->post_title) . '</h4>';
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
                $output .= '<a href="' . get_permalink($issue->ID) . '" class="sjm-view-button">';
                $output .= 'View Issue';
                $output .= '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24">';
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

        $output = '<div class="sjm-single-container">';

        // Breadcrumb
        $output .= '<nav class="sjm-breadcrumb">';
        $output .= '<a href="' . esc_url(home_url('/')) . '">Home</a>';
        $output .= '<span class="sjm-breadcrumb-separator">&rsaquo;</span>';
        if ($issue_journal) {
            $output .= '<a href="' . esc_url(get_permalink($issue_journal->ID)) . '">' . esc_html($issue_journal->post_title) . '</a>';
            $output .= '<span class="sjm-breadcrumb-separator">&rsaquo;</span>';
        }
        $output .= '<span class="sjm-breadcrumb-current">' . esc_html($post->post_title) . '</span>';
        $output .= '</nav>';

        $output .= '<div class="sjm-single-sections">';
        $output .= '<div class="sjm-single-main">';

        // Header section
        $output .= '<div class="sjm-single-header">';
        $output .= '<div class="sjm-single-info">';
        $output .= '<h1>' . esc_html($post->post_title) . '</h1>';
        if ($issue_journal) {
            $output .= '<p class="sjm-single-subtitle"><a href="' . esc_url(get_permalink($issue_journal->ID)) . '">' . esc_html($issue_journal->post_title) . '</a></p>';
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
            $output .= '<span class="sjm-meta-value"><a href="' . esc_url($pdf_url) . '" target="_blank" class="sjm-download-btn">';
            $output .= '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>';
            $output .= 'Download PDF</a></span>';
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
                $output .= '<a href="' . esc_url($member['info']['url']) . '">' . esc_html($member['info']['name']) . '</a>';
                if (!empty($member['info']['email'])) {
                    $output .= ' | <a href="mailto:' . esc_attr($member['info']['email']) . '">' . esc_html($member['info']['email']) . '</a>';
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
                $output .= '<div class="sjm-abstract-section">';
                $output .= '<h4 class="sjm-abstract-title">Abstract</h4>';
                $output .= '<p class="sjm-abstract-content">' . esc_html($issue_abstract) . '</p>';
                $output .= '</div>';
            }
            $output .= '</div>';
        }
        $output .= '</div>';
        // Papers in this issue
        if ($papers) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Papers in this Issue (' . count($papers) . ')</h2>';
            $output .= '<div class="sjm-cards-grid">';
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
                $output .= '<h4>' . esc_html($paper->post_title) . '</h4>';

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
                        $output .= '<p class="sjm-paper-authors-line">' . implode(', ', $author_displays) . '</p>';
                    }
                } elseif ($paper_authors) {
                    $output .= '<p class="sjm-paper-authors-line">' . esc_html($paper_authors) . '</p>';
                }
                $output .= '<div class="sjm-journal-badges">';
                if ($paper_type) $output .= '<span class="sjm-badge">' . esc_html($paper_type) . '</span>';
                if ($paper_pages) $output .= '<span class="sjm-badge">Pages ' . esc_html($paper_pages) . '</span>';
                if ($paper_doi) $output .= '<span class="sjm-badge"><a href="https://doi.org/' . esc_attr($paper_doi) . '" class="sjm-doi-link" target="_blank">DOI</a></span>';
                if ($paper_open_access) $output .= '<span class="sjm-badge">Open Access</span>';
                if ($paper_peer_reviewed) $output .= '<span class="sjm-badge">Peer Reviewed</span>';
                $output .= '</div>';
                $output .= '<div class="sjm-actions-row">';
                if ($paper_pdf_url) {
                    $output .= '<a href="' . esc_url($paper_pdf_url) . '" target="_blank" class="sjm-view-button">';
                    $output .= '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>PDF</a>';
                }
                $output .= '<a href="' . get_permalink($paper->ID) . '" class="sjm-view-button">View Paper <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg></a>';
                $output .= '</div>';
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

        $output = '<div class="sjm-single-container">';

        // Breadcrumb
        $output .= '<nav class="sjm-breadcrumb">';
        $output .= '<a href="' . esc_url(home_url('/')) . '">Home</a>';
        $output .= '<span class="sjm-breadcrumb-separator">&rsaquo;</span>';
        if ($paper_journal) {
            $output .= '<a href="' . esc_url(get_permalink($paper_journal->ID)) . '">' . esc_html($paper_journal->post_title) . '</a>';
            $output .= '<span class="sjm-breadcrumb-separator">&rsaquo;</span>';
        }
        if ($paper_issue) {
            $output .= '<a href="' . esc_url(get_permalink($paper_issue->ID)) . '">' . esc_html($paper_issue->post_title) . '</a>';
            $output .= '<span class="sjm-breadcrumb-separator">&rsaquo;</span>';
        }
        $output .= '<span class="sjm-breadcrumb-current">' . esc_html($post->post_title) . '</span>';
        $output .= '</nav>';

        $output .= '<div class="sjm-single-main">';

        // Header section
        $output .= '<div class="sjm-single-header">';
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
                $output .= '<p class="sjm-authors-line">' . implode(', ', $author_displays) . '</p>';
            }
        } elseif ($paper_authors) {
            $output .= '<p class="sjm-authors-line">' . esc_html($paper_authors) . '</p>';
        }
        
        if ($paper_journal || $paper_issue) {
            $output .= '<p class="sjm-parent-links">';
            if ($paper_journal) {
                $output .= '<a href="' . esc_url(get_permalink($paper_journal->ID)) . '">' . esc_html($paper_journal->post_title) . '</a>';
            }
            if ($paper_issue) {
                $issue_volume = get_post_meta($paper_issue->ID, '_sjm_issue_volume', true);
                $issue_number = get_post_meta($paper_issue->ID, '_sjm_issue_number', true);
                if ($issue_volume && $issue_number) {
                    $output .= ' • <a href="' . esc_url(get_permalink($paper_issue->ID)) . '">Vol. ' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</a>';
                }
            }
            $output .= '</p>';
        }
    
    // Quick badges
    $output .= '<div class="sjm-journal-badges">';
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
            $output .= '<div class="sjm-actions-row">';
            if ($paper_pdf_url) {
                $output .= '<a href="' . esc_url($paper_pdf_url) . '" target="_blank" class="sjm-download-btn">';
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
            $output .= '</div>';
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
        $output .= '<div class="sjm-authors-grid">';
        // Display detailed author information with profile links
        if (!empty($paper_authors_data)) {
            foreach ($paper_authors_data as $author_data) {
                $author = sjm_get_author_by_id($author_data['author_id']);
                if ($author) {
                    $output .= '<div class="sjm-author-card">';
                    $profile_url = sjm_get_author_profile_url($author->id);
                    $output .= '<div class="sjm-author-name">';
                    $output .= '<a href="' . esc_url($profile_url) . '">' . esc_html($author->first_name . ' ' . $author->last_name) . '</a>';
                    if ($author_data['is_corresponding'] == '1') {
                        $output .= ' <span class="sjm-badge sjm-corresponding-badge">Corresponding Author</span>';
                    }
                    $output .= '</div>';
                    $output .= '<div class="sjm-author-info">';
                    if ($author->orcid) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>ORCID:</strong> <a href="https://orcid.org/' . esc_attr($author->orcid) . '" target="_blank" class="sjm-orcid-link">' . esc_html($author->orcid) . '</a>';
                        $output .= '</div>';
                    }
                    if ($author->affiliation) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Affiliation:</strong> ' . esc_html($author->affiliation);
                        $output .= '</div>';
                    }
                    if ($author->email) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Email:</strong> <a href="mailto:' . esc_attr($author->email) . '">' . esc_html($author->email) . '</a>';
                        $output .= '</div>';
                    }
                    if ($author->website) {
                        $output .= '<div class="sjm-author-item">';
                        $output .= '<strong>Website:</strong> <a href="' . esc_url($author->website) . '" target="_blank">' . esc_html($author->website) . '</a>';
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
            $output .= '<div class="sjm-author-card">';
            $output .= '<div class="sjm-author-name"><a href="' . esc_url($corresponding_author['url']) . '">' . esc_html($corresponding_author['name']) . '</a> <span class="sjm-corresponding-badge">Corresponding Author</span></div>';
            $output .= '</div>';
        }
        $output .= '</div>'; // close sjm-authors-grid
        // Affiliations and Keywords in a clean meta-grid
        if ($author_affiliations || $paper_keywords) {
            $output .= '<div class="sjm-meta-grid">';
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
        }
        $output .= '</div>'; // close sjm-section
    
        // Manuscript Tracking
        $manuscript_id = get_post_meta($paper_id, '_sjm_manuscript_id', true);
        if ($manuscript_id) {
            $output .= '<div class="sjm-section">';
            $output .= '<h2 class="sjm-section-title">Manuscript Tracking</h2>';
            $output .= '<div class="sjm-meta-grid">';
        $output .= '<div class="sjm-meta-item">';
            $output .= '<span class="sjm-meta-label">Manuscript ID</span>';
            $output .= '<span class="sjm-meta-value"><span class="sjm-manuscript-id">' . esc_html($manuscript_id) . '</span></span>';
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
                $output .= '<span class="sjm-meta-value"><a href="' . esc_url($license_url) . '" target="_blank">' . esc_html($license_url) . '</a></span>';
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
                $output .= '<div class="sjm-version-section">';
                $output .= '<div class="sjm-version-header">';
                $output .= '<h3>' . esc_html($type) . ' Versions (' . count($type_versions) . ')</h3>';
                $output .= '</div>';

                $output .= '<div class="sjm-version-body">';
                foreach ($type_versions as $version_num => $version) {
                    $version_label = $type . ' v' . ($version_num + 1);
                    $is_latest = ($version_num === count($type_versions) - 1);

                    $output .= '<div class="sjm-version-card">';
                    $output .= '<div class="sjm-version-card-content">';
                    $output .= '<div class="sjm-version-title-row">';
                    $output .= '<h4 class="sjm-version-title">' . esc_html($version_label) . '</h4>';
                    if ($is_latest) {
                        $output .= '<span class="sjm-version-tag sjm-version-tag-latest">LATEST</span>';
                    }
                    if (!empty($version['open_access']) && $version['open_access'] == '1') {
                        $output .= '<span class="sjm-version-tag sjm-version-tag-oa">OPEN ACCESS</span>';
                    }
                    $output .= '</div>';

                    if (!empty($version['description'])) {
                        $output .= '<p class="sjm-version-detail"><strong>Version Notes:</strong> ' . esc_html($version['description']) . '</p>';
                    }

                    // Display DOI if available
                    if (!empty($version['doi'])) {
                        $output .= '<p class="sjm-version-detail"><strong>DOI:</strong> <a href="https://doi.org/' . esc_attr($version['doi']) . '" target="_blank">' . esc_html($version['doi']) . '</a></p>';
                    }

                    // Display version-specific authors/contributors with profile links
                    if (!empty($version['authors'])) {
                        $version_contributors = array();
                        foreach ($version['authors'] as $version_author) {
                            $author = sjm_get_author_by_id($version_author['author_id']);
                            if ($author) {
                                $profile_url = sjm_get_author_profile_url($author->id);
                                $contributor_text = '<a href="' . esc_url($profile_url) . '">' . esc_html($author->first_name . ' ' . $author->last_name) . '</a>';
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
                            $output .= '<p class="sjm-version-detail"><strong>Contributors:</strong> ' . implode('; ', $version_contributors) . '</p>';
                        }
                    }

                    $output .= '<div class="sjm-version-badges">';
                    if (!empty($version['date'])) {
                        $output .= '<span class="sjm-badge">' . date('M j, Y', strtotime($version['date'])) . '</span>';
                    }
                    $output .= '</div>';
                    $output .= '</div>';

                    if (!empty($version['file'])) {
                        $output .= '<div class="sjm-version-actions">';
                        $output .= '<a href="' . esc_url($version['file']) . '" target="_blank" class="sjm-download-btn sjm-download-btn-secondary">';
                        $output .= '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
                        $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';
                        $output .= '</svg>';
                        $output .= 'Download';
                        $output .= '</a>';
                        $output .= '</div>';
                    }

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
            $output .= '<a href="' . esc_url($mailto) . '" class="sjm-download-btn sjm-download-btn-request">Request Full Text by Email</a>';
        } elseif (!$paper_open_access) {
            $output .= '<div class="sjm-not-oa-notice">This paper is not open access. Please contact the corresponding author to request the full text.</div>';
        }
        
            $output .= '</div>';
        
        return $output;
    }
    return $content;
}
add_filter('the_content', 'sjm_single_paper_template');

// Enqueue frontend CSS for single views
function sjm_enqueue_frontend_styles() {
    if (is_singular('journal') || is_singular('journal_issue') || is_singular('paper') || get_query_var('author_profile_id')) {
        wp_enqueue_style('wjm-modern-admin', WJM_PLUGIN_URL . 'assets/css/wjm-modern-admin.css', array(), WJM_VERSION);
        wp_enqueue_style('sjm-academic-shortcodes', plugin_dir_url(__FILE__) . 'academic-shortcodes.css', array('wjm-modern-admin'), WJM_VERSION);
        wp_enqueue_style('sjm-single-templates', WJM_PLUGIN_URL . 'assets/css/wjm-single-templates.css', array('sjm-academic-shortcodes'), WJM_VERSION);
    }
}
add_action('wp_enqueue_scripts', 'sjm_enqueue_frontend_styles');

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
/**
 * Get all authors with optional pagination - Performance optimized
 *
 * @param int $limit Number of authors per page (0 = no limit)
 * @param int $offset Offset for pagination
 * @return array Authors array
 */
function sjm_get_all_authors($limit = 0, $offset = 0) {
    global $wpdb;

    $table_name = $wpdb->prefix . 'sjm_authors';

    // Check if table exists first, create if it doesn't - Fixed SQL injection
    if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) != $table_name) {
        sjm_create_authors_table();
    }

    // Fixed SQL injection - using backticks and esc_sql for table name
    $safe_table = esc_sql($table_name);

    // Performance improvement: Add pagination support
    $query = "SELECT * FROM `{$safe_table}` ORDER BY last_name, first_name";

    if ($limit > 0) {
        $query .= $wpdb->prepare(" LIMIT %d OFFSET %d", $limit, $offset);
    }

    $results = $wpdb->get_results($query);

    // Return empty array if query fails
    return $results ? $results : array();
}

/**
 * Get total count of authors
 *
 * @return int Total authors count
 */
function sjm_get_authors_count() {
    global $wpdb;

    $table_name = $wpdb->prefix . 'sjm_authors';
    $safe_table = esc_sql($table_name);

    return (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$safe_table}`");
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
    // Verify nonce for CSRF protection
    check_ajax_referer('sjm_save_author_nonce', 'nonce');

    // Verify it's an admin user
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
    
    // Fix any existing empty ORCID values - Fixed SQL injection
    $safe_table = esc_sql($table_name);
    $wpdb->query("UPDATE `{$safe_table}` SET orcid = NULL WHERE orcid = ''");

    // Show current table status - Fixed SQL injection
    $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name));
    if (!$table_exists) {
        echo '<div class="notice notice-warning"><p><strong>WARNING: Authors table does not exist!</strong> <a href="' . admin_url('edit.php?post_type=journal&page=sjm-authors&force_create_table=1') . '" class="button">Force Create Table</a></p></div>';
    } else {
        echo '<div class="notice notice-success"><p><strong>Authors table exists.</strong> Table name: ' . $table_name . '</p></div>';
    }
    
    $authors = sjm_get_all_authors();
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Authors</h1>
                <p class="wjm-page-description">Add and manage author profiles (<?php echo count($authors); ?> total)</p>
            </div>
        </div>

        <div class="wjm-grid-2" style="align-items:start;">

            <!-- Add New Author -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Add New Author</h2>
                </div>
                <div class="wjm-card-body">
                    <form method="post" action="">
                        <?php wp_nonce_field('sjm_add_author', 'sjm_author_nonce'); ?>
                        <table class="wjm-settings-table">
                            <tr>
                                <th><label for="orcid">ORCID ID</label></th>
                                <td>
                                    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
                                        <input type="text" id="orcid" name="orcid" placeholder="0000-0000-0000-0000" class="wjm-input" style="flex:1;min-width:160px;">
                                        <button type="button" id="sjm-fetch-orcid" class="wjm-btn wjm-btn-secondary wjm-btn-sm">Fetch from ORCID</button>
                                    </div>
                                    <span id="sjm-orcid-loading" style="display:none;font-size:0.8125rem;color:var(--wjm-text-secondary);">Loading...</span>
                                    <span id="sjm-orcid-message" style="display:none;font-size:0.8125rem;"></span>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="first_name">First Name</label></th>
                                <td><input type="text" id="first_name" name="first_name" class="wjm-input" style="width:100%;"></td>
                            </tr>
                            <tr>
                                <th><label for="last_name">Last Name</label></th>
                                <td><input type="text" id="last_name" name="last_name" class="wjm-input" style="width:100%;"></td>
                            </tr>
                            <tr>
                                <th><label for="email">Email</label></th>
                                <td><input type="email" id="email" name="email" class="wjm-input" style="width:100%;"></td>
                            </tr>
                            <tr>
                                <th><label for="affiliation">Affiliation</label></th>
                                <td><textarea id="affiliation" name="affiliation" rows="3" class="wjm-textarea" style="width:100%;" placeholder="University, Institution, or Organization"></textarea></td>
                            </tr>
                            <tr>
                                <th><label for="bio">Bio</label></th>
                                <td><textarea id="bio" name="bio" rows="4" class="wjm-textarea" style="width:100%;" placeholder="Brief biography or description"></textarea></td>
                            </tr>
                            <tr>
                                <th><label for="website">Website</label></th>
                                <td><input type="url" id="website" name="website" class="wjm-input" style="width:100%;" placeholder="https://"></td>
                            </tr>
                        </table>
                        <div style="margin-top:1rem;">
                            <button type="submit" name="add_author" class="wjm-btn wjm-btn-primary">Add Author</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Existing Authors -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Existing Authors</h2>
                </div>
                <div class="wjm-card-body" style="padding:0;">
                    <?php if ($authors): ?>
                        <table class="wjm-table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>ORCID</th>
                                    <th>Email</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($authors as $author): ?>
                                    <tr>
                                        <td>
                                            <strong><?php echo esc_html($author->first_name . ' ' . $author->last_name); ?></strong>
                                            <?php if ($author->affiliation): ?>
                                                <br><span style="font-size:0.75rem;color:var(--wjm-text-secondary);"><?php echo esc_html(wp_trim_words($author->affiliation, 5)); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td style="font-size:0.8125rem;">
                                            <?php if ($author->orcid): ?>
                                                <a href="https://orcid.org/<?php echo esc_attr($author->orcid); ?>" target="_blank" style="color:var(--wjm-primary);font-family:var(--wjm-font-mono);">
                                                    <?php echo esc_html($author->orcid); ?>
                                                </a>
                                            <?php else: ?>
                                                <span style="color:var(--wjm-text-secondary);">—</span>
                                            <?php endif; ?>
                                        </td>
                                        <td style="font-size:0.8125rem;"><?php echo esc_html($author->email ?: '—'); ?></td>
                                        <td>
                                            <a href="<?php echo esc_url(sjm_get_author_profile_url($author->id)); ?>"
                                               class="wjm-btn wjm-btn-secondary wjm-btn-sm"
                                               target="_blank" style="margin-right:4px;">
                                                Profile
                                            </a>
                                            <form method="post" style="display:inline-block;">
                                                <?php wp_nonce_field('sjm_delete_author', 'sjm_author_nonce'); ?>
                                                <input type="hidden" name="author_id" value="<?php echo esc_attr($author->id); ?>">
                                                <button type="submit" name="delete_author" class="wjm-btn wjm-btn-secondary wjm-btn-sm"
                                                        onclick="return confirm('Delete this author?');">Delete</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <div class="wjm-empty-state">
                            <span class="dashicons dashicons-admin-users"></span>
                            <p>No authors found. Add your first author.</p>
                        </div>
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
        $output .= '<a href="' . esc_url($profile_url) . '" style="color: #1e3a5f; text-decoration: none; font-weight: 500;">' . $author_name . '</a>';
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

// Add jQuery UI for dialogs and modern admin styles
function sjm_admin_enqueue_scripts() {
    global $post_type;

    // Enqueue modern admin CSS on all WJM admin pages
    $screen = get_current_screen();
    if ($screen && (in_array($post_type, array('journal', 'paper', 'issue', 'journal_issue')) ||
        strpos($screen->id, 'wjm-') !== false ||
        strpos($screen->id, 'sjm-') !== false ||
        strpos($screen->id, 'journal') !== false)) {
        wp_enqueue_style('wjm-modern-admin', WJM_PLUGIN_URL . 'assets/css/wjm-modern-admin.css', array(), WJM_VERSION);
    }

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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Import / Export</h1>
                <p class="wjm-page-description">Migrate or back up journals, issues, papers, and authors</p>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="notice notice-success is-dismissible"><p><?php echo esc_html($message); ?></p></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="notice notice-error is-dismissible"><p><?php echo esc_html($error); ?></p></div>
        <?php endif; ?>

        <div class="wjm-grid-2">

            <!-- Import -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-upload"></span>
                        Import Data
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <form method="post" enctype="multipart/form-data">
                        <?php wp_nonce_field('sjm_import_data', 'sjm_import_nonce'); ?>
                        <table class="wjm-settings-table">
                            <tr>
                                <th><label for="import_type">Content Type</label></th>
                                <td>
                                    <select name="import_type" id="import_type" class="wjm-select">
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
                                    <input type="file" name="import_file" id="import_file" accept=".csv" class="wjm-input" />
                                    <p class="description" style="margin-top:0.5rem;">Upload a CSV file. <a href="#" id="download_template" style="color:var(--wjm-primary);">Download template</a></p>
                                </td>
                            </tr>
                            <tr>
                                <th>Options</th>
                                <td>
                                    <label style="display:block;margin-bottom:0.375rem;"><input type="checkbox" name="import_options[]" value="skip_duplicates" /> Skip duplicates</label>
                                    <label><input type="checkbox" name="import_options[]" value="update_existing" /> Update existing items</label>
                                </td>
                            </tr>
                        </table>
                        <div style="margin-top:1rem;">
                            <button type="submit" name="sjm_import" class="wjm-btn wjm-btn-primary">Import Data</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Export -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-download"></span>
                        Export Data
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <form method="post">
                        <?php wp_nonce_field('sjm_export_data', 'sjm_export_nonce'); ?>
                        <table class="wjm-settings-table">
                            <tr>
                                <th><label for="export_type">Content Type</label></th>
                                <td>
                                    <select name="export_type" id="export_type" class="wjm-select">
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
                                    <select name="export_format" id="export_format" class="wjm-select">
                                        <option value="csv">CSV</option>
                                        <option value="json">JSON</option>
                                        <option value="xml">XML</option>
                                    </select>
                                </td>
                            </tr>
                            <tr>
                                <th>Filters</th>
                                <td>
                                    <label style="display:block;margin-bottom:0.5rem;font-size:0.8125rem;color:var(--wjm-text-secondary);">Date Range</label>
                                    <div style="display:flex;gap:0.5rem;margin-bottom:1rem;">
                                        <input type="date" name="export_date_from" class="wjm-input" style="flex:1;" />
                                        <input type="date" name="export_date_to" class="wjm-input" style="flex:1;" />
                                    </div>
                                    <label style="display:block;margin-bottom:0.5rem;font-size:0.8125rem;color:var(--wjm-text-secondary);">Journal</label>
                                    <select name="export_journal" class="wjm-select" style="width:100%;margin-bottom:1rem;">
                                        <option value="">All journals</option>
                                        <?php
                                        $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
                                        foreach ($journals as $journal) {
                                            echo '<option value="' . esc_attr($journal->ID) . '">' . esc_html($journal->post_title) . '</option>';
                                        }
                                        ?>
                                    </select>
                                    <label style="display:block;margin-bottom:0.5rem;font-size:0.8125rem;color:var(--wjm-text-secondary);">Open Access</label>
                                    <select name="export_open_access" class="wjm-select" style="width:100%;">
                                        <option value="">All</option>
                                        <option value="1">Open Access only</option>
                                        <option value="0">Closed Access only</option>
                                    </select>
                                </td>
                            </tr>
                        </table>
                        <div style="margin-top:1rem;">
                            <button type="submit" name="sjm_export" class="wjm-btn wjm-btn-primary">Export Data</button>
                        </div>
                    </form>
                </div>
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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Email Settings</h1>
                <p class="wjm-page-description">Configure notification triggers, sender info, and email templates</p>
            </div>
        </div>

        <div class="wjm-grid-2" style="align-items:start;">

            <!-- Main Settings -->
            <div class="wjm-card" style="grid-column:1 / -1;">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-email-alt"></span>
                        Notification Triggers
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <form method="post">
                        <?php wp_nonce_field('sjm_email_settings', 'sjm_email_nonce'); ?>
                        <table class="wjm-settings-table">
                            <tr>
                                <th>Notifications</th>
                                <td>
                                    <label style="display:block;margin-bottom:0.375rem;"><input type="checkbox" name="paper_submission_editors" <?php checked(isset($settings['paper_submission_editors']) ? $settings['paper_submission_editors'] : true); ?> /> Notify editors when a paper is submitted</label>
                                    <label style="display:block;margin-bottom:0.375rem;"><input type="checkbox" name="paper_submission_authors" <?php checked(isset($settings['paper_submission_authors']) ? $settings['paper_submission_authors'] : true); ?> /> Notify authors of submission confirmation</label>
                                    <label style="display:block;margin-bottom:0.375rem;"><input type="checkbox" name="paper_published_authors" <?php checked(isset($settings['paper_published_authors']) ? $settings['paper_published_authors'] : true); ?> /> Notify authors when paper is published</label>
                                    <label style="display:block;margin-bottom:0.375rem;"><input type="checkbox" name="paper_published_subscribers" <?php checked(isset($settings['paper_published_subscribers']) ? $settings['paper_published_subscribers'] : false); ?> /> Notify subscribers when paper is published</label>
                                    <label style="display:block;margin-bottom:0.375rem;"><input type="checkbox" name="issue_published_subscribers" <?php checked(isset($settings['issue_published_subscribers']) ? $settings['issue_published_subscribers'] : false); ?> /> Notify subscribers when issue is published</label>
                                    <label style="display:block;"><input type="checkbox" name="review_assignment_reviewers" <?php checked(isset($settings['review_assignment_reviewers']) ? $settings['review_assignment_reviewers'] : true); ?> /> Notify reviewers when assigned</label>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="from_email">From Email</label></th>
                                <td>
                                    <input type="email" name="from_email" id="from_email" class="wjm-input"
                                        value="<?php echo esc_attr(isset($settings['from_email']) ? $settings['from_email'] : get_option('admin_email')); ?>" />
                                </td>
                            </tr>
                            <tr>
                                <th><label for="from_name">From Name</label></th>
                                <td>
                                    <input type="text" name="from_name" id="from_name" class="wjm-input"
                                        value="<?php echo esc_attr(isset($settings['from_name']) ? $settings['from_name'] : get_bloginfo('name')); ?>" />
                                </td>
                            </tr>
                            <tr>
                                <th><label for="email_template_header">Header Template</label></th>
                                <td>
                                    <textarea name="email_template_header" id="email_template_header" rows="4" class="wjm-textarea" style="width:100%;"><?php echo esc_textarea(isset($settings['email_template_header']) ? $settings['email_template_header'] : 'Dear {recipient_name},'); ?></textarea>
                                    <p class="description" style="margin-top:0.375rem;">Placeholders: {recipient_name}, {site_name}, {site_url}</p>
                                </td>
                            </tr>
                            <tr>
                                <th><label for="email_template_footer">Footer Template</label></th>
                                <td>
                                    <textarea name="email_template_footer" id="email_template_footer" rows="4" class="wjm-textarea" style="width:100%;"><?php echo esc_textarea(isset($settings['email_template_footer']) ? $settings['email_template_footer'] : 'Best regards,<br>{site_name} Team'); ?></textarea>
                                    <p class="description" style="margin-top:0.375rem;">Placeholders: {site_name}, {site_url}, {unsubscribe_link}</p>
                                </td>
                            </tr>
                        </table>
                        <div style="margin-top:1rem;">
                            <button type="submit" name="sjm_save_email_settings" class="wjm-btn wjm-btn-primary">Save Settings</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Test Email -->
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-email"></span>
                        Test Email
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <p style="font-size:0.875rem;color:var(--wjm-text-secondary);margin-bottom:1rem;">Send a test email to verify your settings are working correctly.</p>
                    <form method="post">
                        <?php wp_nonce_field('sjm_test_email', 'sjm_test_email_nonce'); ?>
                        <div class="wjm-form-group">
                            <input type="email" name="test_email" placeholder="Enter email address" required class="wjm-input" style="width:100%;margin-bottom:0.75rem;" />
                            <button type="submit" name="sjm_test_email" class="wjm-btn wjm-btn-secondary">Send Test Email</button>
                        </div>
                    </form>
                </div>
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
        'edit.php?post_type=journal',
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
        
        // Clear expired transients - Fixed SQL injection
        $current_time = time();
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND option_value < %d",
            '_transient_timeout_%',
            $current_time
        ));
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name NOT LIKE %s AND option_name NOT IN (SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s)",
            '_transient_%',
            '_transient_timeout_%',
            '_transient_timeout_%'
        ));

        // Clean up old rate limiting data - Fixed SQL injection
        $cutoff_time = time() - 86400;
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND option_value < %d",
            'sjm_rate_limit_%',
            $cutoff_time
        ));
        
        // Clean up logs
        $security_log = get_option('wjm_security_log', array());
        if (count($security_log) > 1000) {
            $security_log = array_slice($security_log, -1000);
            update_option('wjm_security_log', $security_log);
        }
        
        echo '<div class="notice notice-success"><p>Plugin cleanup completed successfully!</p></div>';
    }
    
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Plugin Cleanup</h1>
                <p class="wjm-page-description">Clear expired data and optimize plugin performance</p>
            </div>
            <form method="post" style="margin:0;">
                <?php wp_nonce_field('sjm_cleanup', 'cleanup_nonce'); ?>
                <button type="submit" name="run_cleanup" class="wjm-btn wjm-btn-primary">Run Cleanup</button>
            </form>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-trash"></span>
                    What Gets Cleaned Up
                </h2>
            </div>
            <div class="wjm-card-body">
                <ul class="wjm-guide-ul">
                    <li>Expired transients and cached data</li>
                    <li>Old rate limiting data (older than 24 hours)</li>
                    <li>Security logs (keeps last 1,000 entries)</li>
                    <li>Database table optimization</li>
                </ul>
            </div>
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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Plugin Verification</h1>
                <p class="wjm-page-description">System checks and component verification results</p>
            </div>
        </div>

        <?php
        $notice_color = $percentage == 100 ? 'var(--wjm-mint-ink)' : ($percentage >= 80 ? 'var(--wjm-peach-ink)' : 'var(--wjm-danger-ink)');
        $notice_bg    = $percentage == 100 ? 'var(--wjm-mint-bg)' : ($percentage >= 80 ? 'var(--wjm-peach-bg)' : 'var(--wjm-danger-bg)');
        ?>
        <div class="wjm-stats-grid" style="margin-bottom:1.25rem;">
            <div class="wjm-stat-card" style="background:<?php echo $notice_bg; ?>;border:none;">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Overall Score</div>
                    <div class="wjm-stat-value" style="color:<?php echo $notice_color; ?>;"><?php echo $percentage; ?>%</div>
                </div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--mint">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Tests Passed</div>
                    <div class="wjm-stat-value"><?php echo $passed; ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--peach">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Tests Failed</div>
                    <div class="wjm-stat-value"><?php echo ($total - $passed); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">Test Results</h2>
            </div>
            <div class="wjm-card-body" style="padding:0;">
                <table class="wjm-table">
                    <thead>
                        <tr><th>Component</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                        <?php foreach ($tests as $test => $result): ?>
                            <tr>
                                <td><?php echo esc_html(ucwords(str_replace('_', ' ', $test))); ?></td>
                                <td>
                                    <span class="wjm-severity-badge wjm-severity-<?php echo $result ? 'info' : 'error'; ?>">
                                        <?php echo $result ? 'Pass' : 'Fail'; ?>
                                    </span>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Rate Limits</h1>
                <p class="wjm-page-description">Monitor API usage and remaining quota for <?php echo esc_html($user->user_login); ?> (<?php echo esc_html(ucfirst($user_role)); ?>)</p>
            </div>
        </div>

        <div class="wjm-grid-2">
            <?php foreach ($actions as $action):
                $rate_info  = WJM_Security_Manager::get_rate_limit_info($action, $user_id);
                $pct        = min(100, ($rate_info['current_usage'] / max(1, $rate_info['limit'])) * 100);
                $bar_class  = $pct < 50 ? 'wjm-green' : ($pct < 80 ? 'wjm-orange' : 'wjm-red');
                $label      = ucwords(str_replace('_', ' ', $action));
            ?>
                <div class="wjm-card">
                    <div class="wjm-card-header">
                        <h2 class="wjm-card-title"><?php echo esc_html($label); ?></h2>
                    </div>
                    <div class="wjm-card-body">
                        <div class="wjm-usage-numbers">
                            <span class="wjm-usage-current"><?php echo esc_html($rate_info['current_usage']); ?></span>
                            <span class="wjm-usage-divider">/</span>
                            <span class="wjm-usage-total"><?php echo esc_html($rate_info['limit']); ?></span>
                        </div>
                        <div class="wjm-usage-bar">
                            <div class="wjm-bar-fill <?php echo $bar_class; ?>" style="width:<?php echo $pct; ?>%"></div>
                        </div>
                        <div class="wjm-usage-remaining"><?php echo esc_html($rate_info['remaining']); ?> remaining</div>
                        <div class="wjm-reset-time">Resets at <?php echo esc_html(date('H:i', $rate_info['reset_time'])); ?></div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="wjm-card" style="margin-top:1.25rem;">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">Rate Limit Tiers by Role</h2>
            </div>
            <div class="wjm-card-body" style="padding:0;">
                <table class="wjm-table">
                    <thead>
                        <tr><th>Role</th><th>API Calls / hr</th><th>Data Fetches / hr</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>Student</td><td>50</td><td>30</td></tr>
                        <tr><td>Researcher</td><td>100</td><td>60</td></tr>
                        <tr><td>Editor</td><td>200</td><td>120</td></tr>
                        <tr><td>Administrator</td><td>500</td><td>300</td></tr>
                    </tbody>
                </table>
            </div>
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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Security Log</h1>
                <p class="wjm-page-description">Recent security events and activity overview</p>
            </div>
            <form method="post" style="margin:0;">
                <?php wp_nonce_field('sjm_clear_security_log', 'security_nonce'); ?>
                <button type="submit" name="clear_log" class="wjm-btn wjm-btn-secondary"
                        onclick="return confirm('Clear the security log?')">
                    <span class="dashicons dashicons-trash"></span> Clear Log
                </button>
            </form>
        </div>

        <!-- Stats -->
        <div class="wjm-stats-grid">
            <div class="wjm-stat-card wjm-stat-card--sky">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Total Events</div>
                    <div class="wjm-stat-value"><?php echo esc_html(count($security_log)); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--mint">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Active Users</div>
                    <div class="wjm-stat-value"><?php echo esc_html(count(array_unique(array_column($security_log, 'user_id')))); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--peach">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Last 24h Events</div>
                    <div class="wjm-stat-value">
                        <?php
                        $last_24h = array_filter($security_log, function($event) {
                            return strtotime($event['timestamp']) > (time() - 86400);
                        });
                        echo esc_html(count($last_24h));
                        ?>
                    </div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
        </div>

        <!-- Log table -->
        <div class="wjm-card" style="margin-top:1.25rem;">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-list-view"></span>
                    Security Events
                </h2>
            </div>
            <div class="wjm-card-body" style="padding:0;">
                <?php if (empty($security_log)): ?>
                    <div class="wjm-empty-state">
                        <span class="dashicons dashicons-shield"></span>
                        <p>No security events recorded yet.</p>
                    </div>
                <?php else: ?>
                    <table class="wjm-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>IP Address</th>
                                <th>Event</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($security_log, 0, 100) as $event): ?>
                                <tr>
                                    <td style="white-space:nowrap;font-size:0.8125rem;"><?php echo esc_html(date('Y-m-d H:i:s', strtotime($event['timestamp']))); ?></td>
                                    <td>
                                        <?php
                                        if (!empty($event['user_id'])) {
                                            $ev_user = get_user_by('id', $event['user_id']);
                                            echo esc_html($ev_user ? $ev_user->user_login : 'Unknown');
                                        } else {
                                            echo 'Guest';
                                        }
                                        ?>
                                    </td>
                                    <td style="font-size:0.8125rem;font-family:var(--wjm-font-mono);"><?php echo esc_html($event['user_ip']); ?></td>
                                    <td><span class="wjm-severity-badge wjm-severity-info"><?php echo esc_html($event['event']); ?></span></td>
                                    <td style="font-size:0.8125rem;">
                                        <?php if (!empty($event['details'])): ?>
                                            <details>
                                                <summary style="cursor:pointer;color:var(--wjm-primary);">View Details</summary>
                                                <pre style="margin-top:0.5rem;padding:0.5rem;background:var(--wjm-gray-50);border-radius:4px;font-size:0.75rem;overflow-x:auto;"><?php echo esc_html(print_r($event['details'], true)); ?></pre>
                                            </details>
                                        <?php else: ?>
                                            <em style="color:var(--wjm-text-secondary);">—</em>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php if (count($security_log) > 100): ?>
                        <div style="padding:0.875rem 1rem;font-size:0.8125rem;color:var(--wjm-text-secondary);border-top:1px solid var(--wjm-border-light);text-align:center;">
                            Showing latest 100 of <?php echo esc_html(count($security_log)); ?> events.
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>

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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Email Log</h1>
                <p class="wjm-page-description">History of all outgoing email notifications</p>
            </div>
            <form method="post" style="margin:0;">
                <?php wp_nonce_field('sjm_clear_log', 'sjm_clear_log_nonce'); ?>
                <button type="submit" name="sjm_clear_log" class="wjm-btn wjm-btn-secondary"
                        onclick="return confirm('Clear the email log?')">
                    <span class="dashicons dashicons-trash"></span> Clear Log
                </button>
            </form>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-email"></span>
                    Sent Emails
                </h2>
            </div>
            <div class="wjm-card-body" style="padding:0;">
                <?php if (empty($email_log)): ?>
                    <div class="wjm-empty-state">
                        <span class="dashicons dashicons-email-alt"></span>
                        <p>No email log entries found.</p>
                    </div>
                <?php else: ?>
                    <table class="wjm-table">
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
                                    <td style="white-space:nowrap;font-size:0.8125rem;"><?php echo esc_html($entry['timestamp']); ?></td>
                                    <td style="font-size:0.8125rem;"><?php echo esc_html($entry['to']); ?></td>
                                    <td style="font-size:0.8125rem;"><?php echo esc_html($entry['subject']); ?></td>
                                    <td><code class="wjm-code-block" style="font-size:0.75rem;"><?php echo esc_html($entry['template']); ?></code></td>
                                    <td>
                                        <?php if ($entry['success']): ?>
                                            <span class="wjm-severity-badge wjm-severity-info">Sent</span>
                                        <?php else: ?>
                                            <span class="wjm-severity-badge wjm-severity-error">Failed</span>
                                        <?php endif; ?>
                                    </td>
                                    <td style="font-size:0.8125rem;color:var(--wjm-text-secondary);"><?php echo esc_html($entry['error']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

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
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Analytics</h1>
                <p class="wjm-page-description">Content growth, publication activity, and performance overview</p>
            </div>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=sjm_export_analytics&format=csv&start_date=' . $start_date . '&end_date=' . $end_date)); ?>" class="wjm-btn wjm-btn-secondary wjm-btn-sm">Export CSV</a>
                <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=sjm_export_analytics&format=json&start_date=' . $start_date . '&end_date=' . $end_date)); ?>" class="wjm-btn wjm-btn-secondary wjm-btn-sm">Export JSON</a>
            </div>
        </div>

        <!-- Date filter -->
        <div class="wjm-card" style="margin-bottom:1.25rem;">
            <div class="wjm-card-body">
                <form method="get" style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;">
                    <input type="hidden" name="page" value="sjm-analytics">
                    <input type="hidden" name="post_type" value="journal">
                    <label style="font-size:0.8125rem;font-weight:600;">Quick Range</label>
                    <select name="range" id="range" class="wjm-select" onchange="this.form.submit()">
                        <option value="7"   <?php selected($date_range, '7'); ?>>Last 7 days</option>
                        <option value="30"  <?php selected($date_range, '30'); ?>>Last 30 days</option>
                        <option value="90"  <?php selected($date_range, '90'); ?>>Last 90 days</option>
                        <option value="365" <?php selected($date_range, '365'); ?>>Last year</option>
                    </select>
                    <label style="font-size:0.8125rem;font-weight:600;">From</label>
                    <input type="date" name="start_date" id="start_date" class="wjm-input" value="<?php echo esc_attr($start_date); ?>">
                    <label style="font-size:0.8125rem;font-weight:600;">To</label>
                    <input type="date" name="end_date" id="end_date" class="wjm-input" value="<?php echo esc_attr($end_date); ?>">
                    <button type="submit" class="wjm-btn wjm-btn-primary wjm-btn-sm">Apply</button>
                </form>
            </div>
        </div>

        <!-- Key Metrics -->
        <div class="wjm-stats-grid">
            <div class="wjm-stat-card wjm-stat-card--mint">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Journals</div>
                    <div class="wjm-stat-value"><?php echo esc_html($analytics_data['total_journals']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--sky">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Issues</div>
                    <div class="wjm-stat-value"><?php echo esc_html($analytics_data['total_issues']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--violet">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Papers</div>
                    <div class="wjm-stat-value"><?php echo esc_html($analytics_data['total_papers']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--peach">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Authors</div>
                    <div class="wjm-stat-value"><?php echo esc_html($analytics_data['total_authors']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
        </div>

        <!-- Charts -->
        <div class="wjm-grid-2" style="margin-top:1.25rem;">
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Content Growth</h2>
                </div>
                <div class="wjm-card-body" style="height:280px;overflow:hidden;">
                    <canvas id="contentGrowthChart" style="width:100%;height:100%;"></canvas>
                </div>
            </div>
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Publication Activity</h2>
                </div>
                <div class="wjm-card-body" style="height:280px;overflow:hidden;">
                    <canvas id="publicationActivityChart" style="width:100%;height:100%;"></canvas>
                </div>
            </div>
        </div>

        <!-- Tables -->
        <div class="wjm-grid-2" style="margin-top:1.25rem;">
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Top Journals</h2>
                </div>
                <div class="wjm-card-body" style="padding:0;">
                    <table class="wjm-table">
                        <thead>
                            <tr><th>Journal</th><th>Papers</th><th>Issues</th><th>Views</th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($analytics_data['top_journals'] as $journal): ?>
                                <tr>
                                    <td><a href="<?php echo esc_url(get_edit_post_link($journal['id'])); ?>" style="color:var(--wjm-primary);"><?php echo esc_html($journal['title']); ?></a></td>
                                    <td><?php echo esc_html($journal['papers']); ?></td>
                                    <td><?php echo esc_html($journal['issues']); ?></td>
                                    <td><?php echo esc_html($journal['views']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">Recent Activity</h2>
                </div>
                <div class="wjm-card-body" style="padding:0;">
                    <table class="wjm-table">
                        <thead>
                            <tr><th>Action</th><th>Item</th><th>Date</th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($analytics_data['recent_activity'] as $activity): ?>
                                <tr>
                                    <td><span class="wjm-severity-badge wjm-severity-info"><?php echo esc_html($activity['action']); ?></span></td>
                                    <td><a href="<?php echo esc_url($activity['link']); ?>" style="color:var(--wjm-primary);"><?php echo esc_html($activity['title']); ?></a></td>
                                    <td style="font-size:0.8125rem;color:var(--wjm-text-secondary);"><?php echo esc_html($activity['date']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
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

