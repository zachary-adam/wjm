<?php
/**
 * Security Dashboard Template
 * 
 * This template provides a comprehensive security monitoring interface
 * for the Wisdom Journal Manager plugin.
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Security check
if (!WJM_Security_Manager::check_user_capability('api_access')) {
    wp_die('Insufficient permissions to access security dashboard.');
}

// Handle security actions
if (isset($_POST['clear_security_log']) && WJM_Security_Manager::validate_csrf_token($_POST['security_nonce'], 'clear_security_log')) {
    update_option('wjm_security_log', array());
    echo '<div class="notice notice-success"><p>Security log cleared successfully.</p></div>';
}

if (isset($_POST['export_security_log']) && WJM_Security_Manager::validate_csrf_token($_POST['security_nonce'], 'export_security_log')) {
    $security_log = get_option('wjm_security_log', array());
    $filename = 'security-log-' . date('Y-m-d-H-i-s') . '.csv';
    
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    fputcsv($output, array('Timestamp', 'User ID', 'IP Address', 'Event', 'Details', 'Severity', 'User Agent'));
    
    foreach ($security_log as $entry) {
        fputcsv($output, array(
            $entry['timestamp'],
            $entry['user_id'],
            $entry['user_ip'],
            $entry['event'],
            is_array($entry['details']) ? json_encode($entry['details']) : $entry['details'],
            $entry['severity'],
            $entry['user_agent']
        ));
    }
    
    fclose($output);
    exit;
}

$security_log = get_option('wjm_security_log', array());
$recent_events = array_slice($security_log, 0, 50); // Show last 50 events

// Calculate security statistics
$total_events = count($security_log);
$warning_events = count(array_filter($security_log, function($entry) {
    return $entry['severity'] === 'warning';
}));
$error_events = count(array_filter($security_log, function($entry) {
    return $entry['severity'] === 'error';
}));
$info_events = count(array_filter($security_log, function($entry) {
    return $entry['severity'] === 'info';
}));

// Get unique IPs and users
$unique_ips = array_unique(array_column($security_log, 'user_ip'));
$unique_users = array_unique(array_column($security_log, 'user_id'));
?>

<div class="wrap">
    <h1>Security Dashboard</h1>
    <p>Monitor security events and manage security settings for the Wisdom Journal Manager plugin.</p>
    
    <!-- Security Statistics -->
    <div class="wjm-security-stats">
        <div class="wjm-stat-card">
            <h3>Total Events</h3>
            <div class="wjm-stat-number"><?php echo esc_html($total_events); ?></div>
        </div>
        <div class="wjm-stat-card wjm-warning">
            <h3>Warnings</h3>
            <div class="wjm-stat-number"><?php echo esc_html($warning_events); ?></div>
        </div>
        <div class="wjm-stat-card wjm-error">
            <h3>Errors</h3>
            <div class="wjm-stat-number"><?php echo esc_html($error_events); ?></div>
        </div>
        <div class="wjm-stat-card wjm-info">
            <h3>Info</h3>
            <div class="wjm-stat-number"><?php echo esc_html($info_events); ?></div>
        </div>
    </div>
    
    <!-- Security Actions -->
    <div class="wjm-security-actions">
        <form method="post" style="display: inline;">
            <?php wp_nonce_field('clear_security_log', 'security_nonce'); ?>
            <button type="submit" name="clear_security_log" class="button button-secondary" onclick="return confirm('Are you sure you want to clear the security log?')">
                Clear Security Log
            </button>
        </form>
        
        <form method="post" style="display: inline; margin-left: 10px;">
            <?php wp_nonce_field('export_security_log', 'security_nonce'); ?>
            <button type="submit" name="export_security_log" class="button button-secondary">
                Export Security Log
            </button>
        </form>
    </div>
    
    <!-- Recent Security Events -->
    <div class="wjm-security-events">
        <h2>Recent Security Events</h2>
        
        <?php if (!empty($recent_events)): ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>IP Address</th>
                        <th>Event</th>
                        <th>Details</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recent_events as $event): ?>
                        <tr class="wjm-severity-<?php echo esc_attr($event['severity']); ?>">
                            <td><?php echo esc_html($event['timestamp']); ?></td>
                            <td>
                                <?php 
                                if ($event['user_id']) {
                                    $user = get_user_by('id', $event['user_id']);
                                    echo esc_html($user ? $user->display_name : 'Unknown User');
                                } else {
                                    echo 'Guest';
                                }
                                ?>
                            </td>
                            <td><?php echo esc_html($event['user_ip']); ?></td>
                            <td><?php echo esc_html($event['event']); ?></td>
                            <td>
                                <?php 
                                if (is_array($event['details'])) {
                                    echo '<pre>' . esc_html(json_encode($event['details'], JSON_PRETTY_PRINT)) . '</pre>';
                                } else {
                                    echo esc_html($event['details']);
                                }
                                ?>
                            </td>
                            <td>
                                <span class="wjm-severity-badge wjm-severity-<?php echo esc_attr($event['severity']); ?>">
                                    <?php echo esc_html(ucfirst($event['severity'])); ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>No security events recorded yet.</p>
        <?php endif; ?>
    </div>
    
    <!-- Security Settings -->
    <div class="wjm-security-settings">
        <h2>Security Settings</h2>
        
        <form method="post" action="options.php">
            <?php settings_fields('wjm_security_settings'); ?>
            
            <table class="form-table">
                <tr>
                    <th scope="row">Rate Limiting</th>
                    <td>
                        <label>
                            <input type="checkbox" name="wjm_enable_rate_limiting" value="1" 
                                   <?php checked(get_option('wjm_enable_rate_limiting', '1'), '1'); ?> />
                            Enable rate limiting for API calls
                        </label>
                        <p class="description">Prevents abuse of API endpoints and external services.</p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">Security Logging</th>
                    <td>
                        <label>
                            <input type="checkbox" name="wjm_enable_security_logging" value="1" 
                                   <?php checked(get_option('wjm_enable_security_logging', '1'), '1'); ?> />
                            Enable comprehensive security logging
                        </label>
                        <p class="description">Logs all security-related events for monitoring and auditing.</p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">File Upload Security</th>
                    <td>
                        <label>
                            <input type="checkbox" name="wjm_enable_file_validation" value="1" 
                                   <?php checked(get_option('wjm_enable_file_validation', '1'), '1'); ?> />
                            Enable enhanced file upload validation
                        </label>
                        <p class="description">Scans uploaded files for malicious content and validates file types.</p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">API Key Encryption</th>
                    <td>
                        <label>
                            <input type="checkbox" name="wjm_enable_api_encryption" value="1" 
                                   <?php checked(get_option('wjm_enable_api_encryption', '1'), '1'); ?> />
                            Enable API key encryption
                        </label>
                        <p class="description">Encrypts API keys stored in the database for enhanced security.</p>
                    </td>
                </tr>
            </table>
            
            <?php submit_button('Save Security Settings'); ?>
        </form>
    </div>
    
    <!-- Security Recommendations -->
    <div class="wjm-security-recommendations">
        <h2>Security Recommendations</h2>
        
        <div class="wjm-recommendation">
            <h3>✅ Implemented</h3>
            <ul>
                <li>API key encryption using AES-256-CBC</li>
                <li>Comprehensive input sanitization</li>
                <li>Output escaping for XSS prevention</li>
                <li>Rate limiting for API calls</li>
                <li>Enhanced capability checking</li>
                <li>CSRF protection with nonces</li>
                <li>File upload validation</li>
                <li>Security event logging</li>
                <li>Replacement of web scraping with official APIs</li>
            </ul>
        </div>
        
        <div class="wjm-recommendation">
            <h3>🔧 Additional Recommendations</h3>
            <ul>
                <li>Enable HTTPS for all admin pages</li>
                <li>Set up regular security log reviews</li>
                <li>Implement API key rotation procedures</li>
                <li>Configure server-level security headers</li>
                <li>Set up automated security monitoring</li>
                <li>Regular security audits and penetration testing</li>
            </ul>
        </div>
    </div>
</div>

<style>
.wjm-security-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin: 20px 0;
}

.wjm-stat-card {
    background: #fff;
    border: 1px solid #ddd;
    border-radius: 5px;
    padding: 20px;
    text-align: center;
}

.wjm-stat-number {
    font-size: 2em;
    font-weight: bold;
    color: #0073aa;
}

.wjm-stat-card.wjm-warning .wjm-stat-number {
    color: #ffb900;
}

.wjm-stat-card.wjm-error .wjm-stat-number {
    color: #dc3232;
}

.wjm-stat-card.wjm-info .wjm-stat-number {
    color: #00a0d2;
}

.wjm-security-actions {
    margin: 20px 0;
    padding: 15px;
    background: #f9f9f9;
    border-radius: 5px;
}

.wjm-security-events {
    margin: 30px 0;
}

.wjm-severity-badge {
    padding: 3px 8px;
    border-radius: 3px;
    font-size: 0.8em;
    font-weight: bold;
    text-transform: uppercase;
}

.wjm-severity-info {
    background: #e7f3ff;
    color: #0073aa;
}

.wjm-severity-warning {
    background: #fff8e5;
    color: #ffb900;
}

.wjm-severity-error {
    background: #ffeaea;
    color: #dc3232;
}

.wjm-severity-info .wjm-severity-badge {
    background: #0073aa;
    color: white;
}

.wjm-severity-warning .wjm-severity-badge {
    background: #ffb900;
    color: white;
}

.wjm-severity-error .wjm-severity-badge {
    background: #dc3232;
    color: white;
}

.wjm-security-settings {
    margin: 30px 0;
    padding: 20px;
    background: #f9f9f9;
    border-radius: 5px;
}

.wjm-security-recommendations {
    margin: 30px 0;
}

.wjm-recommendation {
    margin: 20px 0;
    padding: 15px;
    background: #fff;
    border-left: 4px solid #0073aa;
    border-radius: 3px;
}

.wjm-recommendation h3 {
    margin-top: 0;
    color: #0073aa;
}

.wjm-recommendation ul {
    margin: 10px 0;
}

.wjm-recommendation li {
    margin: 5px 0;
}
</style>
