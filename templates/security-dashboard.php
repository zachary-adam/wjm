<?php
/**
 * Security Dashboard Template — Wisdom Journal Manager
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!WJM_Security_Manager::check_user_capability('api_access')) {
    wp_die('Insufficient permissions to access security dashboard.');
}

// Handle actions
if (isset($_POST['clear_security_log']) && WJM_Security_Manager::validate_csrf_token($_POST['security_nonce'], 'clear_security_log')) {
    update_option('wjm_security_log', array());
    echo '<div class="notice notice-success"><p>Security log cleared.</p></div>';
}

if (isset($_POST['export_security_log']) && WJM_Security_Manager::validate_csrf_token($_POST['security_nonce'], 'export_security_log')) {
    $security_log = get_option('wjm_security_log', array());
    $filename     = 'security-log-' . date('Y-m-d-H-i-s') . '.csv';
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    $output = fopen('php://output', 'w');
    fputcsv($output, array('Timestamp', 'User ID', 'IP Address', 'Event', 'Details', 'Severity', 'User Agent'));
    foreach ($security_log as $entry) {
        fputcsv($output, array(
            $entry['timestamp'], $entry['user_id'], $entry['user_ip'], $entry['event'],
            is_array($entry['details']) ? json_encode($entry['details']) : $entry['details'],
            $entry['severity'], $entry['user_agent'],
        ));
    }
    fclose($output);
    exit;
}

$security_log   = get_option('wjm_security_log', array());
$recent_events  = array_slice($security_log, 0, 50);
$total_events   = count($security_log);
$warning_events = count(array_filter($security_log, fn($e) => $e['severity'] === 'warning'));
$error_events   = count(array_filter($security_log, fn($e) => $e['severity'] === 'error'));
$info_events    = count(array_filter($security_log, fn($e) => $e['severity'] === 'info'));
?>

<div class="wrap wjm-modern-wrap">

    <div class="wjm-page-header">
        <div>
            <h1 class="wjm-page-title">Security</h1>
            <p class="wjm-page-description">Security events, settings, and recommendations</p>
        </div>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
            <form method="post" style="margin:0;">
                <?php wp_nonce_field('clear_security_log', 'security_nonce'); ?>
                <button type="submit" name="clear_security_log"
                        class="wjm-btn wjm-btn-secondary"
                        onclick="return confirm('Clear the security log?')">
                    <span class="dashicons dashicons-trash"></span> Clear Log
                </button>
            </form>
            <form method="post" style="margin:0;">
                <?php wp_nonce_field('export_security_log', 'security_nonce'); ?>
                <button type="submit" name="export_security_log" class="wjm-btn wjm-btn-secondary">
                    <span class="dashicons dashicons-download"></span> Export CSV
                </button>
            </form>
        </div>
    </div>

    <!-- Stats -->
    <div class="wjm-stats-grid">
        <div class="wjm-stat-card wjm-stat-card--sky">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Total Events</div>
                <div class="wjm-stat-value"><?php echo esc_html($total_events); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
        <div class="wjm-stat-card wjm-stat-card--violet">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Info</div>
                <div class="wjm-stat-value"><?php echo esc_html($info_events); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
        <div class="wjm-stat-card wjm-stat-card--peach">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Warnings</div>
                <div class="wjm-stat-value"><?php echo esc_html($warning_events); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
        <div class="wjm-stat-card wjm-stat-card--danger">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Errors</div>
                <div class="wjm-stat-value"><?php echo esc_html($error_events); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
    </div>

    <!-- Recent events -->
    <div class="wjm-card">
        <div class="wjm-card-header">
            <h2 class="wjm-card-title">
                <span class="dashicons dashicons-list-view"></span>
                Recent Security Events
            </h2>
        </div>
        <div class="wjm-card-body" style="padding:0;">
            <?php if (!empty($recent_events)) : ?>
                <table class="wjm-table">
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
                        <?php foreach ($recent_events as $event) : ?>
                            <tr class="wjm-severity-<?php echo esc_attr($event['severity']); ?>">
                                <td style="white-space:nowrap;font-size:0.8125rem;"><?php echo esc_html($event['timestamp']); ?></td>
                                <td>
                                    <?php
                                    if ($event['user_id']) {
                                        $user = get_user_by('id', $event['user_id']);
                                        echo esc_html($user ? $user->display_name : 'Unknown');
                                    } else {
                                        echo 'Guest';
                                    }
                                    ?>
                                </td>
                                <td style="font-size:0.8125rem;font-family:var(--wjm-font-mono);"><?php echo esc_html($event['user_ip']); ?></td>
                                <td style="font-size:0.8125rem;"><?php echo esc_html($event['event']); ?></td>
                                <td style="font-size:0.8125rem;max-width:240px;">
                                    <?php
                                    if (is_array($event['details'])) {
                                        echo '<code style="font-size:0.75rem;background:var(--wjm-gray-50);padding:2px 4px;border-radius:3px;">'
                                             . esc_html(json_encode($event['details'])) . '</code>';
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
            <?php else : ?>
                <div class="wjm-empty-state">
                    <span class="dashicons dashicons-shield"></span>
                    <p>No security events recorded yet.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Settings -->
    <div class="wjm-card">
        <div class="wjm-card-header">
            <h2 class="wjm-card-title">
                <span class="dashicons dashicons-admin-settings"></span>
                Security Settings
            </h2>
        </div>
        <div class="wjm-card-body">
            <form method="post" action="options.php">
                <?php settings_fields('wjm_security_settings'); ?>
                <table class="wjm-settings-table">
                    <tr>
                        <th>Rate Limiting</th>
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
                        <th>Security Logging</th>
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
                        <th>File Upload Security</th>
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
                        <th>API Key Encryption</th>
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
                <?php submit_button('Save Security Settings', 'primary', 'submit', false, array('class' => 'wjm-btn wjm-btn-primary', 'style' => 'margin-top:1rem;')); ?>
            </form>
        </div>
    </div>

    <!-- Recommendations -->
    <div class="wjm-card">
        <div class="wjm-card-header">
            <h2 class="wjm-card-title">
                <span class="dashicons dashicons-shield-alt"></span>
                Security Recommendations
            </h2>
        </div>
        <div class="wjm-card-body">
            <div class="wjm-rec-grid">
                <div>
                    <p style="font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--wjm-mint-ink);margin-bottom:0.75rem;">
                        Implemented
                    </p>
                    <ul class="wjm-rec-list">
                        <li>✓ API key encryption (AES-256-CBC)</li>
                        <li>✓ Comprehensive input sanitization</li>
                        <li>✓ Output escaping for XSS prevention</li>
                        <li>✓ Rate limiting for API calls</li>
                        <li>✓ Enhanced capability checking</li>
                        <li>✓ CSRF protection with nonces</li>
                        <li>✓ File upload validation</li>
                        <li>✓ Security event logging</li>
                    </ul>
                </div>
                <div>
                    <p style="font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--wjm-peach-ink);margin-bottom:0.75rem;">
                        Recommended Next Steps
                    </p>
                    <ul class="wjm-rec-list">
                        <li>→ Enable HTTPS for all admin pages</li>
                        <li>→ Set up regular security log reviews</li>
                        <li>→ Implement API key rotation procedures</li>
                        <li>→ Configure server-level security headers</li>
                        <li>→ Set up automated security monitoring</li>
                        <li>→ Run periodic security audits</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

</div>
