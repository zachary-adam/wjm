<?php
/**
 * Rate Limit Dashboard Template — Wisdom Journal Manager
 */

if (!defined('ABSPATH')) {
    exit;
}

$user_id = get_current_user_id();
$user    = get_user_by('id', $user_id);

$api_info    = WJM_Security_Manager::get_rate_limit_info('api_call',       $user_id);
$data_info   = WJM_Security_Manager::get_rate_limit_info('data_fetch',     $user_id);
$upload_info = WJM_Security_Manager::get_rate_limit_info('file_upload',    $user_id);
$login_info  = WJM_Security_Manager::get_rate_limit_info('login_attempt',  $user_id);

$api_pct    = min(100, ($api_info['current_usage']    / max(1, $api_info['limit']))    * 100);
$data_pct   = min(100, ($data_info['current_usage']   / max(1, $data_info['limit']))   * 100);
$upload_pct = min(100, ($upload_info['current_usage'] / max(1, $upload_info['limit'])) * 100);
$login_pct  = min(100, ($login_info['current_usage']  / max(1, $login_info['limit']))  * 100);

function wjm_rl_color($pct) {
    if ($pct < 50) return 'green';
    if ($pct < 80) return 'orange';
    return 'red';
}

$role_label = array(
    'student'       => 'Student (Basic)',
    'researcher'    => 'Researcher (Standard)',
    'editor'        => 'Editor (Enhanced)',
    'administrator' => 'Administrator (High)',
);
$role_display = $role_label[$api_info['user_role']] ?? 'Standard User';

// Build initials for avatar
$initials = '';
if ($user) {
    $parts = explode(' ', trim($user->display_name));
    foreach (array_slice($parts, 0, 2) as $p) {
        $initials .= strtoupper(mb_substr($p, 0, 1));
    }
}
?>

<div class="wrap wjm-modern-wrap">

    <div class="wjm-page-header">
        <div>
            <h1 class="wjm-page-title">Rate Limits</h1>
            <p class="wjm-page-description">Current usage and limits for your account</p>
        </div>
    </div>

    <!-- User info -->
    <div class="wjm-user-info-card">
        <div class="wjm-user-avatar"><?php echo esc_html($initials ?: '?'); ?></div>
        <div>
            <div class="wjm-user-name"><?php echo esc_html($user ? $user->display_name : '—'); ?></div>
            <div class="wjm-user-role-text"><?php echo esc_html($user ? $user->user_email : ''); ?></div>
        </div>
        <div class="wjm-role-badge"><?php echo esc_html($role_display); ?></div>
    </div>

    <!-- Limit cards -->
    <div class="wjm-grid-2">

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">API Calls</h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-usage-numbers">
                    <span class="wjm-usage-current"><?php echo esc_html($api_info['current_usage']); ?></span>
                    <span class="wjm-usage-divider">/</span>
                    <span class="wjm-usage-total"><?php echo esc_html($api_info['limit']); ?></span>
                </div>
                <div class="wjm-usage-bar">
                    <div class="wjm-bar-fill wjm-<?php echo wjm_rl_color($api_pct); ?>"
                         style="width:<?php echo $api_pct; ?>%"></div>
                </div>
                <div class="wjm-usage-remaining"><?php echo esc_html($api_info['remaining']); ?> remaining</div>
                <div class="wjm-reset-time">Resets in <?php echo esc_html(round(($api_info['reset_time'] - time()) / 3600, 1)); ?> hrs</div>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">Data Fetching</h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-usage-numbers">
                    <span class="wjm-usage-current"><?php echo esc_html($data_info['current_usage']); ?></span>
                    <span class="wjm-usage-divider">/</span>
                    <span class="wjm-usage-total"><?php echo esc_html($data_info['limit']); ?></span>
                </div>
                <div class="wjm-usage-bar">
                    <div class="wjm-bar-fill wjm-<?php echo wjm_rl_color($data_pct); ?>"
                         style="width:<?php echo $data_pct; ?>%"></div>
                </div>
                <div class="wjm-usage-remaining"><?php echo esc_html($data_info['remaining']); ?> remaining</div>
                <div class="wjm-reset-time">Resets in <?php echo esc_html(round(($data_info['reset_time'] - time()) / 3600, 1)); ?> hrs</div>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">File Uploads</h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-usage-numbers">
                    <span class="wjm-usage-current"><?php echo esc_html($upload_info['current_usage']); ?></span>
                    <span class="wjm-usage-divider">/</span>
                    <span class="wjm-usage-total"><?php echo esc_html($upload_info['limit']); ?></span>
                </div>
                <div class="wjm-usage-bar">
                    <div class="wjm-bar-fill wjm-<?php echo wjm_rl_color($upload_pct); ?>"
                         style="width:<?php echo $upload_pct; ?>%"></div>
                </div>
                <div class="wjm-usage-remaining"><?php echo esc_html($upload_info['remaining']); ?> remaining</div>
                <div class="wjm-reset-time">Resets in <?php echo esc_html(round(($upload_info['reset_time'] - time()) / 86400, 1)); ?> days</div>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">Login Attempts</h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-usage-numbers">
                    <span class="wjm-usage-current"><?php echo esc_html($login_info['current_usage']); ?></span>
                    <span class="wjm-usage-divider">/</span>
                    <span class="wjm-usage-total"><?php echo esc_html($login_info['limit']); ?></span>
                </div>
                <div class="wjm-usage-bar">
                    <div class="wjm-bar-fill wjm-<?php echo wjm_rl_color($login_pct); ?>"
                         style="width:<?php echo $login_pct; ?>%"></div>
                </div>
                <div class="wjm-usage-remaining"><?php echo esc_html($login_info['remaining']); ?> remaining</div>
                <div class="wjm-reset-time">Resets in <?php echo esc_html(round(($login_info['reset_time'] - time()) / 60, 1)); ?> mins</div>
            </div>
        </div>

    </div>

    <!-- Tips -->
    <div class="wjm-card">
        <div class="wjm-card-header">
            <h2 class="wjm-card-title">
                <span class="dashicons dashicons-lightbulb"></span>
                Usage Tips
            </h2>
        </div>
        <div class="wjm-card-body">
            <div class="wjm-tip-grid">
                <div>
                    <p class="wjm-tip-title">Optimize Your Usage</p>
                    <ul class="wjm-tip-list">
                        <li><strong>Batch Operations:</strong> Process multiple papers together to reduce API calls</li>
                        <li><strong>Use Caching:</strong> Previously fetched data is cached for 24 hours</li>
                        <li><strong>Plan Ahead:</strong> Schedule bulk operations during off-peak hours</li>
                        <li><strong>Contact Admin:</strong> Request higher limits for legitimate bulk work</li>
                    </ul>
                </div>
                <div>
                    <p class="wjm-tip-title">Understanding Limits</p>
                    <ul class="wjm-tip-list">
                        <li><strong>API Calls:</strong> External database queries (Scopus, Web of Science, etc.)</li>
                        <li><strong>Data Fetching:</strong> Citation and metadata retrieval</li>
                        <li><strong>File Uploads:</strong> Manuscript and document uploads</li>
                        <li><strong>Login Attempts:</strong> Failed login attempts (security feature)</li>
                    </ul>
                </div>
                <div>
                    <p class="wjm-tip-title">When Limits Are Reached</p>
                    <ul class="wjm-tip-list">
                        <li><strong>Wait for Reset:</strong> Limits automatically reset after the time window</li>
                        <li><strong>Contact Administrator:</strong> Request temporary increases for urgent work</li>
                        <li><strong>Use Offline Mode:</strong> Some features work without API calls</li>
                        <li><strong>Plan Better:</strong> Spread operations over multiple sessions</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- Contact -->
    <div class="wjm-contact-card">
        <p class="wjm-contact-card-title">Need Higher Limits?</p>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);margin-bottom:0.75rem;">
            Contact your administrator for legitimate academic work requiring higher quotas.
        </p>
        <ul class="wjm-contact-list">
            <li><strong>Email:</strong> admin@yourjournal.com</li>
            <li><strong>Include:</strong> Your user ID, reason for request, and expected usage</li>
            <li><strong>Response Time:</strong> Usually within 24 hours</li>
        </ul>
    </div>

</div>
