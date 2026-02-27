<?php
/**
 * Rate Limit Dashboard Template
 * 
 * Shows users their current rate limit usage and provides helpful information
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$user_id = get_current_user_id();
$user = get_user_by('id', $user_id);

// Get rate limit information for different actions
$api_info = WJM_Security_Manager::get_rate_limit_info('api_call', $user_id);
$data_info = WJM_Security_Manager::get_rate_limit_info('data_fetch', $user_id);
$upload_info = WJM_Security_Manager::get_rate_limit_info('file_upload', $user_id);
$login_info = WJM_Security_Manager::get_rate_limit_info('login_attempt', $user_id);

// Calculate usage percentages
$api_percentage = ($api_info['current_usage'] / $api_info['limit']) * 100;
$data_percentage = ($data_info['current_usage'] / $data_info['limit']) * 100;
$upload_percentage = ($upload_info['current_usage'] / $upload_info['limit']) * 100;
$login_percentage = ($login_info['current_usage'] / $login_info['limit']) * 100;

// Determine status colors
function get_status_color($percentage) {
    if ($percentage < 50) return 'green';
    if ($percentage < 80) return 'orange';
    return 'red';
}
?>

<div class="wrap">
    <h1>Rate Limit Dashboard</h1>
    <p>Monitor your current usage and limits for different operations.</p>
    
    <!-- User Information -->
    <div class="wjm-user-info">
        <h2>Your Account Information</h2>
        <p><strong>User:</strong> <?php echo esc_html($user->display_name); ?></p>
        <p><strong>Role:</strong> <?php echo esc_html(ucfirst($api_info['user_role'])); ?></p>
        <p><strong>Account Type:</strong> 
            <?php 
            switch($api_info['user_role']) {
                case 'student':
                    echo 'Student (Basic limits)';
                    break;
                case 'researcher':
                    echo 'Researcher (Standard limits)';
                    break;
                case 'editor':
                    echo 'Editor (Enhanced limits)';
                    break;
                case 'administrator':
                    echo 'Administrator (High limits)';
                    break;
                default:
                    echo 'Standard User';
            }
            ?>
        </p>
    </div>
    
    <!-- Rate Limit Cards -->
    <div class="wjm-rate-limit-cards">
        
        <!-- API Calls -->
        <div class="wjm-limit-card">
            <h3>API Calls</h3>
            <div class="wjm-usage-bar">
                <div class="wjm-bar-fill wjm-<?php echo get_status_color($api_percentage); ?>" 
                     style="width: <?php echo min(100, $api_percentage); ?>%"></div>
            </div>
            <div class="wjm-usage-stats">
                <span class="wjm-current"><?php echo esc_html($api_info['current_usage']); ?></span>
                <span class="wjm-separator">/</span>
                <span class="wjm-limit"><?php echo esc_html($api_info['limit']); ?></span>
                <span class="wjm-remaining">(<?php echo esc_html($api_info['remaining']); ?> remaining)</span>
            </div>
            <p class="wjm-time-info">Resets in <?php echo esc_html(round(($api_info['reset_time'] - time()) / 3600, 1)); ?> hours</p>
        </div>
        
        <!-- Data Fetching -->
        <div class="wjm-limit-card">
            <h3>Data Fetching</h3>
            <div class="wjm-usage-bar">
                <div class="wjm-bar-fill wjm-<?php echo get_status_color($data_percentage); ?>" 
                     style="width: <?php echo min(100, $data_percentage); ?>%"></div>
            </div>
            <div class="wjm-usage-stats">
                <span class="wjm-current"><?php echo esc_html($data_info['current_usage']); ?></span>
                <span class="wjm-separator">/</span>
                <span class="wjm-limit"><?php echo esc_html($data_info['limit']); ?></span>
                <span class="wjm-remaining">(<?php echo esc_html($data_info['remaining']); ?> remaining)</span>
            </div>
            <p class="wjm-time-info">Resets in <?php echo esc_html(round(($data_info['reset_time'] - time()) / 3600, 1)); ?> hours</p>
        </div>
        
        <!-- File Uploads -->
        <div class="wjm-limit-card">
            <h3>File Uploads</h3>
            <div class="wjm-usage-bar">
                <div class="wjm-bar-fill wjm-<?php echo get_status_color($upload_percentage); ?>" 
                     style="width: <?php echo min(100, $upload_percentage); ?>%"></div>
            </div>
            <div class="wjm-usage-stats">
                <span class="wjm-current"><?php echo esc_html($upload_info['current_usage']); ?></span>
                <span class="wjm-separator">/</span>
                <span class="wjm-limit"><?php echo esc_html($upload_info['limit']); ?></span>
                <span class="wjm-remaining">(<?php echo esc_html($upload_info['remaining']); ?> remaining)</span>
            </div>
            <p class="wjm-time-info">Resets in <?php echo esc_html(round(($upload_info['reset_time'] - time()) / 86400, 1)); ?> days</p>
        </div>
        
        <!-- Login Attempts -->
        <div class="wjm-limit-card">
            <h3>Login Attempts</h3>
            <div class="wjm-usage-bar">
                <div class="wjm-bar-fill wjm-<?php echo get_status_color($login_percentage); ?>" 
                     style="width: <?php echo min(100, $login_percentage); ?>%"></div>
            </div>
            <div class="wjm-usage-stats">
                <span class="wjm-current"><?php echo esc_html($login_info['current_usage']); ?></span>
                <span class="wjm-separator">/</span>
                <span class="wjm-limit"><?php echo esc_html($login_info['limit']); ?></span>
                <span class="wjm-remaining">(<?php echo esc_html($login_info['remaining']); ?> remaining)</span>
            </div>
            <p class="wjm-time-info">Resets in <?php echo esc_html(round(($login_info['reset_time'] - time()) / 60, 1)); ?> minutes</p>
        </div>
        
    </div>
    
    <!-- Usage Tips -->
    <div class="wjm-usage-tips">
        <h2>Usage Tips</h2>
        
        <div class="wjm-tip">
            <h3>🎯 Optimize Your Usage</h3>
            <ul>
                <li><strong>Batch Operations:</strong> Process multiple papers together to reduce API calls</li>
                <li><strong>Use Caching:</strong> Previously fetched data is cached for 24 hours</li>
                <li><strong>Plan Ahead:</strong> Schedule bulk operations during off-peak hours</li>
                <li><strong>Contact Admin:</strong> Request higher limits for legitimate bulk work</li>
            </ul>
        </div>
        
        <div class="wjm-tip">
            <h3>📊 Understanding Limits</h3>
            <ul>
                <li><strong>API Calls:</strong> External database queries (Scopus, Web of Science, etc.)</li>
                <li><strong>Data Fetching:</strong> Citation and metadata retrieval</li>
                <li><strong>File Uploads:</strong> Manuscript and document uploads</li>
                <li><strong>Login Attempts:</strong> Failed login attempts (security feature)</li>
            </ul>
        </div>
        
        <div class="wjm-tip">
            <h3>🔧 What to Do When Limits Are Reached</h3>
            <ul>
                <li><strong>Wait for Reset:</strong> Limits automatically reset after the time window</li>
                <li><strong>Contact Administrator:</strong> Request temporary limit increases for urgent work</li>
                <li><strong>Use Offline Mode:</strong> Some features work without API calls</li>
                <li><strong>Plan Better:</strong> Spread operations over multiple sessions</li>
            </ul>
        </div>
    </div>
    
    <!-- Contact Information -->
    <div class="wjm-contact-info">
        <h2>Need Higher Limits?</h2>
        <p>If you need higher limits for legitimate academic work, contact your administrator:</p>
        <ul>
            <li><strong>Email:</strong> admin@yourjournal.com</li>
            <li><strong>Include:</strong> Your user ID, reason for request, and expected usage</li>
            <li><strong>Response Time:</strong> Usually within 24 hours</li>
        </ul>
    </div>
    
</div>

<style>
.wjm-user-info {
    background: #f9f9f9;
    padding: 20px;
    border-radius: 5px;
    margin: 20px 0;
}

.wjm-rate-limit-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin: 30px 0;
}

.wjm-limit-card {
    background: #fff;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.wjm-limit-card h3 {
    margin-top: 0;
    color: #0073aa;
    font-size: 1.2em;
}

.wjm-usage-bar {
    width: 100%;
    height: 20px;
    background: #f0f0f0;
    border-radius: 10px;
    overflow: hidden;
    margin: 15px 0;
}

.wjm-bar-fill {
    height: 100%;
    transition: width 0.3s ease;
}

.wjm-bar-fill.wjm-green {
    background: #4CAF50;
}

.wjm-bar-fill.wjm-orange {
    background: #FF9800;
}

.wjm-bar-fill.wjm-red {
    background: #F44336;
}

.wjm-usage-stats {
    text-align: center;
    font-size: 1.1em;
    margin: 10px 0;
}

.wjm-current {
    color: #0073aa;
    font-weight: bold;
}

.wjm-separator {
    color: #666;
    margin: 0 5px;
}

.wjm-limit {
    color: #333;
    font-weight: bold;
}

.wjm-remaining {
    color: #666;
    font-size: 0.9em;
    margin-left: 10px;
}

.wjm-time-info {
    text-align: center;
    color: #666;
    font-size: 0.9em;
    margin: 5px 0 0 0;
}

.wjm-usage-tips {
    margin: 30px 0;
}

.wjm-tip {
    background: #fff;
    border-left: 4px solid #0073aa;
    padding: 15px;
    margin: 15px 0;
    border-radius: 3px;
}

.wjm-tip h3 {
    margin-top: 0;
    color: #0073aa;
}

.wjm-tip ul {
    margin: 10px 0;
}

.wjm-tip li {
    margin: 5px 0;
    line-height: 1.4;
}

.wjm-contact-info {
    background: #e7f3ff;
    border: 1px solid #0073aa;
    border-radius: 5px;
    padding: 20px;
    margin: 20px 0;
}

.wjm-contact-info h2 {
    margin-top: 0;
    color: #0073aa;
}

.wjm-contact-info ul {
    margin: 10px 0;
}

.wjm-contact-info li {
    margin: 5px 0;
}
</style>
