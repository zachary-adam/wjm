<?php
global $wpdb;
/**
 * Modern Dashboard Template for Simple Journal Manager
 * Next.js inspired design with comprehensive stats and tutorials
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get dashboard data
$total_journals = wp_count_posts('journal')->publish;
$total_issues = wp_count_posts('journal_issue')->publish;
$total_papers = wp_count_posts('paper')->publish;
$total_authors = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}sjm_authors");

// Get recent activity
$recent_papers = get_posts(array(
    'post_type' => 'paper',
    'posts_per_page' => 5,
    'post_status' => 'publish',
    'orderby' => 'date',
    'order' => 'DESC'
));

// Get open access stats
$open_access_journals = get_posts(array(
    'post_type' => 'journal',
    'posts_per_page' => -1,
    'meta_query' => array(
        array('key' => '_sjm_open_access', 'value' => '1')
    )
));

$open_access_papers = get_posts(array(
    'post_type' => 'paper',
    'posts_per_page' => -1,
    'meta_query' => array(
        array('key' => '_sjm_paper_open_access', 'value' => '1')
    )
));

// Get monthly stats for chart
$current_month = gmdate('Y-m');
$monthly_stats = array();
for ($i = 11; $i >= 0; $i--) {
    $date = gmdate('Y-m', strtotime("-$i months"));
    $monthly_stats[$date] = array(
        'journals' => 0,
        'issues' => 0,
        'papers' => 0
    );
}

// Calculate monthly stats
$all_papers = get_posts(array(
    'post_type' => 'paper',
    'posts_per_page' => -1,
    'post_status' => 'publish'
));

foreach ($all_papers as $paper) {
    $paper_date = gmdate('Y-m', strtotime($paper->post_date));
    if (isset($monthly_stats[$paper_date])) {
        $monthly_stats[$paper_date]['papers']++;
    }
}

$all_issues = get_posts(array(
    'post_type' => 'journal_issue',
    'posts_per_page' => -1,
    'post_status' => 'publish'
));

foreach ($all_issues as $issue) {
    $issue_date = gmdate('Y-m', strtotime($issue->post_date));
    if (isset($monthly_stats[$issue_date])) {
        $monthly_stats[$issue_date]['issues']++;
    }
}

$all_journals = get_posts(array(
    'post_type' => 'journal',
    'posts_per_page' => -1,
    'post_status' => 'publish'
));

foreach ($all_journals as $journal) {
    $journal_date = gmdate('Y-m', strtotime($journal->post_date));
    if (isset($monthly_stats[$journal_date])) {
        $monthly_stats[$journal_date]['journals']++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Journal Dashboard</title>
    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #f8f9fa;
            color: #222;
            margin: 0;
        }
        .dashboard-container {
            max-width: 1100px;
            margin: 40px auto;
            padding: 0 24px;
        }
        .dashboard-title {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: #111;
        }
        .dashboard-desc {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 32px;
        }
        .stats-row {
            display: flex;
            gap: 24px;
            margin-bottom: 40px;
        }
        .stat-box {
            flex: 1;
            background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            padding: 32px 0 24px 0;
            text-align: center;
        }
        .stat-number {
            font-size: 2.1rem;
            font-weight: 600;
            color: #2563eb;
            margin-bottom: 6px;
        }
        .stat-label {
            color: #444;
            font-size: 1rem;
            letter-spacing: 0.5px;
        }
        .section {
            background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            margin-bottom: 32px;
            padding: 32px 28px;
        }
        .section-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 18px;
            color: #222;
        }
        .activity-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .activity-item {
            padding: 12px 0;
            border-bottom: 1px solid #f1f1f1;
        }
        .activity-item:last-child {
            border-bottom: none;
        }
        .quick-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 10px;
        }
        .quick-action {
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 10px 18px;
            font-size: 1rem;
            font-weight: 500;
            text-decoration: none;
            transition: background 0.2s;
        }
        .quick-action:hover {
            background: #1746a2;
        }
        @media (max-width: 900px) {
            .stats-row { flex-direction: column; gap: 16px; }
        }
    </style>
</head>
<body>
<div class="dashboard-container">
    <div class="dashboard-title">Journal Dashboard</div>
    <div class="dashboard-desc">Minimal, modern overview of your academic publishing system.</div>
    <div class="stats-row">
        <div class="stat-box">
            <div class="stat-number"><?php echo esc_html($total_journals); ?></div>
            <div class="stat-label">Journals</div>
        </div>
        <div class="stat-box">
            <div class="stat-number"><?php echo esc_html($total_issues); ?></div>
            <div class="stat-label">Issues</div>
        </div>
        <div class="stat-box">
            <div class="stat-number"><?php echo esc_html($total_papers); ?></div>
            <div class="stat-label">Papers</div>
        </div>
        <div class="stat-box">
            <div class="stat-number"><?php echo esc_html($total_authors); ?></div>
            <div class="stat-label">Authors</div>
        </div>
    </div>
    <div class="section">
        <div class="section-title">Recent Papers</div>
        <ul class="activity-list">
            <?php foreach ($recent_papers as $paper): ?>
                <li class="activity-item">
                    <strong><?php echo esc_html($paper->post_title); ?></strong>
                    <span style="color:#888; font-size:0.97em;"> &mdash; <?php echo esc_html(date('M j, Y', strtotime($paper->post_date))); ?></span>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
    <div class="section">
        <div class="section-title">Quick Actions</div>
        <div class="quick-actions">
            <a id="sjm-add-journal" href="<?php echo esc_url(admin_url('post-new.php?post_type=journal')); ?>" class="quick-action">Add Journal</a>
            <a id="sjm-add-issue" href="<?php echo esc_url(admin_url('post-new.php?post_type=journal_issue')); ?>" class="quick-action">Add Issue</a>
            <a id="sjm-add-paper" href="<?php echo esc_url(admin_url('post-new.php?post_type=paper')); ?>" class="quick-action">Add Paper</a>
            <a id="sjm-manage-authors" href="<?php echo esc_url(admin_url('admin.php?page=sjm-authors')); ?>" class="quick-action">Manage Authors</a>
            <a id="sjm-import-export" href="<?php echo esc_url(admin_url('admin.php?page=sjm-import-export')); ?>" class="quick-action">Import/Export</a>
            <a id="sjm-email-settings" href="<?php echo esc_url(admin_url('admin.php?page=sjm-email-settings')); ?>" class="quick-action">Email Settings</a>
            <a id="sjm-plugin-guide" href="<?php echo esc_url(admin_url('admin.php?page=sjm-plugin-guide')); ?>" class="quick-action">Plugin Guide</a>
        </div>
    </div>
</div>
</body>
</html> 