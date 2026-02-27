<?php
global $wpdb;
/**
 * Dashboard Template — Wisdom Journal Manager
 */

if (!defined('ABSPATH')) {
    exit;
}

// Counts
$total_journals = wp_count_posts('journal')->publish;
$total_issues   = wp_count_posts('journal_issue')->publish;
$total_papers   = wp_count_posts('paper')->publish;
$table_name     = esc_sql($wpdb->prefix . 'sjm_authors');
$total_authors  = $wpdb->get_var("SELECT COUNT(*) FROM `{$table_name}`");

// Recent papers
$recent_papers = get_posts(array(
    'post_type'      => 'paper',
    'posts_per_page' => 6,
    'post_status'    => 'publish',
    'orderby'        => 'date',
    'order'          => 'DESC',
));

// Open access stats
$open_access_journals = get_posts(array(
    'post_type'      => 'journal',
    'posts_per_page' => -1,
    'meta_query'     => array(
        array('key' => '_sjm_open_access', 'value' => '1'),
    ),
));

$open_access_papers = get_posts(array(
    'post_type'      => 'paper',
    'posts_per_page' => -1,
    'meta_query'     => array(
        array('key' => '_sjm_paper_open_access', 'value' => '1'),
    ),
));
?>
<div class="wrap wjm-modern-wrap">

    <!-- Page header -->
    <div class="wjm-page-header">
        <div>
            <h1 class="wjm-page-title">Journal Dashboard</h1>
            <p class="wjm-page-description">Overview of your academic publishing system</p>
        </div>
    </div>

    <!-- Stat cards -->
    <div class="wjm-stats-grid">

        <div class="wjm-stat-card wjm-stat-card--journals">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Journals</div>
                <div class="wjm-stat-value"><?php echo esc_html($total_journals); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>

        <div class="wjm-stat-card wjm-stat-card--issues">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Issues</div>
                <div class="wjm-stat-value"><?php echo esc_html($total_issues); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>

        <div class="wjm-stat-card wjm-stat-card--papers">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Papers</div>
                <div class="wjm-stat-value"><?php echo esc_html($total_papers); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>

        <div class="wjm-stat-card wjm-stat-card--authors">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Authors</div>
                <div class="wjm-stat-value"><?php echo esc_html($total_authors); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>

    </div><!-- /.wjm-stats-grid -->

    <!-- Recent papers + Quick actions -->
    <div class="wjm-grid-2">

        <!-- Recent Papers -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-media-document"></span>
                    Recent Papers
                </h2>
            </div>
            <div class="wjm-card-body">
                <?php if (!empty($recent_papers)) : ?>
                    <div class="wjm-list">
                        <?php foreach ($recent_papers as $paper) : ?>
                            <div class="wjm-list-item">
                                <div class="wjm-list-item-dot"></div>
                                <div class="wjm-list-item-content">
                                    <div class="wjm-list-item-title">
                                        <a href="<?php echo esc_url(get_edit_post_link($paper->ID)); ?>">
                                            <?php echo esc_html($paper->post_title); ?>
                                        </a>
                                    </div>
                                    <div class="wjm-list-item-meta">
                                        <?php echo esc_html(date('M j, Y', strtotime($paper->post_date))); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else : ?>
                    <div class="wjm-empty-state">
                        <span class="dashicons dashicons-media-document"></span>
                        <p>No papers published yet</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-admin-tools"></span>
                    Quick Actions
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-action-grid">
                    <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal')); ?>" class="wjm-action-btn wjm-action-btn--primary">
                        <span class="dashicons dashicons-plus"></span> Add Journal
                    </a>
                    <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal_issue')); ?>" class="wjm-action-btn wjm-action-btn--primary">
                        <span class="dashicons dashicons-plus"></span> Add Issue
                    </a>
                    <a href="<?php echo esc_url(admin_url('post-new.php?post_type=paper')); ?>" class="wjm-action-btn wjm-action-btn--primary">
                        <span class="dashicons dashicons-plus"></span> Add Paper
                    </a>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=sjm-authors')); ?>" class="wjm-action-btn wjm-action-btn--secondary">
                        <span class="dashicons dashicons-groups"></span> Manage Authors
                    </a>
                    <a href="<?php echo esc_url(admin_url('edit.php?post_type=journal&page=wjm-backup')); ?>" class="wjm-action-btn wjm-action-btn--secondary">
                        <span class="dashicons dashicons-backup"></span> Backup &amp; Restore
                    </a>
                    <a href="<?php echo esc_url(admin_url('edit.php?post_type=journal&page=wjm-audit-log')); ?>" class="wjm-action-btn wjm-action-btn--secondary">
                        <span class="dashicons dashicons-list-view"></span> Audit Log
                    </a>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=sjm-import-export')); ?>" class="wjm-action-btn wjm-action-btn--secondary">
                        <span class="dashicons dashicons-upload"></span> Import / Export
                    </a>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=sjm-plugin-guide')); ?>" class="wjm-action-btn wjm-action-btn--secondary">
                        <span class="dashicons dashicons-book-alt"></span> Plugin Guide
                    </a>
                </div>
            </div>
        </div>

    </div><!-- /.wjm-grid-2 -->

    <!-- Open Access Statistics -->
    <div class="wjm-card">
        <div class="wjm-card-header">
            <h2 class="wjm-card-title">
                <span class="dashicons dashicons-unlock"></span>
                Open Access Statistics
            </h2>
        </div>
        <div class="wjm-card-body">
            <div class="wjm-stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">

                <div class="wjm-stat-simple">
                    <div class="wjm-stat-simple-value"><?php echo esc_html(count($open_access_journals)); ?></div>
                    <div class="wjm-stat-simple-label">Open Access Journals</div>
                    <div class="wjm-stat-simple-percentage">
                        <?php echo $total_journals > 0 ? esc_html(round(count($open_access_journals) / $total_journals * 100, 1)) : '0'; ?>% of total
                    </div>
                </div>

                <div class="wjm-stat-simple">
                    <div class="wjm-stat-simple-value"><?php echo esc_html(count($open_access_papers)); ?></div>
                    <div class="wjm-stat-simple-label">Open Access Papers</div>
                    <div class="wjm-stat-simple-percentage">
                        <?php echo $total_papers > 0 ? esc_html(round(count($open_access_papers) / $total_papers * 100, 1)) : '0'; ?>% of total
                    </div>
                </div>

            </div>
        </div>
    </div>

</div><!-- /.wjm-modern-wrap -->
