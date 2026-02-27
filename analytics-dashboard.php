<?php
/**
 * Analytics Dashboard
 *
 * @package Wisdom Journal Manager
 */

if (!defined('ABSPATH')) {
    exit;
}

// =============================================
// ADMIN MENU
// =============================================

function wjm_add_analytics_menu() {
    add_menu_page(
        'Analytics', 'Analytics', 'manage_options',
        'wjm-analytics', 'wjm_analytics_dashboard_page',
        'dashicons-chart-bar', 25
    );
    add_submenu_page('wjm-analytics', 'Overview',          'Overview',          'manage_options', 'wjm-analytics',          'wjm_analytics_dashboard_page');
    add_submenu_page('wjm-analytics', 'Paper Analytics',   'Paper Analytics',   'manage_options', 'wjm-paper-analytics',    'wjm_paper_analytics_page');
    add_submenu_page('wjm-analytics', 'Citation Analytics','Citation Analytics','manage_options', 'wjm-citation-analytics', 'wjm_citation_analytics_page');
    add_submenu_page('wjm-analytics', 'Search Analytics',  'Search Analytics',  'manage_options', 'wjm-search-analytics',   'wjm_search_analytics_page');
}
add_action('admin_menu', 'wjm_add_analytics_menu');

// =============================================
// OVERVIEW DASHBOARD
// =============================================

function wjm_analytics_dashboard_page() {
    $metrics_30d     = function_exists('wjm_get_system_metrics')    ? wjm_get_system_metrics(30)        : array('total_views' => 0, 'total_downloads' => 0, 'unique_visitors' => 0);
    $citation_stats  = function_exists('wjm_phase1_get_table_stats') ? wjm_phase1_get_table_stats()      : array();
    $top_viewed      = function_exists('wjm_get_top_papers')         ? wjm_get_top_papers('views', 5, 30)     : array();
    $top_downloaded  = function_exists('wjm_get_top_papers')         ? wjm_get_top_papers('downloads', 5, 30) : array();
    $indexing_stats  = function_exists('wjm_get_indexing_stats')     ? wjm_get_indexing_stats()          : array('total_papers' => 0, 'indexed_papers' => 0, 'coverage_percentage' => 0);
    $total_papers    = wp_count_posts('paper')->publish;
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Analytics</h1>
                <p class="wjm-page-description">Insights across papers, citations, and visitor activity</p>
            </div>
        </div>

        <!-- Summary stats -->
        <div class="wjm-stats-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="wjm-stat-card wjm-stat-card--papers">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Total Papers</div>
                    <div class="wjm-stat-value"><?php echo number_format($total_papers); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--teal">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Views (30 days)</div>
                    <div class="wjm-stat-value"><?php echo number_format($metrics_30d['total_views']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--mint">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Downloads (30 days)</div>
                    <div class="wjm-stat-value"><?php echo number_format($metrics_30d['total_downloads']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--amber">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Total Citations</div>
                    <div class="wjm-stat-value"><?php echo number_format($citation_stats['citations']['total'] ?? 0); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--sky">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Unique Visitors (30d)</div>
                    <div class="wjm-stat-value"><?php echo number_format($metrics_30d['unique_visitors']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--rose">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Search Coverage</div>
                    <div class="wjm-stat-value"><?php echo number_format($indexing_stats['coverage_percentage'], 1); ?>%</div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
        </div>

        <!-- Top papers -->
        <div class="wjm-grid-2">
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-visibility"></span>
                        Top Viewed (30 days)
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <?php if (!empty($top_viewed)) : ?>
                        <table class="wjm-table">
                            <thead><tr><th>Paper</th><th style="text-align:right;width:80px;">Views</th></tr></thead>
                            <tbody>
                                <?php foreach ($top_viewed as $paper) : ?>
                                    <tr>
                                        <td>
                                            <a href="<?php echo esc_url(get_edit_post_link($paper['paper_id'])); ?>" target="_blank">
                                                <?php echo esc_html(wp_trim_words($paper['post_title'], 8)); ?>
                                            </a>
                                        </td>
                                        <td style="text-align:right;">
                                            <strong style="color:var(--wjm-teal-ink)"><?php echo number_format($paper['total']); ?></strong>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <div class="wjm-empty-state"><span class="dashicons dashicons-visibility"></span><p>No data yet.</p></div>
                    <?php endif; ?>
                </div>
            </div>

            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-download"></span>
                        Top Downloaded (30 days)
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <?php if (!empty($top_downloaded)) : ?>
                        <table class="wjm-table">
                            <thead><tr><th>Paper</th><th style="text-align:right;width:100px;">Downloads</th></tr></thead>
                            <tbody>
                                <?php foreach ($top_downloaded as $paper) : ?>
                                    <tr>
                                        <td>
                                            <a href="<?php echo esc_url(get_edit_post_link($paper['paper_id'])); ?>" target="_blank">
                                                <?php echo esc_html(wp_trim_words($paper['post_title'], 8)); ?>
                                            </a>
                                        </td>
                                        <td style="text-align:right;">
                                            <strong style="color:var(--wjm-mint-ink)"><?php echo number_format($paper['total']); ?></strong>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <div class="wjm-empty-state"><span class="dashicons dashicons-download"></span><p>No data yet.</p></div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Citation mini-stats -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-editor-quote"></span>
                    Citation Statistics
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-mini-stat-grid">
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo number_format($citation_stats['citations']['total'] ?? 0); ?></div>
                        <div class="wjm-stat-simple-label">Total Citations</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo number_format($citation_stats['citations']['verified'] ?? 0); ?></div>
                        <div class="wjm-stat-simple-label">Verified</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo number_format($citation_stats['citations']['unverified'] ?? 0); ?></div>
                        <div class="wjm-stat-simple-label">Unverified</div>
                    </div>
                    <div class="wjm-stat-simple">
                        <div class="wjm-stat-simple-value"><?php echo number_format($citation_stats['authors']['with_h_index'] ?? 0); ?></div>
                        <div class="wjm-stat-simple-label">Authors with H-Index</div>
                    </div>
                </div>
            </div>
        </div>

    </div>
    <?php
}

// =============================================
// PAPER ANALYTICS
// =============================================

function wjm_paper_analytics_page() {
    $paper_id = isset($_GET['paper_id']) ? absint($_GET['paper_id']) : 0;
    ?>
    <div class="wrap wjm-modern-wrap">
        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Paper Analytics</h1>
                <p class="wjm-page-description">Detailed metrics for individual papers</p>
            </div>
        </div>

        <?php if ($paper_id) : ?>
            <?php wjm_display_paper_analytics($paper_id); ?>
        <?php else : ?>
            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title"><span class="dashicons dashicons-search"></span> Select a Paper</h2>
                </div>
                <div class="wjm-card-body">
                    <form method="get" style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;">
                        <input type="hidden" name="page" value="wjm-paper-analytics" />
                        <?php
                        wp_dropdown_pages(array(
                            'post_type'         => 'paper',
                            'selected'          => $paper_id,
                            'name'              => 'paper_id',
                            'show_option_none'  => 'Select a paper...',
                            'option_none_value' => '0',
                            'class'             => 'wjm-select',
                        ));
                        ?>
                        <button type="submit" class="wjm-btn wjm-btn-primary">View Analytics</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

function wjm_display_paper_analytics($paper_id) {
    $post = get_post($paper_id);
    if (!$post || $post->post_type !== 'paper') {
        echo '<div class="wjm-alert wjm-alert-error">Invalid paper ID.</div>';
        return;
    }

    $metrics         = function_exists('wjm_get_paper_metrics')    ? wjm_get_paper_metrics($paper_id)          : array('views' => 0, 'downloads' => 0);
    $citation_stats  = function_exists('wjm_get_citation_stats')   ? wjm_get_citation_stats($paper_id)         : array('cited_by_count' => 0, 'citing_count' => 0);
    $unique_visitors = function_exists('wjm_get_unique_visitors')  ? wjm_get_unique_visitors($paper_id, 30)    : 0;
    ?>
    <div class="wjm-card" style="margin-bottom:1rem;">
        <div class="wjm-card-body">
            <div style="font-size:1rem;font-weight:700;color:var(--wjm-text-primary);margin-bottom:0.5rem;">
                <?php echo esc_html($post->post_title); ?>
            </div>
            <div style="display:flex;gap:1rem;flex-wrap:wrap;">
                <a href="<?php echo esc_url(get_edit_post_link($paper_id)); ?>" class="wjm-btn wjm-btn-secondary wjm-btn-sm">Edit Paper</a>
                <a href="<?php echo esc_url(get_permalink($paper_id)); ?>" target="_blank" class="wjm-btn wjm-btn-secondary wjm-btn-sm">View Paper</a>
            </div>
        </div>
    </div>

    <div class="wjm-stats-grid">
        <div class="wjm-stat-card wjm-stat-card--teal">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Total Views</div>
                <div class="wjm-stat-value"><?php echo number_format($metrics['views']); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
        <div class="wjm-stat-card wjm-stat-card--mint">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Total Downloads</div>
                <div class="wjm-stat-value"><?php echo number_format($metrics['downloads']); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
        <div class="wjm-stat-card wjm-stat-card--amber">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Times Cited</div>
                <div class="wjm-stat-value"><?php echo number_format($citation_stats['cited_by_count']); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
        <div class="wjm-stat-card wjm-stat-card--sky">
            <div class="wjm-stat-content">
                <div class="wjm-stat-label">Unique Visitors (30d)</div>
                <div class="wjm-stat-value"><?php echo number_format($unique_visitors); ?></div>
            </div>
            <div class="wjm-stat-bar"></div>
        </div>
    </div>
    <?php
}

// =============================================
// CITATION ANALYTICS
// =============================================

function wjm_citation_analytics_page() {
    global $wpdb;

    $citation_stats = function_exists('wjm_phase1_get_table_stats') ? wjm_phase1_get_table_stats() : array();

    $citation_index_table = $wpdb->prefix . 'wjm_citation_index';
    $posts_table          = $wpdb->prefix . 'posts';

    $most_cited = $wpdb->get_results("
        SELECT ci.paper_id, ci.cited_by_count, p.post_title
        FROM `$citation_index_table` ci
        INNER JOIN `$posts_table` p ON ci.paper_id = p.ID
        WHERE ci.cited_by_count > 0 AND p.post_status = 'publish'
        ORDER BY ci.cited_by_count DESC
        LIMIT 10
    ", ARRAY_A);
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Citation Analytics</h1>
                <p class="wjm-page-description">Citation counts, verification status, and author metrics</p>
            </div>
        </div>

        <div class="wjm-stats-grid">
            <div class="wjm-stat-card wjm-stat-card--amber">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Total Citations</div>
                    <div class="wjm-stat-value"><?php echo number_format($citation_stats['citations']['total'] ?? 0); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--mint">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Verified</div>
                    <div class="wjm-stat-value"><?php echo number_format($citation_stats['citations']['verified'] ?? 0); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--peach">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Unverified</div>
                    <div class="wjm-stat-value"><?php echo number_format($citation_stats['citations']['unverified'] ?? 0); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--sky">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Authors with H-Index</div>
                    <div class="wjm-stat-value"><?php echo number_format($citation_stats['authors']['with_h_index'] ?? 0); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-star-filled"></span>
                    Most Cited Papers
                </h2>
            </div>
            <div class="wjm-card-body">
                <?php if (!empty($most_cited)) : ?>
                    <table class="wjm-table">
                        <thead>
                            <tr>
                                <th style="width:48px;">#</th>
                                <th>Paper Title</th>
                                <th style="text-align:right;width:120px;">Citations</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($most_cited as $i => $paper) : ?>
                                <tr>
                                    <td style="color:var(--wjm-text-muted);font-size:0.75rem;"><?php echo $i + 1; ?></td>
                                    <td>
                                        <a href="<?php echo esc_url(get_edit_post_link($paper['paper_id'])); ?>" target="_blank">
                                            <?php echo esc_html($paper['post_title']); ?>
                                        </a>
                                    </td>
                                    <td style="text-align:right;">
                                        <strong style="color:var(--wjm-amber-ink);"><?php echo number_format($paper['cited_by_count']); ?></strong>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else : ?>
                    <div class="wjm-empty-state">
                        <span class="dashicons dashicons-editor-quote"></span>
                        <p>No citation data available yet.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

    </div>
    <?php
}

// =============================================
// SEARCH ANALYTICS
// =============================================

function wjm_search_analytics_page() {
    $indexing_stats = function_exists('wjm_get_indexing_stats')
        ? wjm_get_indexing_stats()
        : array('total_papers' => 0, 'indexed_papers' => 0, 'coverage_percentage' => 0, 'total_entries' => 0);
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Search Analytics</h1>
                <p class="wjm-page-description">Search index coverage and indexing tools</p>
            </div>
        </div>

        <div class="wjm-stats-grid">
            <div class="wjm-stat-card wjm-stat-card--papers">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Total Papers</div>
                    <div class="wjm-stat-value"><?php echo number_format($indexing_stats['total_papers']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--mint">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Indexed Papers</div>
                    <div class="wjm-stat-value"><?php echo number_format($indexing_stats['indexed_papers']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--teal">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Search Coverage</div>
                    <div class="wjm-stat-value"><?php echo number_format($indexing_stats['coverage_percentage'], 1); ?>%</div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
            <div class="wjm-stat-card wjm-stat-card--sky">
                <div class="wjm-stat-content">
                    <div class="wjm-stat-label">Index Entries</div>
                    <div class="wjm-stat-value"><?php echo number_format($indexing_stats['total_entries']); ?></div>
                </div>
                <div class="wjm-stat-bar"></div>
            </div>
        </div>

        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-admin-tools"></span>
                    Indexing Tools
                </h2>
            </div>
            <div class="wjm-card-body">
                <p style="font-size:0.875rem;color:var(--wjm-text-secondary);margin-bottom:1rem;">
                    Rebuild the full-text search index to improve search accuracy.
                </p>
                <button type="button" id="wjm-bulk-index-btn" class="wjm-btn wjm-btn-primary">
                    <span class="dashicons dashicons-update"></span>
                    Rebuild Search Index
                </button>
                <div id="wjm-indexing-status" style="margin-top:0.875rem;font-size:0.875rem;"></div>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($) {
            $('#wjm-bulk-index-btn').on('click', function() {
                var $btn    = $(this);
                var $status = $('#wjm-indexing-status');
                if (!confirm('This will reindex all published papers. Continue?')) return;
                $btn.prop('disabled', true).html('<span class="dashicons dashicons-update"></span> Indexing…');
                $status.html('<p style="color:var(--wjm-text-muted);">Indexing papers, please wait…</p>');
                $.ajax({
                    url: ajaxurl, type: 'POST',
                    data: { action: 'wjm_bulk_index_papers' },
                    success: function(response) {
                        if (response.success) {
                            $status.html('<p style="color:var(--wjm-success);">Successfully indexed ' + response.data + ' papers.</p>');
                            setTimeout(function() { location.reload(); }, 2000);
                        } else {
                            $status.html('<p style="color:var(--wjm-error);">Error: ' + response.data + '</p>');
                        }
                    },
                    error: function() {
                        $status.html('<p style="color:var(--wjm-error);">Connection error. Please try again.</p>');
                    },
                    complete: function() {
                        $btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Rebuild Search Index');
                    }
                });
            });
        });
        </script>

    </div>
    <?php
}

// =============================================
// AJAX
// =============================================

function wjm_ajax_bulk_index_papers() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
    }
    $count = function_exists('wjm_bulk_index_papers') ? wjm_bulk_index_papers() : 0;
    wp_send_json_success($count);
}
add_action('wp_ajax_wjm_bulk_index_papers', 'wjm_ajax_bulk_index_papers');
