<?php
/**
 * Integration Fixes & Enhancements
 * Ensures all systems work together seamlessly
 *
 * @package Wisdom Journal Manager
 * @version 2.5.1
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// AUTO-TRIGGER INTEGRATIONS
// ========================================

/**
 * When a paper is published, auto-index for search
 */
function wjm_auto_index_on_publish($new_status, $old_status, $post) {
    if ($post->post_type !== 'paper') {
        return;
    }

    if ($new_status === 'publish' && $old_status !== 'publish') {
        if (function_exists('wjm_index_paper')) {
            wjm_index_paper($post->ID);
        }
    }
}
add_action('transition_post_status', 'wjm_auto_index_on_publish', 10, 3);

/**
 * When a paper with co-authors is saved, update author metrics
 */
function wjm_auto_update_author_metrics_on_save($post_id, $post, $update) {
    if ($post->post_type !== 'paper' || $post->post_status !== 'publish') {
        return;
    }

    // Get co-authors
    if (function_exists('wjm_get_coauthors')) {
        $coauthors = wjm_get_coauthors($post_id);

        foreach ($coauthors as $coauthor) {
            if ($coauthor['type'] === 'author_profile' && !empty($coauthor['id'])) {
                if (function_exists('wjm_calculate_author_metrics')) {
                    // Schedule for later to avoid slowing down save
                    wp_schedule_single_event(time() + 60, 'wjm_recalc_author_metrics', array($coauthor['id']));
                }
            }
        }
    }
}
add_action('save_post', 'wjm_auto_update_author_metrics_on_save', 20, 3);

/**
 * Scheduled event to recalculate author metrics
 */
function wjm_scheduled_recalc_author_metrics($author_id) {
    if (function_exists('wjm_calculate_author_metrics')) {
        wjm_calculate_author_metrics($author_id);
    }
}
add_action('wjm_recalc_author_metrics', 'wjm_scheduled_recalc_author_metrics');

/**
 * When DOI is added to a paper, offer to fetch Altmetric data
 */
function wjm_suggest_altmetric_fetch($post_id, $post, $update) {
    if ($post->post_type !== 'paper' || !$update) {
        return;
    }

    $doi = get_post_meta($post_id, 'doi', true);
    $has_altmetric = get_post_meta($post_id, '_altmetric_score', true);

    // If DOI exists but no altmetric data, add admin notice
    if ($doi && !$has_altmetric) {
        set_transient('wjm_suggest_altmetric_' . $post_id, true, 3600);
    }
}
add_action('save_post', 'wjm_suggest_altmetric_fetch', 25, 3);

/**
 * Display admin notice for altmetric suggestion
 */
function wjm_altmetric_suggestion_notice() {
    global $post;

    if (!$post || $post->post_type !== 'paper') {
        return;
    }

    if (get_transient('wjm_suggest_altmetric_' . $post->ID)) {
        echo '<div class="notice notice-info is-dismissible">';
        echo '<p><strong>Tip:</strong> This paper has a DOI. You can fetch Altmetric data in the <strong>Advanced Metrics</strong> meta box to track social media impact!</p>';
        echo '</div>';

        delete_transient('wjm_suggest_altmetric_' . $post->ID);
    }
}
add_action('admin_notices', 'wjm_altmetric_suggestion_notice');

// ========================================
// CROSS-SYSTEM DATA SYNC
// ========================================

/**
 * Sync citation counts across systems
 */
function wjm_sync_citation_counts($paper_id) {
    if (!function_exists('wjm_get_citation_stats') || !function_exists('wjm_calculate_impact_score')) {
        return;
    }

    // Get citation stats
    $citation_stats = wjm_get_citation_stats($paper_id);

    // Store citation count in post meta for quick access
    update_post_meta($paper_id, '_citation_count', $citation_stats['cited_by_count']);

    // Recalculate impact score since citations changed
    wjm_calculate_impact_score($paper_id);
}

/**
 * Hook into citation updates to sync counts
 */
add_action('wjm_citation_added', 'wjm_sync_citation_counts');
add_action('wjm_citation_deleted', 'wjm_sync_citation_counts');
add_action('wjm_citation_verified', 'wjm_sync_citation_counts');

// ========================================
// BULK OPERATIONS SAFETY
// ========================================

/**
 * Add bulk action to recalculate metrics for selected papers
 */
function wjm_add_bulk_actions($bulk_actions) {
    $bulk_actions['wjm_recalc_metrics'] = 'Recalculate Metrics';
    $bulk_actions['wjm_reindex_papers'] = 'Reindex for Search';
    return $bulk_actions;
}
add_filter('bulk_actions-edit-paper', 'wjm_add_bulk_actions');

/**
 * Handle bulk actions
 */
function wjm_handle_bulk_actions($redirect_to, $action, $post_ids) {
    if ($action === 'wjm_recalc_metrics') {
        foreach ($post_ids as $post_id) {
            // Recalculate impact score
            if (function_exists('wjm_calculate_impact_score')) {
                wjm_calculate_impact_score($post_id);
            }

            // Update citation counters
            if (function_exists('wjm_update_citation_counters')) {
                wjm_update_citation_counters($post_id);
            }
        }

        $redirect_to = add_query_arg('wjm_metrics_recalculated', count($post_ids), $redirect_to);
    } elseif ($action === 'wjm_reindex_papers') {
        foreach ($post_ids as $post_id) {
            if (function_exists('wjm_index_paper')) {
                wjm_index_paper($post_id);
            }
        }

        $redirect_to = add_query_arg('wjm_papers_reindexed', count($post_ids), $redirect_to);
    }

    return $redirect_to;
}
add_filter('handle_bulk_actions-edit-paper', 'wjm_handle_bulk_actions', 10, 3);

/**
 * Show admin notice after bulk actions
 */
function wjm_bulk_action_notices() {
    if (!empty($_REQUEST['wjm_metrics_recalculated'])) {
        $count = intval($_REQUEST['wjm_metrics_recalculated']);
        echo '<div class="notice notice-success is-dismissible">';
        echo '<p>' . sprintf('Metrics recalculated for %d paper(s).', $count) . '</p>';
        echo '</div>';
    }

    if (!empty($_REQUEST['wjm_papers_reindexed'])) {
        $count = intval($_REQUEST['wjm_papers_reindexed']);
        echo '<div class="notice notice-success is-dismissible">';
        echo '<p>' . sprintf('%d paper(s) reindexed for search.', $count) . '</p>';
        echo '</div>';
    }
}
add_action('admin_notices', 'wjm_bulk_action_notices');

// ========================================
// DATA VALIDATION & CLEANUP
// ========================================

/**
 * Validate and clean citation data
 */
function wjm_validate_citation_data($citation_data) {
    // Ensure at least one identifier exists
    if (empty($citation_data['cited_paper_id']) && empty($citation_data['cited_doi'])) {
        return new WP_Error('missing_identifier', 'Citation must have either paper ID or DOI');
    }

    // Validate DOI format if provided
    if (!empty($citation_data['cited_doi'])) {
        if (function_exists('wjm_validate_doi')) {
            $doi_check = wjm_validate_doi($citation_data['cited_doi']);
            if (is_array($doi_check) ? !$doi_check['valid'] : !$doi_check) {
                return new WP_Error('invalid_doi', 'Invalid DOI format');
            }
        }
    }

    return true;
}

/**
 * Validate ORCID format (only if not already defined in main plugin)
 */
if (!function_exists('wjm_validate_orcid')) {
    function wjm_validate_orcid($orcid) {
        // Clean ORCID
        $orcid = preg_replace('#^https?://orcid\.org/#i', '', trim($orcid));

        // ORCID format: 0000-0000-0000-000X (last digit can be X)
        if (!preg_match('/^\d{4}-\d{4}-\d{4}-\d{3}[0-9X]$/', $orcid)) {
            return false;
        }

        // Validate checksum (MOD 11-2)
        $orcid_digits = str_replace('-', '', $orcid);
        $total = 0;

        for ($i = 0; $i < 15; $i++) {
            $digit = ($orcid_digits[$i] === 'X') ? 10 : intval($orcid_digits[$i]);
            $total = ($total + $digit) * 2;
        }

        $remainder = $total % 11;
        $check_digit = (12 - $remainder) % 11;
        $check_char = ($check_digit === 10) ? 'X' : strval($check_digit);

        $last_char = substr($orcid_digits, -1);

        return $last_char === $check_char;
    }
}

// ========================================
// PERFORMANCE OPTIMIZATIONS
// ========================================

/**
 * Cache frequently accessed data
 */
function wjm_get_cached_citation_stats($paper_id) {
    $cache_key = 'wjm_citation_stats_' . $paper_id;
    $cached = wp_cache_get($cache_key);

    if ($cached !== false) {
        return $cached;
    }

    if (function_exists('wjm_get_citation_stats')) {
        $stats = wjm_get_citation_stats($paper_id);
        wp_cache_set($cache_key, $stats, '', 3600); // Cache for 1 hour
        return $stats;
    }

    return array('cited_by_count' => 0, 'citing_count' => 0);
}

/**
 * Clear citation cache when updated
 */
function wjm_clear_citation_cache($paper_id) {
    wp_cache_delete('wjm_citation_stats_' . $paper_id);
}
add_action('wjm_citation_updated', 'wjm_clear_citation_cache');

// ========================================
// ERROR HANDLING & LOGGING
// ========================================

/**
 * Log integration errors for debugging
 */
function wjm_log_integration_error($context, $error_message) {
    if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
        error_log(sprintf('[WJM Integration Error] Context: %s | Error: %s', $context, $error_message));
    }
}

/**
 * Safe function caller with error handling
 */
function wjm_safe_call($function_name, $args = array(), $default = null) {
    if (!function_exists($function_name)) {
        wjm_log_integration_error('safe_call', "Function $function_name does not exist");
        return $default;
    }

    try {
        return call_user_func_array($function_name, $args);
    } catch (Exception $e) {
        wjm_log_integration_error('safe_call', "Error calling $function_name: " . $e->getMessage());
        return $default;
    }
}

// ========================================
// ADMIN COLUMNS ENHANCEMENTS
// ========================================

/**
 * Add custom columns to paper list
 */
function wjm_paper_custom_columns($columns) {
    $new_columns = array();

    foreach ($columns as $key => $value) {
        $new_columns[$key] = $value;

        if ($key === 'title') {
            $new_columns['citations'] = 'Citations';
            $new_columns['views'] = 'Views';
            $new_columns['impact_score'] = 'Impact';
        }
    }

    return $new_columns;
}
add_filter('manage_paper_posts_columns', 'wjm_paper_custom_columns');

/**
 * Populate custom columns
 */
function wjm_paper_custom_columns_content($column, $post_id) {
    switch ($column) {
        case 'citations':
            if (function_exists('wjm_get_citation_stats')) {
                $stats = wjm_get_citation_stats($post_id);
                echo '<strong>' . number_format($stats['cited_by_count']) . '</strong>';
            } else {
                echo '-';
            }
            break;

        case 'views':
            if (function_exists('wjm_get_paper_metrics')) {
                $metrics = wjm_get_paper_metrics($post_id);
                echo number_format($metrics['views']);
            } else {
                echo '-';
            }
            break;

        case 'impact_score':
            if (function_exists('wjm_get_impact_score')) {
                $score = wjm_get_impact_score($post_id);
                $color = $score > 50 ? '#00a32a' : ($score > 20 ? '#dba617' : '#646970');
                echo '<span style="color: ' . $color . '; font-weight: bold;">' . number_format($score, 1) . '</span>';
            } else {
                echo '-';
            }
            break;
    }
}
add_action('manage_paper_posts_custom_column', 'wjm_paper_custom_columns_content', 10, 2);

/**
 * Make custom columns sortable
 */
function wjm_paper_sortable_columns($columns) {
    $columns['citations'] = 'citations';
    $columns['views'] = 'views';
    $columns['impact_score'] = 'impact_score';
    return $columns;
}
add_filter('manage_edit-paper_sortable_columns', 'wjm_paper_sortable_columns');

// ========================================
// CLEANUP ON PLUGIN DEACTIVATION
// ========================================

/**
 * Clean up transients and caches
 */
function wjm_cleanup_on_deactivation() {
    // Clear all transients
    global $wpdb;

    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wjm_%' OR option_name LIKE '_transient_timeout_wjm_%'");

    // Clear object cache
    wp_cache_flush();

    // Clear scheduled events
    $timestamp = wp_next_scheduled('wjm_recalc_author_metrics');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'wjm_recalc_author_metrics');
    }
}
register_deactivation_hook(WJM_PLUGIN_FILE, 'wjm_cleanup_on_deactivation');

// ========================================
// COMPATIBILITY CHECKS
// ========================================

/**
 * Check WordPress version compatibility
 */
function wjm_check_wp_version() {
    global $wp_version;

    if (version_compare($wp_version, '5.0', '<')) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-error">';
            echo '<p><strong>Wisdom Journal Manager:</strong> Requires WordPress 5.0 or higher. Please update WordPress.</p>';
            echo '</div>';
        });

        return false;
    }

    return true;
}
add_action('admin_init', 'wjm_check_wp_version');

/**
 * Check PHP version compatibility
 */
function wjm_check_php_version() {
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-error">';
            echo '<p><strong>Wisdom Journal Manager:</strong> Requires PHP 7.4 or higher. Current version: ' . PHP_VERSION . '</p>';
            echo '</div>';
        });

        return false;
    }

    return true;
}
add_action('admin_init', 'wjm_check_php_version');

/**
 * Check required PHP extensions
 */
function wjm_check_php_extensions() {
    $required_extensions = array('curl', 'json', 'mbstring');
    $missing = array();

    foreach ($required_extensions as $ext) {
        if (!extension_loaded($ext)) {
            $missing[] = $ext;
        }
    }

    if (!empty($missing)) {
        add_action('admin_notices', function() use ($missing) {
            echo '<div class="notice notice-warning">';
            echo '<p><strong>Wisdom Journal Manager:</strong> Missing PHP extensions: ' . implode(', ', $missing) . '. Some features may not work correctly.</p>';
            echo '</div>';
        });

        return false;
    }

    return true;
}
add_action('admin_init', 'wjm_check_php_extensions');

// ========================================
// HELPER FUNCTIONS
// ========================================

/**
 * Get paper by DOI
 */
function wjm_get_paper_by_doi($doi) {
    $papers = get_posts(array(
        'post_type' => 'paper',
        'post_status' => 'any',
        'posts_per_page' => 1,
        'meta_key' => 'doi',
        'meta_value' => $doi,
        'fields' => 'ids'
    ));

    return !empty($papers) ? $papers[0] : null;
}

/**
 * Get author by ORCID
 */
function wjm_get_author_by_orcid($orcid_id) {
    $authors = get_posts(array(
        'post_type' => 'wjm_author',
        'post_status' => 'any',
        'posts_per_page' => 1,
        'meta_key' => 'orcid_id',
        'meta_value' => $orcid_id,
        'fields' => 'ids'
    ));

    return !empty($authors) ? $authors[0] : null;
}

/**
 * Format number for display
 */
function wjm_format_number($number, $decimals = 0) {
    if ($number >= 1000000) {
        return number_format($number / 1000000, 1) . 'M';
    } elseif ($number >= 1000) {
        return number_format($number / 1000, 1) . 'K';
    } else {
        return number_format($number, $decimals);
    }
}
