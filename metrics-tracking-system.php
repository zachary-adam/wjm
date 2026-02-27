<?php
/**
 * Metrics Tracking System
 * Tracks views, downloads, and generates analytics for papers
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// CORE TRACKING FUNCTIONS
// ========================================

/**
 * Track a paper event (view or download)
 */
function wjm_track_event($paper_id, $event_type = 'view') {
    global $wpdb;
    $tracking_table = $wpdb->prefix . 'wjm_tracking';

    // Validate paper exists
    if (!get_post($paper_id)) {
        return false;
    }

    // Validate event type
    $valid_events = array('view', 'download', 'abstract_view', 'pdf_download');
    if (!in_array($event_type, $valid_events)) {
        $event_type = 'view';
    }

    // Get user IP (anonymized for privacy)
    $user_ip = wjm_get_anonymized_ip();

    // Get user agent
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field($_SERVER['HTTP_USER_AGENT']), 0, 500) : '';

    // Get country code (if available - requires GeoIP)
    $country_code = wjm_get_country_code($user_ip);

    // Insert tracking event
    $result = $wpdb->insert(
        $tracking_table,
        array(
            'paper_id' => absint($paper_id),
            'event_type' => sanitize_text_field($event_type),
            'user_ip' => $user_ip,
            'user_agent' => $user_agent,
            'country_code' => $country_code,
            'created_at' => current_time('mysql')
        ),
        array('%d', '%s', '%s', '%s', '%s', '%s')
    );

    if ($result) {
        // Update daily metrics
        wjm_update_daily_metric($paper_id, $event_type);
    }

    return $result !== false;
}

/**
 * Update daily metric counter
 */
function wjm_update_daily_metric($paper_id, $metric_type) {
    global $wpdb;
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';
    $today = date('Y-m-d');

    // Normalize metric type
    $normalized_type = str_replace('_', '', strtolower($metric_type));
    if (strpos($normalized_type, 'view') !== false) {
        $metric_type = 'views';
    } elseif (strpos($normalized_type, 'download') !== false) {
        $metric_type = 'downloads';
    }

    // Check if entry exists for today
    $current_value = $wpdb->get_var($wpdb->prepare(
        "SELECT metric_value FROM `$metrics_table` WHERE paper_id = %d AND metric_type = %s AND metric_date = %s",
        absint($paper_id),
        $metric_type,
        $today
    ));

    if ($current_value !== null) {
        // Update existing
        $wpdb->query($wpdb->prepare(
            "UPDATE `$metrics_table` SET metric_value = metric_value + 1 WHERE paper_id = %d AND metric_type = %s AND metric_date = %s",
            absint($paper_id),
            $metric_type,
            $today
        ));
    } else {
        // Insert new
        $wpdb->insert(
            $metrics_table,
            array(
                'paper_id' => absint($paper_id),
                'metric_type' => $metric_type,
                'metric_value' => 1,
                'metric_date' => $today,
                'created_at' => current_time('mysql')
            ),
            array('%d', '%s', '%d', '%s', '%s')
        );
    }

    return true;
}

/**
 * Get anonymized IP address (GDPR compliant)
 */
function wjm_get_anonymized_ip() {
    $ip = '';

    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    // Validate IP
    $ip = filter_var($ip, FILTER_VALIDATE_IP);

    if (!$ip) {
        return '0.0.0.0';
    }

    // Anonymize IP (remove last octet for IPv4, last 80 bits for IPv6)
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        $parts[3] = '0'; // Replace last octet
        $ip = implode('.', $parts);
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $parts = explode(':', $ip);
        for ($i = 4; $i < 8; $i++) {
            if (isset($parts[$i])) {
                $parts[$i] = '0';
            }
        }
        $ip = implode(':', $parts);
    }

    return $ip;
}

/**
 * Get country code from IP (placeholder - requires GeoIP database)
 */
function wjm_get_country_code($ip) {
    // This is a placeholder. In production, use a GeoIP service or database
    // For now, return null
    return null;
}

// ========================================
// METRICS RETRIEVAL FUNCTIONS
// ========================================

/**
 * Get total metrics for a paper
 */
function wjm_get_paper_metrics($paper_id, $metric_type = null) {
    global $wpdb;
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';

    if ($metric_type) {
        // Get specific metric
        $total = $wpdb->get_var($wpdb->prepare(
            "SELECT SUM(metric_value) FROM `$metrics_table` WHERE paper_id = %d AND metric_type = %s",
            absint($paper_id),
            sanitize_text_field($metric_type)
        ));

        return absint($total);
    } else {
        // Get all metrics
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT metric_type, SUM(metric_value) as total FROM `$metrics_table` WHERE paper_id = %d GROUP BY metric_type",
            absint($paper_id)
        ), ARRAY_A);

        $metrics = array(
            'views' => 0,
            'downloads' => 0
        );

        foreach ($results as $row) {
            $metrics[$row['metric_type']] = absint($row['total']);
        }

        return $metrics;
    }
}

/**
 * Get metrics for a date range
 */
function wjm_get_paper_metrics_by_date($paper_id, $start_date, $end_date, $metric_type = null) {
    global $wpdb;
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';

    $where = $wpdb->prepare(
        "WHERE paper_id = %d AND metric_date BETWEEN %s AND %s",
        absint($paper_id),
        sanitize_text_field($start_date),
        sanitize_text_field($end_date)
    );

    if ($metric_type) {
        $where .= $wpdb->prepare(" AND metric_type = %s", sanitize_text_field($metric_type));
    }

    $results = $wpdb->get_results(
        "SELECT metric_date, metric_type, metric_value FROM `$metrics_table` $where ORDER BY metric_date ASC",
        ARRAY_A
    );

    return $results;
}

/**
 * Get top papers by metric
 */
function wjm_get_top_papers($metric_type = 'views', $limit = 10, $days = 30) {
    global $wpdb;
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';
    $posts_table = $wpdb->prefix . 'posts';

    $start_date = date('Y-m-d', strtotime("-$days days"));
    $end_date = date('Y-m-d');

    $sql = $wpdb->prepare(
        "SELECT
            m.paper_id,
            p.post_title,
            SUM(m.metric_value) as total
        FROM `$metrics_table` m
        INNER JOIN `$posts_table` p ON m.paper_id = p.ID
        WHERE m.metric_type = %s
        AND m.metric_date BETWEEN %s AND %s
        AND p.post_status = 'publish'
        GROUP BY m.paper_id
        ORDER BY total DESC
        LIMIT %d",
        sanitize_text_field($metric_type),
        $start_date,
        $end_date,
        absint($limit)
    );

    return $wpdb->get_results($sql, ARRAY_A);
}

/**
 * Get geographic distribution of views
 */
function wjm_get_geographic_distribution($paper_id = null, $days = 30) {
    global $wpdb;
    $tracking_table = $wpdb->prefix . 'wjm_tracking';

    $where = "WHERE country_code IS NOT NULL";

    if ($paper_id) {
        $where .= $wpdb->prepare(" AND paper_id = %d", absint($paper_id));
    }

    $start_date = date('Y-m-d H:i:s', strtotime("-$days days"));
    $where .= $wpdb->prepare(" AND created_at >= %s", $start_date);

    $sql = "SELECT country_code, COUNT(*) as count
            FROM `$tracking_table`
            $where
            GROUP BY country_code
            ORDER BY count DESC
            LIMIT 50";

    return $wpdb->get_results($sql, ARRAY_A);
}

/**
 * Get unique visitors count
 */
function wjm_get_unique_visitors($paper_id, $days = 30) {
    global $wpdb;
    $tracking_table = $wpdb->prefix . 'wjm_tracking';

    $start_date = date('Y-m-d H:i:s', strtotime("-$days days"));

    $count = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(DISTINCT user_ip) FROM `$tracking_table`
        WHERE paper_id = %d AND created_at >= %s",
        absint($paper_id),
        $start_date
    ));

    return absint($count);
}

// ========================================
// AUTO-TRACKING HOOKS
// ========================================

/**
 * Track paper views automatically
 */
function wjm_auto_track_paper_view() {
    if (is_singular('paper')) {
        $paper_id = get_the_ID();

        // Use cookie to prevent multiple counts in same session
        $cookie_name = 'wjm_viewed_' . $paper_id;

        if (!isset($_COOKIE[$cookie_name])) {
            wjm_track_event($paper_id, 'view');

            // Set cookie for 30 minutes
            setcookie($cookie_name, '1', time() + 1800, '/');
        }
    }
}
add_action('wp', 'wjm_auto_track_paper_view');

/**
 * Track PDF downloads
 */
function wjm_track_pdf_download() {
    // Check if this is a PDF download request
    if (isset($_GET['wjm_download_pdf']) && isset($_GET['paper_id'])) {
        $paper_id = absint($_GET['paper_id']);

        // Verify nonce for security
        if (isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'wjm_download_pdf_' . $paper_id)) {
            wjm_track_event($paper_id, 'pdf_download');

            // Get PDF URL
            $pdf_url = get_post_meta($paper_id, 'pdf_url', true);

            if ($pdf_url) {
                // Redirect to PDF
                wp_redirect($pdf_url);
                exit;
            }
        }
    }
}
add_action('template_redirect', 'wjm_track_pdf_download');

// ========================================
// META BOX FOR PAPER METRICS
// ========================================

/**
 * Add Metrics meta box to paper edit screen
 */
function wjm_add_metrics_meta_box() {
    add_meta_box(
        'wjm_metrics_meta_box',
        'Paper Metrics & Analytics',
        'wjm_metrics_meta_box_callback',
        'paper',
        'side',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_metrics_meta_box');

/**
 * Metrics meta box callback
 */
function wjm_metrics_meta_box_callback($post) {
    $metrics = wjm_get_paper_metrics($post->ID);
    $citation_stats = function_exists('wjm_get_citation_stats') ? wjm_get_citation_stats($post->ID) : array('cited_by_count' => 0);
    $unique_visitors = wjm_get_unique_visitors($post->ID, 30);

    // Get last 30 days data
    $start_date = date('Y-m-d', strtotime('-30 days'));
    $end_date = date('Y-m-d');
    $metrics_30_days = wjm_get_paper_metrics_by_date($post->ID, $start_date, $end_date);

    // Calculate views and downloads for last 30 days
    $views_30d = 0;
    $downloads_30d = 0;

    foreach ($metrics_30_days as $metric) {
        if ($metric['metric_type'] === 'views') {
            $views_30d += absint($metric['metric_value']);
        } elseif ($metric['metric_type'] === 'downloads') {
            $downloads_30d += absint($metric['metric_value']);
        }
    }

    ?>
    <div class="wjm-metrics-summary">
        <style>
            .wjm-metric-card {
                background: #f0f0f1;
                padding: 12px;
                border-radius: 6px;
                margin-bottom: 10px;
                text-align: center;
            }
            .wjm-metric-value {
                display: block;
                font-size: 28px;
                font-weight: 700;
                color: #2271b1;
                margin-bottom: 4px;
            }
            .wjm-metric-label {
                display: block;
                font-size: 12px;
                color: #646970;
                text-transform: uppercase;
            }
            .wjm-metric-sublabel {
                display: block;
                font-size: 11px;
                color: #50575e;
                margin-top: 4px;
            }
        </style>

        <!-- Total Views -->
        <div class="wjm-metric-card">
            <span class="wjm-metric-value"><?php echo number_format($metrics['views']); ?></span>
            <span class="wjm-metric-label">Total Views</span>
            <span class="wjm-metric-sublabel"><?php echo number_format($views_30d); ?> in last 30 days</span>
        </div>

        <!-- Total Downloads -->
        <div class="wjm-metric-card">
            <span class="wjm-metric-value"><?php echo number_format($metrics['downloads']); ?></span>
            <span class="wjm-metric-label">Total Downloads</span>
            <span class="wjm-metric-sublabel"><?php echo number_format($downloads_30d); ?> in last 30 days</span>
        </div>

        <!-- Citations -->
        <div class="wjm-metric-card">
            <span class="wjm-metric-value"><?php echo number_format($citation_stats['cited_by_count']); ?></span>
            <span class="wjm-metric-label">Citations</span>
        </div>

        <!-- Unique Visitors -->
        <div class="wjm-metric-card">
            <span class="wjm-metric-value"><?php echo number_format($unique_visitors); ?></span>
            <span class="wjm-metric-label">Unique Visitors</span>
            <span class="wjm-metric-sublabel">Last 30 days</span>
        </div>

        <p style="text-align: center; margin-top: 15px;">
            <a href="<?php echo admin_url('admin.php?page=wjm-analytics&paper_id=' . $post->ID); ?>" class="button button-small">
                View Detailed Analytics →
            </a>
        </p>
    </div>
    <?php
}

// ========================================
// SHORTCODES FOR FRONTEND
// ========================================

/**
 * Shortcode to display paper metrics
 */
function wjm_paper_metrics_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID(),
        'show' => 'all' // all, views, downloads, citations
    ), $atts);

    $metrics = wjm_get_paper_metrics($atts['paper_id']);
    $citation_stats = function_exists('wjm_get_citation_stats') ? wjm_get_citation_stats($atts['paper_id']) : array('cited_by_count' => 0);

    ob_start();
    ?>
    <div class="wjm-paper-metrics">
        <?php if ($atts['show'] === 'all' || $atts['show'] === 'views'): ?>
            <span class="wjm-metric-item">
                <svg width="16" height="16" fill="currentColor" style="vertical-align: middle; margin-right: 4px;">
                    <path d="M8 4C4.5 4 1.5 6.5 0 10c1.5 3.5 4.5 6 8 6s6.5-2.5 8-6c-1.5-3.5-4.5-6-8-6zm0 10c-2.2 0-4-1.8-4-4s1.8-4 4-4 4 1.8 4 4-1.8 4-4 4zm0-6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/>
                </svg>
                <strong><?php echo number_format($metrics['views']); ?></strong> views
            </span>
        <?php endif; ?>

        <?php if ($atts['show'] === 'all' || $atts['show'] === 'downloads'): ?>
            <span class="wjm-metric-item">
                <svg width="16" height="16" fill="currentColor" style="vertical-align: middle; margin-right: 4px;">
                    <path d="M14 9v5H2V9H0v5c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V9h-2zm-7 .5l3.5-3.5 1.5 1.5L8 12 4 7.5 5.5 6z"/>
                </svg>
                <strong><?php echo number_format($metrics['downloads']); ?></strong> downloads
            </span>
        <?php endif; ?>

        <?php if ($atts['show'] === 'all' || $atts['show'] === 'citations'): ?>
            <span class="wjm-metric-item">
                <svg width="16" height="16" fill="currentColor" style="vertical-align: middle; margin-right: 4px;">
                    <path d="M6 14l-2.5-2.5L7 8 3.5 4.5 6 2 10.5 8z"/>
                </svg>
                <strong><?php echo number_format($citation_stats['cited_by_count']); ?></strong> citations
            </span>
        <?php endif; ?>
    </div>

    <style>
        .wjm-paper-metrics {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin: 15px 0;
        }
        .wjm-metric-item {
            display: inline-flex;
            align-items: center;
            color: #646970;
            font-size: 14px;
        }
        .wjm-metric-item strong {
            color: #2271b1;
            margin-right: 3px;
        }
    </style>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_paper_metrics', 'wjm_paper_metrics_shortcode');

/**
 * Shortcode for download PDF button with tracking
 */
function wjm_download_pdf_button_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID(),
        'text' => 'Download PDF'
    ), $atts);

    $pdf_url = get_post_meta($atts['paper_id'], 'pdf_url', true);

    if (!$pdf_url) {
        return '';
    }

    // Generate tracked download URL
    $download_url = add_query_arg(array(
        'wjm_download_pdf' => '1',
        'paper_id' => $atts['paper_id'],
        '_wpnonce' => wp_create_nonce('wjm_download_pdf_' . $atts['paper_id'])
    ), home_url('/'));

    return sprintf(
        '<a href="%s" class="wjm-download-pdf-btn" target="_blank">%s</a>',
        esc_url($download_url),
        esc_html($atts['text'])
    );
}
add_shortcode('wjm_download_pdf', 'wjm_download_pdf_button_shortcode');

// ========================================
// ADMIN FUNCTIONS
// ========================================

/**
 * Get system-wide metrics statistics
 */
function wjm_get_system_metrics($days = 30) {
    global $wpdb;
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';
    $tracking_table = $wpdb->prefix . 'wjm_tracking';

    $start_date = date('Y-m-d', strtotime("-$days days"));
    $end_date = date('Y-m-d');

    // Total views and downloads
    $totals = $wpdb->get_row($wpdb->prepare(
        "SELECT
            SUM(CASE WHEN metric_type = 'views' THEN metric_value ELSE 0 END) as total_views,
            SUM(CASE WHEN metric_type = 'downloads' THEN metric_value ELSE 0 END) as total_downloads
        FROM `$metrics_table`
        WHERE metric_date BETWEEN %s AND %s",
        $start_date,
        $end_date
    ), ARRAY_A);

    // Unique visitors
    $unique_visitors = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(DISTINCT user_ip) FROM `$tracking_table`
        WHERE created_at >= %s",
        date('Y-m-d H:i:s', strtotime("-$days days"))
    ));

    return array(
        'total_views' => absint($totals['total_views']),
        'total_downloads' => absint($totals['total_downloads']),
        'unique_visitors' => absint($unique_visitors),
        'period_days' => $days
    );
}
