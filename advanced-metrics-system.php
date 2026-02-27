<?php
/**
 * Advanced Metrics & Altmetrics System
 * Track alternative metrics: social media, news, policy, etc.
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// ALTMETRIC.COM API INTEGRATION
// ========================================

/**
 * Fetch Altmetric data for a paper
 */
function wjm_fetch_altmetric_data($doi) {
    if (empty($doi)) {
        return new WP_Error('no_doi', 'DOI required for Altmetric data');
    }

    // Clean DOI
    $doi = preg_replace('#^https?://doi\.org/#i', '', $doi);

    // Altmetric API endpoint
    $api_url = 'https://api.altmetric.com/v1/doi/' . rawurlencode($doi);

    $response = wp_remote_get($api_url, array('timeout' => 15));

    if (is_wp_error($response)) {
        return new WP_Error('api_error', 'Failed to connect to Altmetric API');
    }

    $response_code = wp_remote_retrieve_response_code($response);

    if ($response_code !== 200) {
        if ($response_code === 404) {
            // No altmetric data found - this is normal for papers without social mentions
            return array('score' => 0, 'mentions' => array());
        }
        return new WP_Error('api_error', 'Altmetric API error: ' . $response_code);
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!$data) {
        return new WP_Error('parse_error', 'Failed to parse Altmetric data');
    }

    // Parse altmetric data
    $altmetric_data = array(
        'score' => floatval($data['score'] ?? 0),
        'altmetric_id' => $data['altmetric_id'] ?? '',
        'url' => $data['details_url'] ?? '',
        'image' => $data['images']['medium'] ?? '',
        'mentions' => array(
            'twitter' => absint($data['cited_by_tweeters_count'] ?? 0),
            'facebook' => absint($data['cited_by_fbwalls_count'] ?? 0),
            'news' => absint($data['cited_by_msm_count'] ?? 0),
            'blogs' => absint($data['cited_by_feeds_count'] ?? 0),
            'reddit' => absint($data['cited_by_rdts_count'] ?? 0),
            'wikipedia' => absint($data['cited_by_wikipedia_count'] ?? 0),
            'policy' => absint($data['cited_by_policies_count'] ?? 0),
            'patents' => absint($data['cited_by_patents_count'] ?? 0)
        ),
        'last_updated' => current_time('mysql')
    );

    return $altmetric_data;
}

/**
 * Save Altmetric data for a paper
 */
function wjm_save_altmetric_data($paper_id, $altmetric_data) {
    update_post_meta($paper_id, '_altmetric_score', $altmetric_data['score']);
    update_post_meta($paper_id, '_altmetric_mentions', $altmetric_data['mentions']);
    update_post_meta($paper_id, '_altmetric_url', $altmetric_data['url']);
    update_post_meta($paper_id, '_altmetric_image', $altmetric_data['image']);
    update_post_meta($paper_id, '_altmetric_last_updated', $altmetric_data['last_updated']);

    return true;
}

/**
 * Get Altmetric data for a paper
 */
function wjm_get_altmetric_data($paper_id) {
    $score = get_post_meta($paper_id, '_altmetric_score', true);
    $mentions = get_post_meta($paper_id, '_altmetric_mentions', true);
    $url = get_post_meta($paper_id, '_altmetric_url', true);
    $image = get_post_meta($paper_id, '_altmetric_image', true);
    $last_updated = get_post_meta($paper_id, '_altmetric_last_updated', true);

    if ($score === '') {
        return null;
    }

    return array(
        'score' => floatval($score),
        'mentions' => $mentions ?: array(),
        'url' => $url,
        'image' => $image,
        'last_updated' => $last_updated
    );
}

/**
 * Update Altmetric data for a paper
 */
function wjm_update_altmetric_data($paper_id) {
    $doi = get_post_meta($paper_id, 'doi', true);

    if (!$doi) {
        return new WP_Error('no_doi', 'Paper has no DOI');
    }

    $altmetric_data = wjm_fetch_altmetric_data($doi);

    if (is_wp_error($altmetric_data)) {
        return $altmetric_data;
    }

    wjm_save_altmetric_data($paper_id, $altmetric_data);

    return $altmetric_data;
}

// ========================================
// IMPACT SCORE CALCULATION
// ========================================

/**
 * Calculate comprehensive impact score for a paper
 * Combines citations, metrics, and altmetrics
 */
function wjm_calculate_impact_score($paper_id) {
    // Get citation data
    $citation_stats = function_exists('wjm_get_citation_stats') ? wjm_get_citation_stats($paper_id) : array('cited_by_count' => 0);

    // Get metrics data
    $metrics = function_exists('wjm_get_paper_metrics') ? wjm_get_paper_metrics($paper_id) : array('views' => 0, 'downloads' => 0);

    // Get altmetric data
    $altmetric = wjm_get_altmetric_data($paper_id);
    $altmetric_score = $altmetric ? floatval($altmetric['score']) : 0;

    // Get paper age (years since publication)
    $post = get_post($paper_id);
    $publication_date = $post ? $post->post_date : date('Y-m-d');
    $years_since_publication = max(1, (time() - strtotime($publication_date)) / (365 * 24 * 60 * 60));

    // Calculate weighted impact score
    // Formula: (Citations * 10) + (Views / 100) + (Downloads * 2) + (Altmetric Score * 5) / Years
    $raw_score =
        ($citation_stats['cited_by_count'] * 10) +
        ($metrics['views'] / 100) +
        ($metrics['downloads'] * 2) +
        ($altmetric_score * 5);

    // Normalize by age (recent papers get slight boost)
    $impact_score = $raw_score / pow($years_since_publication, 0.5);

    // Round to 2 decimal places
    $impact_score = round($impact_score, 2);

    // Calculate component scores
    $components = array(
        'citation_score' => round(($citation_stats['cited_by_count'] * 10) / pow($years_since_publication, 0.5), 2),
        'usage_score' => round((($metrics['views'] / 100) + ($metrics['downloads'] * 2)) / pow($years_since_publication, 0.5), 2),
        'social_score' => round(($altmetric_score * 5) / pow($years_since_publication, 0.5), 2),
        'total_score' => $impact_score
    );

    // Save impact score
    update_post_meta($paper_id, '_impact_score', $impact_score);
    update_post_meta($paper_id, '_impact_components', $components);
    update_post_meta($paper_id, '_impact_last_calculated', current_time('mysql'));

    return $components;
}

/**
 * Get impact score for a paper
 */
function wjm_get_impact_score($paper_id) {
    $score = get_post_meta($paper_id, '_impact_score', true);

    if ($score === '') {
        // Calculate if not found
        $components = wjm_calculate_impact_score($paper_id);
        return $components['total_score'];
    }

    return floatval($score);
}

/**
 * Get impact score components
 */
function wjm_get_impact_components($paper_id) {
    $components = get_post_meta($paper_id, '_impact_components', true);

    if (!$components) {
        return wjm_calculate_impact_score($paper_id);
    }

    return $components;
}

// ========================================
// SOCIAL MEDIA TRACKING
// ========================================

/**
 * Track social media shares manually
 */
function wjm_track_social_share($paper_id, $platform) {
    $valid_platforms = array('twitter', 'facebook', 'linkedin', 'reddit', 'whatsapp', 'email');

    if (!in_array($platform, $valid_platforms)) {
        return false;
    }

    $meta_key = '_social_shares_' . $platform;
    $current_count = absint(get_post_meta($paper_id, $meta_key, true));
    $new_count = $current_count + 1;

    update_post_meta($paper_id, $meta_key, $new_count);

    // Update total shares
    $total_key = '_social_shares_total';
    $total = absint(get_post_meta($paper_id, $total_key, true));
    update_post_meta($paper_id, $total_key, $total + 1);

    return $new_count;
}

/**
 * Get social share counts
 */
function wjm_get_social_shares($paper_id) {
    return array(
        'twitter' => absint(get_post_meta($paper_id, '_social_shares_twitter', true)),
        'facebook' => absint(get_post_meta($paper_id, '_social_shares_facebook', true)),
        'linkedin' => absint(get_post_meta($paper_id, '_social_shares_linkedin', true)),
        'reddit' => absint(get_post_meta($paper_id, '_social_shares_reddit', true)),
        'whatsapp' => absint(get_post_meta($paper_id, '_social_shares_whatsapp', true)),
        'email' => absint(get_post_meta($paper_id, '_social_shares_email', true)),
        'total' => absint(get_post_meta($paper_id, '_social_shares_total', true))
    );
}

// ========================================
// META BOXES
// ========================================

/**
 * Add Advanced Metrics meta box
 */
function wjm_add_advanced_metrics_meta_box() {
    add_meta_box(
        'wjm_advanced_metrics_meta_box',
        'Advanced Metrics',
        'wjm_advanced_metrics_meta_box_callback',
        'paper',
        'side',
        'default'
    );
}
add_action('add_meta_boxes', 'wjm_add_advanced_metrics_meta_box');

/**
 * Advanced Metrics meta box callback
 */
function wjm_advanced_metrics_meta_box_callback($post) {
    $altmetric = wjm_get_altmetric_data($post->ID);
    $impact_score = wjm_get_impact_score($post->ID);
    $social_shares = wjm_get_social_shares($post->ID);
    $doi = get_post_meta($post->ID, 'doi', true);
    ?>

    <div class="wjm-advanced-metrics-wrapper">
        <!-- Impact Score -->
        <div style="text-align: center; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px; margin-bottom: 15px;">
            <div style="color: white; font-size: 36px; font-weight: 700; margin-bottom: 5px;">
                <?php echo number_format($impact_score, 1); ?>
            </div>
            <div style="color: rgba(255,255,255,0.9); font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">
                Impact Score
            </div>
        </div>

        <!-- Altmetric Section -->
        <div style="margin-bottom: 15px;">
            <h4 style="margin: 0 0 10px 0; font-size: 14px;">Altmetric Attention</h4>

            <?php if ($altmetric): ?>
                <div style="background: #f0f0f1; padding: 12px; border-radius: 6px; margin-bottom: 10px;">
                    <?php if ($altmetric['image']): ?>
                        <div style="text-align: center; margin-bottom: 10px;">
                            <img src="<?php echo esc_url($altmetric['image']); ?>" alt="Altmetric Score" style="max-width: 100px;" />
                        </div>
                    <?php endif; ?>

                    <div style="text-align: center; margin-bottom: 10px;">
                        <strong style="font-size: 24px; color: #2271b1;"><?php echo number_format($altmetric['score'], 1); ?></strong>
                        <br>
                        <small style="color: #646970;">Altmetric Score</small>
                    </div>

                    <div style="font-size: 12px;">
                        <?php foreach ($altmetric['mentions'] as $platform => $count): ?>
                            <?php if ($count > 0): ?>
                                <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e0e0e0;">
                                    <span style="text-transform: capitalize;"><?php echo esc_html($platform); ?></span>
                                    <strong><?php echo number_format($count); ?></strong>
                                </div>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </div>

                    <?php if ($altmetric['url']): ?>
                        <div style="text-align: center; margin-top: 10px;">
                            <a href="<?php echo esc_url($altmetric['url']); ?>" target="_blank" class="button button-small">View Details</a>
                        </div>
                    <?php endif; ?>
                </div>

                <p style="font-size: 11px; color: #646970; margin: 0;">
                    Last updated: <?php echo date('M d, Y', strtotime($altmetric['last_updated'])); ?>
                </p>
            <?php else: ?>
                <p style="color: #646970; font-size: 13px;">
                    <?php if ($doi): ?>
                        No altmetric data available yet.
                    <?php else: ?>
                        Paper needs a DOI to fetch altmetric data.
                    <?php endif; ?>
                </p>
            <?php endif; ?>

            <?php if ($doi): ?>
                <button type="button" id="wjm-fetch-altmetric-btn" class="button button-small" data-paper-id="<?php echo esc_attr($post->ID); ?>" style="width: 100%; margin-top: 10px;">
                    <?php echo $altmetric ? 'Refresh' : 'Fetch'; ?> Altmetric Data
                </button>
            <?php endif; ?>
        </div>

        <!-- Social Shares -->
        <div style="margin-bottom: 15px;">
            <h4 style="margin: 0 0 10px 0; font-size: 14px;">Social Shares</h4>
            <div style="background: #f0f0f1; padding: 12px; border-radius: 6px;">
                <div style="text-align: center; margin-bottom: 10px;">
                    <strong style="font-size: 24px; color: #10b981;"><?php echo number_format($social_shares['total']); ?></strong>
                    <br>
                    <small style="color: #646970;">Total Shares</small>
                </div>
            </div>
        </div>

        <!-- Recalculate Impact -->
        <button type="button" id="wjm-recalculate-impact-btn" class="button button-small" data-paper-id="<?php echo esc_attr($post->ID); ?>" style="width: 100%;">
            Recalculate Impact Score
        </button>

        <div id="wjm-advanced-metrics-status" style="margin-top: 10px;"></div>
    </div>

    <script>
    jQuery(document).ready(function($) {
        // Fetch Altmetric data
        $('#wjm-fetch-altmetric-btn').on('click', function() {
            var $btn = $(this);
            var paperId = $btn.data('paper-id');
            var $status = $('#wjm-advanced-metrics-status');

            $btn.prop('disabled', true).text('Fetching...');
            $status.html('<p style="color: #646970; font-size: 12px;">Connecting to Altmetric...</p>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_fetch_altmetric',
                    paper_id: paperId
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<p style="color: #00a32a; font-size: 12px;">✓ Altmetric data updated!</p>');
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        $status.html('<p style="color: #d63638; font-size: 12px;">Error: ' + response.data + '</p>');
                    }
                },
                error: function() {
                    $status.html('<p style="color: #d63638; font-size: 12px;">Connection error</p>');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Fetch Altmetric Data');
                }
            });
        });

        // Recalculate impact score
        $('#wjm-recalculate-impact-btn').on('click', function() {
            var $btn = $(this);
            var paperId = $btn.data('paper-id');
            var $status = $('#wjm-advanced-metrics-status');

            $btn.prop('disabled', true).text('Calculating...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_recalculate_impact',
                    paper_id: paperId
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<p style="color: #00a32a; font-size: 12px;">✓ Impact score updated!</p>');
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        $status.html('<p style="color: #d63638; font-size: 12px;">Error calculating</p>');
                    }
                },
                error: function() {
                    $status.html('<p style="color: #d63638; font-size: 12px;">Connection error</p>');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Recalculate Impact Score');
                }
            });
        });
    });
    </script>
    <?php
}

// ========================================
// AJAX HANDLERS
// ========================================

/**
 * AJAX: Fetch Altmetric data
 */
function wjm_ajax_fetch_altmetric() {
    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $paper_id = absint($_POST['paper_id']);

    $result = wjm_update_altmetric_data($paper_id);

    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
    }

    wp_send_json_success($result);
}
add_action('wp_ajax_wjm_fetch_altmetric', 'wjm_ajax_fetch_altmetric');

/**
 * AJAX: Recalculate impact score
 */
function wjm_ajax_recalculate_impact() {
    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $paper_id = absint($_POST['paper_id']);

    $components = wjm_calculate_impact_score($paper_id);

    wp_send_json_success($components);
}
add_action('wp_ajax_wjm_recalculate_impact', 'wjm_ajax_recalculate_impact');

/**
 * AJAX: Track social share
 */
function wjm_ajax_track_social_share() {
    $paper_id = absint($_POST['paper_id']);
    $platform = sanitize_text_field($_POST['platform']);

    $count = wjm_track_social_share($paper_id, $platform);

    wp_send_json_success(array('count' => $count));
}
add_action('wp_ajax_wjm_track_social_share', 'wjm_ajax_track_social_share');
add_action('wp_ajax_nopriv_wjm_track_social_share', 'wjm_ajax_track_social_share');

// ========================================
// SHORTCODES
// ========================================

/**
 * Altmetric badge shortcode
 */
function wjm_altmetric_badge_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID(),
        'size' => 'medium'
    ), $atts);

    $altmetric = wjm_get_altmetric_data($atts['paper_id']);

    if (!$altmetric || !$altmetric['image']) {
        return '';
    }

    ob_start();
    ?>
    <div class="wjm-altmetric-badge" style="text-align: center; margin: 20px 0;">
        <a href="<?php echo esc_url($altmetric['url']); ?>" target="_blank">
            <img src="<?php echo esc_url($altmetric['image']); ?>" alt="Altmetric Score: <?php echo esc_attr($altmetric['score']); ?>" style="max-width: 150px;" />
        </a>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_altmetric_badge', 'wjm_altmetric_badge_shortcode');

/**
 * Impact score badge shortcode
 */
function wjm_impact_score_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID()
    ), $atts);

    $impact_score = wjm_get_impact_score($atts['paper_id']);

    ob_start();
    ?>
    <div class="wjm-impact-badge" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 20px; border-radius: 8px; text-align: center;">
        <div style="font-size: 28px; font-weight: 700; margin-bottom: 4px;">
            <?php echo number_format($impact_score, 1); ?>
        </div>
        <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 1px;">
            Impact Score
        </div>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_impact_score', 'wjm_impact_score_shortcode');

/**
 * Social share buttons shortcode
 */
function wjm_social_share_buttons_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID()
    ), $atts);

    $paper_url = get_permalink($atts['paper_id']);
    $paper_title = get_the_title($atts['paper_id']);

    ob_start();
    ?>
    <div class="wjm-social-share-buttons" style="display: flex; gap: 10px; flex-wrap: wrap; margin: 20px 0;">
        <a href="https://twitter.com/intent/tweet?url=<?php echo urlencode($paper_url); ?>&text=<?php echo urlencode($paper_title); ?>" target="_blank" class="wjm-share-btn wjm-share-twitter" data-platform="twitter" data-paper-id="<?php echo esc_attr($atts['paper_id']); ?>" style="background: #1DA1F2; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; display: inline-flex; align-items: center; gap: 8px;">
            Twitter
        </a>

        <a href="https://www.facebook.com/sharer/sharer.php?u=<?php echo urlencode($paper_url); ?>" target="_blank" class="wjm-share-btn wjm-share-facebook" data-platform="facebook" data-paper-id="<?php echo esc_attr($atts['paper_id']); ?>" style="background: #1877F2; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; display: inline-flex; align-items: center; gap: 8px;">
            Facebook
        </a>

        <a href="https://www.linkedin.com/sharing/share-offsite/?url=<?php echo urlencode($paper_url); ?>" target="_blank" class="wjm-share-btn wjm-share-linkedin" data-platform="linkedin" data-paper-id="<?php echo esc_attr($atts['paper_id']); ?>" style="background: #0A66C2; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; display: inline-flex; align-items: center; gap: 8px;">
            LinkedIn
        </a>

        <a href="https://reddit.com/submit?url=<?php echo urlencode($paper_url); ?>&title=<?php echo urlencode($paper_title); ?>" target="_blank" class="wjm-share-btn wjm-share-reddit" data-platform="reddit" data-paper-id="<?php echo esc_attr($atts['paper_id']); ?>" style="background: #FF4500; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; display: inline-flex; align-items: center; gap: 8px;">
            Reddit
        </a>
    </div>

    <script>
    jQuery(document).ready(function($) {
        $('.wjm-share-btn').on('click', function() {
            var platform = $(this).data('platform');
            var paperId = $(this).data('paper-id');

            // Track share
            $.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'wjm_track_social_share',
                    paper_id: paperId,
                    platform: platform
                }
            });
        });
    });
    </script>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_social_share_buttons', 'wjm_social_share_buttons_shortcode');

// ========================================
// BULK OPERATIONS
// ========================================

/**
 * Bulk update altmetric data for all papers with DOIs
 */
function wjm_bulk_update_altmetrics() {
    $papers = get_posts(array(
        'post_type' => 'paper',
        'posts_per_page' => -1,
        'meta_key' => 'doi',
        'meta_compare' => 'EXISTS',
        'fields' => 'ids'
    ));

    $updated = 0;
    $failed = 0;

    foreach ($papers as $paper_id) {
        $result = wjm_update_altmetric_data($paper_id);

        if (!is_wp_error($result)) {
            $updated++;
        } else {
            $failed++;
        }

        // Sleep to avoid rate limiting
        sleep(2);
    }

    return array(
        'updated' => $updated,
        'failed' => $failed,
        'total' => count($papers)
    );
}

/**
 * Bulk recalculate impact scores
 */
function wjm_bulk_recalculate_impact_scores() {
    $papers = get_posts(array(
        'post_type' => 'paper',
        'posts_per_page' => -1,
        'post_status' => 'publish',
        'fields' => 'ids'
    ));

    $calculated = 0;

    foreach ($papers as $paper_id) {
        wjm_calculate_impact_score($paper_id);
        $calculated++;
    }

    return $calculated;
}
