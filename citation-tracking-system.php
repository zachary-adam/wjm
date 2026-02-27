<?php
/**
 * Citation Tracking System
 * Manages paper citations, citation counts, and citation relationships
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// CORE CITATION FUNCTIONS
// ========================================

/**
 * Add a citation to a paper
 */
function wjm_add_citation($paper_id, $cited_data, $extraction_method = 'manual') {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_citations';

    // Validate paper exists
    if (!get_post($paper_id)) {
        return new WP_Error('invalid_paper', 'Paper does not exist');
    }

    // Prepare citation data
    $citation_data = array(
        'paper_id' => absint($paper_id),
        'extraction_method' => sanitize_text_field($extraction_method),
        'created_at' => current_time('mysql'),
        'updated_at' => current_time('mysql')
    );

    // Add cited paper ID or DOI
    if (!empty($cited_data['cited_paper_id'])) {
        $citation_data['cited_paper_id'] = absint($cited_data['cited_paper_id']);
    }

    if (!empty($cited_data['cited_doi'])) {
        $citation_data['cited_doi'] = sanitize_text_field($cited_data['cited_doi']);
    }

    if (!empty($cited_data['citation_text'])) {
        $citation_data['citation_text'] = wp_kses_post($cited_data['citation_text']);
    }

    if (isset($cited_data['citation_order'])) {
        $citation_data['citation_order'] = absint($cited_data['citation_order']);
    }

    if (isset($cited_data['verified'])) {
        $citation_data['verified'] = absint($cited_data['verified']);
    }

    // Insert citation
    $result = $wpdb->insert($table, $citation_data);

    if ($result === false) {
        return new WP_Error('db_error', 'Failed to insert citation');
    }

    $citation_id = $wpdb->insert_id;

    // Update citation counters
    wjm_update_citation_counters($paper_id);

    if (!empty($citation_data['cited_paper_id'])) {
        wjm_update_citation_counters($citation_data['cited_paper_id']);
    }

    // Log audit event
    if (function_exists('wjm_log_audit_event')) {
        wjm_log_audit_event('citation_added', array(
            'citation_id' => $citation_id,
            'paper_id' => $paper_id,
            'cited_paper_id' => $citation_data['cited_paper_id'] ?? null,
            'cited_doi' => $citation_data['cited_doi'] ?? null
        ));
    }

    return $citation_id;
}

/**
 * Get citations for a paper
 */
function wjm_get_paper_citations($paper_id, $args = array()) {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_citations';

    $defaults = array(
        'verified_only' => false,
        'order_by' => 'citation_order',
        'order' => 'ASC',
        'limit' => null,
        'offset' => 0
    );

    $args = wp_parse_args($args, $defaults);

    // Build query
    $where = $wpdb->prepare("WHERE paper_id = %d", absint($paper_id));

    if ($args['verified_only']) {
        $where .= " AND verified = 1";
    }

    $order_by = sanitize_sql_orderby($args['order_by'] . ' ' . $args['order']);

    $limit_clause = '';
    if ($args['limit']) {
        $limit_clause = $wpdb->prepare("LIMIT %d OFFSET %d", absint($args['limit']), absint($args['offset']));
    }

    $sql = "SELECT * FROM `$table` $where ORDER BY $order_by $limit_clause";

    return $wpdb->get_results($sql);
}

/**
 * Get papers that cite this paper (cited by)
 */
function wjm_get_cited_by($paper_id, $args = array()) {
    global $wpdb;
    $citations_table = $wpdb->prefix . 'wjm_citations';
    $posts_table = $wpdb->prefix . 'posts';

    $defaults = array(
        'verified_only' => false,
        'limit' => 50,
        'offset' => 0
    );

    $args = wp_parse_args($args, $defaults);

    // Build query
    $where = $wpdb->prepare("WHERE c.cited_paper_id = %d", absint($paper_id));

    if ($args['verified_only']) {
        $where .= " AND c.verified = 1";
    }

    $limit_clause = $wpdb->prepare("LIMIT %d OFFSET %d", absint($args['limit']), absint($args['offset']));

    $sql = "SELECT p.*, c.citation_text, c.created_at as citation_date
            FROM `$citations_table` c
            INNER JOIN `$posts_table` p ON c.paper_id = p.ID
            $where
            ORDER BY c.created_at DESC
            $limit_clause";

    return $wpdb->get_results($sql);
}

/**
 * Update citation counters for a paper
 */
function wjm_update_citation_counters($paper_id) {
    global $wpdb;
    $citations_table = $wpdb->prefix . 'wjm_citations';
    $index_table = $wpdb->prefix . 'wjm_citation_index';

    // Count how many times this paper is cited (cited_by_count)
    $cited_by_count = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM `$citations_table` WHERE cited_paper_id = %d AND verified = 1",
        absint($paper_id)
    ));

    // Count how many papers this paper cites (citing_count)
    $citing_count = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM `$citations_table` WHERE paper_id = %d",
        absint($paper_id)
    ));

    // Get last cited date
    $last_cited = $wpdb->get_var($wpdb->prepare(
        "SELECT MAX(created_at) FROM `$citations_table` WHERE cited_paper_id = %d",
        absint($paper_id)
    ));

    // Calculate h-index (simplified - for single paper, either 0 or 1)
    $h_index = ($cited_by_count > 0) ? 1 : 0;

    // Check if index entry exists
    $exists = $wpdb->get_var($wpdb->prepare(
        "SELECT id FROM `$index_table` WHERE paper_id = %d",
        absint($paper_id)
    ));

    $data = array(
        'paper_id' => absint($paper_id),
        'cited_by_count' => absint($cited_by_count),
        'citing_count' => absint($citing_count),
        'last_cited' => $last_cited,
        'h_index' => $h_index,
        'updated_at' => current_time('mysql')
    );

    if ($exists) {
        // Update existing
        $wpdb->update($index_table, $data, array('paper_id' => absint($paper_id)));
    } else {
        // Insert new
        $wpdb->insert($index_table, $data);
    }

    return array(
        'cited_by_count' => $cited_by_count,
        'citing_count' => $citing_count,
        'h_index' => $h_index
    );
}

/**
 * Get citation statistics for a paper
 */
function wjm_get_citation_stats($paper_id) {
    global $wpdb;
    $index_table = $wpdb->prefix . 'wjm_citation_index';

    $stats = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM `$index_table` WHERE paper_id = %d",
        absint($paper_id)
    ), ARRAY_A);

    if (!$stats) {
        // Return default stats
        return array(
            'cited_by_count' => 0,
            'citing_count' => 0,
            'h_index' => 0,
            'last_cited' => null
        );
    }

    return $stats;
}

/**
 * Delete a citation
 */
function wjm_delete_citation($citation_id) {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_citations';

    // Get citation details before deleting
    $citation = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM `$table` WHERE id = %d",
        absint($citation_id)
    ));

    if (!$citation) {
        return new WP_Error('not_found', 'Citation not found');
    }

    // Delete citation
    $result = $wpdb->delete($table, array('id' => absint($citation_id)));

    if ($result === false) {
        return new WP_Error('db_error', 'Failed to delete citation');
    }

    // Update counters
    wjm_update_citation_counters($citation->paper_id);

    if ($citation->cited_paper_id) {
        wjm_update_citation_counters($citation->cited_paper_id);
    }

    // Log audit event
    if (function_exists('wjm_log_audit_event')) {
        wjm_log_audit_event('citation_deleted', array(
            'citation_id' => $citation_id,
            'paper_id' => $citation->paper_id
        ));
    }

    return true;
}

/**
 * Verify a citation
 */
function wjm_verify_citation($citation_id, $verified = 1) {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_citations';

    $result = $wpdb->update(
        $table,
        array('verified' => absint($verified), 'updated_at' => current_time('mysql')),
        array('id' => absint($citation_id))
    );

    if ($result === false) {
        return new WP_Error('db_error', 'Failed to verify citation');
    }

    // Get citation to update counters
    $citation = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM `$table` WHERE id = %d",
        absint($citation_id)
    ));

    if ($citation) {
        wjm_update_citation_counters($citation->paper_id);
        if ($citation->cited_paper_id) {
            wjm_update_citation_counters($citation->cited_paper_id);
        }
    }

    return true;
}

// ========================================
// ADMIN UI - CITATIONS META BOX
// ========================================

/**
 * Add Citations meta box to paper edit screen
 */
function wjm_add_citations_meta_box() {
    add_meta_box(
        'wjm_citations_meta_box',
        'Citations',
        'wjm_citations_meta_box_callback',
        'paper',
        'normal',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_citations_meta_box');

/**
 * Citations meta box callback
 */
function wjm_citations_meta_box_callback($post) {
    wp_nonce_field('wjm_save_citations', 'wjm_citations_nonce');

    $citations = wjm_get_paper_citations($post->ID);
    $stats = wjm_get_citation_stats($post->ID);
    $cited_by = wjm_get_cited_by($post->ID, array('limit' => 10));
    ?>

    <div class="wjm-citations-wrapper">

        <!-- Citation Statistics -->
        <div class="wjm-citation-stats" style="background: #f0f0f1; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h4 style="margin-top: 0;">Citation Statistics</h4>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
                <div>
                    <strong style="display: block; color: #2271b1; font-size: 24px;"><?php echo esc_html($stats['cited_by_count']); ?></strong>
                    <span style="font-size: 12px; color: #646970;">Times Cited</span>
                </div>
                <div>
                    <strong style="display: block; color: #00a32a; font-size: 24px;"><?php echo esc_html($stats['citing_count']); ?></strong>
                    <span style="font-size: 12px; color: #646970;">References</span>
                </div>
                <div>
                    <strong style="display: block; color: #d63638; font-size: 24px;"><?php echo esc_html($stats['h_index']); ?></strong>
                    <span style="font-size: 12px; color: #646970;">H-Index</span>
                </div>
            </div>
        </div>

        <!-- Add New Citation -->
        <div class="wjm-add-citation" style="background: white; padding: 15px; border: 1px solid #c3c4c7; border-radius: 4px; margin-bottom: 20px;">
            <h4 style="margin-top: 0;">Add Reference</h4>

            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Search for Paper</label>
                <input type="text" id="wjm-citation-search" class="widefat" placeholder="Search by title, DOI, or author..." />
                <div id="wjm-citation-search-results" style="margin-top: 10px;"></div>
            </div>

            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Or Enter DOI Manually</label>
                <input type="text" id="wjm-citation-doi" class="widefat" placeholder="10.xxxx/xxxxx" />
            </div>

            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Citation Text (Optional)</label>
                <textarea id="wjm-citation-text" class="widefat" rows="3" placeholder="Enter citation context or quote..."></textarea>
            </div>

            <button type="button" id="wjm-add-citation-btn" class="button button-primary">Add Citation</button>
        </div>

        <!-- Existing Citations (References) -->
        <div class="wjm-citations-list">
            <h4>References (<?php echo count($citations); ?>)</h4>

            <?php if (empty($citations)): ?>
                <p style="color: #646970; font-style: italic;">No references added yet.</p>
            <?php else: ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th width="5%">#</th>
                            <th width="40%">Citation</th>
                            <th width="20%">DOI/Paper</th>
                            <th width="15%">Method</th>
                            <th width="10%">Status</th>
                            <th width="10%">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="wjm-citations-tbody">
                        <?php foreach ($citations as $citation): ?>
                            <tr data-citation-id="<?php echo esc_attr($citation->id); ?>">
                                <td><?php echo esc_html($citation->citation_order); ?></td>
                                <td>
                                    <?php if ($citation->citation_text): ?>
                                        <?php echo wp_kses_post(wp_trim_words($citation->citation_text, 20)); ?>
                                    <?php else: ?>
                                        <em style="color: #646970;">No context provided</em>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($citation->cited_paper_id): ?>
                                        <?php $cited_post = get_post($citation->cited_paper_id); ?>
                                        <a href="<?php echo get_edit_post_link($citation->cited_paper_id); ?>" target="_blank">
                                            <?php echo esc_html($cited_post->post_title); ?>
                                        </a>
                                    <?php elseif ($citation->cited_doi): ?>
                                        <code><?php echo esc_html($citation->cited_doi); ?></code>
                                    <?php else: ?>
                                        <em style="color: #646970;">Unknown</em>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="wjm-badge" style="background: #f0f0f1; padding: 3px 8px; border-radius: 3px; font-size: 11px;">
                                        <?php echo esc_html($citation->extraction_method); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($citation->verified): ?>
                                        <span style="color: #00a32a;">✓ Verified</span>
                                    <?php else: ?>
                                        <span style="color: #dba617;">⚠ Unverified</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if (!$citation->verified): ?>
                                        <button type="button" class="button button-small wjm-verify-citation" data-citation-id="<?php echo esc_attr($citation->id); ?>">Verify</button>
                                    <?php endif; ?>
                                    <button type="button" class="button button-small wjm-delete-citation" data-citation-id="<?php echo esc_attr($citation->id); ?>">Delete</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Cited By Section -->
        <?php if (!empty($cited_by)): ?>
            <div class="wjm-cited-by-list" style="margin-top: 30px;">
                <h4>Cited By (<?php echo esc_html($stats['cited_by_count']); ?> papers)</h4>
                <ul style="list-style: none; padding: 0;">
                    <?php foreach ($cited_by as $citing_paper): ?>
                        <li style="padding: 10px; border-bottom: 1px solid #f0f0f1;">
                            <a href="<?php echo get_edit_post_link($citing_paper->ID); ?>" target="_blank" style="font-weight: 600;">
                                <?php echo esc_html($citing_paper->post_title); ?>
                            </a>
                            <br>
                            <small style="color: #646970;">
                                Cited on <?php echo esc_html(date('M d, Y', strtotime($citing_paper->citation_date))); ?>
                            </small>
                            <?php if ($citing_paper->citation_text): ?>
                                <br>
                                <em style="color: #50575e; font-size: 13px;">"<?php echo wp_kses_post(wp_trim_words($citing_paper->citation_text, 15)); ?>"</em>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
                <?php if ($stats['cited_by_count'] > 10): ?>
                    <a href="<?php echo admin_url('admin.php?page=wjm-citations&paper_id=' . $post->ID); ?>" class="button">View All Citations</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    </div>

    <style>
        .wjm-citation-search-result {
            padding: 10px;
            border: 1px solid #e0e0e0;
            margin-bottom: 5px;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .wjm-citation-search-result:hover {
            background: #f0f0f1;
            border-color: #2271b1;
        }
        .wjm-citation-search-result strong {
            display: block;
            margin-bottom: 5px;
        }
        .wjm-citation-search-result small {
            color: #646970;
        }
    </style>

    <?php
}

// ========================================
// AJAX HANDLERS
// ========================================

/**
 * AJAX: Search for papers to cite
 */
function wjm_ajax_search_papers_for_citation() {
    check_ajax_referer('wjm_citations_nonce', 'nonce');

    $search_term = sanitize_text_field($_POST['search_term']);

    // Search in papers
    $args = array(
        'post_type' => 'paper',
        'posts_per_page' => 10,
        's' => $search_term,
        'post_status' => 'publish'
    );

    // Also search by DOI in post meta
    $meta_query = array();
    if (preg_match('/^10\.\d{4,}/', $search_term)) {
        $meta_query = array(
            'relation' => 'OR',
            array(
                'key' => 'doi',
                'value' => $search_term,
                'compare' => 'LIKE'
            )
        );
        $args['meta_query'] = $meta_query;
    }

    $query = new WP_Query($args);
    $results = array();

    if ($query->have_posts()) {
        while ($query->have_posts()) {
            $query->the_post();
            $doi = get_post_meta(get_the_ID(), 'doi', true);
            $authors = get_post_meta(get_the_ID(), 'authors', true);

            $results[] = array(
                'id' => get_the_ID(),
                'title' => get_the_title(),
                'doi' => $doi,
                'authors' => $authors,
                'year' => get_the_date('Y')
            );
        }
        wp_reset_postdata();
    }

    wp_send_json_success($results);
}
add_action('wp_ajax_wjm_search_papers_for_citation', 'wjm_ajax_search_papers_for_citation');

/**
 * AJAX: Add citation
 */
function wjm_ajax_add_citation() {
    check_ajax_referer('wjm_citations_nonce', 'nonce');

    $paper_id = absint($_POST['paper_id']);
    $cited_paper_id = !empty($_POST['cited_paper_id']) ? absint($_POST['cited_paper_id']) : null;
    $cited_doi = !empty($_POST['cited_doi']) ? sanitize_text_field($_POST['cited_doi']) : null;
    $citation_text = !empty($_POST['citation_text']) ? wp_kses_post($_POST['citation_text']) : null;

    // Validate
    if (!$paper_id) {
        wp_send_json_error('Invalid paper ID');
    }

    if (!$cited_paper_id && !$cited_doi) {
        wp_send_json_error('Must provide either cited paper ID or DOI');
    }

    // Get current citation count for order
    global $wpdb;
    $citations_table = $wpdb->prefix . 'wjm_citations';
    $citation_order = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM `$citations_table` WHERE paper_id = %d",
        $paper_id
    )) + 1;

    $cited_data = array(
        'cited_paper_id' => $cited_paper_id,
        'cited_doi' => $cited_doi,
        'citation_text' => $citation_text,
        'citation_order' => $citation_order,
        'verified' => 1 // Auto-verify manual citations
    );

    $citation_id = wjm_add_citation($paper_id, $cited_data, 'manual');

    if (is_wp_error($citation_id)) {
        wp_send_json_error($citation_id->get_error_message());
    }

    wp_send_json_success(array(
        'citation_id' => $citation_id,
        'message' => 'Citation added successfully'
    ));
}
add_action('wp_ajax_wjm_add_citation', 'wjm_ajax_add_citation');

/**
 * AJAX: Delete citation
 */
function wjm_ajax_delete_citation() {
    check_ajax_referer('wjm_citations_nonce', 'nonce');

    $citation_id = absint($_POST['citation_id']);

    $result = wjm_delete_citation($citation_id);

    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
    }

    wp_send_json_success('Citation deleted successfully');
}
add_action('wp_ajax_wjm_delete_citation', 'wjm_ajax_delete_citation');

/**
 * AJAX: Verify citation
 */
function wjm_ajax_verify_citation() {
    check_ajax_referer('wjm_citations_nonce', 'nonce');

    $citation_id = absint($_POST['citation_id']);

    $result = wjm_verify_citation($citation_id, 1);

    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
    }

    wp_send_json_success('Citation verified successfully');
}
add_action('wp_ajax_wjm_verify_citation', 'wjm_ajax_verify_citation');

// ========================================
// ENQUEUE SCRIPTS
// ========================================

/**
 * Enqueue citation management scripts
 */
function wjm_enqueue_citation_scripts($hook) {
    global $post;

    if ($hook !== 'post.php' && $hook !== 'post-new.php') {
        return;
    }

    if (!$post || $post->post_type !== 'paper') {
        return;
    }

    wp_enqueue_script('wjm-citations', WJM_PLUGIN_URL . 'assets/js/citations.js', array('jquery'), WJM_VERSION, true);

    wp_localize_script('wjm-citations', 'wjmCitations', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('wjm_citations_nonce'),
        'paper_id' => $post->ID,
        'strings' => array(
            'confirm_delete' => 'Are you sure you want to delete this citation?',
            'error' => 'An error occurred. Please try again.',
            'success' => 'Citation saved successfully'
        )
    ));
}
add_action('admin_enqueue_scripts', 'wjm_enqueue_citation_scripts');

// ========================================
// SHORTCODES FOR FRONTEND
// ========================================

/**
 * Shortcode to display citation count
 */
function wjm_citation_count_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID()
    ), $atts);

    $stats = wjm_get_citation_stats($atts['paper_id']);

    return '<span class="wjm-citation-count">' . esc_html($stats['cited_by_count']) . '</span>';
}
add_shortcode('wjm_citation_count', 'wjm_citation_count_shortcode');

/**
 * Shortcode to display citations list
 */
function wjm_citations_list_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID(),
        'verified_only' => true
    ), $atts);

    $citations = wjm_get_paper_citations($atts['paper_id'], array(
        'verified_only' => $atts['verified_only']
    ));

    if (empty($citations)) {
        return '<p>No citations available.</p>';
    }

    ob_start();
    ?>
    <div class="wjm-citations-list">
        <h3>References</h3>
        <ol>
            <?php foreach ($citations as $citation): ?>
                <li>
                    <?php if ($citation->cited_paper_id): ?>
                        <?php $cited_post = get_post($citation->cited_paper_id); ?>
                        <a href="<?php echo get_permalink($citation->cited_paper_id); ?>">
                            <?php echo esc_html($cited_post->post_title); ?>
                        </a>
                    <?php elseif ($citation->cited_doi): ?>
                        DOI: <a href="https://doi.org/<?php echo esc_attr($citation->cited_doi); ?>" target="_blank">
                            <?php echo esc_html($citation->cited_doi); ?>
                        </a>
                    <?php endif; ?>

                    <?php if ($citation->citation_text): ?>
                        <div class="citation-context">
                            <?php echo wp_kses_post($citation->citation_text); ?>
                        </div>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ol>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_citations_list', 'wjm_citations_list_shortcode');
