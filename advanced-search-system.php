<?php
/**
 * Advanced Search System
 * Full-text search with indexing for papers
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// SEARCH INDEXING FUNCTIONS
// ========================================

/**
 * Index a paper for full-text search
 */
function wjm_index_paper($paper_id) {
    global $wpdb;
    $search_table = $wpdb->prefix . 'wjm_search_index';

    $post = get_post($paper_id);

    if (!$post || $post->post_type !== 'paper') {
        return false;
    }

    // Get all paper data for indexing
    $title = $post->post_title;
    $abstract = get_post_meta($paper_id, 'abstract', true);
    $authors = get_post_meta($paper_id, 'authors', true);
    $keywords = get_post_meta($paper_id, 'keywords', true);
    $content = $post->post_content;
    $doi = get_post_meta($paper_id, 'doi', true);

    // Index different content types separately
    $index_data = array(
        'title' => $title,
        'abstract' => $abstract,
        'authors' => $authors,
        'keywords' => $keywords,
        'content' => $content,
        'metadata' => implode(' ', array($doi, $authors, $keywords))
    );

    foreach ($index_data as $content_type => $content_text) {
        if (empty($content_text)) {
            continue;
        }

        // Check if entry exists
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM `$search_table` WHERE paper_id = %d AND content_type = %s",
            absint($paper_id),
            sanitize_text_field($content_type)
        ));

        $data = array(
            'paper_id' => absint($paper_id),
            'content_type' => sanitize_text_field($content_type),
            'content_text' => wp_kses_post($content_text),
            'updated_at' => current_time('mysql')
        );

        if ($exists) {
            // Update existing
            $wpdb->update(
                $search_table,
                $data,
                array(
                    'paper_id' => absint($paper_id),
                    'content_type' => sanitize_text_field($content_type)
                )
            );
        } else {
            // Insert new
            $wpdb->insert($search_table, $data);
        }
    }

    // Update post meta to track indexing
    update_post_meta($paper_id, '_wjm_indexed', current_time('mysql'));

    return true;
}

/**
 * Remove paper from search index
 */
function wjm_deindex_paper($paper_id) {
    global $wpdb;
    $search_table = $wpdb->prefix . 'wjm_search_index';

    $wpdb->delete($search_table, array('paper_id' => absint($paper_id)));

    delete_post_meta($paper_id, '_wjm_indexed');

    return true;
}

/**
 * Auto-index paper on save
 */
function wjm_auto_index_paper($post_id, $post, $update) {
    // Only index papers
    if ($post->post_type !== 'paper') {
        return;
    }

    // Only index published papers
    if ($post->post_status !== 'publish') {
        wjm_deindex_paper($post_id);
        return;
    }

    // Index the paper
    wjm_index_paper($post_id);
}
add_action('save_post', 'wjm_auto_index_paper', 10, 3);

/**
 * Remove from index when paper is deleted
 */
function wjm_auto_deindex_paper($post_id) {
    $post = get_post($post_id);

    if ($post && $post->post_type === 'paper') {
        wjm_deindex_paper($post_id);
    }
}
add_action('delete_post', 'wjm_auto_deindex_paper');

/**
 * Bulk index all papers
 */
function wjm_bulk_index_papers() {
    $args = array(
        'post_type' => 'paper',
        'post_status' => 'publish',
        'posts_per_page' => -1,
        'fields' => 'ids'
    );

    $paper_ids = get_posts($args);
    $indexed_count = 0;

    foreach ($paper_ids as $paper_id) {
        if (wjm_index_paper($paper_id)) {
            $indexed_count++;
        }
    }

    return $indexed_count;
}

// ========================================
// ADVANCED SEARCH FUNCTIONS
// ========================================

/**
 * Perform full-text search on papers
 */
function wjm_advanced_search($search_query, $args = array()) {
    global $wpdb;
    $search_table = $wpdb->prefix . 'wjm_search_index';
    $posts_table = $wpdb->prefix . 'posts';

    // Default arguments
    $defaults = array(
        'content_types' => array('title', 'abstract', 'authors', 'keywords', 'content', 'metadata'),
        'limit' => 50,
        'offset' => 0,
        'min_relevance' => 0,
        'order_by' => 'relevance', // relevance, date, title
        'filters' => array() // Additional filters (author, year, journal, etc.)
    );

    $args = wp_parse_args($args, $defaults);

    // Sanitize search query
    $search_query = sanitize_text_field($search_query);

    if (empty($search_query)) {
        return array();
    }

    // Build content type filter
    $content_type_placeholders = implode(',', array_fill(0, count($args['content_types']), '%s'));

    // Build the FULLTEXT MATCH query
    $sql = "SELECT
                s.paper_id,
                p.post_title,
                p.post_date,
                GROUP_CONCAT(s.content_type) as matched_types,
                MAX(MATCH(s.content_text) AGAINST (%s IN NATURAL LANGUAGE MODE)) as relevance
            FROM `$search_table` s
            INNER JOIN `$posts_table` p ON s.paper_id = p.ID
            WHERE MATCH(s.content_text) AGAINST (%s IN NATURAL LANGUAGE MODE)
            AND s.content_type IN ($content_type_placeholders)
            AND p.post_status = 'publish'";

    // Prepare query parameters
    $params = array_merge(
        array($search_query, $search_query),
        $args['content_types']
    );

    // Add filters
    if (!empty($args['filters']['author'])) {
        $sql .= " AND s.paper_id IN (SELECT post_id FROM {$wpdb->prefix}postmeta WHERE meta_key = 'authors' AND meta_value LIKE %s)";
        $params[] = '%' . $wpdb->esc_like($args['filters']['author']) . '%';
    }

    if (!empty($args['filters']['year'])) {
        $sql .= " AND YEAR(p.post_date) = %d";
        $params[] = absint($args['filters']['year']);
    }

    if (!empty($args['filters']['journal_id'])) {
        $sql .= " AND s.paper_id IN (SELECT post_id FROM {$wpdb->prefix}postmeta WHERE meta_key = 'journal_id' AND meta_value = %d)";
        $params[] = absint($args['filters']['journal_id']);
    }

    // Group by paper
    $sql .= " GROUP BY s.paper_id";

    // Filter by minimum relevance
    if ($args['min_relevance'] > 0) {
        $sql .= " HAVING relevance >= %f";
        $params[] = floatval($args['min_relevance']);
    }

    // Order by
    if ($args['order_by'] === 'relevance') {
        $sql .= " ORDER BY relevance DESC";
    } elseif ($args['order_by'] === 'date') {
        $sql .= " ORDER BY p.post_date DESC";
    } elseif ($args['order_by'] === 'title') {
        $sql .= " ORDER BY p.post_title ASC";
    }

    // Limit and offset
    $sql .= " LIMIT %d OFFSET %d";
    $params[] = absint($args['limit']);
    $params[] = absint($args['offset']);

    // Prepare and execute query
    $prepared_sql = $wpdb->prepare($sql, $params);
    $results = $wpdb->get_results($prepared_sql, ARRAY_A);

    // Enhance results with additional data
    foreach ($results as &$result) {
        $paper_id = $result['paper_id'];

        $result['doi'] = get_post_meta($paper_id, 'doi', true);
        $result['authors'] = get_post_meta($paper_id, 'authors', true);
        $result['abstract'] = get_post_meta($paper_id, 'abstract', true);
        $result['keywords'] = get_post_meta($paper_id, 'keywords', true);
        $result['permalink'] = get_permalink($paper_id);
        $result['citation_count'] = function_exists('wjm_get_citation_stats') ? wjm_get_citation_stats($paper_id)['cited_by_count'] : 0;
    }

    return $results;
}

/**
 * Get search suggestions/autocomplete
 */
function wjm_search_suggestions($partial_query, $limit = 10) {
    global $wpdb;
    $search_table = $wpdb->prefix . 'wjm_search_index';

    $partial_query = sanitize_text_field($partial_query);

    if (strlen($partial_query) < 2) {
        return array();
    }

    // Search for titles that start with or contain the query
    $sql = $wpdb->prepare(
        "SELECT DISTINCT content_text as suggestion
        FROM `$search_table`
        WHERE content_type = 'title'
        AND content_text LIKE %s
        LIMIT %d",
        '%' . $wpdb->esc_like($partial_query) . '%',
        absint($limit)
    );

    $results = $wpdb->get_col($sql);

    return $results;
}

/**
 * Get total search results count
 */
function wjm_search_count($search_query, $args = array()) {
    global $wpdb;
    $search_table = $wpdb->prefix . 'wjm_search_index';
    $posts_table = $wpdb->prefix . 'posts';

    $defaults = array(
        'content_types' => array('title', 'abstract', 'authors', 'keywords', 'content', 'metadata'),
        'filters' => array()
    );

    $args = wp_parse_args($args, $defaults);

    $search_query = sanitize_text_field($search_query);

    if (empty($search_query)) {
        return 0;
    }

    $content_type_placeholders = implode(',', array_fill(0, count($args['content_types']), '%s'));

    $sql = "SELECT COUNT(DISTINCT s.paper_id)
            FROM `$search_table` s
            INNER JOIN `$posts_table` p ON s.paper_id = p.ID
            WHERE MATCH(s.content_text) AGAINST (%s IN NATURAL LANGUAGE MODE)
            AND s.content_type IN ($content_type_placeholders)
            AND p.post_status = 'publish'";

    $params = array_merge(array($search_query), $args['content_types']);

    // Add filters
    if (!empty($args['filters']['author'])) {
        $sql .= " AND s.paper_id IN (SELECT post_id FROM {$wpdb->prefix}postmeta WHERE meta_key = 'authors' AND meta_value LIKE %s)";
        $params[] = '%' . $wpdb->esc_like($args['filters']['author']) . '%';
    }

    if (!empty($args['filters']['year'])) {
        $sql .= " AND YEAR(p.post_date) = %d";
        $params[] = absint($args['filters']['year']);
    }

    $prepared_sql = $wpdb->prepare($sql, $params);

    return absint($wpdb->get_var($prepared_sql));
}

// ========================================
// SAVED SEARCHES
// ========================================

/**
 * Save a search for a user
 */
function wjm_save_search($user_id, $search_name, $search_query, $search_filters = array(), $alert_enabled = false) {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_saved_searches';

    $data = array(
        'user_id' => absint($user_id),
        'search_name' => sanitize_text_field($search_name),
        'search_query' => sanitize_text_field($search_query),
        'search_filters' => maybe_serialize($search_filters),
        'alert_enabled' => absint($alert_enabled),
        'created_at' => current_time('mysql')
    );

    $result = $wpdb->insert($table, $data);

    if ($result === false) {
        return new WP_Error('db_error', 'Failed to save search');
    }

    return $wpdb->insert_id;
}

/**
 * Get saved searches for a user
 */
function wjm_get_saved_searches($user_id) {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_saved_searches';

    $results = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM `$table` WHERE user_id = %d ORDER BY created_at DESC",
        absint($user_id)
    ), ARRAY_A);

    // Unserialize filters
    foreach ($results as &$result) {
        $result['search_filters'] = maybe_unserialize($result['search_filters']);
    }

    return $results;
}

/**
 * Delete saved search
 */
function wjm_delete_saved_search($search_id, $user_id) {
    global $wpdb;
    $table = $wpdb->prefix . 'wjm_saved_searches';

    $result = $wpdb->delete(
        $table,
        array(
            'id' => absint($search_id),
            'user_id' => absint($user_id)
        )
    );

    return $result !== false;
}

// ========================================
// SEARCH SHORTCODE & FRONTEND
// ========================================

/**
 * Advanced search form shortcode
 */
function wjm_advanced_search_form_shortcode($atts) {
    $atts = shortcode_atts(array(
        'placeholder' => 'Search papers by title, author, keyword...',
        'show_filters' => 'yes'
    ), $atts);

    ob_start();
    ?>
    <div class="wjm-advanced-search-form">
        <form method="get" action="<?php echo esc_url(home_url('/papers')); ?>" class="wjm-search-form">
            <div class="wjm-search-input-wrapper">
                <input
                    type="text"
                    name="s"
                    id="wjm-search-input"
                    class="wjm-search-input"
                    placeholder="<?php echo esc_attr($atts['placeholder']); ?>"
                    value="<?php echo esc_attr(get_query_var('s')); ?>"
                    autocomplete="off"
                />
                <div id="wjm-search-suggestions" class="wjm-search-suggestions"></div>
            </div>

            <?php if ($atts['show_filters'] === 'yes'): ?>
                <div class="wjm-search-filters">
                    <select name="year" class="wjm-search-filter">
                        <option value="">All Years</option>
                        <?php
                        $current_year = date('Y');
                        for ($year = $current_year; $year >= $current_year - 20; $year--) {
                            $selected = (get_query_var('year') == $year) ? 'selected' : '';
                            echo "<option value='$year' $selected>$year</option>";
                        }
                        ?>
                    </select>

                    <select name="journal_id" class="wjm-search-filter">
                        <option value="">All Journals</option>
                        <?php
                        $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
                        foreach ($journals as $journal) {
                            $selected = (get_query_var('journal_id') == $journal->ID) ? 'selected' : '';
                            echo "<option value='" . esc_attr($journal->ID) . "' $selected>" . esc_html($journal->post_title) . "</option>";
                        }
                        ?>
                    </select>

                    <input type="text" name="author" class="wjm-search-filter" placeholder="Author name..." value="<?php echo esc_attr(get_query_var('author_name')); ?>" />
                </div>
            <?php endif; ?>

            <button type="submit" class="wjm-search-submit">
                <svg width="20" height="20" fill="currentColor">
                    <path d="M14.5 13h-.79l-.28-.27A6.5 6.5 0 0 0 15 8.5 6.5 6.5 0 1 0 8.5 15c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L19.49 18l-4.99-5zm-6 0C6.01 13 4 10.99 4 8.5S6.01 4 8.5 4 13 6.01 13 8.5 10.99 13 8.5 13z"/>
                </svg>
                Search
            </button>
        </form>
    </div>

    <style>
        .wjm-advanced-search-form {
            margin: 30px 0;
        }
        .wjm-search-form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .wjm-search-input-wrapper {
            position: relative;
        }
        .wjm-search-input {
            width: 100%;
            padding: 15px 20px;
            font-size: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 12px;
            transition: all 0.3s;
        }
        .wjm-search-input:focus {
            outline: none;
            border-color: #2271b1;
            box-shadow: 0 0 0 3px rgba(34, 113, 177, 0.1);
        }
        .wjm-search-suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-top: 5px;
            max-height: 300px;
            overflow-y: auto;
            display: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            z-index: 1000;
        }
        .wjm-search-suggestions.active {
            display: block;
        }
        .wjm-search-suggestion-item {
            padding: 12px 20px;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f1;
        }
        .wjm-search-suggestion-item:hover {
            background: #f0f6fc;
        }
        .wjm-search-filters {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }
        .wjm-search-filter {
            padding: 12px 15px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        .wjm-search-submit {
            padding: 15px 30px;
            background: linear-gradient(135deg, #2271b1 0%, #1e5a8e 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s;
        }
        .wjm-search-submit:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(34, 113, 177, 0.3);
        }
    </style>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_search_form', 'wjm_advanced_search_form_shortcode');

// ========================================
// AJAX HANDLERS
// ========================================

/**
 * AJAX: Get search suggestions
 */
function wjm_ajax_search_suggestions() {
    $query = isset($_GET['q']) ? sanitize_text_field($_GET['q']) : '';

    $suggestions = wjm_search_suggestions($query, 10);

    wp_send_json_success($suggestions);
}
add_action('wp_ajax_wjm_search_suggestions', 'wjm_ajax_search_suggestions');
add_action('wp_ajax_nopriv_wjm_search_suggestions', 'wjm_ajax_search_suggestions');

/**
 * AJAX: Perform advanced search
 */
function wjm_ajax_advanced_search() {
    $query = isset($_POST['query']) ? sanitize_text_field($_POST['query']) : '';
    $filters = isset($_POST['filters']) && is_array($_POST['filters']) ? array_map('sanitize_text_field', $_POST['filters']) : array();

    $results = wjm_advanced_search($query, array(
        'filters' => $filters,
        'limit' => 20
    ));

    $total = wjm_search_count($query, array('filters' => $filters));

    wp_send_json_success(array(
        'results' => $results,
        'total' => $total
    ));
}
add_action('wp_ajax_wjm_advanced_search', 'wjm_ajax_advanced_search');
add_action('wp_ajax_nopriv_wjm_advanced_search', 'wjm_ajax_advanced_search');

// ========================================
// ADMIN TOOLS
// ========================================

/**
 * Get indexing statistics
 */
function wjm_get_indexing_stats() {
    global $wpdb;
    $search_table = $wpdb->prefix . 'wjm_search_index';
    $posts_table = $wpdb->prefix . 'posts';

    $total_papers = $wpdb->get_var("SELECT COUNT(*) FROM `$posts_table` WHERE post_type = 'paper' AND post_status = 'publish'");

    $indexed_papers = $wpdb->get_var("SELECT COUNT(DISTINCT paper_id) FROM `$search_table`");

    $total_entries = $wpdb->get_var("SELECT COUNT(*) FROM `$search_table`");

    return array(
        'total_papers' => absint($total_papers),
        'indexed_papers' => absint($indexed_papers),
        'total_entries' => absint($total_entries),
        'coverage_percentage' => $total_papers > 0 ? round(($indexed_papers / $total_papers) * 100, 2) : 0
    );
}
