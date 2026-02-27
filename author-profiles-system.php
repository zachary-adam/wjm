<?php
/**
 * Author Profiles & ORCID Integration System
 * Comprehensive author management with ORCID verification
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// AUTHOR CUSTOM POST TYPE
// ========================================

/**
 * Register Author custom post type
 */
function wjm_register_author_cpt() {
    $labels = array(
        'name' => 'Authors',
        'singular_name' => 'Author',
        'add_new' => 'Add New',
        'add_new_item' => 'Add New Author',
        'edit_item' => 'Edit Author',
        'new_item' => 'New Author',
        'view_item' => 'View Author',
        'search_items' => 'Search Authors',
        'not_found' => 'No authors found',
        'not_found_in_trash' => 'No authors found in trash',
        'all_items' => 'All Authors',
        'menu_name' => 'Authors',
        'name_admin_bar' => 'Author'
    );

    $args = array(
        'labels' => $labels,
        'public' => true,
        'publicly_queryable' => true,
        'show_ui' => true,
        'show_in_menu' => true,
        'query_var' => true,
        'rewrite' => array('slug' => 'author-profile'),
        'capability_type' => 'post',
        'has_archive' => true,
        'hierarchical' => false,
        'menu_position' => 26,
        'menu_icon' => 'dashicons-admin-users',
        'supports' => array('title', 'editor', 'thumbnail'),
        'show_in_rest' => true
    );

    register_post_type('wjm_author', $args);
}
add_action('init', 'wjm_register_author_cpt');

// ========================================
// ORCID API INTEGRATION
// ========================================

/**
 * Fetch author data from ORCID API
 */
function wjm_orcid_get_author_data($orcid_id) {
    // Validate ORCID format
    $orcid_validation = wjm_validate_orcid($orcid_id);
    if (is_array($orcid_validation) ? !$orcid_validation['valid'] : !$orcid_validation) {
        return new WP_Error('invalid_orcid', is_array($orcid_validation) ? $orcid_validation['message'] : 'Invalid ORCID format');
    }

    // Clean ORCID (remove https://orcid.org/ if present)
    $orcid_id = preg_replace('#^https?://orcid\.org/#i', '', $orcid_id);

    // ORCID Public API endpoint
    $api_url = 'https://pub.orcid.org/v3.0/' . rawurlencode($orcid_id);

    $args = array(
        'timeout' => 15,
        'headers' => array(
            'Accept' => 'application/json'
        )
    );

    // Fetch person data
    $response = wp_remote_get($api_url . '/person', $args);

    if (is_wp_error($response)) {
        return new WP_Error('api_error', 'Failed to connect to ORCID API: ' . $response->get_error_message());
    }

    $response_code = wp_remote_retrieve_response_code($response);

    if ($response_code !== 200) {
        if ($response_code === 404) {
            return new WP_Error('not_found', 'ORCID not found');
        }
        return new WP_Error('api_error', 'ORCID API returned error: ' . $response_code);
    }

    $body = wp_remote_retrieve_body($response);
    $person_data = json_decode($body, true);

    // Fetch works data
    $works_response = wp_remote_get($api_url . '/works', $args);
    $works_data = array();

    if (!is_wp_error($works_response) && wp_remote_retrieve_response_code($works_response) === 200) {
        $works_body = wp_remote_retrieve_body($works_response);
        $works_json = json_decode($works_body, true);
        $works_data = $works_json['group'] ?? array();
    }

    // Parse author data
    $author_data = wjm_parse_orcid_data($person_data, $works_data, $orcid_id);

    return $author_data;
}

/**
 * Parse ORCID API response
 */
function wjm_parse_orcid_data($person_data, $works_data, $orcid_id) {
    $name_data = $person_data['name'] ?? array();
    $bio_data = $person_data['biography'] ?? array();
    $emails = $person_data['emails']['email'] ?? array();
    $keywords = $person_data['keywords']['keyword'] ?? array();

    // Parse name
    $given_names = $name_data['given-names']['value'] ?? '';
    $family_name = $name_data['family-name']['value'] ?? '';
    $full_name = trim($given_names . ' ' . $family_name);

    // Parse biography
    $biography = $bio_data['content'] ?? '';

    // Parse email (first verified email)
    $email = '';
    foreach ($emails as $email_data) {
        if (isset($email_data['verified']) && $email_data['verified'] === true) {
            $email = $email_data['email'];
            break;
        }
    }

    // Parse keywords
    $keyword_list = array();
    foreach ($keywords as $keyword_data) {
        if (isset($keyword_data['content'])) {
            $keyword_list[] = $keyword_data['content'];
        }
    }

    // Parse works
    $publications = array();
    foreach ($works_data as $work_group) {
        $work_summary = $work_group['work-summary'][0] ?? null;

        if ($work_summary) {
            $title = $work_summary['title']['title']['value'] ?? '';
            $year = $work_summary['publication-date']['year']['value'] ?? '';
            $type = $work_summary['type'] ?? '';

            $external_ids = $work_summary['external-ids']['external-id'] ?? array();
            $doi = '';

            foreach ($external_ids as $external_id) {
                if ($external_id['external-id-type'] === 'doi') {
                    $doi = $external_id['external-id-value'];
                    break;
                }
            }

            $publications[] = array(
                'title' => $title,
                'year' => $year,
                'type' => $type,
                'doi' => $doi
            );
        }
    }

    return array(
        'orcid_id' => $orcid_id,
        'full_name' => $full_name,
        'given_names' => $given_names,
        'family_name' => $family_name,
        'biography' => $biography,
        'email' => $email,
        'keywords' => $keyword_list,
        'publications' => $publications,
        'publication_count' => count($publications),
        'orcid_url' => 'https://orcid.org/' . $orcid_id
    );
}

/**
 * Create author from ORCID
 */
function wjm_create_author_from_orcid($orcid_id) {
    // Fetch ORCID data
    $author_data = wjm_orcid_get_author_data($orcid_id);

    if (is_wp_error($author_data)) {
        return $author_data;
    }

    // Check if author already exists
    $existing = get_posts(array(
        'post_type' => 'wjm_author',
        'meta_key' => 'orcid_id',
        'meta_value' => $author_data['orcid_id'],
        'posts_per_page' => 1,
        'fields' => 'ids'
    ));

    if (!empty($existing)) {
        return new WP_Error('duplicate', 'Author with this ORCID already exists', array('author_id' => $existing[0]));
    }

    // Create author post
    $post_data = array(
        'post_type' => 'wjm_author',
        'post_title' => $author_data['full_name'],
        'post_content' => $author_data['biography'],
        'post_status' => 'publish'
    );

    $author_id = wp_insert_post($post_data);

    if (is_wp_error($author_id)) {
        return $author_id;
    }

    // Save metadata
    $meta_fields = array(
        'orcid_id' => $author_data['orcid_id'],
        'orcid_verified' => 1,
        'given_names' => $author_data['given_names'],
        'family_name' => $author_data['family_name'],
        'email' => $author_data['email'],
        'keywords' => implode(', ', $author_data['keywords']),
        'orcid_url' => $author_data['orcid_url'],
        'orcid_imported_date' => current_time('mysql'),
        'orcid_publication_count' => $author_data['publication_count']
    );

    foreach ($meta_fields as $key => $value) {
        if (!empty($value)) {
            update_post_meta($author_id, $key, $value);
        }
    }

    // Match and link publications
    wjm_link_orcid_publications($author_id, $author_data['publications']);

    // Calculate author metrics
    if (function_exists('wjm_calculate_author_metrics')) {
        wjm_calculate_author_metrics($author_id);
    }

    // Log audit event
    if (function_exists('wjm_log_audit_event')) {
        wjm_log_audit_event('author_created_from_orcid', array(
            'author_id' => $author_id,
            'orcid_id' => $author_data['orcid_id']
        ));
    }

    return array(
        'author_id' => $author_id,
        'author_data' => $author_data
    );
}

/**
 * Link ORCID publications to existing papers
 */
function wjm_link_orcid_publications($author_id, $publications) {
    $linked_count = 0;

    foreach ($publications as $publication) {
        if (empty($publication['doi'])) {
            continue;
        }

        // Find paper by DOI
        $paper = get_posts(array(
            'post_type' => 'paper',
            'meta_key' => 'doi',
            'meta_value' => $publication['doi'],
            'posts_per_page' => 1,
            'fields' => 'ids'
        ));

        if (!empty($paper)) {
            $paper_id = $paper[0];

            // Link author to paper
            $author_ids = get_post_meta($paper_id, 'author_ids', true);
            if (!$author_ids) {
                $author_ids = array();
            } elseif (!is_array($author_ids)) {
                $author_ids = array($author_ids);
            }

            if (!in_array($author_id, $author_ids)) {
                $author_ids[] = $author_id;
                update_post_meta($paper_id, 'author_ids', $author_ids);
                $linked_count++;
            }
        }
    }

    update_post_meta($author_id, 'linked_papers_count', $linked_count);

    return $linked_count;
}

// ========================================
// AUTHOR METRICS CALCULATION
// ========================================

/**
 * Calculate comprehensive author metrics
 */
function wjm_calculate_author_metrics($author_id) {
    global $wpdb;

    // Get all papers by this author
    $paper_ids = wjm_get_author_papers($author_id);

    if (empty($paper_ids)) {
        return array(
            'total_papers' => 0,
            'total_citations' => 0,
            'h_index' => 0,
            'i10_index' => 0
        );
    }

    // Get citation counts for each paper
    $citation_index_table = $wpdb->prefix . 'wjm_citation_index';
    $citation_counts = array();

    foreach ($paper_ids as $paper_id) {
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT cited_by_count FROM `$citation_index_table` WHERE paper_id = %d",
            $paper_id
        ));
        $citation_counts[] = absint($count);
    }

    // Sort citation counts in descending order
    rsort($citation_counts);

    // Calculate h-index
    $h_index = 0;
    foreach ($citation_counts as $index => $citations) {
        if ($citations >= ($index + 1)) {
            $h_index = $index + 1;
        } else {
            break;
        }
    }

    // Calculate i10-index (papers with 10+ citations)
    $i10_index = 0;
    foreach ($citation_counts as $citations) {
        if ($citations >= 10) {
            $i10_index++;
        }
    }

    // Total citations
    $total_citations = array_sum($citation_counts);

    // Get publication years
    $years = array();
    foreach ($paper_ids as $paper_id) {
        $post = get_post($paper_id);
        if ($post) {
            $years[] = date('Y', strtotime($post->post_date));
        }
    }

    $first_year = !empty($years) ? min($years) : null;
    $last_year = !empty($years) ? max($years) : null;

    // Save to author_metrics table
    $author_metrics_table = $wpdb->prefix . 'wjm_author_metrics';

    $data = array(
        'author_id' => absint($author_id),
        'total_papers' => count($paper_ids),
        'total_citations' => $total_citations,
        'h_index' => $h_index,
        'i10_index' => $i10_index,
        'first_publication_year' => $first_year,
        'last_publication_year' => $last_year,
        'updated_at' => current_time('mysql')
    );

    // Check if exists
    $exists = $wpdb->get_var($wpdb->prepare(
        "SELECT id FROM `$author_metrics_table` WHERE author_id = %d",
        absint($author_id)
    ));

    if ($exists) {
        $wpdb->update($author_metrics_table, $data, array('author_id' => absint($author_id)));
    } else {
        $wpdb->insert($author_metrics_table, $data);
    }

    // Save to post meta for quick access
    update_post_meta($author_id, '_metrics_h_index', $h_index);
    update_post_meta($author_id, '_metrics_i10_index', $i10_index);
    update_post_meta($author_id, '_metrics_total_citations', $total_citations);
    update_post_meta($author_id, '_metrics_total_papers', count($paper_ids));

    return $data;
}

/**
 * Get all papers by an author
 */
function wjm_get_author_papers($author_id) {
    global $wpdb;

    // Query papers where author_ids meta contains this author_id
    $query = $wpdb->prepare(
        "SELECT DISTINCT post_id
        FROM {$wpdb->postmeta} pm
        INNER JOIN {$wpdb->posts} p ON pm.post_id = p.ID
        WHERE pm.meta_key = 'author_ids'
        AND pm.meta_value LIKE %s
        AND p.post_type = 'paper'
        AND p.post_status = 'publish'",
        '%' . $wpdb->esc_like(serialize(strval($author_id))) . '%'
    );

    $paper_ids = $wpdb->get_col($query);

    return array_map('absint', $paper_ids);
}

/**
 * Get author metrics
 */
function wjm_get_author_metrics($author_id) {
    global $wpdb;
    $author_metrics_table = $wpdb->prefix . 'wjm_author_metrics';

    $metrics = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM `$author_metrics_table` WHERE author_id = %d",
        absint($author_id)
    ), ARRAY_A);

    if (!$metrics) {
        // Calculate if not found
        return wjm_calculate_author_metrics($author_id);
    }

    return $metrics;
}

// ========================================
// META BOXES
// ========================================

/**
 * Add Author Information meta box (for manual entry)
 */
function wjm_add_author_info_meta_box() {
    add_meta_box(
        'wjm_author_info_meta_box',
        'Author Information',
        'wjm_author_info_meta_box_callback',
        'wjm_author',
        'normal',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_author_info_meta_box');

/**
 * Author Information meta box callback
 */
function wjm_author_info_meta_box_callback($post) {
    wp_nonce_field('wjm_save_author_info', 'wjm_author_info_nonce');

    $email = get_post_meta($post->ID, 'email', true);
    $affiliation = get_post_meta($post->ID, 'affiliation', true);
    $website = get_post_meta($post->ID, 'website', true);
    $keywords = get_post_meta($post->ID, 'keywords', true);
    $given_names = get_post_meta($post->ID, 'given_names', true);
    $family_name = get_post_meta($post->ID, 'family_name', true);
    ?>

    <table class="form-table">
        <tr>
            <th><label for="wjm_given_names">Given Names (First Name)</label></th>
            <td>
                <input type="text" id="wjm_given_names" name="wjm_given_names" value="<?php echo esc_attr($given_names); ?>" class="regular-text" />
                <p class="description">Author's first/given name(s)</p>
            </td>
        </tr>
        <tr>
            <th><label for="wjm_family_name">Family Name (Last Name)</label></th>
            <td>
                <input type="text" id="wjm_family_name" name="wjm_family_name" value="<?php echo esc_attr($family_name); ?>" class="regular-text" />
                <p class="description">Author's last/family name</p>
            </td>
        </tr>
        <tr>
            <th><label for="wjm_email">Email Address</label></th>
            <td>
                <input type="email" id="wjm_email" name="wjm_email" value="<?php echo esc_attr($email); ?>" class="regular-text" />
                <p class="description">Contact email address</p>
            </td>
        </tr>
        <tr>
            <th><label for="wjm_affiliation">Affiliation</label></th>
            <td>
                <input type="text" id="wjm_affiliation" name="wjm_affiliation" value="<?php echo esc_attr($affiliation); ?>" class="regular-text" />
                <p class="description">Institution or organization</p>
            </td>
        </tr>
        <tr>
            <th><label for="wjm_website">Website URL</label></th>
            <td>
                <input type="url" id="wjm_website" name="wjm_website" value="<?php echo esc_attr($website); ?>" class="regular-text" />
                <p class="description">Personal or professional website</p>
            </td>
        </tr>
        <tr>
            <th><label for="wjm_keywords">Keywords</label></th>
            <td>
                <input type="text" id="wjm_keywords" name="wjm_keywords" value="<?php echo esc_attr($keywords); ?>" class="regular-text" />
                <p class="description">Research interests or keywords (comma-separated)</p>
            </td>
        </tr>
    </table>

    <style>
        #wjm_author_info_meta_box .form-table th {
            width: 200px;
            padding: 15px 10px 15px 0;
        }
        #wjm_author_info_meta_box .form-table td {
            padding: 15px 10px;
        }
    </style>
    <?php
}

/**
 * Save Author Information meta box data
 */
function wjm_save_author_info_meta_box($post_id) {
    // Check nonce
    if (!isset($_POST['wjm_author_info_nonce']) || !wp_verify_nonce($_POST['wjm_author_info_nonce'], 'wjm_save_author_info')) {
        return;
    }

    // Check autosave
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
        return;
    }

    // Check permissions
    if (!current_user_can('edit_post', $post_id)) {
        return;
    }

    // Save fields
    if (isset($_POST['wjm_given_names'])) {
        update_post_meta($post_id, 'given_names', sanitize_text_field($_POST['wjm_given_names']));
    }

    if (isset($_POST['wjm_family_name'])) {
        update_post_meta($post_id, 'family_name', sanitize_text_field($_POST['wjm_family_name']));
    }

    if (isset($_POST['wjm_email'])) {
        $email = sanitize_email($_POST['wjm_email']);
        update_post_meta($post_id, 'email', $email);
    }

    if (isset($_POST['wjm_affiliation'])) {
        update_post_meta($post_id, 'affiliation', sanitize_text_field($_POST['wjm_affiliation']));
    }

    if (isset($_POST['wjm_website'])) {
        $website = esc_url_raw($_POST['wjm_website']);
        update_post_meta($post_id, 'website', $website);
    }

    if (isset($_POST['wjm_keywords'])) {
        update_post_meta($post_id, 'keywords', sanitize_text_field($_POST['wjm_keywords']));
    }
}
add_action('save_post_wjm_author', 'wjm_save_author_info_meta_box');

/**
 * Add ORCID meta box to author edit screen
 */
function wjm_add_orcid_meta_box() {
    add_meta_box(
        'wjm_orcid_meta_box',
        'ORCID Integration',
        'wjm_orcid_meta_box_callback',
        'wjm_author',
        'side',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_orcid_meta_box');

/**
 * ORCID meta box callback
 */
function wjm_orcid_meta_box_callback($post) {
    wp_nonce_field('wjm_save_orcid', 'wjm_orcid_nonce');

    $orcid_id = get_post_meta($post->ID, 'orcid_id', true);
    $orcid_verified = get_post_meta($post->ID, 'orcid_verified', true);
    $orcid_imported_date = get_post_meta($post->ID, 'orcid_imported_date', true);
    ?>

    <div class="wjm-orcid-wrapper">
        <?php if ($orcid_verified): ?>
            <div style="background: #d7f0d2; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
                <strong style="color: #00a32a;">✓ ORCID Verified</strong>
                <br>
                <small style="color: #2c3338;">
                    <a href="https://orcid.org/<?php echo esc_attr($orcid_id); ?>" target="_blank">
                        <?php echo esc_html($orcid_id); ?>
                    </a>
                </small>
                <?php if ($orcid_imported_date): ?>
                    <br>
                    <small style="color: #646970;">
                        Imported: <?php echo date('M d, Y', strtotime($orcid_imported_date)); ?>
                    </small>
                <?php endif; ?>
            </div>

            <button type="button" id="wjm-refresh-orcid-btn" class="button button-small" data-author-id="<?php echo esc_attr($post->ID); ?>">
                Refresh from ORCID
            </button>
        <?php else: ?>
            <p style="margin-top: 0; color: #646970; font-size: 13px;">
                Import author data from ORCID profile.
            </p>

            <div style="margin-bottom: 10px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">ORCID iD</label>
                <input type="text" id="wjm-orcid-input" class="widefat" placeholder="0000-0000-0000-0000" value="<?php echo esc_attr($orcid_id); ?>" />
                <small style="color: #646970;">Format: 0000-0000-0000-0000</small>
            </div>

            <button type="button" id="wjm-import-orcid-btn" class="button button-primary button-small" data-author-id="<?php echo esc_attr($post->ID); ?>">
                Import from ORCID
            </button>

            <div id="wjm-orcid-status" style="margin-top: 10px;"></div>
        <?php endif; ?>
    </div>

    <script>
    jQuery(document).ready(function($) {
        // Import from ORCID
        $('#wjm-import-orcid-btn').on('click', function() {
            var $btn = $(this);
            var orcid = $('#wjm-orcid-input').val().trim();
            var authorId = $btn.data('author-id');
            var $status = $('#wjm-orcid-status');

            if (!orcid) {
                $status.html('<p style="color: #d63638;">Please enter an ORCID iD</p>');
                return;
            }

            $btn.prop('disabled', true).text('Importing...');
            $status.html('<p style="color: #646970;">Fetching data from ORCID...</p>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_import_from_orcid',
                    nonce: '<?php echo wp_create_nonce("wjm_save_orcid"); ?>',
                    orcid_id: orcid,
                    author_id: authorId
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<p style="color: #00a32a;">✓ Successfully imported from ORCID! Refreshing...</p>');
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        $status.html('<p style="color: #d63638;">Error: ' + response.data + '</p>');
                    }
                },
                error: function() {
                    $status.html('<p style="color: #d63638;">Connection error. Please try again.</p>');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Import from ORCID');
                }
            });
        });

        // Refresh ORCID data
        $('#wjm-refresh-orcid-btn').on('click', function() {
            var $btn = $(this);
            var authorId = $btn.data('author-id');

            $btn.prop('disabled', true).text('Refreshing...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_refresh_orcid_data',
                    nonce: '<?php echo wp_create_nonce("wjm_save_orcid"); ?>',
                    author_id: authorId
                },
                success: function(response) {
                    if (response.success) {
                        alert('ORCID data refreshed successfully!');
                        location.reload();
                    } else {
                        alert('Error: ' + response.data);
                    }
                },
                error: function() {
                    alert('Connection error. Please try again.');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Refresh from ORCID');
                }
            });
        });
    });
    </script>
    <?php
}

/**
 * Add Author Metrics meta box
 */
function wjm_add_author_metrics_meta_box() {
    add_meta_box(
        'wjm_author_metrics_meta_box',
        'Author Metrics',
        'wjm_author_metrics_meta_box_callback',
        'wjm_author',
        'side',
        'default'
    );
}
add_action('add_meta_boxes', 'wjm_add_author_metrics_meta_box');

/**
 * Author Metrics meta box callback
 */
function wjm_author_metrics_meta_box_callback($post) {
    $metrics = wjm_get_author_metrics($post->ID);
    ?>

    <div class="wjm-author-metrics">
        <style>
            .wjm-metric-row {
                padding: 12px;
                border-bottom: 1px solid #f0f0f1;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .wjm-metric-row:last-child {
                border-bottom: none;
            }
            .wjm-metric-label {
                font-size: 13px;
                color: #646970;
            }
            .wjm-metric-value {
                font-size: 20px;
                font-weight: 700;
                color: #2271b1;
            }
        </style>

        <div class="wjm-metric-row">
            <span class="wjm-metric-label">H-Index</span>
            <span class="wjm-metric-value"><?php echo esc_html($metrics['h_index'] ?? 0); ?></span>
        </div>

        <div class="wjm-metric-row">
            <span class="wjm-metric-label">i10-Index</span>
            <span class="wjm-metric-value"><?php echo esc_html($metrics['i10_index'] ?? 0); ?></span>
        </div>

        <div class="wjm-metric-row">
            <span class="wjm-metric-label">Total Papers</span>
            <span class="wjm-metric-value"><?php echo esc_html($metrics['total_papers'] ?? 0); ?></span>
        </div>

        <div class="wjm-metric-row">
            <span class="wjm-metric-label">Total Citations</span>
            <span class="wjm-metric-value"><?php echo esc_html($metrics['total_citations'] ?? 0); ?></span>
        </div>

        <?php if (!empty($metrics['first_publication_year'])): ?>
            <div class="wjm-metric-row">
                <span class="wjm-metric-label">Active Years</span>
                <span class="wjm-metric-value" style="font-size: 14px;">
                    <?php echo esc_html($metrics['first_publication_year']); ?> - <?php echo esc_html($metrics['last_publication_year']); ?>
                </span>
            </div>
        <?php endif; ?>

        <p style="text-align: center; margin: 15px 0 0 0;">
            <button type="button" id="wjm-recalculate-metrics-btn" class="button button-small" data-author-id="<?php echo esc_attr($post->ID); ?>">
                Recalculate Metrics
            </button>
        </p>
    </div>

    <script>
    jQuery(document).ready(function($) {
        $('#wjm-recalculate-metrics-btn').on('click', function() {
            var $btn = $(this);
            var authorId = $btn.data('author-id');

            $btn.prop('disabled', true).text('Calculating...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_recalculate_author_metrics',
                    author_id: authorId
                },
                success: function(response) {
                    if (response.success) {
                        alert('Metrics recalculated successfully!');
                        location.reload();
                    } else {
                        alert('Error calculating metrics');
                    }
                },
                error: function() {
                    alert('Connection error');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Recalculate Metrics');
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
 * AJAX: Import from ORCID
 */
function wjm_ajax_import_from_orcid() {
    check_ajax_referer('wjm_save_orcid', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $orcid_id = sanitize_text_field($_POST['orcid_id']);
    $author_id = absint($_POST['author_id']);

    // Fetch ORCID data
    $author_data = wjm_orcid_get_author_data($orcid_id);

    if (is_wp_error($author_data)) {
        wp_send_json_error($author_data->get_error_message());
    }

    // Update post
    $post_data = array(
        'ID' => $author_id,
        'post_title' => $author_data['full_name'],
        'post_content' => $author_data['biography']
    );

    wp_update_post($post_data);

    // Save metadata
    update_post_meta($author_id, 'orcid_id', $author_data['orcid_id']);
    update_post_meta($author_id, 'orcid_verified', 1);
    update_post_meta($author_id, 'given_names', $author_data['given_names']);
    update_post_meta($author_id, 'family_name', $author_data['family_name']);
    update_post_meta($author_id, 'email', $author_data['email']);
    update_post_meta($author_id, 'keywords', implode(', ', $author_data['keywords']));
    update_post_meta($author_id, 'orcid_url', $author_data['orcid_url']);
    update_post_meta($author_id, 'orcid_imported_date', current_time('mysql'));
    update_post_meta($author_id, 'orcid_publication_count', $author_data['publication_count']);

    // Link publications
    wjm_link_orcid_publications($author_id, $author_data['publications']);

    // Calculate metrics
    wjm_calculate_author_metrics($author_id);

    wp_send_json_success($author_data);
}
add_action('wp_ajax_wjm_import_from_orcid', 'wjm_ajax_import_from_orcid');

/**
 * AJAX: Refresh ORCID data
 */
function wjm_ajax_refresh_orcid_data() {
    check_ajax_referer('wjm_save_orcid', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $author_id = absint($_POST['author_id']);
    $orcid_id = get_post_meta($author_id, 'orcid_id', true);

    if (!$orcid_id) {
        wp_send_json_error('No ORCID ID found');
    }

    // Re-import
    $author_data = wjm_orcid_get_author_data($orcid_id);

    if (is_wp_error($author_data)) {
        wp_send_json_error($author_data->get_error_message());
    }

    // Update
    update_post_meta($author_id, 'orcid_publication_count', $author_data['publication_count']);
    update_post_meta($author_id, 'orcid_imported_date', current_time('mysql'));

    wjm_link_orcid_publications($author_id, $author_data['publications']);
    wjm_calculate_author_metrics($author_id);

    wp_send_json_success();
}
add_action('wp_ajax_wjm_refresh_orcid_data', 'wjm_ajax_refresh_orcid_data');

/**
 * AJAX: Recalculate author metrics
 */
function wjm_ajax_recalculate_author_metrics() {
    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $author_id = absint($_POST['author_id']);

    $metrics = wjm_calculate_author_metrics($author_id);

    wp_send_json_success($metrics);
}
add_action('wp_ajax_wjm_recalculate_author_metrics', 'wjm_ajax_recalculate_author_metrics');

// ========================================
// SHORTCODES
// ========================================

/**
 * Author profile shortcode
 */
function wjm_author_profile_shortcode($atts) {
    $atts = shortcode_atts(array(
        'author_id' => 0
    ), $atts);

    if (!$atts['author_id']) {
        return '<p>Author ID required</p>';
    }

    $author = get_post($atts['author_id']);

    if (!$author || $author->post_type !== 'wjm_author') {
        return '<p>Author not found</p>';
    }

    $orcid_id = get_post_meta($atts['author_id'], 'orcid_id', true);
    $metrics = wjm_get_author_metrics($atts['author_id']);
    $papers = wjm_get_author_papers($atts['author_id']);

    ob_start();
    ?>
    <div class="sjm-author-profile">
        <div class="sjm-author-profile-header">
            <?php if (has_post_thumbnail($atts['author_id'])): ?>
                <div class="sjm-author-photo">
                    <?php echo get_the_post_thumbnail($atts['author_id'], 'medium'); ?>
                </div>
            <?php endif; ?>

            <div class="sjm-author-profile-info">
                <h2><?php echo esc_html($author->post_title); ?></h2>

                <?php if ($orcid_id): ?>
                    <p>
                        <a href="https://orcid.org/<?php echo esc_attr($orcid_id); ?>" target="_blank" class="sjm-orcid-link">
                            <img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" alt="ORCID">
                            <?php echo esc_html($orcid_id); ?>
                        </a>
                    </p>
                <?php endif; ?>

                <div class="sjm-author-bio">
                    <?php echo wp_kses_post(wpautop($author->post_content)); ?>
                </div>
            </div>
        </div>

        <div class="sjm-author-metrics-display">
            <div class="sjm-metric-box">
                <div class="sjm-metric-value"><?php echo esc_html($metrics['h_index'] ?? 0); ?></div>
                <div class="sjm-metric-label">H-Index</div>
            </div>
            <div class="sjm-metric-box">
                <div class="sjm-metric-value"><?php echo esc_html($metrics['i10_index'] ?? 0); ?></div>
                <div class="sjm-metric-label">i10-Index</div>
            </div>
            <div class="sjm-metric-box">
                <div class="sjm-metric-value"><?php echo esc_html($metrics['total_papers'] ?? 0); ?></div>
                <div class="sjm-metric-label">Papers</div>
            </div>
            <div class="sjm-metric-box">
                <div class="sjm-metric-value"><?php echo esc_html($metrics['total_citations'] ?? 0); ?></div>
                <div class="sjm-metric-label">Citations</div>
            </div>
        </div>

        <?php if (!empty($papers)): ?>
            <div class="sjm-author-publications">
                <h3>Publications</h3>
                <ul>
                    <?php foreach ($papers as $paper_id): ?>
                        <?php $paper = get_post($paper_id); ?>
                        <li>
                            <a href="<?php echo get_permalink($paper_id); ?>">
                                <?php echo esc_html($paper->post_title); ?>
                            </a>
                            <small>(<?php echo date('Y', strtotime($paper->post_date)); ?>)</small>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_author_profile', 'wjm_author_profile_shortcode');
