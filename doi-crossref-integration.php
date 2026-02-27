<?php
/**
 * DOI & Crossref Integration
 * Automatic metadata retrieval, citation data, and DOI validation
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// CROSSREF API FUNCTIONS
// ========================================

/**
 * Fetch paper metadata from Crossref by DOI
 */
function wjm_crossref_get_metadata($doi) {
    // Validate DOI format
    $doi_validation = wjm_validate_doi($doi);
    if (is_array($doi_validation) ? !$doi_validation['valid'] : !$doi_validation) {
        return new WP_Error('invalid_doi', is_array($doi_validation) ? $doi_validation['message'] : 'Invalid DOI format');
    }

    // Clean DOI (remove https://doi.org/ if present)
    $doi = preg_replace('#^https?://doi\.org/#i', '', $doi);

    // Crossref API endpoint
    $api_url = 'https://api.crossref.org/works/' . rawurlencode($doi);

    // Set custom user agent (Crossref recommends this)
    $args = array(
        'timeout' => 15,
        'headers' => array(
            'User-Agent' => 'WisdomJournalManager/2.0 (mailto:' . get_option('admin_email') . ')'
        )
    );

    // Make API request
    $response = wp_remote_get($api_url, $args);

    if (is_wp_error($response)) {
        return new WP_Error('api_error', 'Failed to connect to Crossref API: ' . $response->get_error_message());
    }

    $response_code = wp_remote_retrieve_response_code($response);

    if ($response_code !== 200) {
        if ($response_code === 404) {
            return new WP_Error('not_found', 'DOI not found in Crossref database');
        }
        return new WP_Error('api_error', 'Crossref API returned error: ' . $response_code);
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!isset($data['message'])) {
        return new WP_Error('parse_error', 'Failed to parse Crossref response');
    }

    $work = $data['message'];

    // Parse metadata
    $metadata = array(
        'doi' => $work['DOI'] ?? $doi,
        'title' => isset($work['title'][0]) ? $work['title'][0] : '',
        'authors' => wjm_crossref_parse_authors($work['author'] ?? array()),
        'abstract' => strip_tags($work['abstract'] ?? ''),
        'publication_date' => wjm_crossref_parse_date($work['published-print'] ?? $work['published-online'] ?? $work['created'] ?? null),
        'journal' => $work['container-title'][0] ?? '',
        'volume' => $work['volume'] ?? '',
        'issue' => $work['issue'] ?? '',
        'pages' => $work['page'] ?? '',
        'publisher' => $work['publisher'] ?? '',
        'issn' => isset($work['ISSN'][0]) ? $work['ISSN'][0] : '',
        'type' => $work['type'] ?? '',
        'url' => $work['URL'] ?? 'https://doi.org/' . $doi,
        'citations_count' => $work['is-referenced-by-count'] ?? 0,
        'references' => $work['reference'] ?? array()
    );

    return $metadata;
}

/**
 * Parse authors from Crossref data
 */
function wjm_crossref_parse_authors($authors_data) {
    if (empty($authors_data) || !is_array($authors_data)) {
        return '';
    }

    $authors = array();

    foreach ($authors_data as $author) {
        $name_parts = array();

        if (isset($author['given'])) {
            $name_parts[] = $author['given'];
        }

        if (isset($author['family'])) {
            $name_parts[] = $author['family'];
        }

        if (!empty($name_parts)) {
            $authors[] = implode(' ', $name_parts);
        }
    }

    return implode(', ', $authors);
}

/**
 * Parse date from Crossref data
 */
function wjm_crossref_parse_date($date_data) {
    if (!$date_data || !isset($date_data['date-parts'])) {
        return '';
    }

    $parts = $date_data['date-parts'][0] ?? array();

    if (empty($parts)) {
        return '';
    }

    // Date parts are [year, month, day]
    $year = $parts[0] ?? 0;
    $month = isset($parts[1]) ? str_pad($parts[1], 2, '0', STR_PAD_LEFT) : '01';
    $day = isset($parts[2]) ? str_pad($parts[2], 2, '0', STR_PAD_LEFT) : '01';

    if ($year > 0) {
        return "$year-$month-$day";
    }

    return '';
}

/**
 * Import paper from DOI
 */
function wjm_import_from_doi($doi, $additional_data = array()) {
    // Get metadata from Crossref
    $metadata = wjm_crossref_get_metadata($doi);

    if (is_wp_error($metadata)) {
        return $metadata;
    }

    // Check if paper already exists with this DOI
    $existing = get_posts(array(
        'post_type' => 'paper',
        'meta_key' => 'doi',
        'meta_value' => $metadata['doi'],
        'posts_per_page' => 1,
        'fields' => 'ids'
    ));

    if (!empty($existing)) {
        return new WP_Error('duplicate', 'A paper with this DOI already exists', array('paper_id' => $existing[0]));
    }

    // Create paper post
    $post_data = array(
        'post_type' => 'paper',
        'post_title' => $metadata['title'],
        'post_content' => $metadata['abstract'],
        'post_status' => 'draft', // Set as draft for review
        'post_date' => $metadata['publication_date'] ? $metadata['publication_date'] : current_time('mysql')
    );

    // Merge with additional data
    $post_data = array_merge($post_data, $additional_data);

    $paper_id = wp_insert_post($post_data);

    if (is_wp_error($paper_id)) {
        return $paper_id;
    }

    // Save metadata
    $meta_fields = array(
        'doi' => $metadata['doi'],
        'authors' => $metadata['authors'],
        'abstract' => $metadata['abstract'],
        'publication_date' => $metadata['publication_date'],
        'journal_name' => $metadata['journal'],
        'volume' => $metadata['volume'],
        'issue' => $metadata['issue'],
        'pages' => $metadata['pages'],
        'publisher' => $metadata['publisher'],
        'issn' => $metadata['issn'],
        'paper_type' => $metadata['type'],
        'external_url' => $metadata['url'],
        '_crossref_imported' => current_time('mysql'),
        '_crossref_citations_count' => $metadata['citations_count']
    );

    foreach ($meta_fields as $key => $value) {
        if (!empty($value)) {
            update_post_meta($paper_id, $key, $value);
        }
    }

    // Import references if available
    if (!empty($metadata['references'])) {
        wjm_import_crossref_references($paper_id, $metadata['references']);
    }

    // Index paper for search
    if (function_exists('wjm_index_paper')) {
        wjm_index_paper($paper_id);
    }

    // Log audit event
    if (function_exists('wjm_log_audit_event')) {
        wjm_log_audit_event('paper_imported_from_doi', array(
            'paper_id' => $paper_id,
            'doi' => $metadata['doi']
        ));
    }

    return array(
        'paper_id' => $paper_id,
        'metadata' => $metadata
    );
}

/**
 * Import references from Crossref data
 */
function wjm_import_crossref_references($paper_id, $references) {
    if (!function_exists('wjm_add_citation')) {
        return false;
    }

    $imported_count = 0;

    foreach ($references as $reference) {
        // Try to get DOI from reference
        $cited_doi = $reference['DOI'] ?? null;

        if (!$cited_doi) {
            continue;
        }

        // Build citation text
        $citation_parts = array();

        if (isset($reference['author'])) {
            $citation_parts[] = $reference['author'];
        }

        if (isset($reference['article-title'])) {
            $citation_parts[] = '"' . $reference['article-title'] . '"';
        }

        if (isset($reference['journal-title'])) {
            $citation_parts[] = $reference['journal-title'];
        }

        if (isset($reference['year'])) {
            $citation_parts[] = '(' . $reference['year'] . ')';
        }

        $citation_text = implode(', ', $citation_parts);

        // Check if cited paper exists in our database
        $cited_paper = get_posts(array(
            'post_type' => 'paper',
            'meta_key' => 'doi',
            'meta_value' => $cited_doi,
            'posts_per_page' => 1,
            'fields' => 'ids'
        ));

        $cited_data = array(
            'cited_doi' => $cited_doi,
            'citation_text' => $citation_text,
            'verified' => 1 // Auto-verify Crossref citations
        );

        if (!empty($cited_paper)) {
            $cited_data['cited_paper_id'] = $cited_paper[0];
        }

        $result = wjm_add_citation($paper_id, $cited_data, 'crossref');

        if (!is_wp_error($result)) {
            $imported_count++;
        }
    }

    return $imported_count;
}

/**
 * Update citation count from Crossref
 */
function wjm_update_crossref_citation_count($paper_id) {
    $doi = get_post_meta($paper_id, 'doi', true);

    if (!$doi) {
        return false;
    }

    $metadata = wjm_crossref_get_metadata($doi);

    if (is_wp_error($metadata)) {
        return false;
    }

    if (isset($metadata['citations_count'])) {
        update_post_meta($paper_id, '_crossref_citations_count', absint($metadata['citations_count']));
        update_post_meta($paper_id, '_crossref_last_updated', current_time('mysql'));

        return absint($metadata['citations_count']);
    }

    return false;
}

// ========================================
// META BOX FOR DOI IMPORT
// ========================================

/**
 * Add DOI Import meta box
 */
function wjm_add_doi_import_meta_box() {
    add_meta_box(
        'wjm_doi_import_meta_box',
        'Import from DOI',
        'wjm_doi_import_meta_box_callback',
        'paper',
        'side',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_doi_import_meta_box');

/**
 * DOI Import meta box callback
 */
function wjm_doi_import_meta_box_callback($post) {
    wp_nonce_field('wjm_doi_import', 'wjm_doi_import_nonce');

    $doi = get_post_meta($post->ID, 'doi', true);
    $crossref_imported = get_post_meta($post->ID, '_crossref_imported', true);
    $crossref_citations = get_post_meta($post->ID, '_crossref_citations_count', true);
    $last_updated = get_post_meta($post->ID, '_crossref_last_updated', true);
    ?>

    <div class="wjm-doi-import-wrapper">
        <?php if ($crossref_imported): ?>
            <div style="background: #d7f0d2; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
                <strong style="color: #00a32a;">✓ Imported from Crossref</strong>
                <br>
                <small style="color: #2c3338;">
                    <?php echo date('M d, Y', strtotime($crossref_imported)); ?>
                </small>
            </div>

            <?php if ($crossref_citations !== ''): ?>
                <div style="margin-bottom: 15px;">
                    <strong>Crossref Citations:</strong> <?php echo esc_html($crossref_citations); ?>
                    <?php if ($last_updated): ?>
                        <br>
                        <small style="color: #646970;">
                            Updated: <?php echo date('M d, Y', strtotime($last_updated)); ?>
                        </small>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <button type="button" id="wjm-update-crossref-data" class="button button-small" data-paper-id="<?php echo esc_attr($post->ID); ?>">
                Refresh Crossref Data
            </button>
        <?php else: ?>
            <p style="margin-top: 0; color: #646970; font-size: 13px;">
                Automatically fill paper metadata from DOI using Crossref API.
            </p>

            <div style="margin-bottom: 10px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">DOI</label>
                <input type="text" id="wjm-doi-input" class="widefat" placeholder="10.xxxx/xxxxx" value="<?php echo esc_attr($doi); ?>" />
            </div>

            <button type="button" id="wjm-fetch-doi-metadata" class="button button-primary button-small" data-paper-id="<?php echo esc_attr($post->ID); ?>">
                Fetch Metadata
            </button>

            <div id="wjm-doi-import-status" style="margin-top: 10px;"></div>
        <?php endif; ?>
    </div>

    <script>
    jQuery(document).ready(function($) {
        // Fetch metadata from DOI
        $('#wjm-fetch-doi-metadata').on('click', function() {
            var $btn = $(this);
            var doi = $('#wjm-doi-input').val().trim();
            var paperId = $btn.data('paper-id');
            var $status = $('#wjm-doi-import-status');

            if (!doi) {
                $status.html('<p style="color: #d63638;">Please enter a DOI</p>');
                return;
            }

            $btn.prop('disabled', true).text('Fetching...');
            $status.html('<p style="color: #646970;">Connecting to Crossref...</p>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_fetch_doi_metadata',
                    nonce: '<?php echo wp_create_nonce("wjm_doi_import"); ?>',
                    doi: doi,
                    paper_id: paperId
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<p style="color: #00a32a;">✓ Metadata fetched successfully! Refreshing page...</p>');

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
                    $btn.prop('disabled', false).text('Fetch Metadata');
                }
            });
        });

        // Update Crossref data
        $('#wjm-update-crossref-data').on('click', function() {
            var $btn = $(this);
            var paperId = $btn.data('paper-id');

            $btn.prop('disabled', true).text('Updating...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_update_crossref_citation_count',
                    nonce: '<?php echo wp_create_nonce("wjm_doi_import"); ?>',
                    paper_id: paperId
                },
                success: function(response) {
                    if (response.success) {
                        alert('Crossref data updated successfully!');
                        location.reload();
                    } else {
                        alert('Error: ' + response.data);
                    }
                },
                error: function() {
                    alert('Connection error. Please try again.');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Refresh Crossref Data');
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
 * AJAX: Fetch DOI metadata
 */
function wjm_ajax_fetch_doi_metadata() {
    check_ajax_referer('wjm_doi_import', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $doi = sanitize_text_field($_POST['doi']);
    $paper_id = absint($_POST['paper_id']);

    // Fetch metadata
    $metadata = wjm_crossref_get_metadata($doi);

    if (is_wp_error($metadata)) {
        wp_send_json_error($metadata->get_error_message());
    }

    // Update post with metadata
    $post_data = array(
        'ID' => $paper_id,
        'post_title' => $metadata['title'],
        'post_content' => $metadata['abstract']
    );

    wp_update_post($post_data);

    // Save metadata
    $meta_fields = array(
        'doi' => $metadata['doi'],
        'authors' => $metadata['authors'],
        'abstract' => $metadata['abstract'],
        'publication_date' => $metadata['publication_date'],
        'journal_name' => $metadata['journal'],
        'volume' => $metadata['volume'],
        'issue' => $metadata['issue'],
        'pages' => $metadata['pages'],
        'publisher' => $metadata['publisher'],
        'issn' => $metadata['issn'],
        'paper_type' => $metadata['type'],
        'external_url' => $metadata['url'],
        '_crossref_imported' => current_time('mysql'),
        '_crossref_citations_count' => $metadata['citations_count']
    );

    foreach ($meta_fields as $key => $value) {
        if (!empty($value)) {
            update_post_meta($paper_id, $key, $value);
        }
    }

    // Import references
    if (!empty($metadata['references']) && function_exists('wjm_add_citation')) {
        $ref_count = wjm_import_crossref_references($paper_id, $metadata['references']);
        $metadata['imported_references'] = $ref_count;
    }

    wp_send_json_success($metadata);
}
add_action('wp_ajax_wjm_fetch_doi_metadata', 'wjm_ajax_fetch_doi_metadata');

/**
 * AJAX: Update Crossref citation count
 */
function wjm_ajax_update_crossref_citation_count() {
    check_ajax_referer('wjm_doi_import', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $paper_id = absint($_POST['paper_id']);

    $result = wjm_update_crossref_citation_count($paper_id);

    if ($result === false) {
        wp_send_json_error('Failed to update citation count');
    }

    wp_send_json_success(array('citations_count' => $result));
}
add_action('wp_ajax_wjm_update_crossref_citation_count', 'wjm_ajax_update_crossref_citation_count');

// ========================================
// ADMIN TOOLS
// ========================================

/**
 * Bulk import papers from DOI list
 */
function wjm_bulk_import_from_dois($doi_list) {
    $results = array(
        'success' => array(),
        'failed' => array()
    );

    foreach ($doi_list as $doi) {
        $doi = trim($doi);

        if (empty($doi)) {
            continue;
        }

        $result = wjm_import_from_doi($doi);

        if (is_wp_error($result)) {
            $results['failed'][] = array(
                'doi' => $doi,
                'error' => $result->get_error_message()
            );
        } else {
            $results['success'][] = array(
                'doi' => $doi,
                'paper_id' => $result['paper_id']
            );
        }

        // Sleep to avoid rate limiting
        sleep(1);
    }

    return $results;
}

/**
 * Validate DOI (already exists in main plugin, but included here for completeness)
 */
if (!function_exists('wjm_validate_doi')) {
    function wjm_validate_doi($doi) {
        // Clean DOI
        $doi = trim($doi);
        $doi = preg_replace('#^https?://doi\.org/#i', '', $doi);

        // DOI format: 10.xxxx/xxxxx
        // The prefix is always 10.
        // Directory indicator is at least 4 digits
        // Suffix can contain any characters
        $pattern = '/^10\.\d{4,}(\.\d+)*\/[^\s]+$/';

        return preg_match($pattern, $doi) === 1;
    }
}
