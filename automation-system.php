<?php
/**
 * Citation & Views Automation System
 * 
 * This file provides automated citation and view tracking for academic papers
 * by integrating with multiple academic databases and APIs.
 * 
 * @package Wisdom Journal Manager
 * @version 1.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// CITATION & VIEWS AUTOMATION SYSTEM
// ========================================

/**
 * Mask API key for display - Security improvement
 * Shows only last 4 characters, rest are masked with asterisks
 *
 * @param string $encrypted_key The encrypted API key
 * @return string Masked key for display (e.g., "**********xyz1")
 */
function sjm_mask_api_key($encrypted_key) {
    if (empty($encrypted_key)) {
        return '';
    }

    // Show "Set" if key exists, or last 4 chars if we can decrypt
    if (strlen($encrypted_key) > 4) {
        $last_four = substr($encrypted_key, -4);
        return str_repeat('*', 12) . $last_four;
    }

    return str_repeat('*', 16);
}

// Add automation settings to the admin menu
function sjm_add_automation_settings_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Citation & Views Automation',
        'Automation',
        'manage_options',
        'sjm-automation',
        'sjm_automation_settings_page'
    );
}
add_action('admin_menu', 'sjm_add_automation_settings_page');

// Automation settings page
function sjm_automation_settings_page() {
    // Handle form submission
    if (isset($_POST['save_automation_settings']) && WJM_Security_Manager::validate_csrf_token($_POST['sjm_automation_nonce'], 'sjm_save_automation_settings')) {
        
        // Check user capabilities
        if (!WJM_Security_Manager::check_user_capability('api_access')) {
            wp_die('Insufficient permissions to save automation settings.');
        }
        
        // Get existing settings to preserve unchanged API keys
        $existing_settings = get_option('sjm_automation_settings', array());

        $settings = array(
            'enable_auto_citations' => isset($_POST['enable_auto_citations']) ? '1' : '0',
            'update_frequency' => WJM_Security_Manager::sanitize_input($_POST['update_frequency'], 'text'),
            'google_scholar_enabled' => isset($_POST['google_scholar_enabled']) ? '1' : '0',
            'scopus_enabled' => isset($_POST['scopus_enabled']) ? '1' : '0',
            'webofscience_enabled' => isset($_POST['webofscience_enabled']) ? '1' : '0',
            'crossref_enabled' => isset($_POST['crossref_enabled']) ? '1' : '0',
            'last_update' => current_time('mysql')
        );

        // Only update API keys if new values provided (not empty) - Security improvement
        $scopus_key_input = trim($_POST['scopus_api_key'] ?? '');
        if (!empty($scopus_key_input)) {
            $settings['scopus_api_key'] = WJM_Security_Manager::encrypt_api_key(WJM_Security_Manager::sanitize_input($scopus_key_input, 'api_key'));
        } else {
            // Keep existing key
            $settings['scopus_api_key'] = $existing_settings['scopus_api_key'] ?? '';
        }

        $wos_key_input = trim($_POST['webofscience_api_key'] ?? '');
        if (!empty($wos_key_input)) {
            $settings['webofscience_api_key'] = WJM_Security_Manager::encrypt_api_key(WJM_Security_Manager::sanitize_input($wos_key_input, 'api_key'));
        } else {
            // Keep existing key
            $settings['webofscience_api_key'] = $existing_settings['webofscience_api_key'] ?? '';
        }

        update_option('sjm_automation_settings', $settings);
        echo '<div class="notice notice-success"><p>Automation settings saved successfully!</p></div>';
    }
    
    $settings       = get_option('sjm_automation_settings', array());
    $recent_updates = get_option('sjm_automation_log', array());

    $frequencies = array(
        'daily'  => 'Daily',
        'weekly' => 'Weekly',
        'monthly'=> 'Monthly',
        'manual' => 'Manual Only',
    );

    $scopus_placeholder = !empty($settings['scopus_api_key'])
        ? 'Current: ' . sjm_mask_api_key($settings['scopus_api_key']) . ' (leave blank to keep)'
        : 'Enter your Scopus API key';

    $wos_placeholder = !empty($settings['webofscience_api_key'])
        ? 'Current: ' . sjm_mask_api_key($settings['webofscience_api_key']) . ' (leave blank to keep)'
        : 'Enter your Web of Science API key';
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Citation Automation</h1>
                <p class="wjm-page-description">Automatically fetch and update citation counts and view statistics</p>
            </div>
            <button type="button" id="sjm-manual-update-all" class="wjm-btn wjm-btn-secondary">
                Update All Papers Now
            </button>
            <span id="sjm-update-status" style="font-size:0.875rem;align-self:center;"></span>
        </div>

        <!-- Settings form -->
        <div class="wjm-card" style="margin-bottom:1.25rem;">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-admin-settings"></span>
                    General Settings
                </h2>
            </div>
            <div class="wjm-card-body">
                <form method="post" action="">
                    <?php wp_nonce_field('sjm_save_automation_settings', 'sjm_automation_nonce'); ?>
                    <table class="wjm-settings-table">
                        <tr>
                            <th><label for="enable_auto_citations">Citation Automation</label></th>
                            <td>
                                <label><input type="checkbox" id="enable_auto_citations" name="enable_auto_citations" value="1"
                                    <?php checked($settings['enable_auto_citations'] ?? '0', '1'); ?> />
                                    Automatically fetch citation counts
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="update_frequency">Update Frequency</label></th>
                            <td>
                                <select id="update_frequency" name="update_frequency" class="wjm-select">
                                    <?php foreach ($frequencies as $val => $lbl): ?>
                                        <option value="<?php echo esc_attr($val); ?>" <?php selected($settings['update_frequency'] ?? 'weekly', $val); ?>>
                                            <?php echo esc_html($lbl); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                        </tr>
                    </table>

                    <h3 style="font-size:0.8125rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--wjm-text-secondary);margin:1.5rem 0 0.75rem;">Data Sources</h3>
                    <table class="wjm-settings-table">
                        <tr>
                            <th>Google Scholar</th>
                            <td>
                                <label><input type="checkbox" id="google_scholar_enabled" name="google_scholar_enabled" value="1"
                                    <?php checked($settings['google_scholar_enabled'] ?? '1', '1'); ?> />
                                    Use Google Scholar (free, no API key required)
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th>CrossRef</th>
                            <td>
                                <label><input type="checkbox" id="crossref_enabled" name="crossref_enabled" value="1"
                                    <?php checked($settings['crossref_enabled'] ?? '1', '1'); ?> />
                                    Use CrossRef (free, DOI-based)
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th>Scopus</th>
                            <td>
                                <label><input type="checkbox" id="scopus_enabled" name="scopus_enabled" value="1"
                                    <?php checked($settings['scopus_enabled'] ?? '0', '1'); ?> />
                                    Use Scopus (requires API key)
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="scopus_api_key">Scopus API Key</label></th>
                            <td>
                                <input type="password" id="scopus_api_key" name="scopus_api_key" value="" class="wjm-input"
                                    placeholder="<?php echo esc_attr($scopus_placeholder); ?>" autocomplete="new-password" />
                                <?php if (!empty($settings['scopus_api_key'])): ?>
                                    <p class="description">Current key is set. Enter a new key to update.</p>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <th>Web of Science</th>
                            <td>
                                <label><input type="checkbox" id="webofscience_enabled" name="webofscience_enabled" value="1"
                                    <?php checked($settings['webofscience_enabled'] ?? '0', '1'); ?> />
                                    Use Web of Science (requires API key)
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="webofscience_api_key">Web of Science API Key</label></th>
                            <td>
                                <input type="password" id="webofscience_api_key" name="webofscience_api_key" value="" class="wjm-input"
                                    placeholder="<?php echo esc_attr($wos_placeholder); ?>" autocomplete="new-password" />
                                <?php if (!empty($settings['webofscience_api_key'])): ?>
                                    <p class="description">Current key is set. Enter a new key to update.</p>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </table>

                    <div style="margin-top:1rem;">
                        <button type="submit" name="save_automation_settings" class="wjm-btn wjm-btn-primary">Save Settings</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-backup"></span>
                    Recent Activity
                </h2>
            </div>
            <div class="wjm-card-body" style="padding:0;">
                <?php if (!empty($recent_updates)): ?>
                    <table class="wjm-table">
                        <thead>
                            <tr><th>Date</th><th>Action</th><th>Papers Updated</th><th>Status</th></tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($recent_updates, 0, 10) as $update): ?>
                                <tr>
                                    <td style="font-size:0.8125rem;"><?php echo esc_html($update['date']); ?></td>
                                    <td style="font-size:0.8125rem;"><?php echo esc_html($update['action']); ?></td>
                                    <td><?php echo esc_html($update['papers_updated']); ?></td>
                                    <td><span class="wjm-severity-badge wjm-severity-info"><?php echo esc_html($update['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div class="wjm-empty-state">
                        <span class="dashicons dashicons-clock"></span>
                        <p>No recent activity.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

    </div>
    <?php
    
    // JavaScript for manual updates
    echo '<script>
    jQuery(document).ready(function($) {
        $("#sjm-manual-update-all").click(function() {
            var button = $(this);
            var status = $("#sjm-update-status");
            
            button.prop("disabled", true).text("Updating...");
            status.text("Starting update...");
            
            $.post(ajaxurl, {
                action: "sjm_manual_update_citations_views",
                nonce: "' . wp_create_nonce('sjm_manual_update') . '"
            }, function(response) {
                if (response.success) {
                    status.html("<span style=\"color: green;\">✓ " + response.data.message + "</span>");
                    setTimeout(function() {
                        location.reload();
                    }, 2000);
                } else {
                    status.html("<span style=\"color: red;\">✗ " + response.data + "</span>");
                }
                button.prop("disabled", false).text("Update All Papers");
            });
        });
    });
    </script>';
}

// AJAX handler for manual updates
function sjm_manual_update_citations_views() {
    if (!wp_verify_nonce($_POST['nonce'], 'sjm_manual_update')) {
        wp_send_json_error('Security check failed.');
    }
    
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Permission denied.');
    }
    
    $result = sjm_update_all_papers_citations_views();
    
    if ($result['success']) {
        wp_send_json_success(array('message' => $result['message']));
    } else {
        wp_send_json_error($result['message']);
    }
}
add_action('wp_ajax_sjm_manual_update_citations_views', 'sjm_manual_update_citations_views');

// Main function to update all papers
function sjm_update_all_papers_citations_views() {
    $settings = get_option('sjm_automation_settings', array());
    
    if (empty($settings['enable_auto_citations'])) {
        return array('success' => false, 'message' => 'Automation is disabled in settings.');
    }
    
    $papers = get_posts(array(
        'post_type' => 'paper',
        'posts_per_page' => -1,
        'post_status' => 'publish'
    ));
    
    $updated_count = 0;
    $errors = array();
    
    foreach ($papers as $paper) {
        $result = sjm_update_paper_citations_views($paper->ID);
        if ($result['success']) {
            $updated_count++;
        } else {
            $errors[] = $result['message'];
        }
    }
    
    // Log the activity
    $log_entry = array(
        'date' => current_time('mysql'),
        'action' => 'Manual Update',
        'papers_updated' => $updated_count . '/' . count($papers),
        'status' => empty($errors) ? 'Success' : 'Partial Success'
    );
    
    $log = get_option('sjm_automation_log', array());
    array_unshift($log, $log_entry);
    $log = array_slice($log, 0, 50); // Keep only last 50 entries
    update_option('sjm_automation_log', $log);
    
    $message = "Updated $updated_count papers successfully.";
    if (!empty($errors)) {
        $message .= " Errors: " . implode(', ', array_slice($errors, 0, 3));
    }
    
    return array('success' => true, 'message' => $message);
}

// Update citations and views for a single paper
function sjm_update_paper_citations_views($paper_id) {
    $settings = get_option('sjm_automation_settings', array());
    $doi = get_post_meta($paper_id, '_sjm_paper_doi', true);
    $title = get_the_title($paper_id);
    $authors = sjm_get_paper_authors_string($paper_id);
    
    $total_citations = 0;
    $total_views = 0;
    $sources_used = array();
    
    // Google Scholar (if enabled)
    if (!empty($settings['google_scholar_enabled'])) {
        $gs_data = sjm_fetch_google_scholar_data($title, $authors, $doi);
        if ($gs_data['success']) {
            $total_citations += $gs_data['citations'];
            $total_views += $gs_data['views'];
            $sources_used[] = 'Google Scholar';
        }
    }
    
    // CrossRef (if enabled)
    if (!empty($settings['crossref_enabled']) && !empty($doi)) {
        $crossref_data = sjm_fetch_crossref_data($doi);
        if ($crossref_data['success']) {
            $total_citations += $crossref_data['citations'];
            $sources_used[] = 'CrossRef';
        }
    }
    
    // Scopus (if enabled and API key provided)
    if (!empty($settings['scopus_enabled']) && !empty($settings['scopus_api_key'])) {
        $scopus_data = sjm_fetch_scopus_data($doi, $title, $settings['scopus_api_key']);
        if ($scopus_data['success']) {
            $total_citations += $scopus_data['citations'];
            $sources_used[] = 'Scopus';
        }
    }
    
    // Web of Science (if enabled and API key provided)
    if (!empty($settings['webofscience_enabled']) && !empty($settings['webofscience_api_key'])) {
        $wos_data = sjm_fetch_webofscience_data($doi, $title, $settings['webofscience_api_key']);
        if ($wos_data['success']) {
            $total_citations += $wos_data['citations'];
            $sources_used[] = 'Web of Science';
        }
    }
    
    // Update the paper metadata
    if (!empty($settings['enable_auto_citations'])) {
        if (is_numeric($total_citations) && $total_citations > 0) {
            update_post_meta($paper_id, '_sjm_citation_count', $total_citations);
        } else {
            update_post_meta($paper_id, '_sjm_citation_count', 0);
        }
    }

    if (!empty($settings['enable_auto_views'])) {
        if (is_numeric($total_views) && $total_views > 0) {
            update_post_meta($paper_id, '_sjm_views_count', $total_views);
        } else {
            update_post_meta($paper_id, '_sjm_views_count', 0);
        }
    }
    
    // Store automation metadata
    update_post_meta($paper_id, '_sjm_last_automation_update', current_time('mysql'));
    update_post_meta($paper_id, '_sjm_automation_sources', implode(', ', $sources_used));
    
    return array(
        'success' => true,
        'citations' => $total_citations,
        'views' => $total_views,
        'sources' => $sources_used
    );
}

// Enhanced academic data fetching with multiple sources
function sjm_fetch_academic_data($title, $authors, $doi) {
    $results = array(
        'citations' => 0,
        'views' => 0,
        'sources' => array()
    );
    
    // Advanced rate limiting check with user feedback
    $rate_limit_result = WJM_Security_Manager::check_rate_limit('data_fetch', get_current_user_id());
    
    if (!$rate_limit_result['allowed']) {
        $reset_time = date('H:i', $rate_limit_result['reset_time']);
        return array(
            'success' => false, 
            'message' => sprintf(
                'Rate limit exceeded. You can make %d more requests after %s. Contact an administrator if you need higher limits.',
                $rate_limit_result['remaining'],
                $reset_time
            )
        );
    }
    
    // 1. CrossRef (most reliable, free, DOI-based)
    if (!empty($doi)) {
        $crossref_data = sjm_fetch_crossref_data($doi);
        if ($crossref_data['success']) {
            $results['citations'] += $crossref_data['citations'];
            $results['sources'][] = 'CrossRef';
        }
    }
    
    // 2. Semantic Scholar API (free, reliable alternative to Google Scholar)
    $semantic_data = sjm_fetch_semantic_scholar_data($title, $authors, $doi);
    if ($semantic_data['success']) {
        $results['citations'] = max($results['citations'], $semantic_data['citations']);
        $results['views'] = max($results['views'], $semantic_data['views']);
        $results['sources'][] = 'Semantic Scholar';
    }
    
    // 3. arXiv API (if paper has arXiv ID)
    $arxiv_id = sjm_extract_arxiv_id($doi, $title);
    if ($arxiv_id) {
        $arxiv_data = sjm_fetch_arxiv_data($arxiv_id);
        if ($arxiv_data['success']) {
            $results['views'] = max($results['views'], $arxiv_data['views']);
            $results['sources'][] = 'arXiv';
        }
    }
    
    // Log successful data fetch
    WJM_Security_Manager::log_security_event('academic_data_fetched', array(
        'title' => substr($title, 0, 100),
        'doi' => $doi,
        'sources' => $results['sources']
    ), 'info');
    
    return array(
        'success' => true,
        'citations' => $results['citations'],
        'views' => $results['views'],
        'sources' => $results['sources']
    );
}

// Semantic Scholar API (reliable alternative to Google Scholar)
function sjm_fetch_semantic_scholar_data($title, $authors, $doi) {
    $search_query = urlencode($title);
    $url = "https://api.semanticscholar.org/graph/v1/paper/search?query=" . $search_query . "&limit=1";
    
    $response = wp_remote_get($url, array(
        'timeout' => 15,
        'headers' => array(
            'User-Agent' => 'Wisdom Journal Manager/1.0 (mailto:admin@example.com)'
        )
    ));
    
    if (is_wp_error($response)) {
        return array('success' => false, 'message' => 'Failed to fetch Semantic Scholar data');
    }
    
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);
    
    if (!$data || !isset($data['data']) || empty($data['data'])) {
        return array('success' => false, 'message' => 'No data found in Semantic Scholar');
    }
    
    $paper = $data['data'][0];
    $citations = isset($paper['citationCount']) ? intval($paper['citationCount']) : 0;
    $views = isset($paper['viewCount']) ? intval($paper['viewCount']) : 0;
    
    return array(
        'success' => true,
        'citations' => $citations,
        'views' => $views
    );
}

// arXiv API integration
function sjm_fetch_arxiv_data($arxiv_id) {
    $url = "http://export.arxiv.org/api/query?id_list=" . urlencode($arxiv_id);
    
    $response = wp_remote_get($url, array(
        'timeout' => 15,
        'headers' => array(
            'User-Agent' => 'Wisdom Journal Manager/1.0'
        )
    ));
    
    if (is_wp_error($response)) {
        return array('success' => false, 'message' => 'Failed to fetch arXiv data');
    }
    
    $body = wp_remote_retrieve_body($response);
    
    // Parse XML response
    $xml = simplexml_load_string($body);
    if (!$xml) {
        return array('success' => false, 'message' => 'Invalid arXiv response');
    }
    
    $views = 0;
    // Note: arXiv doesn't provide view counts via API, but we can track downloads
    if (isset($xml->entry)) {
        $entry = $xml->entry;
        // Extract download count if available
        if (isset($entry->link)) {
            foreach ($entry->link as $link) {
                if ((string)$link['title'] === 'pdf') {
                    // Could implement download tracking here
                    $views = 0; // Placeholder
                    break;
                }
            }
        }
    }
    
    return array(
        'success' => true,
        'views' => $views
    );
}

// Extract arXiv ID from DOI or title
function sjm_extract_arxiv_id($doi, $title) {
    // Check if DOI contains arXiv reference
    if (strpos($doi, 'arxiv') !== false) {
        preg_match('/arxiv\.org\/(abs\/)?(\d+\.\d+)/', $doi, $matches);
        if (isset($matches[2])) {
            return $matches[2];
        }
    }
    
    // Check title for arXiv reference
    if (preg_match('/arxiv:(\d+\.\d+)/i', $title, $matches)) {
        return $matches[1];
    }
    
    return null;
}

// CrossRef data fetching
function sjm_fetch_crossref_data($doi) {
    $url = "https://api.crossref.org/works/" . urlencode($doi);
    
    $response = wp_remote_get($url, array(
        'timeout' => 30,
        'headers' => array(
            'User-Agent' => 'Wisdom Journal Manager/1.0 (mailto:admin@example.com)'
        )
    ));
    
    if (is_wp_error($response)) {
        return array('success' => false, 'message' => 'Failed to fetch CrossRef data');
    }
    
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);
    
    if (!$data || !isset($data['message'])) {
        return array('success' => false, 'message' => 'Invalid CrossRef response');
    }
    
    // Extract citation count if available
    $citations = 0;
    if (isset($data['message']['is-referenced-by-count'])) {
        $citations = intval($data['message']['is-referenced-by-count']);
    }
    
    return array(
        'success' => true,
        'citations' => $citations
    );
}

// Scopus data fetching with encrypted API key
function sjm_fetch_scopus_data($doi, $title, $encrypted_api_key) {
    if (empty($doi)) {
        return array('success' => false, 'message' => 'DOI required for Scopus');
    }
    
    // Decrypt API key
    $api_key = WJM_Security_Manager::decrypt_api_key($encrypted_api_key);
    if (empty($api_key)) {
        return array('success' => false, 'message' => 'Invalid Scopus API key');
    }
    
    // Advanced rate limiting for API calls
    $rate_limit_result = WJM_Security_Manager::check_rate_limit('api_call', get_current_user_id());
    
    if (!$rate_limit_result['allowed']) {
        $reset_time = date('H:i', $rate_limit_result['reset_time']);
        return array(
            'success' => false, 
            'message' => sprintf(
                'API rate limit exceeded. You can make %d more API calls after %s.',
                $rate_limit_result['remaining'],
                $reset_time
            )
        );
    }
    
    $url = "https://api.elsevier.com/content/search/scopus?query=DOI(" . urlencode($doi) . ")&apiKey=" . urlencode($api_key);
    
    $response = wp_remote_get($url, array(
        'timeout' => 30,
        'headers' => array(
            'Accept' => 'application/json'
        )
    ));
    
    if (is_wp_error($response)) {
        WJM_Security_Manager::log_security_event('scopus_api_error', array('doi' => $doi, 'error' => $response->get_error_message()), 'error');
        return array('success' => false, 'message' => 'Failed to fetch Scopus data');
    }
    
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);
    
    if (!$data || !isset($data['search-results'])) {
        return array('success' => false, 'message' => 'Invalid Scopus response');
    }
    
    $citations = 0;
    if (isset($data['search-results']['entry'][0]['citedby-count'])) {
        $citations = intval($data['search-results']['entry'][0]['citedby-count']);
    }
    
    // Log successful API call
    WJM_Security_Manager::log_security_event('scopus_api_success', array('doi' => $doi, 'citations' => $citations), 'info');
    
    return array(
        'success' => true,
        'citations' => $citations
    );
}

// Web of Science data fetching with encrypted API key
function sjm_fetch_webofscience_data($doi, $title, $encrypted_api_key) {
    if (empty($doi)) {
        return array('success' => false, 'message' => 'DOI required for Web of Science');
    }
    
    // Decrypt API key
    $api_key = WJM_Security_Manager::decrypt_api_key($encrypted_api_key);
    if (empty($api_key)) {
        return array('success' => false, 'message' => 'Invalid Web of Science API key');
    }
    
    // Advanced rate limiting for API calls
    $rate_limit_result = WJM_Security_Manager::check_rate_limit('api_call', get_current_user_id());
    
    if (!$rate_limit_result['allowed']) {
        $reset_time = date('H:i', $rate_limit_result['reset_time']);
        return array(
            'success' => false, 
            'message' => sprintf(
                'API rate limit exceeded. You can make %d more API calls after %s.',
                $rate_limit_result['remaining'],
                $reset_time
            )
        );
    }
    
    $url = "https://ws.clarivate.com/apis/wos/v1/search";
    
    $response = wp_remote_post($url, array(
        'timeout' => 30,
        'headers' => array(
            'X-ApiKey' => $api_key,
            'Content-Type' => 'application/json'
        ),
        'body' => json_encode(array(
            'query' => "DO=" . $doi,
            'count' => 1,
            'firstRecord' => 1
        ))
    ));
    
    if (is_wp_error($response)) {
        WJM_Security_Manager::log_security_event('webofscience_api_error', array('doi' => $doi, 'error' => $response->get_error_message()), 'error');
        return array('success' => false, 'message' => 'Failed to fetch Web of Science data');
    }
    
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);
    
    if (!$data || !isset($data['Records'])) {
        return array('success' => false, 'message' => 'Invalid Web of Science response');
    }
    
    $citations = 0;
    if (isset($data['Records']['REC'][0]['dynamic_data']['citation_related']['tc_list']['silo_tc']['local_count'])) {
        $citations = intval($data['Records']['REC'][0]['dynamic_data']['citation_related']['tc_list']['silo_tc']['local_count']);
    }
    
    // Log successful API call
    WJM_Security_Manager::log_security_event('webofscience_api_success', array('doi' => $doi, 'citations' => $citations), 'info');
    
    return array(
        'success' => true,
        'citations' => $citations
    );
}

// Scheduled automation (if enabled)
function sjm_schedule_automation() {
    $settings = get_option('sjm_automation_settings', array());
    
    if (empty($settings['enable_auto_citations'])) {
        return;
    }
    
    $frequency = $settings['update_frequency'] ?? 'weekly';
    
    if ($frequency === 'manual') {
        return;
    }
    
    // Schedule the event if not already scheduled
    if (!wp_next_scheduled('sjm_automation_update')) {
        wp_schedule_event(time(), $frequency, 'sjm_automation_update');
    }
}
add_action('init', 'sjm_schedule_automation');

// Hook for scheduled updates
function sjm_run_scheduled_automation() {
    $settings = get_option('sjm_automation_settings', array());
    
    if (empty($settings['enable_auto_citations'])) {
        return;
    }
    
    $result = sjm_update_all_papers_citations_views();
    
    // Log the scheduled activity
    $log_entry = array(
        'date' => current_time('mysql'),
        'action' => 'Scheduled Update',
        'papers_updated' => $result['success'] ? 'Completed' : 'Failed',
        'status' => $result['success'] ? 'Success' : 'Error'
    );
    
    $log = get_option('sjm_automation_log', array());
    array_unshift($log, $log_entry);
    $log = array_slice($log, 0, 50);
    update_option('sjm_automation_log', $log);
}
add_action('sjm_automation_update', 'sjm_run_scheduled_automation');

// Add automation status to paper edit screen
function sjm_add_automation_status_meta_box() {
    add_meta_box(
        'sjm_automation_status',
        'Automation Status',
        'sjm_automation_status_meta_box',
        'paper',
        'side'
    );
}
add_action('add_meta_boxes', 'sjm_add_automation_status_meta_box');

function sjm_automation_status_meta_box($post) {
    $last_update = get_post_meta($post->ID, '_sjm_last_automation_update', true);
    $sources = get_post_meta($post->ID, '_sjm_automation_sources', true);
    $citation_count = get_post_meta($post->ID, '_sjm_citation_count', true);
    $views_count = get_post_meta($post->ID, '_sjm_views_count', true);
    
    echo '<div style="padding: 10px;">';
    
    if ($last_update) {
        echo '<p><strong>Last Updated:</strong><br>' . esc_html($last_update) . '</p>';
    } else {
        echo '<p><em>No automation data available</em></p>';
    }
    
    if ($sources) {
        echo '<p><strong>Sources:</strong><br>' . esc_html($sources) . '</p>';
    }
    
    if ($citation_count) {
        echo '<p><strong>Citations:</strong> ' . esc_html($citation_count) . '</p>';
    }
    
    if ($views_count) {
        echo '<p><strong>Views:</strong> ' . esc_html($views_count) . '</p>';
    }
    
    echo '<button type="button" id="sjm-update-this-paper" class="button button-secondary" data-paper-id="' . $post->ID . '">Update This Paper</button>';
    echo '<span id="sjm-update-status-' . $post->ID . '" style="margin-left: 10px;"></span>';
    
    echo '</div>';
    
    echo '<script>
    jQuery(document).ready(function($) {
        $("#sjm-update-this-paper").click(function() {
            var button = $(this);
            var paperId = button.data("paper-id");
            var status = $("#sjm-update-status-" + paperId);
            
            button.prop("disabled", true).text("Updating...");
            status.text("Updating...");
            
            $.post(ajaxurl, {
                action: "sjm_update_single_paper",
                paper_id: paperId,
                nonce: "' . wp_create_nonce('sjm_update_single_paper') . '"
            }, function(response) {
                if (response.success) {
                    status.html("<span style=\"color: green;\">✓ Updated</span>");
                    setTimeout(function() {
                        location.reload();
                    }, 1000);
                } else {
                    status.html("<span style=\"color: red;\">✗ " + response.data + "</span>");
                }
                button.prop("disabled", false).text("Update This Paper");
            });
        });
    });
    </script>';
}

// AJAX handler for updating single paper
function sjm_update_single_paper() {
    if (!wp_verify_nonce($_POST['nonce'], 'sjm_update_single_paper')) {
        wp_send_json_error('Security check failed.');
    }
    
    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Permission denied.');
    }
    
    $paper_id = intval($_POST['paper_id']);
    $result = sjm_update_paper_citations_views($paper_id);
    
    if ($result['success']) {
        wp_send_json_success('Paper updated successfully');
    } else {
        wp_send_json_error($result['message']);
    }
}
add_action('wp_ajax_sjm_update_single_paper', 'sjm_update_single_paper');

// Add automation dashboard widget
function sjm_add_automation_dashboard_widget() {
    wp_add_dashboard_widget(
        'sjm_automation_widget',
        'Citation & Views Automation',
        'sjm_automation_dashboard_widget_content'
    );
}
add_action('wp_dashboard_setup', 'sjm_add_automation_dashboard_widget');

function sjm_automation_dashboard_widget_content() {
    $settings = get_option('sjm_automation_settings', array());
    $recent_log = get_option('sjm_automation_log', array());
    
    echo '<div style="padding: 10px;">';
    
    if (!empty($settings['enable_auto_citations'])) {
        echo '<p><strong>Status:</strong> <span style="color: green;">✓ Active</span></p>';
        echo '<p><strong>Frequency:</strong> ' . esc_html(ucfirst($settings['update_frequency'] ?? 'weekly')) . '</p>';
        
        if (!empty($recent_log)) {
            $last_update = $recent_log[0];
            echo '<p><strong>Last Update:</strong> ' . esc_html($last_update['date']) . '</p>';
            echo '<p><strong>Result:</strong> ' . esc_html($last_update['papers_updated']) . ' papers</p>';
        }
        
        echo '<p><a href="' . admin_url('edit.php?post_type=journal&page=sjm-automation') . '" class="button button-secondary">Manage Automation</a></p>';
    } else {
        echo '<p><strong>Status:</strong> <span style="color: red;">✗ Disabled</span></p>';
        echo '<p><a href="' . admin_url('edit.php?post_type=journal&page=sjm-automation') . '" class="button button-primary">Enable Automation</a></p>';
    }
    
    echo '</div>';
}

// Cleanup on plugin deactivation
function sjm_cleanup_automation() {
    wp_clear_scheduled_hook('sjm_automation_update');
}
register_deactivation_hook(WJM_PLUGIN_FILE, 'sjm_cleanup_automation');
?> 