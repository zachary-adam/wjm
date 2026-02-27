<?php
/**
 * Updated Shortcodes with Consistent Academic Design
 * For Wisdom Journal Manager Plugin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Updated Journals Shortcode
function sjm_journals_shortcode_new($atts = array()) {
    $atts = shortcode_atts(array(
        'layout' => 'grid', // 'grid' or 'list'
        'publisher' => '',
        'subject_area' => '',
        'language' => '',
        'open_access' => '',
        'peer_reviewed' => '',
        'year' => '',
        'per_page' => 12
    ), $atts);
    
    // Enqueue the CSS file
    wp_enqueue_style('sjm-academic-shortcodes', plugin_dir_url(__FILE__) . 'academic-shortcodes.css', array(), '1.0.0');
    
    // Build query args
    $args = array(
        'post_type' => 'journal',
        'posts_per_page' => intval($atts['per_page']),
        'meta_query' => array('relation' => 'AND')
    );
    
    // Add filters
    if (!empty($atts['publisher'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_publisher',
            'value' => $atts['publisher'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['subject_area'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_subject_areas',
            'value' => $atts['subject_area'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['language'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_language',
            'value' => $atts['language'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['open_access'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_open_access',
            'value' => '1',
            'compare' => '='
        );
    }
    
    if (!empty($atts['peer_reviewed'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_peer_reviewed',
            'value' => '1',
            'compare' => '='
        );
    }
    
    if (!empty($atts['year'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_founding_year',
            'value' => $atts['year'],
            'compare' => '='
        );
    }
    
    $journals = get_posts($args);
    
    // Get unique values for filters
    $all_journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    $publishers = array();
    $languages = array();
    $subject_areas = array();
    
    foreach ($all_journals as $journal) {
        $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
        $language = get_post_meta($journal->ID, '_sjm_language', true);
        $subjects = get_post_meta($journal->ID, '_sjm_subject_areas', true);
        
        if ($publisher && !in_array($publisher, $publishers)) {
            $publishers[] = $publisher;
        }
        if ($language && !in_array($language, $languages)) {
            $languages[] = $language;
        }
        if ($subjects) {
            $subject_list = array_map('trim', explode(',', $subjects));
            foreach ($subject_list as $subject) {
                if ($subject && !in_array($subject, $subject_areas)) {
                    $subject_areas[] = $subject;
                }
            }
        }
    }
    
    sort($publishers);
    sort($languages);
    sort($subject_areas);
    
    if (!$journals && empty($_GET['sjm_journal_filter'])) {
        return '<div class="sjm-container"><div class="sjm-empty-state"><h3>No Journals Found</h3><p>No academic journals are currently available.</p></div></div>';
    }
    
    $output = '<div class="sjm-container">';
    
    // Search filters for journals
    $output .= '<form method="get" class="sjm-filters">';
    $output .= '<input type="hidden" name="sjm_journal_filter" value="1">';
    
    $output .= '<div class="sjm-filters-grid">';
    
    // Publisher filter
    if (!empty($publishers)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Publisher</label>';
        $output .= '<select name="publisher" class="sjm-filter-select">';
        $output .= '<option value="">All Publishers</option>';
        foreach ($publishers as $publisher) {
            $selected = (isset($_GET['publisher']) && $_GET['publisher'] == $publisher) ? 'selected' : '';
            $output .= '<option value="' . esc_attr($publisher) . '" ' . $selected . '>' . esc_html($publisher) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Subject Area filter
    if (!empty($subject_areas)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Subject Area</label>';
        $output .= '<select name="subject_area" class="sjm-filter-select">';
        $output .= '<option value="">All Subject Areas</option>';
        foreach ($subject_areas as $subject) {
            $selected = (isset($_GET['subject_area']) && $_GET['subject_area'] == $subject) ? 'selected' : '';
            $output .= '<option value="' . esc_attr($subject) . '" ' . $selected . '>' . esc_html($subject) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Language filter
    if (!empty($languages)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Language</label>';
        $output .= '<select name="language" class="sjm-filter-select">';
        $output .= '<option value="">All Languages</option>';
        foreach ($languages as $language) {
            $selected = (isset($_GET['language']) && $_GET['language'] == $language) ? 'selected' : '';
            $output .= '<option value="' . esc_attr($language) . '" ' . $selected . '>' . esc_html($language) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Access Type filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Access Type</label>';
    $output .= '<select name="open_access" class="sjm-filter-select">';
    $output .= '<option value="">All Access Types</option>';
    $selected = (isset($_GET['open_access']) && $_GET['open_access'] == '1') ? 'selected' : '';
    $output .= '<option value="1" ' . $selected . '>Open Access Only</option>';
    $output .= '</select>';
    $output .= '</div>';
    
    // Review Status filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Review Status</label>';
    $output .= '<select name="peer_reviewed" class="sjm-filter-select">';
    $output .= '<option value="">All Review Types</option>';
    $selected = (isset($_GET['peer_reviewed']) && $_GET['peer_reviewed'] == '1') ? 'selected' : '';
    $output .= '<option value="1" ' . $selected . '>Peer Reviewed Only</option>';
    $output .= '</select>';
    $output .= '</div>';
    
    $output .= '</div>'; // Close filters-grid
    
    // Filter buttons
    $output .= '<div class="sjm-filter-buttons">';
    $output .= '<a href="' . get_permalink() . '" class="sjm-filter-button">Clear Filters</a>';
    $output .= '<button type="submit" class="sjm-filter-button sjm-filter-button-primary">Apply Filters</button>';
    $output .= '</div>';
    
    $output .= '</form>';
    
    // Handle URL parameters for filtering
    if (isset($_GET['sjm_journal_filter'])) {
        $filter_args = array(
            'post_type' => 'journal',
            'posts_per_page' => intval($atts['per_page']),
            'meta_query' => array('relation' => 'AND')
        );
        
        if (!empty($_GET['publisher'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_publisher',
                'value' => $_GET['publisher'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['subject_area'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_subject_areas',
                'value' => $_GET['subject_area'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['language'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_language',
                'value' => $_GET['language'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['open_access'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_open_access',
                'value' => '1',
                'compare' => '='
            );
        }
        
        if (!empty($_GET['peer_reviewed'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_peer_reviewed',
                'value' => '1',
                'compare' => '='
            );
        }
        
        $journals = get_posts($filter_args);
    }
    
    if (!$journals) {
        $output .= '<div class="sjm-empty-state"><h3>No Journals Found</h3><p>No journals match your search criteria. Please try adjusting your filters.</p></div>';
        $output .= '</div>';
        return $output;
    }
    
    // Display journals
    if ($atts['layout'] === 'list') {
        $output .= '<div class="sjm-list">';
        
        foreach ($journals as $journal) {
            $issn = get_post_meta($journal->ID, '_sjm_issn', true);
            $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
            $subjects = get_post_meta($journal->ID, '_sjm_subject_areas', true);
            $language = get_post_meta($journal->ID, '_sjm_language', true);
            $open_access = get_post_meta($journal->ID, '_sjm_open_access', true);
            $peer_reviewed = get_post_meta($journal->ID, '_sjm_peer_reviewed', true);
            $founding_year = get_post_meta($journal->ID, '_sjm_founding_year', true);
            $impact_factor = get_post_meta($journal->ID, '_sjm_impact_factor', true);
            $cover_image = get_post_meta($journal->ID, '_sjm_cover_image', true);
            $permalink = get_permalink($journal->ID);
            
            $output .= '<div class="sjm-card-list">';
            
            // Journal cover
            $output .= '<div class="sjm-cover-list">';
            if ($cover_image) {
                $output .= '<img src="' . esc_url($cover_image) . '" alt="' . esc_attr($journal->post_title) . '" />';
            } else {
                $output .= '<div class="sjm-cover-placeholder"></div>';
            }
            $output .= '</div>';
            
            // Journal info
            $output .= '<div class="sjm-content-list">';
            $output .= '<h3 class="sjm-title sjm-title-list">' . esc_html($journal->post_title) . '</h3>';
            
            if ($publisher) {
                $output .= '<p class="sjm-subtitle">Published by ' . esc_html($publisher) . '</p>';
            }
            
            if ($journal->post_content) {
                $output .= '<p class="sjm-description sjm-description-list">' . esc_html(wp_trim_words($journal->post_content, 25)) . '</p>';
            }
            
            // Metadata
            $output .= '<div class="sjm-meta">';
            if ($issn) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">ISSN:</span> <span class="sjm-meta-value">' . esc_html($issn) . '</span></div>';
            }
            if ($founding_year) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Founded:</span> <span class="sjm-meta-value">' . esc_html($founding_year) . '</span></div>';
            }
            if ($impact_factor) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Impact Factor:</span> <span class="sjm-meta-value">' . esc_html($impact_factor) . '</span></div>';
            }
            if ($language) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Language:</span> <span class="sjm-meta-value">' . esc_html($language) . '</span></div>';
            }
            $output .= '</div>';
            
            // Badges
            $output .= '<div class="sjm-badges sjm-badges-list">';
            if ($subjects) {
                $subject_list = array_map('trim', explode(',', $subjects));
                foreach (array_slice($subject_list, 0, 3) as $subject) {
                    $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html($subject) . '</span>';
                }
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge sjm-badge-success">Open Access</span>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge sjm-badge-primary">Peer Reviewed</span>';
            }
            $output .= '</div>';
            
            $output .= '</div>';
            
            // Actions
            $output .= '<div class="sjm-actions-list">';
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-button sjm-button-primary">';
            $output .= 'View Journal';
            $output .= '<svg class="sjm-button-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            $output .= '</div>';
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
    } else {
        // Grid layout (default)
        $output .= '<div class="sjm-grid">';
        
        foreach ($journals as $journal) {
            $issn = get_post_meta($journal->ID, '_sjm_issn', true);
            $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
            $subjects = get_post_meta($journal->ID, '_sjm_subject_areas', true);
            $language = get_post_meta($journal->ID, '_sjm_language', true);
            $open_access = get_post_meta($journal->ID, '_sjm_open_access', true);
            $peer_reviewed = get_post_meta($journal->ID, '_sjm_peer_reviewed', true);
            $founding_year = get_post_meta($journal->ID, '_sjm_founding_year', true);
            $impact_factor = get_post_meta($journal->ID, '_sjm_impact_factor', true);
            $cover_image = get_post_meta($journal->ID, '_sjm_cover_image', true);
            $permalink = get_permalink($journal->ID);
            
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-card">';
            
            // Journal cover
            $output .= '<div class="sjm-cover">';
            if ($cover_image) {
                $output .= '<img src="' . esc_url($cover_image) . '" alt="' . esc_attr($journal->post_title) . '" />';
            } else {
                $output .= '<div class="sjm-cover-placeholder"></div>';
            }
            $output .= '</div>';
            
            // Journal info
            $output .= '<div class="sjm-content">';
            $output .= '<h3 class="sjm-title">' . esc_html($journal->post_title) . '</h3>';
            
            if ($publisher) {
                $output .= '<p class="sjm-subtitle">Published by ' . esc_html($publisher) . '</p>';
            }
            
            if ($journal->post_content) {
                $output .= '<p class="sjm-description">' . esc_html(wp_trim_words($journal->post_content, 20)) . '</p>';
            }
            
            // Metadata
            $output .= '<div class="sjm-meta">';
            if ($issn) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">ISSN:</span> <span class="sjm-meta-value">' . esc_html($issn) . '</span></div>';
            }
            if ($impact_factor) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">IF:</span> <span class="sjm-meta-value">' . esc_html($impact_factor) . '</span></div>';
            }
            $output .= '</div>';
            
            // Badges
            $output .= '<div class="sjm-badges">';
            if ($subjects) {
                $subject_list = array_map('trim', explode(',', $subjects));
                foreach (array_slice($subject_list, 0, 2) as $subject) {
                    $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html($subject) . '</span>';
                }
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge sjm-badge-success">Open Access</span>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge sjm-badge-primary">Peer Reviewed</span>';
            }
            $output .= '</div>';
            
            // Actions
            $output .= '<div class="sjm-actions">';
            $output .= '<span class="sjm-button">';
            $output .= 'View Journal';
            $output .= '<svg class="sjm-button-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</span>';
            $output .= '</div>';
            
            $output .= '</div>';
            $output .= '</a>';
        }
        
        $output .= '</div>';
    }
    
    $output .= '</div>';
    
    return $output;
}

// Updated Papers Shortcode
function sjm_papers_shortcode_new($atts = array()) {
    $atts = shortcode_atts(array(
        'layout' => 'grid', // 'grid' or 'list'
        'journal_id' => '',
        'issue_id' => '',
        'paper_type' => '',
        'author' => '',
        'keyword' => '',
        'year' => '',
        'per_page' => 12
    ), $atts);
    
    // Enqueue the CSS file
    wp_enqueue_style('sjm-academic-shortcodes', plugin_dir_url(__FILE__) . 'academic-shortcodes.css', array(), '1.0.0');
    
    // Build query args
    $args = array(
        'post_type' => 'paper',
        'posts_per_page' => intval($atts['per_page']),
        'meta_query' => array('relation' => 'AND')
    );
    
    // Add filters
    if (!empty($atts['journal_id'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_journal',
            'value' => $atts['journal_id'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['issue_id'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_issue',
            'value' => $atts['issue_id'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['paper_type'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_type',
            'value' => $atts['paper_type'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['author'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_authors',
            'value' => $atts['author'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['keyword'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_paper_keywords',
            'value' => $atts['keyword'],
            'compare' => 'LIKE'
        );
    }
    
    if (!empty($atts['year'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_acceptance_date',
            'value' => $atts['year'],
            'compare' => 'LIKE'
        );
    }
    
    $papers = get_posts($args);
    
    // Get all journals and paper types for filters
    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    $paper_types = array('Research Article', 'Review Article', 'Case Study', 'Short Communication', 'Editorial', 'Letter', 'Manuscript');
    
    if (!$papers && empty($_GET['sjm_filter'])) {
        return '<div class="sjm-container"><div class="sjm-empty-state"><h3>No Papers Found</h3><p>No research papers are currently available.</p></div></div>';
    }
    
    $output = '<div class="sjm-container">';
    
    // Search filters
    $output .= '<form method="get" class="sjm-filters">';
    $output .= '<input type="hidden" name="sjm_filter" value="1">';
    
    $output .= '<div class="sjm-filters-grid">';
    
    // Journal filter
    if (!empty($journals)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Journal</label>';
        $output .= '<select name="journal_id" class="sjm-filter-select">';
        $output .= '<option value="">All Journals</option>';
        foreach ($journals as $journal) {
            $selected = (isset($_GET['journal_id']) && $_GET['journal_id'] == $journal->ID) ? 'selected' : '';
            $output .= '<option value="' . $journal->ID . '" ' . $selected . '>' . esc_html($journal->post_title) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Paper type filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Paper Type</label>';
    $output .= '<select name="paper_type" class="sjm-filter-select">';
    $output .= '<option value="">All Types</option>';
    foreach ($paper_types as $type) {
        $selected = (isset($_GET['paper_type']) && $_GET['paper_type'] == $type) ? 'selected' : '';
        $output .= '<option value="' . esc_attr($type) . '" ' . $selected . '>' . esc_html($type) . '</option>';
    }
    $output .= '</select>';
    $output .= '</div>';
    
    // Author filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Author</label>';
    $output .= '<input type="text" name="author" class="sjm-filter-input" placeholder="Search by author..." value="' . esc_attr(isset($_GET['author']) ? $_GET['author'] : '') . '">';
    $output .= '</div>';
    
    // Keyword filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Keywords</label>';
    $output .= '<input type="text" name="keyword" class="sjm-filter-input" placeholder="Search keywords..." value="' . esc_attr(isset($_GET['keyword']) ? $_GET['keyword'] : '') . '">';
    $output .= '</div>';
    
    // Year filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Year</label>';
    $output .= '<input type="number" name="year" class="sjm-filter-input" placeholder="2024" min="1900" max="2030" value="' . esc_attr(isset($_GET['year']) ? $_GET['year'] : '') . '">';
    $output .= '</div>';
    
    $output .= '</div>'; // Close filters-grid
    
    // Filter buttons
    $output .= '<div class="sjm-filter-buttons">';
    $output .= '<a href="' . get_permalink() . '" class="sjm-filter-button">Clear Filters</a>';
    $output .= '<button type="submit" class="sjm-filter-button sjm-filter-button-primary">Apply Filters</button>';
    $output .= '</div>';
    
    $output .= '</form>';
    
    // Handle URL parameters for filtering
    if (isset($_GET['sjm_filter'])) {
        $filter_args = array(
            'post_type' => 'paper',
            'posts_per_page' => intval($atts['per_page']),
            'meta_query' => array('relation' => 'AND')
        );
        
        if (!empty($_GET['journal_id'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_journal',
                'value' => $_GET['journal_id'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['paper_type'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_type',
                'value' => $_GET['paper_type'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['author'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_authors',
                'value' => $_GET['author'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['keyword'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_paper_keywords',
                'value' => $_GET['keyword'],
                'compare' => 'LIKE'
            );
        }
        
        if (!empty($_GET['year'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_acceptance_date',
                'value' => $_GET['year'],
                'compare' => 'LIKE'
            );
        }
        
        $papers = get_posts($filter_args);
    }
    
    if (!$papers) {
        $output .= '<div class="sjm-empty-state"><h3>No Papers Found</h3><p>No papers match your search criteria. Please try adjusting your filters.</p></div>';
        $output .= '</div>';
        return $output;
    }
    
    // Display papers
    if ($atts['layout'] === 'list') {
        $output .= '<div class="sjm-list">';
        
        foreach ($papers as $paper) {
            $paper_journal_id = get_post_meta($paper->ID, '_sjm_paper_journal', true);
            $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
            $paper_authors = get_post_meta($paper->ID, '_sjm_paper_authors', true);
            $paper_authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
            if (!is_array($paper_authors_data)) $paper_authors_data = array();
            $paper_abstract = get_post_meta($paper->ID, '_sjm_paper_abstract', true);
            $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
            $paper_keywords = get_post_meta($paper->ID, '_sjm_paper_keywords', true);
            $paper_doi = get_post_meta($paper->ID, '_sjm_paper_doi', true);
            $open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
            $peer_reviewed = get_post_meta($paper->ID, '_sjm_paper_peer_reviewed', true);
            $acceptance_date = get_post_meta($paper->ID, '_sjm_acceptance_date', true);
            $permalink = get_permalink($paper->ID);
            
            $output .= '<div class="sjm-card-list">';
            
            // Paper info
            $output .= '<div class="sjm-content-list">';
            $output .= '<h3 class="sjm-title sjm-title-list">' . esc_html($paper->post_title) . '</h3>';
            
            // Display enhanced author information
            if (!empty($paper_authors_data)) {
                usort($paper_authors_data, function($a, $b) {
                    return intval($a['order']) - intval($b['order']);
                });
                
                $output .= '<div class="sjm-authors">';
                $author_displays = array();
                foreach ($paper_authors_data as $author_data) {
                    $author = sjm_get_author_by_id($author_data['author_id']);
                    if ($author) {
                        $author_displays[] = '<span class="sjm-author sjm-author-link">' . esc_html($author->first_name . ' ' . $author->last_name) . '</span>';
                    }
                }
                $output .= implode(', ', $author_displays);
                $output .= '</div>';
            } elseif ($paper_authors) {
                $output .= '<div class="sjm-authors"><span class="sjm-author">' . esc_html($paper_authors) . '</span></div>';
            }
            
            if ($paper_abstract) {
                $output .= '<p class="sjm-description sjm-description-list">' . esc_html(wp_trim_words($paper_abstract, 30)) . '</p>';
            }
            
            // Metadata
            $output .= '<div class="sjm-meta">';
            if ($paper_journal) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Journal:</span> <span class="sjm-meta-value">' . esc_html($paper_journal->post_title) . '</span></div>';
            }
            if ($acceptance_date) {
                $year = gmdate('Y', strtotime($acceptance_date));
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Year:</span> <span class="sjm-meta-value">' . esc_html($year) . '</span></div>';
            }
            if ($paper_doi) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">DOI:</span> <span class="sjm-meta-value">' . esc_html($paper_doi) . '</span></div>';
            }
            $output .= '</div>';
            
            // Badges
            $output .= '<div class="sjm-badges sjm-badges-list">';
            if ($paper_type) {
                $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html($paper_type) . '</span>';
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge sjm-badge-success">Open Access</span>';
            } else {
                $output .= '<span class="sjm-badge sjm-badge-error">Subscription</span>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge sjm-badge-primary">Peer Reviewed</span>';
            }
            $output .= '</div>';
            
            $output .= '</div>';
            
            // Actions
            $output .= '<div class="sjm-actions-list">';
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-button sjm-button-primary">';
            $output .= 'View Paper';
            $output .= '<svg class="sjm-button-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            $output .= '</div>';
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
    } else {
        // Grid layout (default)
        $output .= '<div class="sjm-grid">';
        
        foreach ($papers as $paper) {
            $paper_journal_id = get_post_meta($paper->ID, '_sjm_paper_journal', true);
            $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
            $paper_authors = get_post_meta($paper->ID, '_sjm_paper_authors', true);
            $paper_authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
            if (!is_array($paper_authors_data)) $paper_authors_data = array();
            $paper_abstract = get_post_meta($paper->ID, '_sjm_paper_abstract', true);
            $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
            $paper_keywords = get_post_meta($paper->ID, '_sjm_paper_keywords', true);
            $paper_doi = get_post_meta($paper->ID, '_sjm_paper_doi', true);
            $open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
            $peer_reviewed = get_post_meta($paper->ID, '_sjm_paper_peer_reviewed', true);
            $acceptance_date = get_post_meta($paper->ID, '_sjm_acceptance_date', true);
            $permalink = get_permalink($paper->ID);
            
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-card">';
            
            // Paper info
            $output .= '<div class="sjm-content">';
            $output .= '<h3 class="sjm-title">' . esc_html($paper->post_title) . '</h3>';
            
            // Display enhanced author information
            if (!empty($paper_authors_data)) {
                usort($paper_authors_data, function($a, $b) {
                    return intval($a['order']) - intval($b['order']);
                });
                
                $output .= '<div class="sjm-authors">';
                $author_displays = array();
                foreach (array_slice($paper_authors_data, 0, 3) as $author_data) {
                    $author = sjm_get_author_by_id($author_data['author_id']);
                    if ($author) {
                        $author_displays[] = '<span class="sjm-author">' . esc_html($author->first_name . ' ' . $author->last_name) . '</span>';
                    }
                }
                if (count($paper_authors_data) > 3) {
                    $author_displays[] = '<span class="sjm-author">et al.</span>';
                }
                $output .= implode(', ', $author_displays);
                $output .= '</div>';
            } elseif ($paper_authors) {
                $output .= '<div class="sjm-authors"><span class="sjm-author">' . esc_html(wp_trim_words($paper_authors, 5)) . '</span></div>';
            }
            
            if ($paper_abstract) {
                $output .= '<p class="sjm-description">' . esc_html(wp_trim_words($paper_abstract, 20)) . '</p>';
            }
            
            // Metadata
            $output .= '<div class="sjm-meta">';
            if ($paper_journal) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Journal:</span> <span class="sjm-meta-value">' . esc_html(wp_trim_words($paper_journal->post_title, 3)) . '</span></div>';
            }
            if ($acceptance_date) {
                $year = gmdate('Y', strtotime($acceptance_date));
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Year:</span> <span class="sjm-meta-value">' . esc_html($year) . '</span></div>';
            }
            $output .= '</div>';
            
            // Badges
            $output .= '<div class="sjm-badges">';
            if ($paper_type) {
                $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html($paper_type) . '</span>';
            }
            if ($open_access) {
                $output .= '<span class="sjm-badge sjm-badge-success">Open Access</span>';
            } else {
                $output .= '<span class="sjm-badge sjm-badge-error">Subscription</span>';
            }
            if ($peer_reviewed) {
                $output .= '<span class="sjm-badge sjm-badge-primary">Peer Reviewed</span>';
            }
            $output .= '</div>';
            
            // Actions
            $output .= '<div class="sjm-actions">';
            $output .= '<span class="sjm-button">';
            $output .= 'View Paper';
            $output .= '<svg class="sjm-button-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</span>';
            $output .= '</div>';
            
            $output .= '</div>';
            $output .= '</a>';
        }
        
        $output .= '</div>';
    }
    
    $output .= '</div>';
    
    return $output;
}

// Updated Issues Shortcode
function sjm_issues_shortcode_new($atts = array()) {
    $atts = shortcode_atts(array(
        'layout' => 'grid', // 'grid' or 'list'
        'journal_id' => '',
        'volume' => '',
        'year' => '',
        'special_issue' => '',
        'per_page' => 12
    ), $atts);
    
    // Enqueue the CSS file
    wp_enqueue_style('sjm-academic-shortcodes', plugin_dir_url(__FILE__) . 'academic-shortcodes.css', array(), '1.0.0');
    
    // Build query args
    $args = array(
        'post_type' => 'journal_issue',
        'posts_per_page' => intval($atts['per_page']),
        'meta_query' => array('relation' => 'AND'),
        'orderby' => 'meta_value_num',
        'meta_key' => '_sjm_issue_year',
        'order' => 'DESC'
    );
    
    // Add filters
    if (!empty($atts['journal_id'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_issue_journal',
            'value' => $atts['journal_id'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['volume'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_issue_volume',
            'value' => $atts['volume'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['year'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_issue_year',
            'value' => $atts['year'],
            'compare' => '='
        );
    }
    
    if (!empty($atts['special_issue'])) {
        $args['meta_query'][] = array(
            'key' => '_sjm_special_issue',
            'value' => '1',
            'compare' => '='
        );
    }
    
    $issues = get_posts($args);
    
    // Get all journals for filters
    $journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
    
    // Get unique years and volumes
    $all_issues = get_posts(array('post_type' => 'journal_issue', 'posts_per_page' => -1));
    $years = array();
    $volumes = array();
    
    foreach ($all_issues as $issue) {
        $year = get_post_meta($issue->ID, '_sjm_issue_year', true);
        $volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
        
        if ($year && !in_array($year, $years)) {
            $years[] = $year;
        }
        if ($volume && !in_array($volume, $volumes)) {
            $volumes[] = $volume;
        }
    }
    
    rsort($years);
    sort($volumes);
    
    if (!$issues && empty($_GET['sjm_issue_filter'])) {
        return '<div class="sjm-container"><div class="sjm-empty-state"><h3>No Issues Found</h3><p>No journal issues are currently available.</p></div></div>';
    }
    
    $output = '<div class="sjm-container">';
    
    // Search filters for issues
    $output .= '<form method="get" class="sjm-filters">';
    $output .= '<input type="hidden" name="sjm_issue_filter" value="1">';
    
    $output .= '<div class="sjm-filters-grid">';
    
    // Journal filter
    if (!empty($journals)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Journal</label>';
        $output .= '<select name="journal_id" class="sjm-filter-select">';
        $output .= '<option value="">All Journals</option>';
        foreach ($journals as $journal) {
            $selected = (isset($_GET['journal_id']) && $_GET['journal_id'] == $journal->ID) ? 'selected' : '';
            $output .= '<option value="' . $journal->ID . '" ' . $selected . '>' . esc_html($journal->post_title) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Volume filter
    if (!empty($volumes)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Volume</label>';
        $output .= '<select name="volume" class="sjm-filter-select">';
        $output .= '<option value="">All Volumes</option>';
        foreach ($volumes as $volume) {
            $selected = (isset($_GET['volume']) && $_GET['volume'] == $volume) ? 'selected' : '';
            $output .= '<option value="' . esc_attr($volume) . '" ' . $selected . '>Volume ' . esc_html($volume) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Year filter
    if (!empty($years)) {
        $output .= '<div class="sjm-filter-group">';
        $output .= '<label class="sjm-filter-label">Year</label>';
        $output .= '<select name="year" class="sjm-filter-select">';
        $output .= '<option value="">All Years</option>';
        foreach ($years as $year) {
            $selected = (isset($_GET['year']) && $_GET['year'] == $year) ? 'selected' : '';
            $output .= '<option value="' . esc_attr($year) . '" ' . $selected . '>' . esc_html($year) . '</option>';
        }
        $output .= '</select>';
        $output .= '</div>';
    }
    
    // Special Issue filter
    $output .= '<div class="sjm-filter-group">';
    $output .= '<label class="sjm-filter-label">Issue Type</label>';
    $output .= '<select name="special_issue" class="sjm-filter-select">';
    $output .= '<option value="">All Issues</option>';
    $selected = (isset($_GET['special_issue']) && $_GET['special_issue'] == '1') ? 'selected' : '';
    $output .= '<option value="1" ' . $selected . '>Special Issues Only</option>';
    $output .= '</select>';
    $output .= '</div>';
    
    $output .= '</div>'; // Close filters-grid
    
    // Filter buttons
    $output .= '<div class="sjm-filter-buttons">';
    $output .= '<a href="' . get_permalink() . '" class="sjm-filter-button">Clear Filters</a>';
    $output .= '<button type="submit" class="sjm-filter-button sjm-filter-button-primary">Apply Filters</button>';
    $output .= '</div>';
    
    $output .= '</form>';
    
    // Handle URL parameters for filtering
    if (isset($_GET['sjm_issue_filter'])) {
        $filter_args = array(
            'post_type' => 'journal_issue',
            'posts_per_page' => intval($atts['per_page']),
            'meta_query' => array('relation' => 'AND'),
            'orderby' => 'meta_value_num',
            'meta_key' => '_sjm_issue_year',
            'order' => 'DESC'
        );
        
        if (!empty($_GET['journal_id'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_issue_journal',
                'value' => $_GET['journal_id'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['volume'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_issue_volume',
                'value' => $_GET['volume'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['year'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_issue_year',
                'value' => $_GET['year'],
                'compare' => '='
            );
        }
        
        if (!empty($_GET['special_issue'])) {
            $filter_args['meta_query'][] = array(
                'key' => '_sjm_special_issue',
                'value' => '1',
                'compare' => '='
            );
        }
        
        $issues = get_posts($filter_args);
    }
    
    if (!$issues) {
        $output .= '<div class="sjm-empty-state"><h3>No Issues Found</h3><p>No issues match your search criteria. Please try adjusting your filters.</p></div>';
        $output .= '</div>';
        return $output;
    }
    
    // Display issues
    if ($atts['layout'] === 'list') {
        $output .= '<div class="sjm-list">';
        
        foreach ($issues as $issue) {
            $issue_journal_id = get_post_meta($issue->ID, '_sjm_issue_journal', true);
            $issue_journal = $issue_journal_id ? get_post($issue_journal_id) : null;
            $issue_number = get_post_meta($issue->ID, '_sjm_issue_number', true);
            $issue_volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
            $issue_year = get_post_meta($issue->ID, '_sjm_issue_year', true);
            $publication_date = get_post_meta($issue->ID, '_sjm_publication_date', true);
            $special_issue = get_post_meta($issue->ID, '_sjm_special_issue', true);
            $special_issue_title = get_post_meta($issue->ID, '_sjm_special_issue_title', true);
            $cover_image = get_post_meta($issue->ID, '_sjm_issue_cover_image', true);
            $permalink = get_permalink($issue->ID);
            
            $output .= '<div class="sjm-card-list">';
            
            // Issue cover
            $output .= '<div class="sjm-cover-list">';
            if ($cover_image) {
                $output .= '<img src="' . esc_url($cover_image) . '" alt="' . esc_attr($issue->post_title) . '" />';
            } else {
                $output .= '<div class="sjm-cover-placeholder"></div>';
            }
            $output .= '</div>';
            
            // Issue info
            $output .= '<div class="sjm-content-list">';
            $output .= '<h3 class="sjm-title sjm-title-list">' . esc_html($issue->post_title) . '</h3>';
            
            if ($issue_journal) {
                $output .= '<p class="sjm-subtitle">' . esc_html($issue_journal->post_title) . '</p>';
            }
            
            if ($issue->post_content) {
                $output .= '<p class="sjm-description sjm-description-list">' . esc_html(wp_trim_words($issue->post_content, 25)) . '</p>';
            }
            
            // Metadata
            $output .= '<div class="sjm-meta">';
            if ($issue_volume && $issue_number) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Volume:</span> <span class="sjm-meta-value">' . esc_html($issue_volume) . ', Issue ' . esc_html($issue_number) . '</span></div>';
            }
            if ($issue_year) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Year:</span> <span class="sjm-meta-value">' . esc_html($issue_year) . '</span></div>';
            }
            if ($publication_date) {
                $formatted_date = gmdate('F Y', strtotime($publication_date));
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Published:</span> <span class="sjm-meta-value">' . esc_html($formatted_date) . '</span></div>';
            }
            $output .= '</div>';
            
            // Badges
            $output .= '<div class="sjm-badges sjm-badges-list">';
            if ($special_issue) {
                $output .= '<span class="sjm-badge sjm-badge-warning">Special Issue</span>';
                if ($special_issue_title) {
                    $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html(wp_trim_words($special_issue_title, 3)) . '</span>';
                }
            } else {
                $output .= '<span class="sjm-badge sjm-badge-primary">Regular Issue</span>';
            }
            if ($issue_year) {
                $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html($issue_year) . '</span>';
            }
            $output .= '</div>';
            
            $output .= '</div>';
            
            // Actions
            $output .= '<div class="sjm-actions-list">';
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-button sjm-button-primary">';
            $output .= 'View Issue';
            $output .= '<svg class="sjm-button-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</a>';
            $output .= '</div>';
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
    } else {
        // Grid layout (default)
        $output .= '<div class="sjm-grid">';
        
        foreach ($issues as $issue) {
            $issue_journal_id = get_post_meta($issue->ID, '_sjm_issue_journal', true);
            $issue_journal = $issue_journal_id ? get_post($issue_journal_id) : null;
            $issue_number = get_post_meta($issue->ID, '_sjm_issue_number', true);
            $issue_volume = get_post_meta($issue->ID, '_sjm_issue_volume', true);
            $issue_year = get_post_meta($issue->ID, '_sjm_issue_year', true);
            $publication_date = get_post_meta($issue->ID, '_sjm_publication_date', true);
            $special_issue = get_post_meta($issue->ID, '_sjm_special_issue', true);
            $special_issue_title = get_post_meta($issue->ID, '_sjm_special_issue_title', true);
            $cover_image = get_post_meta($issue->ID, '_sjm_issue_cover_image', true);
            $permalink = get_permalink($issue->ID);
            
            $output .= '<a href="' . esc_url($permalink) . '" class="sjm-card">';
            
            // Issue cover
            $output .= '<div class="sjm-cover">';
            if ($cover_image) {
                $output .= '<img src="' . esc_url($cover_image) . '" alt="' . esc_attr($issue->post_title) . '" />';
            } else {
                $output .= '<div class="sjm-cover-placeholder"></div>';
            }
            $output .= '</div>';
            
            // Issue info
            $output .= '<div class="sjm-content">';
            $output .= '<h3 class="sjm-title">' . esc_html($issue->post_title) . '</h3>';
            
            if ($issue_journal) {
                $output .= '<p class="sjm-subtitle">' . esc_html($issue_journal->post_title) . '</p>';
            }
            
            if ($issue->post_content) {
                $output .= '<p class="sjm-description">' . esc_html(wp_trim_words($issue->post_content, 15)) . '</p>';
            }
            
            // Metadata
            $output .= '<div class="sjm-meta">';
            if ($issue_volume && $issue_number) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Vol:</span> <span class="sjm-meta-value">' . esc_html($issue_volume) . ', No. ' . esc_html($issue_number) . '</span></div>';
            }
            if ($issue_year) {
                $output .= '<div class="sjm-meta-item"><span class="sjm-meta-label">Year:</span> <span class="sjm-meta-value">' . esc_html($issue_year) . '</span></div>';
            }
            $output .= '</div>';
            
            // Badges
            $output .= '<div class="sjm-badges">';
            if ($special_issue) {
                $output .= '<span class="sjm-badge sjm-badge-warning">Special Issue</span>';
            } else {
                $output .= '<span class="sjm-badge sjm-badge-primary">Regular Issue</span>';
            }
            if ($issue_year) {
                $output .= '<span class="sjm-badge sjm-badge-secondary">' . esc_html($issue_year) . '</span>';
            }
            $output .= '</div>';
            
            // Actions
            $output .= '<div class="sjm-actions">';
            $output .= '<span class="sjm-button">';
            $output .= 'View Issue';
            $output .= '<svg class="sjm-button-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">';
            $output .= '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>';
            $output .= '</svg>';
            $output .= '</span>';
            $output .= '</div>';
            
            $output .= '</div>';
            $output .= '</a>';
        }
        
        $output .= '</div>';
    }
    
    $output .= '</div>';
    
    return $output;
} 