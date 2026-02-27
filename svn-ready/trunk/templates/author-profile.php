<?php

get_header();

$author_id = get_query_var('author_profile_id');
$author = sjm_get_author_by_id($author_id);

if (!$author) {
    echo '<div class="sjm-single-container">';
    echo '<h1>Author not found</h1>';
    echo '<p>The requested author profile could not be found.</p>';
    echo '</div>';
    get_footer();
    return;
}

// Get author's publications with detailed role information
$papers = get_posts(array(
    'post_type' => 'paper',
    'posts_per_page' => -1,
    'meta_query' => array(
        array(
            'key' => '_sjm_paper_authors_data',
            'value' => '"author_id";i:' . intval($author_id),
            'compare' => 'LIKE'
        )
    )
));

// Get author's journal contributions with roles
$journals = get_posts(array(
    'post_type' => 'journal',
    'posts_per_page' => -1,
    'meta_query' => array(
        array(
            'key' => '_sjm_journal_authors_data',
            'value' => '"author_id";i:' . intval($author_id),
            'compare' => 'LIKE'
        )
    )
));

// Get author's version contributions
$version_contributions = array();
foreach ($papers as $paper) {
    $versions_data = get_post_meta($paper->ID, '_sjm_paper_versions_data', true);
    if (is_array($versions_data)) {
        foreach ($versions_data as $version) {
            if (isset($version['contributors']) && is_array($version['contributors'])) {
                foreach ($version['contributors'] as $contributor) {
                    if ($contributor['author_id'] == $author_id) {
                        $version_contributions[] = array(
                            'paper' => $paper,
                            'version' => $version,
                            'role' => $contributor['role'],
                            'contributions' => $contributor['contributions']
                        );
                    }
                }
            }
        }
    }
}

// Function to get role color and style
function sjm_get_role_style($role) {
    $role_styles = array(
        'Author' => array('bg' => '#e3f2fd', 'color' => '#1976d2', 'icon' => '✍️'),
        'Corresponding Author' => array('bg' => '#f3e5f5', 'color' => '#7b1fa2', 'icon' => '✉️'),
        'Reviewer' => array('bg' => '#e8f5e8', 'color' => '#388e3c', 'icon' => '🔍'),
        'Editor' => array('bg' => '#fff3e0', 'color' => '#f57c00', 'icon' => '✏️'),
        'Guest Editor' => array('bg' => '#fce4ec', 'color' => '#c2185b', 'icon' => '👥'),
        'Contributor' => array('bg' => '#f1f8e9', 'color' => '#689f38', 'icon' => '🤝'),
        'Collaborator' => array('bg' => '#e0f2f1', 'color' => '#00796b', 'icon' => '🔗'),
        'default' => array('bg' => '#f5f5f5', 'color' => '#616161', 'icon' => '👤')
    );
    
    return isset($role_styles[$role]) ? $role_styles[$role] : $role_styles['default'];
}
?>

<style>
:root {
  --sjm-bg: #fff;
  --sjm-bg-alt: #f7f8fa;
  --sjm-border: #e5e7eb;
  --sjm-border-dark: #d1d5db;
  --sjm-text: #222;
  --sjm-text-light: #6b7280;
  --sjm-accent: #2563eb;
  --sjm-accent-light: #e0e7ff;
  --sjm-badge-bg: #f3f4f6;
  --sjm-badge-text: #374151;
}

.sjm-author-profile {
  max-width: 1100px;
  margin: 0 auto;
  padding: 32px 12px;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: var(--sjm-bg);
}

.sjm-author-header {
  display: flex;
  flex-wrap: wrap;
  gap: 32px;
  margin-bottom: 32px;
  padding: 24px;
  background: var(--sjm-bg-alt);
  border-radius: 14px;
  border: 1px solid var(--sjm-border);
  color: var(--sjm-text);
  align-items: center;
}

.sjm-author-avatar {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  background: var(--sjm-border);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2.5rem;
  font-weight: 700;
  color: var(--sjm-text-light);
  border: 2px solid var(--sjm-border-dark);
}

.sjm-author-info h1 {
  font-size: 2rem;
  margin: 0 0 8px 0;
  font-weight: 700;
  color: var(--sjm-text);
}

.sjm-author-info .sjm-author-title {
  font-size: 1.1rem;
  margin: 0 0 16px 0;
  color: var(--sjm-text-light);
  font-weight: 500;
}

.sjm-author-links {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.sjm-author-link {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 7px 14px;
  background: var(--sjm-bg);
  border: 1px solid var(--sjm-border);
  border-radius: 18px;
  color: var(--sjm-text-light);
  text-decoration: none;
  font-size: 13px;
  font-weight: 500;
  transition: border 0.2s, color 0.2s;
}
.sjm-author-link:hover {
  border-color: var(--sjm-accent);
  color: var(--sjm-accent);
}

.sjm-author-sections {
  display: flex;
  flex-wrap: wrap;
  gap: 32px;
}
.sjm-author-main {
  flex: 1 1 400px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}
.sjm-author-sidebar {
  flex: 0 0 280px;
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.sjm-section {
  background: var(--sjm-bg);
  border-radius: 12px;
  padding: 22px 20px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.04);
  border: 1px solid var(--sjm-border);
  margin-bottom: 16px;
  overflow-x: auto;
}
.sjm-section h2 {
  font-size: 1.2rem;
  margin: 0 0 16px 0;
  color: var(--sjm-text);
  font-weight: 600;
  border-bottom: 1px solid var(--sjm-border);
  padding-bottom: 7px;
}
.sjm-section h3 {
  font-size: 1.05rem;
  margin: 0 0 12px 0;
  color: var(--sjm-text-light);
  font-weight: 600;
}

.sjm-stats {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  justify-content: flex-start;
}
.sjm-stat-item {
  flex: 1 1 80px;
  min-width: 80px;
  background: var(--sjm-bg-alt);
  border-radius: 8px;
  padding: 10px 0;
  text-align: center;
  border: 1px solid var(--sjm-border);
}
.sjm-stat-number {
  font-size: 1.3rem;
  font-weight: 700;
  color: var(--sjm-accent);
}
.sjm-stat-label {
  font-size: 0.93rem;
  color: var(--sjm-text-light);
}

.sjm-info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 16px;
}
@media (max-width: 600px) {
  .sjm-info-grid {
    grid-template-columns: 1fr;
  }
}

.sjm-badge, .sjm-role-tag {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 10px;
  font-size: 0.82rem;
  margin-right: 5px;
  margin-bottom: 3px;
  background: var(--sjm-badge-bg);
  color: var(--sjm-badge-text);
  font-weight: 500;
  border: 1px solid var(--sjm-border);
}

.sjm-contribution-item {
  margin-bottom: 14px;
  border-bottom: 1px solid var(--sjm-border);
  padding-bottom: 10px;
}
.sjm-contribution-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.sjm-contribution-title {
  font-size: 1.05rem;
  font-weight: 600;
  margin: 0;
  color: var(--sjm-text);
}
.sjm-contribution-meta {
  font-size: 0.93rem;
  color: var(--sjm-text-light);
}
.sjm-contribution-details {
  margin-top: 4px;
  font-size: 0.95rem;
  color: var(--sjm-text);
}
.sjm-publication-abstract {
  margin-top: 6px;
  font-size: 0.95rem;
  color: #444;
}
.sjm-tags-container {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

/* Responsive Styles */
@media (max-width: 900px) {
  .sjm-author-sections {
    flex-direction: column;
    gap: 0;
  }
  .sjm-author-sidebar {
    flex-direction: row;
    gap: 16px;
    margin-top: 24px;
  }
  .sjm-section {
    padding: 14px;
  }
}
@media (max-width: 600px) {
  .sjm-author-profile {
    padding: 6px 1vw;
  }
  .sjm-author-header {
    flex-direction: column;
    gap: 14px;
    padding: 10px;
    text-align: center;
  }
  .sjm-author-avatar {
    width: 70px;
    height: 70px;
    font-size: 1.2rem;
    margin: 0 auto 7px auto;
  }
  .sjm-author-info h1 {
    font-size: 1.1rem;
  }
  .sjm-section {
    padding: 7px;
  }
  .sjm-author-sidebar {
    flex-direction: column;
    gap: 7px;
  }
}
</style>

<div class="sjm-author-profile">
    <div class="sjm-author-header">
        <div class="sjm-author-avatar">
            <?php echo strtoupper(substr($author->first_name, 0, 1) . substr($author->last_name, 0, 1)); ?>
        </div>
        <div class="sjm-author-info">
            <h1><?php echo esc_html($author->first_name . ' ' . $author->last_name); ?></h1>
            <?php if ($author->affiliation): ?>
                <div class="sjm-author-title"><?php echo esc_html($author->affiliation); ?></div>
            <?php endif; ?>
            
            <div class="sjm-author-links">
                <?php if ($author->orcid): ?>
                    <a href="https://orcid.org/<?php echo esc_attr($author->orcid); ?>" target="_blank" class="sjm-author-link">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 0C5.372 0 0 5.372 0 12s5.372 12 12 12 12-5.372 12-12S18.628 0 12 0zM7.369 4.378c.525 0 .947.431.947.947 0 .525-.422.947-.947.947-.525 0-.946-.422-.946-.947 0-.525.421-.947.946-.947zm-.722 3.038h1.444v10.041H6.647V7.416zm3.562 0h3.9c3.712 0 5.344 2.653 5.344 5.025 0 2.578-2.016 5.016-5.325 5.016h-3.919V7.416zm1.444 1.303v7.444h2.297c2.359 0 3.588-1.444 3.588-3.722 0-2.016-1.091-3.722-3.847-3.722h-2.038z"/>
                        </svg>
                        ORCID
                    </a>
                <?php endif; ?>
                
                <?php if ($author->email): ?>
                    <a href="mailto:<?php echo esc_attr($author->email); ?>" class="sjm-author-link">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                            <polyline points="22,6 12,13 2,6"/>
                        </svg>
                        Email
                    </a>
                <?php endif; ?>
                
                <?php if ($author->website): ?>
                    <a href="<?php echo esc_url($author->website); ?>" target="_blank" class="sjm-author-link">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                        </svg>
                        Website
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="sjm-author-sections">
        <div class="sjm-author-main">
            <?php if ($author->bio): ?>
                <div class="sjm-section">
                    <h2>Biography</h2>
                    <p style="color: #374151; line-height: 1.7; font-size: 15px;"><?php echo nl2br(esc_html($author->bio)); ?></p>
                </div>
            <?php endif; ?>
            
            <?php if ($papers): ?>
                <div class="sjm-section">
                    <h2>Publications (<?php echo count($papers); ?>)</h2>
                    <?php foreach ($papers as $paper): 
                        $paper_journal_id = get_post_meta($paper->ID, '_sjm_paper_journal', true);
                        $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
                        $paper_issue_id = get_post_meta($paper->ID, '_sjm_paper_issue', true);
                        $paper_issue = $paper_issue_id ? get_post($paper_issue_id) : null;
                        $paper_authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
                        if (!is_array($paper_authors_data)) $paper_authors_data = array();
                        $paper_abstract = get_post_meta($paper->ID, '_sjm_paper_abstract', true);
                        $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
                        $acceptance_date = get_post_meta($paper->ID, '_sjm_acceptance_date', true);
                        $paper_doi = get_post_meta($paper->ID, '_sjm_paper_doi', true);
                        $paper_open_access = get_post_meta($paper->ID, '_sjm_paper_open_access', true);
                        $paper_peer_reviewed = get_post_meta($paper->ID, '_sjm_paper_peer_reviewed', true);
                        
                        // Find this author's role in the paper
                        $author_roles = array();
                        $author_contributions = '';
                        foreach ($paper_authors_data as $author_data) {
                            if ($author_data['author_id'] == $author_id) {
                                $author_contributions = $author_data['contributions'];
                                $author_roles[] = 'Author';
                                if ($author_data['is_corresponding'] == '1') {
                                    $author_roles[] = 'Corresponding Author';
                                }
                                break;
                            }
                        }
                        ?>
                        <div class="sjm-contribution-item">
                            <div class="sjm-contribution-header">
                                <div>
                                    <h3 class="sjm-contribution-title">
                                        <a href="<?php echo get_permalink($paper->ID); ?>" style="color: #212529; text-decoration: none;">
                                            <?php echo esc_html($paper->post_title); ?>
                                        </a>
                                    </h3>
                                    <div class="sjm-contribution-meta">
                                        <?php if ($paper_journal): ?>
                                            <strong><?php echo esc_html($paper_journal->post_title); ?></strong>
                                        <?php endif; ?>
                                        <?php if ($paper_issue): ?>
                                            - <?php echo esc_html($paper_issue->post_title); ?>
                                        <?php endif; ?>
                                        <?php if ($acceptance_date): ?>
                                            (<?php echo date('Y', strtotime($acceptance_date)); ?>)
                                        <?php endif; ?>
                                        <?php if ($paper_type): ?>
                                            - <?php echo esc_html($paper_type); ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="sjm-tags-container">
                                    <?php foreach ($author_roles as $role): 
                                        $role_style = sjm_get_role_style($role);
                                        ?>
                                        <span class="sjm-role-tag" style="background-color: <?php echo $role_style['bg']; ?>; color: <?php echo $role_style['color']; ?>;">
                                            <?php echo $role_style['icon']; ?> <?php echo esc_html($role); ?>
                                        </span>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            
                            <?php if ($author_contributions): ?>
                                <div class="sjm-contribution-details">
                                    <strong style="color: #495057; font-size: 14px;">My Contributions:</strong>
                                    <p class="sjm-contribution-text"><?php echo esc_html($author_contributions); ?></p>
                                </div>
                            <?php endif; ?>
                            
                            <?php if ($paper_abstract): ?>
                                <div class="sjm-publication-abstract">
                                    <?php echo esc_html(wp_trim_words($paper_abstract, 30)); ?>
                                </div>
                            <?php endif; ?>
                            
                            <div class="sjm-badges">
                                <?php if ($paper_type): ?>
                                    <span class="sjm-badge"><?php echo esc_html($paper_type); ?></span>
                                <?php endif; ?>
                                <?php if ($paper_doi): ?>
                                    <span class="sjm-badge">DOI</span>
                                <?php endif; ?>
                                <?php if ($paper_open_access): ?>
                                    <span class="sjm-badge">Open Access</span>
                                <?php endif; ?>
                                <?php if ($paper_peer_reviewed): ?>
                                    <span class="sjm-badge">Peer Reviewed</span>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($version_contributions): ?>
                <div class="sjm-section">
                    <h2>Version-Specific Contributions (<?php echo count($version_contributions); ?>)</h2>
                    <?php foreach ($version_contributions as $contribution): 
                        $role_style = sjm_get_role_style($contribution['role']);
                        ?>
                        <div class="sjm-contribution-item">
                            <div class="sjm-contribution-header">
                                <div>
                                    <h3 class="sjm-contribution-title">
                                        <a href="<?php echo get_permalink($contribution['paper']->ID); ?>" style="color: #212529; text-decoration: none;">
                                            <?php echo esc_html($contribution['paper']->post_title); ?>
                                        </a>
                                        <span class="sjm-version-badge">
                                            <?php echo esc_html($contribution['version']['version_number']); ?>
                                        </span>
                                    </h3>
                                    <div class="sjm-contribution-meta">
                                        Version: <?php echo esc_html($contribution['version']['version_number']); ?>
                                        <?php if (!empty($contribution['version']['version_date'])): ?>
                                            - <?php echo date('M j, Y', strtotime($contribution['version']['version_date'])); ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="sjm-tags-container">
                                    <span class="sjm-role-tag" style="background-color: <?php echo $role_style['bg']; ?>; color: <?php echo $role_style['color']; ?>;">
                                        <?php echo $role_style['icon']; ?> <?php echo esc_html($contribution['role']); ?>
                                    </span>
                                </div>
                            </div>
                            
                            <?php if (!empty($contribution['contributions'])): ?>
                                <div class="sjm-contribution-details">
                                    <strong style="color: #495057; font-size: 14px;">Version Contributions:</strong>
                                    <p class="sjm-contribution-text"><?php echo esc_html($contribution['contributions']); ?></p>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($journals): ?>
                <div class="sjm-section">
                    <h2>Journal Contributions (<?php echo count($journals); ?>)</h2>
                    <?php foreach ($journals as $journal):
                        $journal_authors_data = get_post_meta($journal->ID, '_sjm_journal_authors_data', true);
                        if (!is_array($journal_authors_data)) $journal_authors_data = array();
                        
                        // Find this author's role in the journal
                        $journal_role = '';
                        $journal_period = '';
                        foreach ($journal_authors_data as $journal_author) {
                            if ($journal_author['author_id'] == $author_id) {
                                $journal_role = $journal_author['role'];
                                $journal_period = $journal_author['period'];
                                break;
                            }
                        }
                        
                        $role_style = sjm_get_role_style($journal_role);
                        ?>
                        <div class="sjm-contribution-item">
                            <div class="sjm-contribution-header">
                                <div>
                                    <h3 class="sjm-contribution-title">
                                        <a href="<?php echo get_permalink($journal->ID); ?>" style="color: #212529; text-decoration: none;">
                                            <?php echo esc_html($journal->post_title); ?>
                                        </a>
                                    </h3>
                                    <div class="sjm-contribution-meta">
                                        <?php if ($journal_period): ?>
                                            Period: <?php echo esc_html($journal_period); ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="sjm-tags-container">
                                    <?php if ($journal_role): ?>
                                        <span class="sjm-role-tag" style="background-color: <?php echo $role_style['bg']; ?>; color: <?php echo $role_style['color']; ?>;">
                                            <?php echo $role_style['icon']; ?> <?php echo esc_html($journal_role); ?>
                                        </span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
        
        <div class="sjm-author-sidebar">
            <div class="sjm-section">
                <h2>Statistics</h2>
                <div class="sjm-stats">
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($papers); ?></div>
                        <div class="sjm-stat-label">Publications</div>
                    </div>
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($journals); ?></div>
                        <div class="sjm-stat-label">Journals</div>
                    </div>
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($version_contributions); ?></div>
                        <div class="sjm-stat-label">Version Contributions</div>
                    </div>
                </div>
            </div>
            
            <div class="sjm-section">
                <h2>Contact Information</h2>
                <div class="sjm-info-grid">
                    <?php if ($author->email): ?>
                        <div class="sjm-info-item">
                            <div class="sjm-info-label">Email:</div>
                            <div class="sjm-info-value">
                                <a href="mailto:<?php echo esc_attr($author->email); ?>" style="color: #2563eb;">
                                    <?php echo esc_html($author->email); ?>
                                </a>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($author->orcid): ?>
                        <div class="sjm-info-item">
                            <div class="sjm-info-label">ORCID:</div>
                            <div class="sjm-info-value">
                                <a href="https://orcid.org/<?php echo esc_attr($author->orcid); ?>" target="_blank" style="color: #059669;">
                                    <?php echo esc_html($author->orcid); ?>
                                </a>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($author->affiliation): ?>
                        <div class="sjm-info-item">
                            <div class="sjm-info-label">Affiliation:</div>
                            <div class="sjm-info-value"><?php echo esc_html($author->affiliation); ?></div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($author->website): ?>
                        <div class="sjm-info-item">
                            <div class="sjm-info-label">Website:</div>
                            <div class="sjm-info-value">
                                <a href="<?php echo esc_url($author->website); ?>" target="_blank" style="color: #2563eb;">
                                    <?php echo esc_html($author->website); ?>
                                </a>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php get_footer(); ?> 