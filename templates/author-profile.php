<?php
get_header();

$author_id = get_query_var('author_profile_id');
$author    = sjm_get_author_by_id($author_id);

if (!$author) {
    echo '<div class="sjm-single-container">';
    echo '<h1>Author not found</h1>';
    echo '<p>The requested author profile could not be found.</p>';
    echo '</div>';
    get_footer();
    return;
}

// Papers this author contributed to
$papers = get_posts(array(
    'post_type'      => 'paper',
    'posts_per_page' => -1,
    'meta_query'     => array(array(
        'key'     => '_sjm_paper_authors_data',
        'value'   => '"author_id";i:' . intval($author_id),
        'compare' => 'LIKE',
    )),
));

// Journals this author contributed to
$journals = get_posts(array(
    'post_type'      => 'journal',
    'posts_per_page' => -1,
    'meta_query'     => array(array(
        'key'     => '_sjm_journal_authors_data',
        'value'   => '"author_id";i:' . intval($author_id),
        'compare' => 'LIKE',
    )),
));

// Role badge colour map (no emojis)
$role_colors = array(
    'Author'               => array('bg' => '#e8f0f8', 'color' => '#1e3a5f'),
    'Corresponding Author' => array('bg' => '#f0ebf8', 'color' => '#5b21b6'),
    'Reviewer'             => array('bg' => '#ecfdf5', 'color' => '#065f46'),
    'Editor'               => array('bg' => '#fef3c7', 'color' => '#92400e'),
    'Guest Editor'         => array('bg' => '#fce7f3', 'color' => '#9d174d'),
    'Contributor'          => array('bg' => '#f0fdf4', 'color' => '#166534'),
    'default'              => array('bg' => '#f1f5f9', 'color' => '#475569'),
);

$initials = strtoupper(substr($author->first_name, 0, 1) . substr($author->last_name, 0, 1));
?>

<div class="sjm-single-container">

    <!-- Breadcrumb -->
    <nav class="sjm-breadcrumb">
        <a href="<?php echo esc_url(home_url('/')); ?>">Home</a>
        <span class="sjm-breadcrumb-separator">&rsaquo;</span>
        <span class="sjm-breadcrumb-current"><?php echo esc_html($author->first_name . ' ' . $author->last_name); ?></span>
    </nav>

    <!-- Author Header -->
    <div class="sjm-author-profile-header">
        <div class="sjm-author-photo">
            <div class="sjm-author-initials"><?php echo esc_html($initials); ?></div>
        </div>
        <div class="sjm-author-profile-info">
            <h2><?php echo esc_html($author->first_name . ' ' . $author->last_name); ?></h2>
            <?php if ($author->affiliation): ?>
                <p class="sjm-authors-line" style="margin-bottom:16px;"><?php echo esc_html($author->affiliation); ?></p>
            <?php endif; ?>
            <div class="sjm-actions-row">
                <?php if ($author->orcid): ?>
                    <a href="https://orcid.org/<?php echo esc_attr($author->orcid); ?>" target="_blank" class="sjm-download-btn sjm-download-btn-secondary" style="font-size:13px;padding:7px 14px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0"><path d="M12 0C5.372 0 0 5.372 0 12s5.372 12 12 12 12-5.372 12-12S18.628 0 12 0zM7.369 4.378c.525 0 .947.431.947.947 0 .525-.422.947-.947.947-.525 0-.946-.422-.946-.947 0-.525.421-.947.946-.947zm-.722 3.038h1.444v10.041H6.647V7.416zm3.562 0h3.9c3.712 0 5.344 2.653 5.344 5.025 0 2.578-2.016 5.016-5.325 5.016h-3.919V7.416zm1.444 1.303v7.444h2.297c2.359 0 3.588-1.444 3.588-3.722 0-2.016-1.091-3.722-3.847-3.722h-2.038z"/></svg>
                        ORCID
                    </a>
                <?php endif; ?>
                <?php if ($author->email): ?>
                    <a href="mailto:<?php echo esc_attr($author->email); ?>" class="sjm-download-btn sjm-download-btn-secondary" style="font-size:13px;padding:7px 14px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        Email
                    </a>
                <?php endif; ?>
                <?php if ($author->website): ?>
                    <a href="<?php echo esc_url($author->website); ?>" target="_blank" class="sjm-download-btn sjm-download-btn-secondary" style="font-size:13px;padding:7px 14px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                        Website
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Stats -->
    <div class="sjm-author-metrics-display">
        <div class="sjm-metric-box">
            <div class="sjm-metric-value"><?php echo count($papers); ?></div>
            <div class="sjm-metric-label">Publications</div>
        </div>
        <div class="sjm-metric-box">
            <div class="sjm-metric-value"><?php echo count($journals); ?></div>
            <div class="sjm-metric-label">Journals</div>
        </div>
        <?php
        $total_citations = 0;
        $total_views     = 0;
        foreach ($papers as $p) {
            $total_citations += (int) get_post_meta($p->ID, '_sjm_citation_count', true);
            $total_views     += (int) get_post_meta($p->ID, '_sjm_views_count',    true);
        }
        ?>
        <div class="sjm-metric-box">
            <div class="sjm-metric-value"><?php echo $total_citations; ?></div>
            <div class="sjm-metric-label">Citations</div>
        </div>
        <div class="sjm-metric-box">
            <div class="sjm-metric-value"><?php echo $total_views; ?></div>
            <div class="sjm-metric-label">Total Views</div>
        </div>
    </div>

    <!-- Biography -->
    <?php if ($author->bio): ?>
    <div class="sjm-section">
        <h2 class="sjm-section-title">Biography</h2>
        <p style="font-size:15px;color:#374151;line-height:1.75;margin:0;"><?php echo nl2br(esc_html($author->bio)); ?></p>
    </div>
    <?php endif; ?>

    <!-- Contact Information -->
    <?php if ($author->email || $author->orcid || $author->affiliation || $author->website): ?>
    <div class="sjm-section">
        <h2 class="sjm-section-title">Contact &amp; Details</h2>
        <div class="sjm-meta-grid">
            <?php if ($author->email): ?>
            <div class="sjm-meta-item">
                <span class="sjm-meta-label">Email</span>
                <span class="sjm-meta-value"><a href="mailto:<?php echo esc_attr($author->email); ?>"><?php echo esc_html($author->email); ?></a></span>
            </div>
            <?php endif; ?>
            <?php if ($author->orcid): ?>
            <div class="sjm-meta-item">
                <span class="sjm-meta-label">ORCID</span>
                <span class="sjm-meta-value"><a href="https://orcid.org/<?php echo esc_attr($author->orcid); ?>" target="_blank" class="sjm-orcid-link"><?php echo esc_html($author->orcid); ?></a></span>
            </div>
            <?php endif; ?>
            <?php if ($author->affiliation): ?>
            <div class="sjm-meta-item">
                <span class="sjm-meta-label">Affiliation</span>
                <span class="sjm-meta-value"><?php echo esc_html($author->affiliation); ?></span>
            </div>
            <?php endif; ?>
            <?php if ($author->website): ?>
            <div class="sjm-meta-item">
                <span class="sjm-meta-label">Website</span>
                <span class="sjm-meta-value"><a href="<?php echo esc_url($author->website); ?>" target="_blank"><?php echo esc_html($author->website); ?></a></span>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Publications -->
    <?php if ($papers): ?>
    <div class="sjm-section">
        <h2 class="sjm-section-title">Publications (<?php echo count($papers); ?>)</h2>
        <div class="sjm-author-publications">
            <ul>
                <?php foreach ($papers as $paper):
                    $j_id        = get_post_meta($paper->ID, '_sjm_paper_journal',      true);
                    $i_id        = get_post_meta($paper->ID, '_sjm_paper_issue',        true);
                    $ptype       = get_post_meta($paper->ID, '_sjm_paper_type',         true);
                    $doi         = get_post_meta($paper->ID, '_sjm_paper_doi',          true);
                    $oa          = get_post_meta($paper->ID, '_sjm_paper_open_access',  true);
                    $acc         = get_post_meta($paper->ID, '_sjm_acceptance_date',    true);
                    $abstract    = get_post_meta($paper->ID, '_sjm_paper_abstract',     true);
                    $pjournal    = $j_id ? get_post($j_id) : null;
                    $pissue      = $i_id ? get_post($i_id) : null;
                    $year        = $acc ? date('Y', strtotime($acc)) : '';

                    // Find role in this paper
                    $authors_data = get_post_meta($paper->ID, '_sjm_paper_authors_data', true);
                    $is_corr = false;
                    if (is_array($authors_data)) {
                        foreach ($authors_data as $ad) {
                            if ($ad['author_id'] == $author_id && !empty($ad['is_corresponding'])) {
                                $is_corr = true;
                            }
                        }
                    }
                ?>
                <li>
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                        <div style="flex:1;min-width:0;">
                            <a href="<?php echo esc_url(get_permalink($paper->ID)); ?>" style="font-size:15px;font-weight:600;color:#111827;text-decoration:none;line-height:1.4;display:block;margin-bottom:4px;"><?php echo esc_html($paper->post_title); ?></a>
                            <small>
                                <?php if ($pjournal): ?><strong><?php echo esc_html($pjournal->post_title); ?></strong><?php endif; ?>
                                <?php if ($pissue): ?>
                                    <?php
                                    $vol = get_post_meta($pissue->ID, '_sjm_issue_volume', true);
                                    $num = get_post_meta($pissue->ID, '_sjm_issue_number', true);
                                    if ($vol && $num) echo ' · Vol. ' . esc_html($vol) . ', No. ' . esc_html($num);
                                    ?>
                                <?php endif; ?>
                                <?php if ($year): ?> · <?php echo esc_html($year); ?><?php endif; ?>
                            </small>
                            <?php if ($abstract): ?>
                                <p style="font-size:13px;color:#6b7280;margin:6px 0 0;line-height:1.55;"><?php echo esc_html(wp_trim_words($abstract, 30)); ?></p>
                            <?php endif; ?>
                        </div>
                        <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end;flex-shrink:0;">
                            <?php if ($is_corr): ?>
                                <span class="sjm-corresponding-badge">Corresponding</span>
                            <?php endif; ?>
                            <?php if ($ptype): ?><span class="sjm-badge"><?php echo esc_html($ptype); ?></span><?php endif; ?>
                            <?php if ($oa): ?><span class="sjm-badge" style="background:#f0fdf4;color:#16a34a;border-color:#bbf7d0;">Open Access</span><?php endif; ?>
                            <?php if ($doi): ?><span class="sjm-badge">DOI</span><?php endif; ?>
                        </div>
                    </div>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <?php endif; ?>

    <!-- Journal Contributions -->
    <?php if ($journals): ?>
    <div class="sjm-section">
        <h2 class="sjm-section-title">Journal Contributions (<?php echo count($journals); ?>)</h2>
        <div class="sjm-author-publications">
            <ul>
                <?php foreach ($journals as $journal):
                    $jad       = get_post_meta($journal->ID, '_sjm_journal_authors_data', true);
                    $role      = '';
                    $period    = '';
                    if (is_array($jad)) {
                        foreach ($jad as $ja) {
                            if ($ja['author_id'] == $author_id) {
                                $role   = $ja['role']   ?? '';
                                $period = $ja['period'] ?? '';
                                break;
                            }
                        }
                    }
                    $rc = isset($role_colors[$role]) ? $role_colors[$role] : $role_colors['default'];
                ?>
                <li>
                    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                        <div>
                            <a href="<?php echo esc_url(get_permalink($journal->ID)); ?>" style="font-size:15px;font-weight:600;color:#111827;text-decoration:none;"><?php echo esc_html($journal->post_title); ?></a>
                            <?php if ($period): ?><small> · <?php echo esc_html($period); ?></small><?php endif; ?>
                        </div>
                        <?php if ($role): ?>
                            <span style="display:inline-block;padding:3px 10px;border-radius:3px;font-size:11px;font-weight:600;letter-spacing:.04em;background:<?php echo esc_attr($rc['bg']); ?>;color:<?php echo esc_attr($rc['color']); ?>;"><?php echo esc_html($role); ?></span>
                        <?php endif; ?>
                    </div>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <?php endif; ?>

    <?php if (!$papers && !$journals): ?>
    <div class="sjm-section">
        <p style="color:#6b7280;font-size:15px;">No publications or journal contributions found for this author yet.</p>
    </div>
    <?php endif; ?>

</div>

<?php get_footer(); ?>
