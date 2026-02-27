<?php
/**
 * Plugin Guide Template — Wisdom Journal Manager
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap wjm-modern-wrap">

    <div class="wjm-page-header">
        <div>
            <h1 class="wjm-page-title">Plugin Guide</h1>
            <p class="wjm-page-description">Everything you need to get started with Wisdom Journal Manager</p>
        </div>
    </div>

    <!-- Hero -->
    <div class="wjm-guide-hero">
        <div class="wjm-guide-hero-title">Wisdom Journal Manager</div>
        <div class="wjm-guide-hero-desc">Effortless Academic Publishing for WordPress</div>
        <p class="wjm-guide-hero-sub">
            A modern, minimal, and powerful system for managing journals, issues, papers,
            authors, peer review, and more. Built for clarity, speed, and real academic workflows.
        </p>
        <div class="wjm-guide-actions">
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal')); ?>"       class="wjm-btn wjm-btn-primary">Add Journal</a>
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal_issue')); ?>" class="wjm-btn wjm-btn-primary">Add Issue</a>
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=paper')); ?>"         class="wjm-btn wjm-btn-primary">Add Paper</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=sjm-dashboard')); ?>"         class="wjm-btn wjm-btn-secondary">Dashboard</a>
        </div>
    </div>

    <!-- How it works -->
    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">How It Works</h2>
        <ol class="wjm-guide-ol">
            <li><b>Create a Journal</b> — Add your journal with ISSN, publisher, and open access settings.</li>
            <li><b>Add Issues</b> — Organize content by issues (volume, number, date).</li>
            <li><b>Submit Papers</b> — Authors submit papers with metadata and multiple authors.</li>
            <li><b>Editorial Workflow</b> — Assign editors and reviewers, track peer review, make decisions.</li>
            <li><b>Publish</b> — Publish accepted papers, notify authors and readers, manage open access.</li>
            <li><b>Analyze &amp; Export</b> — Use analytics, export/import data, and access the REST API.</li>
        </ol>
    </div>

    <!-- How to use -->
    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">How to Use</h2>
        <ul class="wjm-guide-ul">
            <li>Use the <b>Journals</b> menu to add and manage journals, issues, and papers.</li>
            <li>Manage <b>Authors</b> and assign them to papers. Each author can have a profile and ORCID.</li>
            <li>Track editorial workflow, assign roles, and manage peer review from the dashboard.</li>
            <li>Configure <b>Email Settings</b> for notifications and test emails.</li>
            <li>Import and export data in CSV, JSON, or XML for backup or migration.</li>
            <li>Access analytics for insights on submissions, publications, and activity.</li>
            <li>Integrate with external systems using the REST API.</li>
        </ul>
    </div>

    <!-- Visual workflow -->
    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">Visual Workflow</h2>
        <div style="overflow-x:auto;padding:0.5rem 0;">
            <svg width="100%" height="60" viewBox="0 0 900 60" xmlns="http://www.w3.org/2000/svg"
                 style="max-width:100%;min-width:600px;">
                <g font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif" font-size="13" font-weight="600">
                    <rect x="10"  y="8" width="120" height="44" rx="10" fill="#111827"/>
                    <text x="70"  y="34" fill="#fff" text-anchor="middle" dominant-baseline="middle">Journal</text>
                    <rect x="160" y="8" width="120" height="44" rx="10" fill="#111827"/>
                    <text x="220" y="34" fill="#fff" text-anchor="middle" dominant-baseline="middle">Issue</text>
                    <rect x="310" y="8" width="120" height="44" rx="10" fill="#111827"/>
                    <text x="370" y="34" fill="#fff" text-anchor="middle" dominant-baseline="middle">Paper</text>
                    <rect x="460" y="8" width="120" height="44" rx="10" fill="#111827"/>
                    <text x="520" y="34" fill="#fff" text-anchor="middle" dominant-baseline="middle">Review</text>
                    <rect x="610" y="8" width="120" height="44" rx="10" fill="#111827"/>
                    <text x="670" y="34" fill="#fff" text-anchor="middle" dominant-baseline="middle">Decision</text>
                    <rect x="760" y="8" width="120" height="44" rx="10" fill="#22c55e"/>
                    <text x="820" y="34" fill="#fff" text-anchor="middle" dominant-baseline="middle">Publish</text>
                </g>
                <g stroke="#d1d5db" stroke-width="1.5" fill="none" stroke-dasharray="4 2">
                    <line x1="130" y1="30" x2="160" y2="30"/>
                    <line x1="280" y1="30" x2="310" y2="30"/>
                    <line x1="430" y1="30" x2="460" y2="30"/>
                    <line x1="580" y1="30" x2="610" y2="30"/>
                    <line x1="730" y1="30" x2="760" y2="30"/>
                </g>
            </svg>
        </div>
    </div>

    <!-- Key features -->
    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">Key Features</h2>
        <ul class="wjm-guide-ul">
            <li>Full editorial workflow (submission, review, decision, publish)</li>
            <li>Open access and hybrid journal support</li>
            <li>Bulk import/export (CSV, JSON, XML)</li>
            <li>REST API for integration — all endpoints under <code class="wjm-code-block">/wp-json/sjm/v1/</code></li>
            <li>Customizable email notifications</li>
            <li>Role-based permissions for all academic roles</li>
            <li>Analytics dashboard for insights on citations, views, and downloads</li>
            <li>DOI registration via Crossref integration</li>
        </ul>
    </div>

    <!-- FAQ -->
    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">FAQ</h2>
        <ul class="wjm-guide-ul" style="list-style:none;padding:0;">
            <li style="padding:0.875rem 0;border-bottom:1px solid var(--wjm-border-light);">
                <strong style="color:var(--wjm-text-primary);display:block;margin-bottom:0.25rem;">
                    How do I fix author profile URLs (404 errors)?
                </strong>
                Go to <b>Settings → Permalinks</b> and click <b>Save Changes</b> to flush rewrite rules.
            </li>
            <li style="padding:0.875rem 0;border-bottom:1px solid var(--wjm-border-light);">
                <strong style="color:var(--wjm-text-primary);display:block;margin-bottom:0.25rem;">
                    Can I migrate data from another system?
                </strong>
                Yes — use the Import/Export page to migrate journals, issues, papers, and authors.
            </li>
            <li style="padding:0.875rem 0;border-bottom:1px solid var(--wjm-border-light);">
                <strong style="color:var(--wjm-text-primary);display:block;margin-bottom:0.25rem;">
                    How do I customize email templates?
                </strong>
                Go to <b>Journals → Email Settings</b> to edit and test email templates.
            </li>
            <li style="padding:0.875rem 0;">
                <strong style="color:var(--wjm-text-primary);display:block;margin-bottom:0.25rem;">
                    Where can I find the REST API endpoints?
                </strong>
                All endpoints are under <code class="wjm-code-block">/wp-json/sjm/v1/</code>.
            </li>
        </ul>
    </div>

</div>
