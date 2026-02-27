<?php
/**
 * Workflow Guide Template — Wisdom Journal Manager
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap wjm-modern-wrap">

    <div class="wjm-page-header">
        <div>
            <h1 class="wjm-page-title">Workflow Guide</h1>
            <p class="wjm-page-description">A comprehensive guide to all features, settings, and workflows</p>
        </div>
        <div class="wjm-guide-actions" style="justify-content:flex-end;">
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal')); ?>"       class="wjm-btn wjm-btn-primary wjm-btn-sm">Add Journal</a>
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal_issue')); ?>" class="wjm-btn wjm-btn-primary wjm-btn-sm">Add Issue</a>
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=paper')); ?>"         class="wjm-btn wjm-btn-primary wjm-btn-sm">Add Paper</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=sjm-dashboard')); ?>"         class="wjm-btn wjm-btn-secondary wjm-btn-sm">Dashboard</a>
        </div>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">Overview</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Wisdom Journal Manager is a complete academic publishing solution for WordPress. It supports journals,
            issues, papers, authors, editorial workflow, peer review, open access, import/export, REST API,
            and email notifications. This guide covers every feature and how to use them.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">1. Journals &amp; Issues</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Create and manage journals with ISSN, publisher, and open access settings. Add issues to journals,
            set volume, number, and publication date. Organize papers by issue.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">2. Papers &amp; Authors</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Submit papers with metadata, author info, and abstract. Assign multiple authors. Track paper status,
            peer review, and open access compliance. Author profiles are available for each contributor.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">3. Editorial Workflow</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Assign editors and reviewers. Track review status, editorial decisions, and communicate with authors.
            All actions are logged for transparency.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">4. Import &amp; Export</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Bulk import or export journals, issues, papers, and authors in CSV, JSON, or XML format.
            Use the Import/Export page in the admin for data migration or backup.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">5. REST API</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;margin-bottom:0.75rem;">
            Access all content types via the REST API. Use the API for integrations, mobile apps, or external systems.
        </p>
        <code class="wjm-code-block" style="display:block;white-space:pre;">GET /wp-json/sjm/v1/journals
GET /wp-json/sjm/v1/papers
GET /wp-json/sjm/v1/authors</code>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">6. Email Notifications</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Automatic email notifications for paper submission, review, and publication.
            Customize templates and test emails in <b>Journals → Email Settings</b>. All emails are logged for review.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">7. User Roles &amp; Permissions</h2>
        <ul class="wjm-guide-ul">
            <li><b>Editor-in-Chief</b> — Full control over all content and editorial decisions</li>
            <li><b>Managing Editor</b> — Manages submissions, assignments, and workflow</li>
            <li><b>Guest Editor</b> — Handles a specific issue or section</li>
            <li><b>Reviewer</b> — Submits peer review reports</li>
            <li><b>Author</b> — Submits and tracks their own papers</li>
            <li><b>Copyeditor / Proofreader / Layout Editor</b> — Production roles with scoped access</li>
        </ul>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">8. Settings &amp; Customization</h2>
        <p style="font-size:0.875rem;color:var(--wjm-text-secondary);line-height:1.65;">
            Configure plugin settings for email, import/export, and workflow from the admin menu.
            All options are designed for clarity and minimal friction.
        </p>
    </div>

    <div class="wjm-guide-step">
        <h2 class="wjm-guide-step-title">9. Publishing Workflow</h2>
        <ol class="wjm-guide-ol">
            <li>Create journal</li>
            <li>Add issues</li>
            <li>Submit papers</li>
            <li>Assign reviewers</li>
            <li>Make editorial decision</li>
            <li>Publish paper</li>
            <li>Notify authors and readers</li>
        </ol>
    </div>

</div>
