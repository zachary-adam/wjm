<?php
/**
 * Comprehensive Workflow Guide for Simple Journal Manager
 * Detailed explanation of the entire academic publishing system
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plugin Guide</title>
    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #f8f9fa;
            color: #222;
            margin: 0;
        }
        .container {
            max-width: 900px;
            margin: 40px auto;
            padding: 0 24px;
        }
        .title {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: #111;
        }
        .desc {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 32px;
        }
        .step {
            background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            margin-bottom: 28px;
            padding: 28px 24px;
        }
        .step-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #2563eb;
            margin-bottom: 10px;
        }
        .step-desc {
            color: #444;
            font-size: 1rem;
            margin-bottom: 8px;
        }
        .code-block {
            background: #f1f5f9;
            color: #222;
            font-family: 'Menlo', 'Monaco', 'Consolas', monospace;
            font-size: 0.97rem;
            padding: 12px 16px;
            border-radius: 6px;
            margin: 12px 0 0 0;
            overflow-x: auto;
        }
        .quick-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 10px;
        }
        .quick-action {
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 10px 18px;
            font-size: 1rem;
            font-weight: 500;
            text-decoration: none;
            transition: background 0.2s;
        }
        .quick-action:hover {
            background: #1746a2;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="title">Plugin Guide</div>
    <div class="desc">A comprehensive, minimal, and modern guide to all features, settings, and workflows in Simple Journal Manager.</div>
    <div class="step">
        <div class="step-title">Overview</div>
        <div class="step-desc">Simple Journal Manager is a complete academic publishing solution for WordPress. It supports journals, issues, papers, authors, editorial workflow, peer review, open access, import/export, REST API, and email notifications. This guide covers every feature and how to use them.</div>
    </div>
    <div class="step">
        <div class="step-title">1. Journals & Issues</div>
        <div class="step-desc">Create and manage journals with ISSN, publisher, and open access settings. Add issues to journals, set volume, number, and publication date. Organize papers by issue.</div>
    </div>
    <div class="step">
        <div class="step-title">2. Papers & Authors</div>
        <div class="step-desc">Submit papers with metadata, author info, and abstract. Assign multiple authors. Track paper status, peer review, and open access compliance. Author profiles are available for each contributor.</div>
    </div>
    <div class="step">
        <div class="step-title">3. Editorial Workflow</div>
        <div class="step-desc">Assign editors and reviewers. Track review status, editorial decisions, and communicate with authors. All actions are logged for transparency.</div>
    </div>
    <div class="step">
        <div class="step-title">4. Import & Export</div>
        <div class="step-desc">Bulk import or export journals, issues, papers, and authors in CSV, JSON, or XML format. Use the Import/Export page in the admin for data migration or backup.</div>
    </div>
    <div class="step">
        <div class="step-title">5. REST API</div>
        <div class="step-desc">Access all content types via the REST API. Example endpoints:<br>
        <span class="code-block">GET /wp-json/sjm/v1/journals<br>GET /wp-json/sjm/v1/papers<br>GET /wp-json/sjm/v1/authors</span><br>
        Use the API for integrations, mobile apps, or external systems.</div>
    </div>
    <div class="step">
        <div class="step-title">6. Email Notifications</div>
        <div class="step-desc">Automatic email notifications for paper submission, review, and publication. Customize templates and test emails in Email Settings. All emails are logged for review.</div>
    </div>
    <div class="step">
        <div class="step-title">7. User Roles & Permissions</div>
        <div class="step-desc">Supports multiple roles: Editor-in-Chief, Managing Editor, Guest Editor, Reviewer, Author, Copyeditor, Proofreader, Layout Editor. Each role has specific permissions and dashboard access.</div>
    </div>
    <div class="step">
        <div class="step-title">8. Settings & Customization</div>
        <div class="step-desc">Configure plugin settings for email, import/export, and workflow. Access settings from the admin menu. All options are designed for clarity and minimalism.</div>
    </div>
    <div class="step">
        <div class="step-title">9. Publishing Workflow</div>
        <div class="step-desc">The typical workflow: Create journal → Add issues → Submit papers → Assign reviewers → Editorial decision → Publish paper → Notify authors and readers. All steps are managed in a clean, modern interface.</div>
    </div>
    <div class="step">
        <div class="step-title">Quick Actions</div>
        <div class="quick-actions">
            <a id="sjm-add-journal-guide" href="<?php echo esc_url(admin_url('post-new.php?post_type=journal')); ?>" class="quick-action">Add Journal</a>
            <a id="sjm-add-issue-guide" href="<?php echo esc_url(admin_url('post-new.php?post_type=journal_issue')); ?>" class="quick-action">Add Issue</a>
            <a id="sjm-add-paper-guide" href="<?php echo esc_url(admin_url('post-new.php?post_type=paper')); ?>" class="quick-action">Add Paper</a>
            <a id="sjm-dashboard-guide" href="<?php echo esc_url(admin_url('admin.php?page=sjm-dashboard')); ?>" class="quick-action">Dashboard</a>
        </div>
    </div>
</div>
</body>
</html> 