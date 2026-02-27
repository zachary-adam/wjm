<?php
/**
 * Comprehensive Plugin Guide for Simple Journal Manager
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
    <div style="background:#fff;padding:40px 32px 32px 32px;border-radius:18px;box-shadow:0 2px 16px 0 rgba(0,0,0,0.04);margin-bottom:36px;text-align:center;">
        <div style="font-size:2.5rem;font-weight:800;color:#2563eb;margin-bottom:10px;">Simple Journal Manager</div>
        <div style="font-size:1.25rem;color:#444;margin-bottom:18px;">Effortless Academic Publishing for WordPress</div>
        <div style="font-size:1.05rem;color:#666;max-width:600px;margin:0 auto 18px auto;">A modern, minimal, and powerful system for managing journals, issues, papers, authors, peer review, and more. Built for clarity, speed, and real academic workflows.</div>
        <div class="quick-actions" style="justify-content:center;">
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal')); ?>" class="quick-action">Add Journal</a>
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=journal_issue')); ?>" class="quick-action">Add Issue</a>
            <a href="<?php echo esc_url(admin_url('post-new.php?post_type=paper')); ?>" class="quick-action">Add Paper</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=sjm-dashboard')); ?>" class="quick-action">Dashboard</a>
    </div>
    </div>
    <div class="step">
        <div class="step-title" style="font-size:1.4rem;color:#111;">How It Works</div>
        <div class="step-desc" style="margin-bottom:0;">
            <ol style="margin:0 0 0 1.2em;padding:0 0 0 0.5em;color:#444;">
                <li><b>Create a Journal:</b> Add your journal with ISSN, publisher, and open access settings.</li>
                <li><b>Add Issues:</b> Organize content by issues (volume, number, date).</li>
                <li><b>Submit Papers:</b> Authors submit papers with metadata and multiple authors.</li>
                <li><b>Editorial Workflow:</b> Assign editors/reviewers, track peer review, make decisions.</li>
                <li><b>Publish:</b> Publish accepted papers, notify authors/readers, and manage open access.</li>
                <li><b>Analyze & Export:</b> Use analytics, export/import data, and access REST API.</li>
            </ol>
    </div>
    </div>
    <div class="step">
        <div class="step-title" style="font-size:1.4rem;color:#111;">How to Use</div>
        <div class="step-desc" style="margin-bottom:0;">
            <ul style="margin:0 0 0 1.2em;padding:0 0 0 0.5em;color:#444;list-style:square;">
                <li>Use the <b>Journals</b> menu to add/manage journals, issues, and papers.</li>
                <li>Manage <b>Authors</b> and assign them to papers. Each author can have a profile and ORCID.</li>
                <li>Track editorial workflow, assign roles, and manage peer review from the dashboard.</li>
                <li>Configure <b>Email Settings</b> for notifications and test emails.</li>
                <li>Import/export data in CSV, JSON, or XML for backup or migration.</li>
                <li>Access analytics for insights on submissions, publications, and activity.</li>
                <li>Integrate with external systems using the REST API.</li>
            </ul>
    </div>
    </div>
    <div class="step">
        <div class="step-title">Visual Workflow</div>
        <div style="margin:18px 0 0 0;">
            <svg width="100%" height="70" viewBox="0 0 900 70" fill="none" xmlns="http://www.w3.org/2000/svg" style="max-width:100%;height:70px;">
                <g font-family="Inter,Arial,sans-serif" font-size="16" font-weight="600">
                    <rect x="10" y="10" width="120" height="50" rx="12" fill="#2563eb"/>
                    <text x="70" y="40" fill="#fff" text-anchor="middle" alignment-baseline="middle">Journal</text>
                    <rect x="160" y="10" width="120" height="50" rx="12" fill="#2563eb"/>
                    <text x="220" y="40" fill="#fff" text-anchor="middle" alignment-baseline="middle">Issue</text>
                    <rect x="310" y="10" width="120" height="50" rx="12" fill="#2563eb"/>
                    <text x="370" y="40" fill="#fff" text-anchor="middle" alignment-baseline="middle">Paper</text>
                    <rect x="460" y="10" width="120" height="50" rx="12" fill="#2563eb"/>
                    <text x="520" y="40" fill="#fff" text-anchor="middle" alignment-baseline="middle">Review</text>
                    <rect x="610" y="10" width="120" height="50" rx="12" fill="#2563eb"/>
                    <text x="670" y="40" fill="#fff" text-anchor="middle" alignment-baseline="middle">Decision</text>
                    <rect x="760" y="10" width="120" height="50" rx="12" fill="#2563eb"/>
                    <text x="820" y="40" fill="#fff" text-anchor="middle" alignment-baseline="middle">Publish</text>
                </g>
                <g stroke="#2563eb" stroke-width="3" fill="none">
                    <line x1="130" y1="35" x2="160" y2="35"/>
                    <line x1="280" y1="35" x2="310" y2="35"/>
                    <line x1="430" y1="35" x2="460" y2="35"/>
                    <line x1="580" y1="35" x2="610" y2="35"/>
                    <line x1="730" y1="35" x2="760" y2="35"/>
                </g>
            </svg>
    </div>
    </div>
    <div class="step">
        <div class="step-title">Key Features</div>
        <div class="step-desc">
            <ul style="margin:0 0 0 1.2em;padding:0 0 0 0.5em;color:#444;list-style:square;">
                <li>Minimal, modern, and accessible UI</li>
                <li>Full editorial workflow (submission, review, decision, publish)</li>
                <li>Open access and hybrid journal support</li>
                <li>Bulk import/export (CSV, JSON, XML)</li>
                <li>REST API for integration</li>
                <li>Customizable email notifications</li>
                <li>Role-based permissions for all academic roles</li>
                <li>Analytics dashboard for insights</li>
            </ul>
    </div>
    </div>
    <div class="step">
        <div class="step-title">FAQ</div>
        <div class="step-desc">
            <b>Q: How do I fix author profile URLs (404 errors)?</b><br>
            A: Go to <b>Settings → Permalinks</b> and click <b>Save Changes</b> to flush rewrite rules. This will update the author profile URLs.<br><br>
            <b>Q: Can I migrate data from another system?</b><br>
            A: Yes, use the Import/Export page to migrate journals, issues, papers, and authors.<br><br>
            <b>Q: How do I customize email templates?</b><br>
            A: Go to <b>Journals → Email Settings</b> to edit and test email templates.<br><br>
            <b>Q: Where can I find the REST API endpoints?</b><br>
            A: All endpoints are under <span class="code-block">/wp-json/sjm/v1/</span> (see above for examples).
        </div>
    </div>
</div>
</body>
</html> 