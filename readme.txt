=== Wisdom Journal Manager ===
Contributors: maazahmad, shariqhashme
Tags: journal, academic, research, publication, citations, authors, papers, scholarly, doi, orcid
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

World's First Affordable Journal Manager — a full-stack WordPress solution for managing academic journals, issues, papers, and authors with automated citation tracking and enterprise-grade security.

== Description ==

**Wisdom Journal Manager** by Aethex is a complete academic publishing platform for WordPress. It covers the full publication hierarchy — Journals → Issues → Papers → Authors — with editorial workflow, automation, frontend templates, and enterprise-grade security baked in.

Whether you run a single journal or a portfolio of publications, Wisdom Journal Manager provides everything you need out of the box.

= Core Hierarchy =

* **Journals** — the top-level container; each journal has its own ISSN, editorial board, branding, and settings.
* **Issues** — publication units linked to a journal; support volume/number/year, special issues, and guest editors.
* **Papers** — the scholarly items; rich metadata including DOI, versioning, open access flag, author affiliations, compliance fields, and automated citation/view metrics.
* **Authors** — dedicated author profiles with ORCID integration, linked to papers for accurate attribution.

= Key Features =

**Journal Management**
* ISSN, publisher, founding year, frequency, language, subject areas, impact factor
* Open Access and Peer Reviewed toggles
* DOI prefix, indexing flags (CrossRef, Semantic Scholar, etc.)
* Logo and cover image uploads
* Assign Editor-in-Chief, Managing Editor, Copy/Layout editors

**Issue Management**
* Link issues to any journal
* Volume, issue number, year, and publication date
* Special Issue support with a custom title
* Guest editors, issue editors, reviewers, copy/layout editors
* Cover image, full-issue PDF URL, keywords, and abstract

**Paper Management**
* DOI, paper type, submission/acceptance/publication dates
* Open access and peer-reviewed flags
* Structured author data: name, email, affiliation, ORCID, website, bio, and corresponding-author flag
* Versioning system: version number, date, type, notes, and full version history UI
* Compliance: funding statement, conflicts of interest, ethics approval numbers/committee, data availability
* Rights: copyright holder/year, license type and URL, reuse permissions
* Publication lifecycle: status, tracking history, corrections/errata
* Automated citation and view count updates

**Author Profiles**
* Dedicated author records in `wp_sjm_authors`
* First/last name, email, affiliation, bio, website, ORCID
* Frontend author profile page and `[wjm_author_profile id="X"]` shortcode
* Link authors to papers with display order and corresponding-author designation

**Editorial Workflow**
* Assign roles per journal or issue: Editor-in-Chief, Managing Editor, Editors, Reviewers, Copy/Layout
* Status tracking with timestamps and notes
* Role-based capability checks enforced across all admin actions

**Automation & Academic API Integrations**
* CrossRef — DOI-based citation data (free)
* Semantic Scholar — academic paper data and citations (free)
* arXiv — preprint and paper data (free)
* Scopus — comprehensive citation database (requires API key)
* Web of Science — citation indexing and analysis (requires API key)
* Schedule daily, weekly, or monthly automatic updates
* Manual "Update All" and per-paper "Update This Paper" buttons
* All API keys stored encrypted at rest (AES-256-CBC)

**Frontend Templates & Shortcodes**
* Clean, minimal academic design (no page builder required)
* Single-view pages for journals, issues, papers, and author profiles
* Breadcrumb navigation on all single-view pages
* Responsive layouts for desktop, tablet, and mobile
* `[journals]` — journal listing grid or list
* `[issues]` — issue listing with filters
* `[papers]` — paper listing with keyword, author, type, and year filters
* `[wjm_author_profile id="X"]` — display a single author's profile on any page

**Enterprise Security**
* AES-256-CBC encryption for all API keys (using WordPress salts)
* Role-based rate limiting with friendly messages
* Comprehensive input sanitization and output escaping
* CSRF protection via nonces on all forms
* Granular capability checks — only authorized roles can perform sensitive actions
* Security event logging with severity levels, IP address, user context, and timestamps
* SQL-safe parameterized queries throughout

**Data Operations**
* Import CSV/JSON data for journals, issues, and papers
* Export to CSV, JSON, or XML for backup or migration
* Field validation during import with error reporting
* Sample import templates available to download

= Shortcode Reference =

**Journals**
`[journals]`
`[journals layout="grid|list" publisher="Aethex" open_access="1" peer_reviewed="1" year="2024" per_page="12"]`

**Issues**
`[issues]`
`[issues journal_id="123" volume="5" year="2024" special_issue="1" per_page="12"]`

**Papers**
`[papers]`
`[papers journal_id="123" issue_id="456" paper_type="Research Article" author="Lovelace" keyword="Automation" year="2024" per_page="24"]`

**Author Profile**
`[wjm_author_profile id="42"]`

= User Roles & Rate Limits =

* **Student**: read access; 50 API calls/hour, 30 data fetches/hour
* **Researcher**: read + manage own papers; 100 API calls/hour, 60 data fetches/hour
* **Editor**: manage journals/issues/papers, run automation; 200 API calls/hour, 120 data fetches/hour
* **Administrator**: all capabilities; 500 API calls/hour, 300 data fetches/hour

= Perfect For =

* Academic institutions managing one or more peer-reviewed journals
* Research organizations with structured publication workflows
* University departments publishing faculty and student research
* Independent publishers needing secure, scalable journal management
* Organizations requiring automated citation tracking and compliance fields

== Installation ==

= System Requirements =

* WordPress 5.0 or higher (tested up to 6.7)
* PHP 7.4 or higher
* MySQL 5.6 or higher (or compatible MariaDB)
* PHP extensions: curl, json
* Memory limit: 256 MB minimum (512 MB recommended)
* HTTPS strongly recommended for all admin operations

= Installation Steps =

1. In WordPress Admin, go to **Plugins → Add New → Upload Plugin**.
2. Select the plugin ZIP file and click **Install Now**.
3. Click **Activate Plugin**.
4. Navigate to **Journals → Plugin Verification** to confirm all components are working.
5. Go to **Journals → User Roles** to configure role assignments.
6. Optionally, go to **Journals → Automation** to add API keys and enable citation updates.

= Quick Start (Add Your First Content) =

1. Go to **Journals → Add New** — create a Journal (ISSN, publisher, logo, editors).
2. Go to **Issues → Add New** — create an Issue linked to your Journal (volume, number, year).
3. Go to **Papers → Add New** — add Papers with DOI, authors, versioning, and file links.
4. Go to **Authors** — add author profiles and link them to papers.
5. Create a WordPress Page and add a shortcode (e.g. `[journals]`) to display your content.
6. Go to **Journals → Automation** to enable scheduled citation updates.

== Feature Documentation ==

= Journals =

Create and manage journals at **Journals → Add New**.

Fields:
* Name (post title), ISSN, Publisher, Founding year, Frequency, Language, Subject areas
* Impact factor (optional), Website, Contact email
* Open Access toggle, Peer Reviewed toggle
* Indexing flags: CrossRef, Semantic Scholar, Scopus, etc.
* DOI prefix (e.g. `10.12345`) for consistent paper DOIs
* Logo and Cover image uploads
* Editorial board: Editor-in-Chief, Managing Editor, Copyeditors, Layout editors

Frontend: Each journal has its own single-view page; use `[journals]` shortcode for listings.

= Issues =

Create issues at **Issues → Add New**.

Fields:
* Journal (required — links this issue to a journal)
* Volume, Issue number, Year, Publication date
* Special Issue flag with optional custom title
* Keywords, Abstract/summary, Page range
* Guest editors, Issue editors, Reviewers, Copy/Layout editors
* Cover image, Full-issue PDF URL
* Total papers counter (informational)

Frontend: Use `[issues]` shortcode for listings; each issue has its own single-view page.

= Papers =

Create papers at **Papers → Add New**.

Fields:
* Title, DOI, Paper type, Keywords, Page range
* Journal and Issue relationships
* Submission date, Acceptance date, Publication date
* Open access and Peer reviewed flags
* Abstract, PDF URL, Manuscript URL
* Structured author data: name, email, ORCID, affiliation, website, bio, corresponding author flag
* Versioning: add version number, type, date, and notes; full history displayed on the frontend
* Compliance: funding statement, conflicts of interest, ethics approval (committee + approval numbers), data availability statement
* Rights: copyright holder, copyright year, license type, license URL, reuse permissions
* Publication lifecycle: submission status, tracking history, corrections/errata
* Metrics: citation count, view count (updated via Automation)

Frontend: Use `[papers]` shortcode for listings; each paper has its own single-view page with breadcrumb navigation.

= Author Profiles =

Create author profiles at **Authors → Add New**.

Fields:
* First name, Last name, Email (optional), Affiliation, Bio
* Website URL, ORCID identifier

Linking: Authors are linked to papers with a display order and corresponding-author designation.

Frontend:
* Each author has a profile page at their post URL.
* Use `[wjm_author_profile id="42"]` on any page to embed an author's profile.

= Automation (Citations & Views) =

Located at **Journals → Automation**.

Settings:
* Enable/disable automation globally
* Update frequency: daily, weekly, or monthly
* Select active sources: CrossRef, Semantic Scholar, arXiv (all free); Scopus/Web of Science (require API keys)
* Enter and save API keys (stored encrypted)

Actions:
* **Update All Papers** — trigger a full update manually
* **Update This Paper** — per-paper update button on the edit screen
* Scheduled runs execute automatically in the background

= Security Suite =

* **Encryption**: AES-256-CBC for all stored API keys (derived from WordPress secret keys/salts)
* **Rate Limiting**: role-based quotas for `api_call` and `data_fetch` action types; friendly error messages when limits are reached
* **CSRF Protection**: nonces verified on all form submissions
* **Input Validation**: all user inputs sanitized before storage; all outputs escaped for their HTML context
* **Capability Checks**: every admin action verifies the current user has the required capability
* **SQL Safety**: all database queries use prepared statements
* **Security Log**: located at **Journals → Security Log** — records severity level, user, IP address, action context, and timestamp

= Rate Limits Dashboard =

Located at **Journals → Rate Limits**.

Shows for each action type: current usage, quota, remaining, and time until reset. Administrators can review usage across users.

= Import / Export =

Located at **Journals → Import/Export**.

* Import: upload a CSV or JSON file; required fields are validated before import
* Export: download all journals, issues, or papers as CSV, JSON, or XML
* Download sample import templates from the Import screen

= Admin Menu Map =

* **Journals → Journals** — list and manage journals
* **Journals → Add New** — create a journal
* **Journals → Issues** — list and manage issues
* **Journals → Papers** — list and manage papers
* **Journals → Authors** — author profiles and directory
* **Journals → Automation** — citation/view update settings and manual runs
* **Journals → Security Log** — security event audit trail
* **Journals → Rate Limits** — view usage and quotas
* **Journals → Plugin Verification** — self-check panel
* **Journals → Import/Export** — data migration tools

== Frequently Asked Questions ==

= Is this plugin secure? =

Yes. The plugin implements enterprise-level security including:
* AES-256-CBC encryption for all API keys (using WordPress salts)
* Role-based rate limiting to prevent abuse
* Complete input sanitization and output escaping
* CSRF nonce verification on all forms
* Security event logging with full audit trail
* Granular capability checks — only authorized roles can perform sensitive actions

= What academic APIs does it integrate with? =

* **CrossRef** (free) — DOI-based citation data
* **Semantic Scholar** (free) — academic paper metadata and citations
* **arXiv** (free) — preprint and paper data
* **Scopus** (premium, requires API key) — comprehensive citation database
* **Web of Science** (premium, requires API key) — citation indexing and analysis

= How does rate limiting work? =

Rate limiting is role-based and prevents API/server abuse. Limits reset hourly:
* Students: 50 API calls, 30 data fetches per hour
* Researchers: 100 API calls, 60 data fetches per hour
* Editors: 200 API calls, 120 data fetches per hour
* Administrators: 500 API calls, 300 data fetches per hour

= Can I import existing journal data? =

Yes. Go to **Journals → Import/Export** to import CSV or JSON files. Download the sample template to see the required field format. Large datasets should be imported in batches on hosts with limited PHP memory.

= How do I display content on the frontend? =

Create a WordPress Page and add a shortcode:
* `[journals]` — displays all journals
* `[issues journal_id="123"]` — displays issues for a specific journal
* `[papers issue_id="456"]` — displays papers in a specific issue
* `[wjm_author_profile id="42"]` — displays an author profile

Each journal, issue, paper, and author also has its own automatically generated single-view page with breadcrumb navigation and a clean academic design.

= What roles does the plugin create? =

The plugin registers four custom roles:
* **Journal Editor-in-Chief** — full editorial control
* **Journal Editor** — manage issues and papers
* **Journal Reviewer** — read and review access
* **Journal Author** — submit and manage own papers

Standard WordPress Administrator and Editor roles are also supported.

= How do I update citations for my papers? =

Go to **Journals → Automation**, enable automation, select your preferred sources (CrossRef recommended for DOI-based papers), and click **Update All Papers**. You can also update individual papers from their edit screen. Enable scheduled automation to run updates automatically on your chosen frequency.

= What happens when I delete the plugin? =

Deactivating the plugin keeps all your data. Deleting the plugin via WordPress removes plugin options and scheduled events, but your journal, issue, paper, and author content remains in the database unless manually removed.

= Does the plugin send any data externally? =

Only to the selected academic APIs (CrossRef, Semantic Scholar, arXiv, and optionally Scopus/Web of Science) for citation and metadata retrieval. No telemetry is sent anywhere. All requests originate from your server, not from the user's browser.

= Where can I get help? =

* WordPress.org support forum: https://wordpress.org/support/plugin/wisdom-journal-manager/
* Aethex website: http://aethexweb.com
* Built-in troubleshooting: **Journals → Plugin Verification**
* Security event review: **Journals → Security Log**

== Troubleshooting ==

**Journals menu not visible**
Ensure your WordPress user has at least Editor-level capabilities and the plugin is activated. Check **Journals → User Roles** to confirm role assignment.

**"Attempt to read property 'ID' on null" notice**
This occurs when a Paper edit screen is opened without a valid `$post` context. Update to the latest version (handled) or open Papers through **Journals → Papers** rather than a direct URL.

**Citations not updating**
1. Enable automation at **Journals → Automation**.
2. Verify your API credentials are entered and saved correctly.
3. Check **Journals → Rate Limits** — if limits are exceeded, wait for the hourly reset.
4. Check **Journals → Security Log** for any blocked requests.

**Import fails**
1. Verify your CSV/JSON headers match the sample template exactly.
2. Ensure all required fields are present.
3. Try importing a smaller batch (50–100 rows) to test.
4. Increase PHP `upload_max_filesize` and `post_max_size` on restricted hosts.

**Frontend pages have no styling**
Ensure your theme is not globally overriding the plugin's CSS. The plugin loads its CSS only on journal/issue/paper/author single-view pages. If conflicts exist, add higher-specificity overrides in your theme's custom CSS.

**API keys not working after saving**
API keys are encrypted on save. Re-enter the key and save again. Verify your server can reach the external API domain (check for firewall or proxy restrictions with your host).

== Performance & Scalability ==

* Enable page caching on shortcode listing pages to reduce database load.
* Set automation frequency to weekly unless daily updates are required.
* Use shortcode filters (journal, year, type, keyword) and pagination for large datasets — avoid loading hundreds of papers on one page.
* Rate limits prevent API and server spikes; Administrators have the highest quotas.
* The author table (`wp_sjm_authors`) is separate from WordPress posts for efficient author queries.

== Privacy & Compliance ==

* **Data stored**: journal, issue, paper, and author records; operational and security logs.
* **External calls**: only to selected academic APIs for metadata retrieval; initiated from your server, not from user browsers.
* **No telemetry**: the plugin does not phone home or track usage externally.
* Use the WordPress personal data export/erase tools (Tools → Export Personal Data / Erase Personal Data) to handle data subject requests for author or user records.
* Publish a site-level privacy notice appropriate to your institution describing what author data you collect and why.

== Data Model ==

= Custom Post Types =

* `journal` — journals
* `journal_issue` — issues
* `paper` — papers
* `wjm_author` — author profiles

= Key Post Meta =

**Journal:** `_sjm_issn`, `_sjm_publisher`, `_sjm_founding_year`, `_sjm_frequency`, `_sjm_language`, `_sjm_subject_areas`, `_sjm_impact_factor`, `_sjm_open_access`, `_sjm_peer_reviewed`, `_sjm_doi_prefix`, `_sjm_eic`, `_sjm_managing_editor`

**Issue:** `_sjm_issue_journal`, `_sjm_issue_volume`, `_sjm_issue_number`, `_sjm_issue_year`, `_sjm_issue_date`, `_sjm_special_issue`, `_sjm_special_issue_title`, `_sjm_issue_pdf_url`, `_sjm_issue_cover`

**Paper:** `_sjm_paper_journal`, `_sjm_paper_issue`, `_sjm_paper_doi`, `_sjm_paper_type`, `_sjm_paper_authors`, `_sjm_paper_pdf_url`, `_sjm_paper_manuscript_url`, `_sjm_open_access`, `_sjm_version_history`, `_sjm_citation_count`, `_sjm_views_count`, `_sjm_submission_date`, `_sjm_acceptance_date`

= Database Tables =

* `wp_sjm_authors` — author profiles (first/last name, email, affiliation, bio, website, ORCID, created/updated timestamps)

= CSS Class Namespaces =

* `sjm-*` — frontend listing and single-view component classes
* `wjm-*` — admin UI classes

== Developer Information ==

= Action Hooks =

* `sjm_before_save_journal` — fires before a journal is saved
* `sjm_after_save_journal` — fires after a journal is saved
* `sjm_before_save_paper` — fires before a paper is saved
* `sjm_after_save_paper` — fires after a paper is saved
* `sjm_rate_limit_exceeded` — fires when a rate limit is exceeded (passes action type and user ID)
* `sjm_security_event_logged` — fires when a security event is recorded (passes event data array)

= Filter Hooks =

* `sjm_journal_query_args` — modify the WP_Query args for journal listings
* `sjm_issue_query_args` — modify the WP_Query args for issue listings
* `sjm_paper_query_args` — modify the WP_Query args for paper listings

= CSS Enqueue =

The plugin enqueues the following CSS on single-view pages only (not on every page):

1. `wjm-modern-admin.css` — CSS custom properties / design tokens (`--wjm-*` variables)
2. `academic-shortcodes.css` — listing-page component styles (`--sjm-*` variables, shortcode grids)
3. `wjm-single-templates.css` — single-view page styles (templates, breadcrumbs, metadata grids, author cards)

To override plugin styles in your theme, use `.sjm-single-container` as a parent selector for sufficient specificity.

= Security Class =

`WJM_Security_Manager` — handles encryption, rate limiting, nonce verification, capability checks, and security logging.

= File Structure =

* `wisdom-journal-manager.php` — main plugin file; custom post types, meta boxes, admin UI, frontend templates, enqueue hooks
* `author-profiles-system.php` — author profile CPT, admin screens, and `[wjm_author_profile]` shortcode
* `updated-shortcodes.php` — `[journals]`, `[issues]`, `[papers]` shortcodes
* `advanced-search-system.php` — search and filtering system
* `analytics-dashboard.php` — analytics widgets and dashboard
* `automation-system.php` — citation/view automation engine
* `citation-tracking-system.php` — citation tracking and metrics
* `doi-crossref-integration.php` — CrossRef API integration
* `advanced-metrics-system.php` — metrics aggregation
* `collaboration-tools.php` — editorial collaboration features
* `assets/css/wjm-modern-admin.css` — admin design tokens and variables
* `assets/css/wjm-single-templates.css` — frontend single-view styles
* `academic-shortcodes.css` — frontend listing/shortcode styles

== Screenshots ==

1. Journals list in WP Admin with key metadata at a glance
2. Creating a Journal — ISSN, publisher, editorial board, and branding fields
3. Creating an Issue — volume/number/year, special issue flag, and editor assignments
4. Creating a Paper — DOI, authors with ORCID, versioning history, and compliance fields
5. Automation settings — API source selection with encrypted key storage
6. Security Log — events with severity, user, IP, and timestamp
7. Rate Limits dashboard — usage, quota, remaining, and reset time per action
8. Author profile admin and frontend display
9. Frontend Journals grid using the [journals] shortcode
10. Single Paper page — breadcrumb, abstract, metadata grid, author cards, and download buttons

== Changelog ==

= 1.0.0 =
* Initial public release

**Core Plugin**
* Complete Journals → Issues → Papers → Authors hierarchy
* Custom post types: `journal`, `journal_issue`, `paper`, `wjm_author`
* Custom database table `wp_sjm_authors` for author profiles with ORCID support
* Full meta box system for all fields across journals, issues, and papers

**Editorial Workflow**
* Role assignments per journal and issue (Editor-in-Chief, Managing Editor, Editors, Reviewers, Copy/Layout)
* Paper status tracking with timestamps, notes, and history
* Versioning system with multiple version types, dates, and notes

**Automation & API Integrations**
* CrossRef, Semantic Scholar, and arXiv integrations (free, no key required)
* Scopus and Web of Science integrations (premium API keys)
* Scheduled automation (daily/weekly/monthly) and manual update triggers
* Per-paper "Update This Paper" button on edit screens

**Frontend Templates**
* Single-view templates for journals, issues, papers, and author profiles
* Clean minimal academic design — white background, blue accent, card-based metadata
* Breadcrumb navigation on all single-view pages (Journal > Issue > Paper hierarchy)
* `[journals]`, `[issues]`, `[papers]` shortcodes with grid and list layouts
* `[wjm_author_profile id="X"]` shortcode for embedding author profiles
* Responsive design: desktop, tablet (768px), and mobile (480px) breakpoints
* Print-friendly styles for paper single-view pages
* External CSS system (zero inline styles) — `academic-shortcodes.css` + `wjm-single-templates.css`

**Security**
* AES-256-CBC encryption for all API keys using WordPress salts
* Role-based rate limiting for API calls and data fetches with hourly quotas
* CSRF nonce verification on all form submissions
* Input sanitization and output escaping throughout
* SQL prepared statements for all database queries
* Security event logging with severity levels, user context, IP, and timestamps

**Data Operations**
* Import/Export system: CSV, JSON, XML support for journals, issues, and papers
* Field validation during import with descriptive error messages
* Sample import templates available to download

**Admin Experience**
* Plugin Verification panel — self-check all plugin components
* Rate Limits dashboard — view usage and remaining quota
* Security Log dashboard — audit trail with filters

== Upgrade Notice ==

= 1.0.0 =
Initial release. Please read the installation instructions, create a test journal before going live, and clear your WordPress object cache and browser cache after activation to ensure all assets load correctly.

== Credits ==

* **Built by**: Maaz Ahmad, Shariq Hashme
* **Company**: Aethex (http://aethexweb.com)
* Follows WordPress coding standards and security best practices
* GPLv2 or later license
