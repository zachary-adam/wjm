=== Wisdom Journal Manager ===
Contributors: maazahmad, shariqhashme, aethex
Tags: journal, academic, research, publication, citations, authors, papers, scholarly
Requires at least: 5.0
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Complete academic journal management system with enterprise-level security, automated citation tracking, and comprehensive author management.

== Description ==

**Wisdom Journal Manager** is a full-stack WordPress solution for managing academic journals end‑to‑end. It covers Journals → Issues → Papers, Authors/Contributors, editorial workflow, automation, and enterprise-grade security.

= Key Features (high-level) =

* **Complete Journal → Issue → Paper hierarchy**
* **Authors & Contributors with ORCID support**
* **Editorial roles and workflow** (Editor‑in‑Chief, Editors, Reviewers, Copy/Layout)
* **Automation** for citations/views using official APIs
* **Enterprise Security**: encryption, rate limits, CSRF, capability checks, logging
* **Import/Export** CSV/JSON, analytics widgets, shortcodes and templates

= Detailed Features =

– **Journals**
* Add/edit journals with ISSN, publisher, founding year, frequency, language, subject areas, impact factor, website, email
* Upload logo and cover; mark Open Access; indexing info; DOI prefix
* Assign Editor‑in‑Chief, Managing Editor, Copy/Layout editors

– **Issues**
* Link each Issue to a Journal
* Volume, issue number, year, publication date, special issue flag and title
* Guest editors, issue editors, reviewers, copy/layout editors
* Cover image, PDF URL, keywords, abstract, total papers

– **Papers**
* Rich metadata: DOI, keywords, pages, PDF/Manuscript URL, open access, funding, conflicts of interest, ethics approvals
* Authors and affiliations (structured author data with emails, ORCID, website, bio)
* Submission/acceptance dates, paper type, peer‑reviewed flag
* Versioning system: version type, number, date, notes, and version history UI
* Automatic/manually triggered citation and views updates per paper

– **Authors & Contributors**
* Dedicated author profiles stored in `wp_sjm_authors` (first/last name, email, affiliation, bio, website, ORCID)
* Frontend author profile templates and author lists

– **Editorial Workflow**
* Assign guest editors, issue editors, reviewers, copy/layout editors at the issue level
* Custom capabilities per role; checks enforced across admin actions

– **Automation & APIs**
* CrossRef (DOI citations), Semantic Scholar (search-based), arXiv (preprints)
* Optional Scopus and Web of Science via API keys (encrypted at rest)
* Manual “Update All” and single‑paper update buttons; scheduled updates (daily/weekly/monthly)

– **Security**
* AES‑256‑CBC encryption for API keys (using WP salts)
* Role‑based rate limiting with friendly messages
* Sanitization/escaping, CSRF nonces, capability checks, SQL‑safe queries
* Security Log dashboard with severity levels and IP/user context

– **Data Ops & UX**
* Import/Export tools (CSV/JSON/XML)
* Shortcodes for frontend grids and single views
* Analytics widgets for quick overviews

= Security Features =

* **API Key Encryption**: AES-256-CBC encryption for all sensitive data
* **Advanced Rate Limiting**: Role-based rate limiting system
* **Input/Output Sanitization**: Complete data validation and escaping
* **CSRF Protection**: Comprehensive cross-site request forgery protection
* **Security Event Logging**: Complete audit trail of security events
* **Capability Checks**: Granular access control based on user roles

= API Integrations =

* **CrossRef**: DOI-based citation data (free)
* **Semantic Scholar**: Academic paper data and citations (free)
* **arXiv**: Preprint and paper data (free)
* **Scopus**: Comprehensive citation database (premium)
* **Web of Science**: Citation indexing and analysis (premium)

= User Roles =

* **Student**: 50 API calls/hour, 30 data fetches/hour
* **Researcher**: 100 API calls/hour, 60 data fetches/hour
* **Editor**: 200 API calls/hour, 120 data fetches/hour
* **Administrator**: 500 API calls/hour, 300 data fetches/hour

= Perfect For =

* Academic institutions managing multiple journals
* Research organizations with publication workflows
* Publishers requiring secure, scalable journal management
* Universities with complex author management needs
* Organizations needing automated citation tracking

= Why Choose Wisdom Journal Manager? =

* **Enterprise Security**: Military-grade security implementation
* **Professional Quality**: Clean, maintainable, well-documented code
* **WordPress Standards**: Follows WordPress coding and security standards
* **Production Ready**: Tested and verified for production use
* **Comprehensive Documentation**: Complete user and technical documentation

== Installation ==

= System Requirements =

* WordPress 5.0 or higher
* PHP 7.4 or higher
* MySQL 5.6 or higher
* Memory Limit: 256MB minimum (512MB recommended)

= Installation Steps =

1. Upload all plugin files to `/wp-content/plugins/wisdom-journal-manager/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to Journals → Plugin Verification to ensure all components are working
4. Configure user roles at Journals → User Roles
5. Set up API keys at Journals → Automation (optional)

= Quick Start (Add Data) =

1. Go to Journals → Add New to create a Journal (fill ISSN, publisher, logo/cover, editors)
2. Go to Issues → Add New to create Issues linked to the Journal (volume/number/year)
3. Go to Papers → Add New to add Papers with DOI, authors, versioning, and files
4. Optional: Add Authors via Authors menu and link them to papers
5. Use Journals → Automation to enable/update citations and views

= Post-Installation Configuration =

1. **Configure User Roles**: Go to Journals → User Roles
2. **Set Up API Keys**: Go to Journals → Automation
3. **Review Security**: Check Journals → Security Log
4. **Test Features**: Create a test journal and paper

== Feature Documentation ==

= Journals =

Fields and actions (Journals → Add New):
- ISSN
- Publisher, Founding year, Frequency, Language, Subject areas, Impact factor
- Website, Contact email
- Open Access, Peer Reviewed toggles
- Indexing (CrossRef, Semantic Scholar, etc.)
- DOI Prefix (for consistent DOIs)
- Logo / Cover uploads
- Editorial assignments: Editor‑in‑Chief, Managing Editor, Copyeditors, Layout editors

Display: Frontend single journal page and `[journals]` shortcode grid/list

= Issues =

Create via Issues → Add New:
- Link to Journal (required)
- Volume, Issue number, Year, Publication date
- Special Issue flag and optional title
- Keywords, Abstract, Page range, Cover image, PDF URL
- Guest editors, Issue editors, Reviewers, Copy/Layout editors
- Total papers counter (informational)

Display: Frontend single issue page and `[issues]` shortcode

= Papers =

Create via Papers → Add New:
- Relationships: Journal, Issue
- Core: DOI, Paper type, Submission/Acceptance dates, Open access, Peer‑reviewed
- Content: Abstract, Keywords, Pages, Manuscript/PDF URL
- Authors: simple list or structured author data with name, email, affiliation, ORCID, website, bio
- Versioning: type, number, date, notes, history (UI to add multiple versions)
- Compliance: Funding, COI declaration/details, Ethics approvals (numbers/committee), Data availability
- Rights: Copyright holder/year, License type/url, Reuse permissions
- Publication lifecycle: Submission status, Tracking history, Publication/Retraction/Corrections
- Metrics: Citations and Views (via automation or manual)

Display: Frontend single paper template and `[papers]` shortcode

= Authors & Contributors =

- Structured author records stored in `wp_sjm_authors` with: first/last name, email, affiliation, bio, website, ORCID
- Attach authors to Journals and Papers; frontend author profile template available

= Editorial Workflow =

- Assign roles per journal/issue: EIC, Managing Editor, Editors, Reviewers, Copy/Layout
- Capability checks across actions; only permitted roles can save sensitive settings

= Automation (Citations & Views) =

- Location: Journals → Automation
- Settings: enable automation, update frequency, enable sources (CrossRef, Semantic Scholar, arXiv; optional Scopus/WoS with API keys)
- Actions: “Update All Papers” button, per‑paper “Update This Paper” button, and scheduled runs
- Security: rate‑limited and logged; API keys encrypted at rest

= Security Suite =

- Encryption: AES‑256‑CBC for API keys (WordPress salts)
- Rate limiting: role‑based (Student/Researcher/Editor/Admin) for `api_call` and `data_fetch`
- CSRF: nonces on forms; strict capability checks
- Sanitization/escaping throughout; SQL‑safe queries
- Logs: Journals → Security Log (severity, user, IP, context)

= Rate Limits Dashboard =

- Location: Journals → Rate Limits
- Shows current usage, quota, remaining, and reset time per action

= Import / Export =

- CSV/JSON/XML support for journals/issues/papers
- Validates fields during import; provides sample templates

= Shortcodes & Attributes =

- `[journals layout="grid|list" publisher="" subject_area="" language="" open_access="1" peer_reviewed="1" year="" per_page="12"]`
- `[issues layout="grid|list" journal_id="" volume="" year="" special_issue="1" per_page="12"]`
- `[papers layout="grid|list" journal_id="" issue_id="" paper_type="" author="" keyword="" year="" per_page="12"]`

= Admin Tools =

- Security Log, Rate Limits, Automation, Plugin Verification (self‑check panel)

= Demo Data (for screenshots/testing) =

- Optional helper plugin “Wisdom Journal Manager – Demo Data Seeder”
- After activating, go to Journals → Demo Data → Generate Full Demo Dataset
- Creates example journals, issues, papers, authors, users, and enables automation; removable with one click

== Admin Menu Map ==

- Journals → Journals (list), Add New
- Journals → Issues (custom post type)
- Journals → Papers (custom post type)
- Journals → Authors (directory and profiles)
- Journals → Automation (citations/views)
- Journals → Security Log
- Journals → Rate Limits
- Journals → Plugin Verification
- Journals → Import/Export

== Roles & Capabilities (overview) ==

- Student: read, limited API/data limits
- Researcher: read, edit own papers, higher API/data limits
- Editor: manage journals/issues/papers, run automation
- Administrator: all capabilities, manage settings, view logs

== Shortcode Cookbook ==

- List all journals: `[journals]`
- Journals (publisher=“Aethex”, open access only): `[journals publisher="Aethex" open_access="1" layout="list"]`
- Issues for a journal in 2024: `[issues journal_id="123" year="2024"]`
- Special issues only: `[issues special_issue="1"]`
- Papers in a specific issue: `[papers issue_id="456" per_page="24"]`
- Papers by author and keyword: `[papers author="Lovelace" keyword="Automation"]`
- Only research articles: `[papers paper_type="Research Article"]`

== Data Model (quick overview) ==

- Custom Post Types: `journal`, `journal_issue`, `paper`
- Key Journal meta: `_sjm_issn`, `_sjm_publisher`, `_sjm_founding_year`, `_sjm_frequency`, `_sjm_language`, `_sjm_subject_areas`, `_sjm_impact_factor`, `_sjm_open_access`, `_sjm_peer_reviewed`, `_sjm_doi_prefix`
- Key Issue meta: `_sjm_issue_journal`, `_sjm_issue_volume`, `_sjm_issue_number`, `_sjm_issue_year`, `_sjm_special_issue`, `_sjm_special_issue_title`
- Key Paper meta: `_sjm_paper_journal`, `_sjm_paper_issue`, `_sjm_paper_doi`, `_sjm_paper_type`, `_sjm_paper_authors`, `_sjm_version_history`, `_sjm_citation_count`, `_sjm_views_count`
- Author table: `wp_sjm_authors` with first/last name, email, affiliation, bio, website, ORCID

== Troubleshooting ==

- Menus not visible: ensure the parent slug is `edit.php?post_type=journal` and your user has Editor/Admin capabilities.
- Warning “Attempt to read property ID on null”: caused by missing `$post` context. Update to latest version (fixed) or ensure you open a Paper edit screen.
- Citations not updating: enable automation in Journals → Automation and ensure rate limits are not exceeded.
- API keys not working: keys are encrypted; re‑enter valid keys and save. Check server can reach CrossRef/Semantic Scholar.
- Import fails: validate CSV headers and required fields; large files may need increased PHP `upload_max_filesize`.

== Performance & Scalability ==

- Use caching for shortcode pages; set update frequency weekly unless you need daily
- Avoid huge admin lists by using filters (publisher, year, type)
- Rate limits prevent spikes; Administrators have highest quotas

== Privacy ==

- No telemetry. API requests are proxied from your server to the selected academic sources.
- Authors and paper metadata are stored in your WordPress database only.

== Uninstall ==

- Deactivating keeps data. Deleting the plugin via WordPress runs uninstall to remove plugin options and scheduled events; posts and author table remain unless manually removed.

== Frequently Asked Questions ==

= Is this plugin secure? =

Yes! The plugin implements enterprise-level security features including:
* AES-256-CBC encryption for API keys
* Advanced rate limiting to prevent abuse
* Comprehensive input/output sanitization
* CSRF protection on all forms
* Security event logging and monitoring

= What APIs does it integrate with? =

The plugin integrates with multiple academic APIs:
* CrossRef (free) - DOI-based citation data
* Semantic Scholar (free) - Academic paper data
* arXiv (free) - Preprint and paper data
* Scopus (premium) - Comprehensive citation database
* Web of Science (premium) - Citation indexing

= How does rate limiting work? =

Rate limiting is role-based and prevents API abuse:
* Students: 50 API calls/hour
* Researchers: 100 API calls/hour
* Editors: 200 API calls/hour
* Administrators: 500 API calls/hour

= Can I import existing journal data? =

Yes! The plugin includes a comprehensive import/export system:
* Import CSV files with journal data
* Export data in CSV, JSON, or XML format
* Automatic data validation during import
* Download import templates

= Is there documentation available? =

Yes! Complete documentation is included:
* User guide with step-by-step instructions
* Technical documentation for developers
* Security documentation and best practices
* Troubleshooting guide

= What user roles are available? =

The plugin creates custom user roles:
* Journal Editor-in-Chief
* Journal Editor
* Journal Reviewer
* Journal Author
* Journal Subscriber

= How do I get support? =

* Check the comprehensive documentation included with the plugin
* Use the built-in troubleshooting tools (Journals → Plugin Verification)
* Review security logs (Journals → Security Log)
* Check rate limit status (Journals → Rate Limits)

== Screenshots ==

1. Journals list in WP Admin
2. Creating a Journal with key metadata
3. Creating an Issue linked to a Journal
4. Creating a Paper with authors, DOI, and versioning
5. Automation settings with official APIs (keys masked)
6. Security Log with detailed events and actions
7. Rate Limits overview with usage and reset times
8. Authors management and frontend author profile
9. Frontend Journals grid (shortcode)
10. Single Paper page with rich metadata

== Changelog ==

= 1.0.0 =
* Initial release with enterprise-level security
* API key encryption using AES-256-CBC
* Advanced rate limiting system
* Input/output sanitization and escaping
* Security event logging and monitoring
* Security dashboard and rate limit dashboard
* Plugin verification and cleanup tools
* API integrations with Semantic Scholar, CrossRef, arXiv, Scopus, Web of Science
* Enhanced user experience with helpful notices
* Complete documentation and user guides
* Professional code quality and maintainability
* Performance optimizations and caching
* Complete journal management system
* Issue and paper management
* Author management with ORCID integration
* Custom user roles
* Shortcode functionality
* Email notification system
* Import/export capabilities

= 1.0.0-beta =
* Beta release - preparing for initial release

== Upgrade Notice ==

= 1.0.0 =
This initial release includes comprehensive security features and complete journal management functionality. Please review the documentation and test thoroughly before using in production.

== Developer Information ==

= Hooks and Filters =

The plugin provides numerous hooks and filters for customization:

* `sjm_before_save_journal` - Fired before saving a journal
* `sjm_after_save_journal` - Fired after saving a journal
* `sjm_before_save_paper` - Fired before saving a paper
* `sjm_after_save_paper` - Fired after saving a paper
* `sjm_rate_limit_exceeded` - Fired when rate limit is exceeded
* `sjm_security_event_logged` - Fired when security event is logged

= Custom Post Types =

* `journal` - Journal custom post type
* `journal_issue` - Journal issue custom post type
* `paper` - Paper custom post type

= Database Tables =

* `wp_sjm_authors` - Authors table with ORCID integration

= Security Class =

* `WJM_Security_Manager` - Comprehensive security management class

For detailed developer documentation, see the included technical documentation.

== Credits ==

* Built with WordPress best practices
* Uses WordPress security standards
* Implements enterprise-level security features
* Follows WordPress coding standards
