=== Wisdom Journal Manager ===
Contributors: zacharyadam
Tags: academic, journal, publishing, peer-review, citations, orcid, doi, jats
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 2.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

World-class modular academic publishing for WordPress — peer review, submissions, DOI, JATS, citations, REST API.

== Description ==

Wisdom Journal Manager (WJM) turns WordPress into a full scholarly publishing platform:

* Journals → Issues → Papers hierarchy
* ORCID-aware author database
* Full editorial workflow (submit → review → accept → publish)
* Double-blind peer review with structured recommendations
* Front-end manuscript submission portal
* Citation tracking (CrossRef, Semantic Scholar, Scopus, Web of Science)
* AES-256-CBC encrypted API credentials + audit log
* JATS XML export + CrossRef DOI registration
* REST API at `/wp-json/wjm/v1/`

== Installation ==

1. Upload the zip via Plugins → Add New → Upload Plugin
2. Activate Wisdom Journal Manager
3. Open Journals → Plugin Verification
4. Configure DOI prefix + API keys under Journals → Settings
5. Authors submit via the auto-created "Submit Manuscript" page

== Shortcodes ==

* `[journals]` `[issues]` `[papers]` `[wjm_author_profile]`
* `[wjm_search]` `[wjm_paper_metrics]`
* `[wjm_submit]` `[wjm_my_submissions]`

== REST API ==

* `GET /wp-json/wjm/v1/journals`
* `GET /wp-json/wjm/v1/papers`
* `GET /wp-json/wjm/v1/papers/{id}`
* `POST /wp-json/wjm/v1/papers/{id}/status`
* `GET /wp-json/wjm/v1/stats`

== Changelog ==

= 2.2.0 =
* OJS-style DOI Manager: pattern tokens (%j %v %i %a %x %Y), auto-assign on accept/publish
* CrossRef + DataCite deposit (test/production), batch issue DOIs, per-journal acronym/prefix

= 2.1.0 =
* Editor Inbox with status filters and pending badge
* Getting Started checklist + post-activation guide
* Reviewer access to assigned private manuscripts/files
* Auto-upgrade path for schema/roles/pages on version bump

= 2.0.0 =
* Peer review (assign, invite, blind review, recommendations)
* Editorial workflow state machine + email notifications
* Author submission portal + manuscript uploads
* JATS XML export + CrossRef DOI registration
* REST API + public paper/journal templates

= 1.0.0 =
* Initial modular architecture release
