=== Wisdom Journal Manager ===
Contributors: aethex
Donate link: https://aethexweb.com
Tags: academic, journal, publishing, peer-review, doi
Requires at least: 5.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Calm scholarly publishing for WordPress — submit, Inbox, peer review, publish. Money, DOI, and Stripe are optional.

== Description ==

Wisdom Journal Manager (WJM) turns WordPress into a journal workflow that stays easy to learn.

Author: **Zachary Adam** (Aethex Web Solutions).

* One loop: authors submit → Inbox → review → publish
* Demo-first Home with a 3-step learn path
* 3-minute Help inside the Journals menu
* Public manuscript submission (authors never need wp-admin)
* Editor Inbox (board / list), claim, waiting timers
* Peer review invites, structured forms, reminders, recognition email
* Decision letters, desk reject, editor-side appeals
* Oxford-style double-blind files (anonymized manuscript + title page)
* Soft integrity heuristics — never auto-reject
* Journals → Issues → Papers, galleys, early view
* CRediT roles, ORCID Public API lookup / connect / works import
* DOAJ readiness checklist (you apply on doaj.org)
* Advanced hub for optional Money, DOI, iThenticate, integrations
* Stripe / DOI / iThenticate stay off until you paste *your* vendor keys
* Minimal JATS export, shortcodes, REST API at `/wp-json/wjm/v1/`

= Day one vs later =

Day one: Import demo → Inbox → decide → publish.

Later (optional): Stripe APC, Crossref/DataCite DOI deposit, iThenticate — using credentials you provide. DOAJ listing is applied on doaj.org. ORCID Public API is for lookup/connect; WJM does not write peer-review credit to ORCID.

== Installation ==

1. Upload the plugin zip via Plugins → Add New → Upload Plugin, or install from this directory when live
2. Activate Wisdom Journal Manager
3. Open Journals → Home
4. Click Import demo (recommended), or create a blank journal
5. Open Inbox and try a sample paper; share the author submit page when ready

== Frequently Asked Questions ==

= Who is the author? =

Zachary Adam / Aethex Web Solutions. WordPress.org contributor: aethex.

= Do authors need wp-admin? =

No. Share the public submit page. Access controls who can submit.

= Must I use Stripe or DOI? =

No. Skip both until you need them. They live under Advanced and require your vendor keys to Enable. That is not a plugin paywall — the keys are yours.

= Can the plugin auto-list me in DOAJ? =

No. Use Advanced → DOAJ readiness, then apply at doaj.org. Only DOAJ accepts journals.

= Does WJM write peer-review credit to ORCID? =

No. Public ORCID (lookup / connect / import works) uses a free Client ID + Secret. Reviewer Recognition emails thank reviewers — they add credit in their own ORCID account.

= Advanced menu vs paper extras? =

Advanced is an optional toolbox (Money, DOI, ORCID…). “Show paper extras” only adds extra boxes on paper/journal screens. They are separate.

= Will integrity / plagiarism flags reject papers? =

Never automatically. Flags assist editors — you decide.

= Does this plugin phone home? =

No usage tracking, no license server, no forced phone-home. Third-party APIs run only when you enable the feature and (where required) add your own keys. See External services.

== External services ==

This plugin may connect to third-party services when you use the related feature. Data sent is limited to what that feature needs (for example a DOI string, ORCID iD, or payment session). The plugin does not send site analytics to the author.

= Google Fonts =

Admin and public UI may load Inter and Source Serif 4 from fonts.googleapis.com / fonts.gstatic.com for typography.

* Service: Google Fonts — https://fonts.google.com/
* Terms: https://policies.google.com/terms
* Privacy: https://policies.google.com/privacy

= ORCID (optional) =

When ORCID is enabled: public profile lookup, OAuth connect/login, and works import via orcid.org (or sandbox.orcid.org).

* Service: ORCID — https://orcid.org/
* Privacy: https://info.orcid.org/privacy-policy/

= Stripe (optional) =

When Money / APC uses Stripe and you add your Stripe keys: Checkout sessions and webhook verification via api.stripe.com.

* Service: Stripe — https://stripe.com/
* Privacy: https://stripe.com/privacy

= Crossref / DataCite (optional) =

When DOI deposit is enabled with your membership credentials: DOI registration via Crossref or DataCite APIs. Crossref metadata lookup may also be used for citations / preprint helpers.

* Crossref: https://www.crossref.org/ — https://www.crossref.org/privacy/
* DataCite: https://datacite.org/ — https://datacite.org/privacy-policy/

= Citation providers (optional) =

When citation refresh runs: Semantic Scholar and/or Scopus (if you add those API keys). Crossref is used without a paid key for open metadata.

* Semantic Scholar: https://www.semanticscholar.org/
* Scopus (Elsevier): per your Elsevier developer agreement

= Preprint helpers (optional) =

Submit form “import from preprint” may call bioRxiv/medRxiv, OSF, or Crossref APIs for public metadata.

= iThenticate / Turnitin (optional) =

When enabled with your tenant API base + key: similarity checks against your Turnitin/iThenticate endpoint.

= Webhooks (optional) =

If you set a webhook URL, workflow events are POSTed to *your* URL only.

= DOAJ =

DOAJ readiness links to doaj.org for information and applications. The plugin does not submit your journal for you.

== Screenshots ==

1. Home — one next step and 3-step learn path
2. Inbox — daily editorial board (claim, review, publish)
3. Help — 3-minute learn loop
4. Advanced — optional toolbox (Money, DOI, ORCID, …)
5. Author submit page — public form, no wp-admin required

== Changelog ==

= 1.0.0 =
* Initial directory release: Home / Help learn path, Inbox, peer review, submissions
* Double-blind file policy, soft integrity, CRediT, editor-side appeals, early view
* Advanced hub: credential-gated Stripe, DOI, iThenticate; ORCID Public API; DOAJ checklist
* Shortcodes, REST API, minimal JATS export
* Honest limits documented (no ORCID Member write, no Web of Science citation counts)

== Upgrade Notice ==

= 1.0.0 =
Initial release. Activate, open Journals → Home, import demo, then work the Inbox.
