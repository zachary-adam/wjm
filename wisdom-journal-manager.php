<?php
/**
 * Plugin Name:       Wisdom Journal Manager
 * Plugin URI:        https://github.com/aethex/wisdom-journal-manager
 * Description:       Scholarly publishing for WordPress — submit, Inbox, peer review, publish. Optional Money, DOI, Stripe, and ORCID Public API.
 * Version:           1.0.0
 * Requires at least: 5.0
 * Requires PHP:      7.4
 * Author:            Zachary Adam
 * Author URI:        https://aethexweb.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wisdom-journal-manager
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WJM_VERSION', '1.0.0' );
define( 'WJM_PLUGIN_FILE', __FILE__ );
define( 'WJM_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WJM_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WJM_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

require_once WJM_PLUGIN_DIR . 'includes/database/phase1-database-schema.php';
require_once WJM_PLUGIN_DIR . 'includes/database/class-wjm-relational-schema.php';
require_once WJM_PLUGIN_DIR . 'includes/database/class-wjm-repository.php';
require_once WJM_PLUGIN_DIR . 'includes/database/class-wjm-sync.php';
require_once WJM_PLUGIN_DIR . 'includes/database/class-wjm-migrator.php';
require_once WJM_PLUGIN_DIR . 'includes/class-wjm-activator.php';
require_once WJM_PLUGIN_DIR . 'includes/class-wjm-roles.php';
require_once WJM_PLUGIN_DIR . 'includes/security/class-wjm-encryption.php';
require_once WJM_PLUGIN_DIR . 'includes/security/class-wjm-rate-limiter.php';
require_once WJM_PLUGIN_DIR . 'includes/security/class-wjm-audit.php';
require_once WJM_PLUGIN_DIR . 'includes/cpt/class-wjm-post-types.php';
require_once WJM_PLUGIN_DIR . 'includes/cpt/class-wjm-meta.php';
require_once WJM_PLUGIN_DIR . 'includes/authors/author-profiles-system.php';
require_once WJM_PLUGIN_DIR . 'includes/authors/author-system-unification.php';
require_once WJM_PLUGIN_DIR . 'includes/workflow/class-wjm-workflow.php';
require_once WJM_PLUGIN_DIR . 'includes/peer-review/class-wjm-peer-review.php';
require_once WJM_PLUGIN_DIR . 'includes/peer-review/class-wjm-reviewer-access.php';
require_once WJM_PLUGIN_DIR . 'includes/peer-review/class-wjm-reviewer-recognition.php';
require_once WJM_PLUGIN_DIR . 'includes/editorial/class-wjm-editorial-trust.php';
require_once WJM_PLUGIN_DIR . 'includes/submissions/class-wjm-submissions.php';
require_once WJM_PLUGIN_DIR . 'includes/submissions/class-wjm-drafts.php';
require_once WJM_PLUGIN_DIR . 'includes/next/class-wjm-extensions.php';
require_once WJM_PLUGIN_DIR . 'includes/next/class-wjm-issue-assembler.php';
require_once WJM_PLUGIN_DIR . 'includes/integrations/class-wjm-orcid.php';
require_once WJM_PLUGIN_DIR . 'includes/integrations/class-wjm-preprint.php';
require_once WJM_PLUGIN_DIR . 'includes/integrations/class-wjm-oai.php';
require_once WJM_PLUGIN_DIR . 'includes/integrations/class-wjm-ithenticate.php';
require_once WJM_PLUGIN_DIR . 'includes/next/class-wjm-integrity.php';
require_once WJM_PLUGIN_DIR . 'includes/email/class-wjm-email.php';
require_once WJM_PLUGIN_DIR . 'includes/export/class-wjm-jats.php';
require_once WJM_PLUGIN_DIR . 'includes/export/class-wjm-doi.php';
require_once WJM_PLUGIN_DIR . 'includes/rest/class-wjm-rest-api.php';
require_once WJM_PLUGIN_DIR . 'includes/templates/class-wjm-templates.php';
require_once WJM_PLUGIN_DIR . 'includes/seo/class-wjm-seo.php';
require_once WJM_PLUGIN_DIR . 'includes/payments/class-wjm-payments.php';
require_once WJM_PLUGIN_DIR . 'includes/payments/class-wjm-deals.php';
require_once WJM_PLUGIN_DIR . 'includes/payments/class-wjm-subscriptions.php';
require_once WJM_PLUGIN_DIR . 'includes/production/class-wjm-production.php';
require_once WJM_PLUGIN_DIR . 'includes/api/class-wjm-api-client.php';
require_once WJM_PLUGIN_DIR . 'includes/citations/citation-tracking-system.php';
require_once WJM_PLUGIN_DIR . 'includes/citations/advanced-metrics-system.php';
require_once WJM_PLUGIN_DIR . 'includes/search/advanced-search-system.php';
require_once WJM_PLUGIN_DIR . 'includes/collaboration/collaboration-tools.php';
require_once WJM_PLUGIN_DIR . 'includes/automation/automation-system.php';
require_once WJM_PLUGIN_DIR . 'includes/automation/automated-pages.php';
require_once WJM_PLUGIN_DIR . 'includes/shortcodes/class-wjm-shortcodes.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-admin.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-simple-ui.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/analytics-dashboard.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-diagnostics.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-editor-inbox.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-getting-started.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-help.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-product-guard.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-access.php';
require_once WJM_PLUGIN_DIR . 'includes/admin/class-wjm-demo.php';
require_once WJM_PLUGIN_DIR . 'includes/class-wjm-upgrade.php';
require_once WJM_PLUGIN_DIR . 'includes/class-wjm.php';

register_activation_hook( __FILE__, array( 'WJM_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WJM_Activator', 'deactivate' ) );

/**
 * Bootstrap the plugin.
 */
function wjm() {
	return WJM::instance();
}

add_action( 'plugins_loaded', 'wjm' );
