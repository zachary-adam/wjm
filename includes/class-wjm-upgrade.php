<?php
/**
 * Version upgrades, page seeding, rewrite flush.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Upgrade {

	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'maybe_run' ) );
	}

	public static function maybe_run() {
		$stored = get_option( 'wjm_version', '0' );
		if ( version_compare( (string) $stored, WJM_VERSION, '>=' ) ) {
			return;
		}

		WJM_Database_Schema::create_tables();
		WJM_Roles::register_roles();
		WJM_Automated_Pages::ensure_catalog_page();
		WJM_Automated_Pages::ensure_submit_page();
		WJM_Automation_System::schedule_events();
		flush_rewrite_rules( false );
		update_option( 'wjm_version', WJM_VERSION );

		WJM_Audit::log( 'info', 'plugin_upgraded', 'Upgraded to ' . WJM_VERSION );
	}
}
