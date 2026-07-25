<?php
/**
 * Plugin activation / deactivation.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Activator {

	/**
	 * Run on plugin activation.
	 */
	public static function activate() {
		WJM_Database_Schema::create_tables();
		WJM_Roles::register_roles();
		WJM_Post_Types::register();
		flush_rewrite_rules();

		update_option( 'wjm_version', WJM_VERSION );

		if ( class_exists( 'WJM_Migrator' ) ) {
			WJM_Migrator::run();
		}

		if ( ! get_option( 'wjm_citation_schedule' ) ) {
			add_option( 'wjm_citation_schedule', 'weekly' );
		}

		WJM_Automated_Pages::ensure_catalog_page();
		WJM_Automated_Pages::ensure_submit_page();
		WJM_Automation_System::schedule_events();
		set_transient( 'wjm_activation_redirect', 1, 60 );
	}

	/**
	 * Run on plugin deactivation. Content and settings are preserved.
	 */
	public static function deactivate() {
		WJM_Automation_System::clear_events();
		flush_rewrite_rules();
	}
}
