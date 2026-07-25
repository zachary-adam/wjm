<?php
/**
 * Relational core schema: journals → issues → papers.
 *
 * CPT posts remain for permalinks/admin UI; these tables are the structured
 * source of truth with real foreign-key columns and indexes.
 *
 * Related modules (reviews, citations, galleys) continue to key off post_id
 * for WordPress attachment/capability compatibility.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Relational_Schema {

	const VERSION = '3.0.0';

	/**
	 * Create relational entity tables.
	 */
	public static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset  = $wpdb->get_charset_collate();
		$journals = $wpdb->prefix . 'sjm_journals';
		$issues   = $wpdb->prefix . 'sjm_issues';
		$papers   = $wpdb->prefix . 'sjm_papers';

		$sql_journals = "CREATE TABLE {$journals} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			post_id bigint(20) unsigned NOT NULL,
			title text NOT NULL,
			slug varchar(200) NOT NULL DEFAULT '',
			issn varchar(32) DEFAULT NULL,
			publisher varchar(255) DEFAULT NULL,
			editorial_board longtext,
			doi_prefix varchar(32) DEFAULT NULL,
			doi_acronym varchar(64) DEFAULT NULL,
			status varchar(20) NOT NULL DEFAULT 'publish',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY post_id (post_id),
			KEY slug (slug),
			KEY issn (issn),
			KEY status (status)
		) {$charset};";

		$sql_issues = "CREATE TABLE {$issues} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			post_id bigint(20) unsigned NOT NULL,
			journal_id bigint(20) unsigned DEFAULT NULL,
			journal_post_id bigint(20) unsigned DEFAULT NULL,
			title text NOT NULL,
			slug varchar(200) NOT NULL DEFAULT '',
			volume varchar(40) DEFAULT NULL,
			number varchar(40) DEFAULT NULL,
			special_issue tinyint(1) NOT NULL DEFAULT 0,
			guest_editors text,
			status varchar(20) NOT NULL DEFAULT 'publish',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY post_id (post_id),
			KEY journal_id (journal_id),
			KEY journal_post_id (journal_post_id),
			KEY volume_number (volume, number),
			KEY status (status)
		) {$charset};";

		$sql_papers = "CREATE TABLE {$papers} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			post_id bigint(20) unsigned NOT NULL,
			issue_id bigint(20) unsigned DEFAULT NULL,
			journal_id bigint(20) unsigned DEFAULT NULL,
			issue_post_id bigint(20) unsigned DEFAULT NULL,
			journal_post_id bigint(20) unsigned DEFAULT NULL,
			title text NOT NULL,
			slug varchar(200) NOT NULL DEFAULT '',
			doi varchar(255) DEFAULT NULL,
			abstract longtext,
			paper_type varchar(60) DEFAULT NULL,
			open_access tinyint(1) NOT NULL DEFAULT 0,
			submission_date date DEFAULT NULL,
			acceptance_date date DEFAULT NULL,
			page_range varchar(60) DEFAULT NULL,
			funding text,
			conflicts text,
			ethics text,
			data_availability text,
			workflow_status varchar(40) NOT NULL DEFAULT 'draft',
			citation_total int(11) NOT NULL DEFAULT 0,
			apc_amount decimal(12,2) DEFAULT NULL,
			apc_status varchar(20) DEFAULT 'unpaid',
			author_user_id bigint(20) unsigned DEFAULT NULL,
			status varchar(20) NOT NULL DEFAULT 'publish',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY post_id (post_id),
			KEY doi (doi),
			KEY issue_id (issue_id),
			KEY journal_id (journal_id),
			KEY issue_post_id (issue_post_id),
			KEY journal_post_id (journal_post_id),
			KEY workflow_status (workflow_status),
			KEY paper_type (paper_type),
			KEY open_access (open_access),
			KEY citation_total (citation_total),
			KEY status (status),
			KEY author_user_id (author_user_id)
		) {$charset};";

		dbDelta( $sql_journals );
		dbDelta( $sql_issues );
		dbDelta( $sql_papers );

		self::maybe_add_foreign_keys();
		update_option( 'wjm_relational_db_version', self::VERSION );
	}

	/**
	 * Best-effort InnoDB foreign keys (ignored if not supported).
	 */
	private static function maybe_add_foreign_keys() {
		global $wpdb;
		$journals = $wpdb->prefix . 'sjm_journals';
		$issues   = $wpdb->prefix . 'sjm_issues';
		$papers   = $wpdb->prefix . 'sjm_papers';

		$wpdb->hide_errors();
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$existing = (array) $wpdb->get_col( "SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = '{$issues}' AND CONSTRAINT_TYPE = 'FOREIGN KEY'" );
		if ( ! in_array( 'fk_sjm_issue_journal', $existing, true ) ) {
			$wpdb->query( "ALTER TABLE {$issues} ADD CONSTRAINT fk_sjm_issue_journal FOREIGN KEY (journal_id) REFERENCES {$journals}(id) ON DELETE SET NULL ON UPDATE CASCADE" );
		}

		$existing = (array) $wpdb->get_col( "SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = '{$papers}' AND CONSTRAINT_TYPE = 'FOREIGN KEY'" );
		if ( ! in_array( 'fk_sjm_paper_issue', $existing, true ) ) {
			$wpdb->query( "ALTER TABLE {$papers} ADD CONSTRAINT fk_sjm_paper_issue FOREIGN KEY (issue_id) REFERENCES {$issues}(id) ON DELETE SET NULL ON UPDATE CASCADE" );
		}
		if ( ! in_array( 'fk_sjm_paper_journal', $existing, true ) ) {
			$wpdb->query( "ALTER TABLE {$papers} ADD CONSTRAINT fk_sjm_paper_journal FOREIGN KEY (journal_id) REFERENCES {$journals}(id) ON DELETE SET NULL ON UPDATE CASCADE" );
		}
		// phpcs:enable
		$wpdb->show_errors();
	}

	/**
	 * @param string $key journals|issues|papers
	 * @return string
	 */
	public static function table( $key ) {
		global $wpdb;
		$map = array(
			'journals' => $wpdb->prefix . 'sjm_journals',
			'issues'   => $wpdb->prefix . 'sjm_issues',
			'papers'   => $wpdb->prefix . 'sjm_papers',
		);
		return isset( $map[ $key ] ) ? $map[ $key ] : '';
	}
}
