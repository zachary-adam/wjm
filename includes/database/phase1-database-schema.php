<?php
/**
 * Database schema management for WJM custom tables.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Database_Schema {

	const DB_VERSION = '2.0.0';

	/**
	 * Create or upgrade custom tables.
	 */
	public static function create_tables() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset       = $wpdb->get_charset_collate();
		$authors       = $wpdb->prefix . 'sjm_authors';
		$paper_authors = $wpdb->prefix . 'sjm_paper_authors';
		$citations     = $wpdb->prefix . 'sjm_citations';
		$audit         = $wpdb->prefix . 'sjm_audit_log';
		$rate          = $wpdb->prefix . 'sjm_rate_limits';
		$collab        = $wpdb->prefix . 'sjm_collaboration_notes';
		$workflow      = $wpdb->prefix . 'sjm_workflow_log';
		$reviews       = $wpdb->prefix . 'sjm_reviews';
		$reviewers     = $wpdb->prefix . 'sjm_review_assignments';
		$files         = $wpdb->prefix . 'sjm_manuscripts';
		$emails        = $wpdb->prefix . 'sjm_email_log';

		$sql_authors = "CREATE TABLE {$authors} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned DEFAULT NULL,
			orcid varchar(19) DEFAULT NULL,
			first_name varchar(100) NOT NULL DEFAULT '',
			last_name varchar(100) NOT NULL DEFAULT '',
			email varchar(191) DEFAULT NULL,
			affiliation text,
			bio longtext,
			h_index int(11) DEFAULT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY orcid (orcid),
			KEY user_id (user_id),
			KEY last_name (last_name)
		) {$charset};";

		$sql_paper_authors = "CREATE TABLE {$paper_authors} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			author_id bigint(20) unsigned NOT NULL,
			author_order int(11) NOT NULL DEFAULT 1,
			is_corresponding tinyint(1) NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			UNIQUE KEY paper_author (paper_id, author_id),
			KEY author_id (author_id)
		) {$charset};";

		$sql_citations = "CREATE TABLE {$citations} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			source varchar(50) NOT NULL,
			citation_count int(11) NOT NULL DEFAULT 0,
			download_count int(11) NOT NULL DEFAULT 0,
			altmetric_score decimal(10,2) DEFAULT NULL,
			raw_payload longtext,
			fetched_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY paper_source (paper_id, source),
			KEY paper_id (paper_id)
		) {$charset};";

		$sql_audit = "CREATE TABLE {$audit} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			severity varchar(20) NOT NULL DEFAULT 'info',
			event_type varchar(100) NOT NULL,
			message text NOT NULL,
			user_id bigint(20) unsigned DEFAULT NULL,
			ip_address varchar(45) DEFAULT NULL,
			context longtext,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY severity (severity),
			KEY event_type (event_type),
			KEY created_at (created_at)
		) {$charset};";

		$sql_rate = "CREATE TABLE {$rate} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL,
			bucket varchar(50) NOT NULL,
			hit_count int(11) NOT NULL DEFAULT 0,
			window_start datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY user_bucket (user_id, bucket),
			KEY window_start (window_start)
		) {$charset};";

		$sql_collab = "CREATE TABLE {$collab} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			object_type varchar(50) NOT NULL,
			object_id bigint(20) unsigned NOT NULL,
			user_id bigint(20) unsigned NOT NULL,
			note longtext NOT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY object_lookup (object_type, object_id)
		) {$charset};";

		$sql_workflow = "CREATE TABLE {$workflow} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			from_status varchar(50) DEFAULT NULL,
			to_status varchar(50) NOT NULL,
			user_id bigint(20) unsigned DEFAULT NULL,
			note text,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY paper_id (paper_id),
			KEY to_status (to_status)
		) {$charset};";

		$sql_assignments = "CREATE TABLE {$reviewers} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			reviewer_user_id bigint(20) unsigned NOT NULL,
			assigned_by bigint(20) unsigned DEFAULT NULL,
			status varchar(30) NOT NULL DEFAULT 'invited',
			due_date date DEFAULT NULL,
			blind_type varchar(20) NOT NULL DEFAULT 'double',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY paper_reviewer (paper_id, reviewer_user_id),
			KEY reviewer_user_id (reviewer_user_id),
			KEY status (status)
		) {$charset};";

		$sql_reviews = "CREATE TABLE {$reviews} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			assignment_id bigint(20) unsigned NOT NULL,
			paper_id bigint(20) unsigned NOT NULL,
			reviewer_user_id bigint(20) unsigned NOT NULL,
			recommendation varchar(30) NOT NULL DEFAULT '',
			score tinyint(3) unsigned DEFAULT NULL,
			comments_editor longtext,
			comments_author longtext,
			is_blind tinyint(1) NOT NULL DEFAULT 1,
			submitted_at datetime DEFAULT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY assignment_id (assignment_id),
			KEY paper_id (paper_id)
		) {$charset};";

		$sql_files = "CREATE TABLE {$files} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			attachment_id bigint(20) unsigned NOT NULL,
			file_role varchar(40) NOT NULL DEFAULT 'manuscript',
			version_label varchar(40) DEFAULT NULL,
			uploaded_by bigint(20) unsigned DEFAULT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY paper_id (paper_id),
			KEY attachment_id (attachment_id)
		) {$charset};";

		$sql_emails = "CREATE TABLE {$emails} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned DEFAULT NULL,
			to_email varchar(191) NOT NULL,
			subject varchar(255) NOT NULL,
			template_key varchar(80) NOT NULL,
			status varchar(20) NOT NULL DEFAULT 'sent',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY paper_id (paper_id)
		) {$charset};";

		dbDelta( $sql_authors );
		dbDelta( $sql_paper_authors );
		dbDelta( $sql_citations );
		dbDelta( $sql_audit );
		dbDelta( $sql_rate );
		dbDelta( $sql_collab );
		dbDelta( $sql_workflow );
		dbDelta( $sql_assignments );
		dbDelta( $sql_reviews );
		dbDelta( $sql_files );
		dbDelta( $sql_emails );

		update_option( 'wjm_db_version', self::DB_VERSION );
	}

	/**
	 * Maybe upgrade schema when plugin version changes.
	 */
	public static function maybe_upgrade() {
		$current = get_option( 'wjm_db_version', '0' );
		if ( version_compare( (string) $current, self::DB_VERSION, '<' ) ) {
			self::create_tables();
		}
	}

	/**
	 * Table name helpers.
	 *
	 * @param string $key Table key.
	 * @return string
	 */
	public static function table( $key ) {
		global $wpdb;
		$map = array(
			'authors'       => $wpdb->prefix . 'sjm_authors',
			'paper_authors' => $wpdb->prefix . 'sjm_paper_authors',
			'citations'     => $wpdb->prefix . 'sjm_citations',
			'audit'         => $wpdb->prefix . 'sjm_audit_log',
			'rate'          => $wpdb->prefix . 'sjm_rate_limits',
			'collaboration' => $wpdb->prefix . 'sjm_collaboration_notes',
			'workflow'      => $wpdb->prefix . 'sjm_workflow_log',
			'assignments'   => $wpdb->prefix . 'sjm_review_assignments',
			'reviews'       => $wpdb->prefix . 'sjm_reviews',
			'manuscripts'   => $wpdb->prefix . 'sjm_manuscripts',
			'email_log'     => $wpdb->prefix . 'sjm_email_log',
		);
		return isset( $map[ $key ] ) ? $map[ $key ] : '';
	}
}
