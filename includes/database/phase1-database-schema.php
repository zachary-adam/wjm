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

	const DB_VERSION = '3.4.0';

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
		$galleys       = $wpdb->prefix . 'sjm_galleys';
		$copyedit      = $wpdb->prefix . 'sjm_copyedit_tasks';
		$subscriptions = $wpdb->prefix . 'sjm_subscriptions';

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
			credit_role varchar(191) DEFAULT NULL,
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
			invite_token varchar(64) DEFAULT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY paper_reviewer (paper_id, reviewer_user_id),
			UNIQUE KEY invite_token (invite_token),
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

		$sql_galleys = "CREATE TABLE {$galleys} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			attachment_id bigint(20) unsigned NOT NULL,
			label varchar(100) NOT NULL DEFAULT 'PDF',
			galley_type varchar(30) NOT NULL DEFAULT 'pdf',
			locale varchar(20) NOT NULL DEFAULT 'en_US',
			is_public tinyint(1) NOT NULL DEFAULT 1,
			sort_order int(11) NOT NULL DEFAULT 0,
			uploaded_by bigint(20) unsigned DEFAULT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY paper_id (paper_id),
			KEY is_public (is_public)
		) {$charset};";

		$sql_copyedit = "CREATE TABLE {$copyedit} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			paper_id bigint(20) unsigned NOT NULL,
			task_key varchar(60) NOT NULL,
			label varchar(191) NOT NULL,
			is_done tinyint(1) NOT NULL DEFAULT 0,
			done_by bigint(20) unsigned DEFAULT NULL,
			done_at datetime DEFAULT NULL,
			notes text,
			PRIMARY KEY  (id),
			UNIQUE KEY paper_task (paper_id, task_key),
			KEY paper_id (paper_id)
		) {$charset};";

		$sql_subscriptions = "CREATE TABLE {$subscriptions} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL,
			journal_post_id bigint(20) unsigned NOT NULL,
			stripe_subscription_id varchar(191) NOT NULL,
			stripe_customer_id varchar(191) DEFAULT NULL,
			stripe_session_id varchar(191) DEFAULT NULL,
			status varchar(40) NOT NULL DEFAULT 'active',
			current_period_end datetime DEFAULT NULL,
			cancel_at_period_end tinyint(1) NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY stripe_subscription_id (stripe_subscription_id),
			KEY user_journal (user_id, journal_post_id),
			KEY journal_post_id (journal_post_id),
			KEY status (status)
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
		dbDelta( $sql_galleys );
		dbDelta( $sql_copyedit );
		dbDelta( $sql_subscriptions );

		if ( class_exists( 'WJM_Relational_Schema' ) ) {
			WJM_Relational_Schema::create_tables();
		}

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
			'galleys'        => $wpdb->prefix . 'sjm_galleys',
			'copyedit'       => $wpdb->prefix . 'sjm_copyedit_tasks',
			'subscriptions'  => $wpdb->prefix . 'sjm_subscriptions',
		);
		return isset( $map[ $key ] ) ? $map[ $key ] : '';
	}
}
