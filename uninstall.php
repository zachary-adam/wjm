<?php
/**
 * Uninstall: remove plugin options and custom tables.
 * Journal / Issue / Paper CPT content is preserved in wp_posts.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$options = array(
	'wjm_version',
	'wjm_db_version',
	'wjm_citation_schedule',
	'wjm_catalog_page_id',
	'wjm_submit_page_id',
	'wjm_indexes_dirty',
	'wjm_doi_prefix',
	'wjm_doi_settings',
	'wjm_api_crossref',
	'wjm_api_semantic_scholar',
	'wjm_api_scopus',
	'wjm_api_wos',
	'wjm_crossref_user',
	'wjm_crossref_pass',
	'wjm_datacite_user',
	'wjm_datacite_pass',
	'wjm_doi_last_connection_test',
);

foreach ( $options as $option ) {
	delete_option( $option );
}

$tables = array(
	$wpdb->prefix . 'sjm_authors',
	$wpdb->prefix . 'sjm_paper_authors',
	$wpdb->prefix . 'sjm_citations',
	$wpdb->prefix . 'sjm_audit_log',
	$wpdb->prefix . 'sjm_rate_limits',
	$wpdb->prefix . 'sjm_collaboration_notes',
	$wpdb->prefix . 'sjm_workflow_log',
	$wpdb->prefix . 'sjm_review_assignments',
	$wpdb->prefix . 'sjm_reviews',
	$wpdb->prefix . 'sjm_manuscripts',
	$wpdb->prefix . 'sjm_email_log',
);

foreach ( $tables as $table ) {
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
}

$roles = array( 'sjm_student', 'sjm_researcher', 'sjm_editor', 'sjm_reviewer' );
foreach ( $roles as $role ) {
	remove_role( $role );
}
