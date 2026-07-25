<?php
/**
 * Data access layer for relational journals / issues / papers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Repository {

	/**
	 * @param int $post_id Journal post ID.
	 * @return object|null
	 */
	public static function get_journal_by_post( $post_id ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'journals' );
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE post_id = %d", absint( $post_id ) )
		);
	}

	/**
	 * @param int $post_id Issue post ID.
	 * @return object|null
	 */
	public static function get_issue_by_post( $post_id ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'issues' );
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE post_id = %d", absint( $post_id ) )
		);
	}

	/**
	 * @param int $post_id Paper post ID.
	 * @return object|null
	 */
	public static function get_paper_by_post( $post_id ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'papers' );
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE post_id = %d", absint( $post_id ) )
		);
	}

	/**
	 * @param int $journal_post_id Journal CPT ID.
	 * @return object[]
	 */
	public static function get_issues_for_journal_post( $journal_post_id ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'issues' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE journal_post_id = %d AND status = 'publish' ORDER BY volume DESC, number DESC, id DESC",
				absint( $journal_post_id )
			)
		);
	}

	/**
	 * @param int $journal_post_id Journal CPT ID.
	 * @param int $limit Limit.
	 * @return object[]
	 */
	public static function get_papers_for_journal_post( $journal_post_id, $limit = 50 ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'papers' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE journal_post_id = %d AND status = 'publish' ORDER BY created_at DESC LIMIT %d",
				absint( $journal_post_id ),
				absint( $limit )
			)
		);
	}

	/**
	 * @param int $issue_post_id Issue CPT ID.
	 * @return object[]
	 */
	public static function get_papers_for_issue_post( $issue_post_id ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'papers' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE issue_post_id = %d ORDER BY id ASC",
				absint( $issue_post_id )
			)
		);
	}

	/**
	 * Faceted paper search against relational table.
	 *
	 * @param array $args Filters.
	 * @return object[]
	 */
	public static function search_papers( $args = array() ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'papers' );
		$where = array( "status = 'publish'" );
		$params = array();

		if ( ! empty( $args['journal_post_id'] ) ) {
			$where[]  = 'journal_post_id = %d';
			$params[] = absint( $args['journal_post_id'] );
		}
		if ( ! empty( $args['paper_type'] ) ) {
			$where[]  = 'paper_type = %s';
			$params[] = sanitize_key( $args['paper_type'] );
		}
		if ( ! empty( $args['year'] ) ) {
			$where[]  = 'YEAR(created_at) = %d';
			$params[] = absint( $args['year'] );
		}
		if ( ! empty( $args['keyword'] ) ) {
			$like     = '%' . $wpdb->esc_like( sanitize_text_field( $args['keyword'] ) ) . '%';
			$where[]  = '(title LIKE %s OR abstract LIKE %s OR doi LIKE %s)';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}
		if ( ! empty( $args['workflow_status'] ) ) {
			$where[]  = 'workflow_status = %s';
			$params[] = sanitize_key( $args['workflow_status'] );
		}

		$limit = isset( $args['limit'] ) ? absint( $args['limit'] ) : 50;
		$sql   = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . ' ORDER BY created_at DESC LIMIT ' . $limit;

		if ( $params ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		return $wpdb->get_results( $sql );
	}

	/**
	 * Analytics rollup from relational papers.
	 *
	 * @return array
	 */
	public static function stats() {
		global $wpdb;
		$journals = WJM_Relational_Schema::table( 'journals' );
		$issues   = WJM_Relational_Schema::table( 'issues' );
		$papers   = WJM_Relational_Schema::table( 'papers' );

		return array(
			'journals'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$journals} WHERE status = 'publish'" ),
			'issues'      => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$issues} WHERE status = 'publish'" ),
			'papers'      => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$papers} WHERE status = 'publish'" ),
			'citations'   => (int) $wpdb->get_var( "SELECT COALESCE(SUM(citation_total),0) FROM {$papers}" ),
			'open_access' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$papers} WHERE open_access = 1 AND status = 'publish'" ),
			'under_review'=> (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$papers} WHERE workflow_status = 'under_review'" ),
		);
	}

	/**
	 * Prefer relational field, fall back to post meta.
	 *
	 * @param int    $post_id Paper post ID.
	 * @param string $field   Column name.
	 * @param string $meta_key Meta key fallback.
	 * @return mixed
	 */
	public static function paper_field( $post_id, $field, $meta_key = '' ) {
		$row = self::get_paper_by_post( $post_id );
		if ( $row && isset( $row->{$field} ) && '' !== $row->{$field} && null !== $row->{$field} ) {
			return $row->{$field};
		}
		if ( $meta_key ) {
			return get_post_meta( $post_id, $meta_key, true );
		}
		return null;
	}
}
