<?php
/**
 * Keep relational tables in sync with CPT + postmeta.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Sync {

	public static function init() {
		add_action( 'sjm_after_save_journal', array( __CLASS__, 'sync_journal' ) );
		add_action( 'save_post_sjm_journal', array( __CLASS__, 'on_save_journal' ), 99, 2 );
		add_action( 'save_post_sjm_issue', array( __CLASS__, 'sync_issue' ), 99, 2 );
		add_action( 'sjm_after_save_paper', array( __CLASS__, 'sync_paper' ) );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'on_save_paper' ), 99, 2 );
		add_action( 'sjm_workflow_transition', array( __CLASS__, 'on_workflow' ), 5, 4 );
		add_action( 'sjm_doi_registered', array( __CLASS__, 'on_doi' ), 10, 2 );
		add_action( 'sjm_citations_updated', array( __CLASS__, 'on_citations' ), 10, 2 );
		add_action( 'before_delete_post', array( __CLASS__, 'on_delete' ) );
		add_action( 'transition_post_status', array( __CLASS__, 'on_status' ), 10, 3 );
	}

	/**
	 * @param int     $post_id Post ID.
	 * @param WP_Post $post Post.
	 */
	public static function on_save_journal( $post_id, $post ) {
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		self::sync_journal( $post_id );
		unset( $post );
	}

	/**
	 * @param int     $post_id Post ID.
	 * @param WP_Post $post Post.
	 */
	public static function on_save_paper( $post_id, $post ) {
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		self::sync_paper( $post_id );
		unset( $post );
	}

	/**
	 * @param int $paper_id Paper post ID.
	 * @param int $total Citation total.
	 */
	public static function on_citations( $paper_id, $total ) {
		global $wpdb;
		$wpdb->update(
			WJM_Relational_Schema::table( 'papers' ),
			array( 'citation_total' => absint( $total ) ),
			array( 'post_id' => absint( $paper_id ) ),
			array( '%d' ),
			array( '%d' )
		);
	}

	/**
	 * @param int $post_id Journal post ID.
	 */
	public static function sync_journal( $post_id ) {
		$post = get_post( $post_id );
		if ( ! $post || 'sjm_journal' !== $post->post_type ) {
			return;
		}

		global $wpdb;
		$table = WJM_Relational_Schema::table( 'journals' );
		$row   = array(
			'post_id'         => absint( $post_id ),
			'title'           => $post->post_title,
			'slug'            => $post->post_name,
			'issn'            => get_post_meta( $post_id, '_sjm_issn', true ) ?: null,
			'publisher'       => get_post_meta( $post_id, '_sjm_publisher', true ) ?: null,
			'editorial_board' => get_post_meta( $post_id, '_sjm_editorial_board', true ) ?: null,
			'doi_prefix'      => get_post_meta( $post_id, '_sjm_doi_prefix', true ) ?: null,
			'doi_acronym'     => get_post_meta( $post_id, '_sjm_doi_acronym', true ) ?: null,
			'status'          => $post->post_status,
		);

		$existing = WJM_Repository::get_journal_by_post( $post_id );
		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'post_id' => $post_id ) );
		} else {
			$wpdb->insert( $table, $row );
		}
	}

	/**
	 * @param int     $post_id Issue post ID.
	 * @param WP_Post $post Post.
	 */
	public static function sync_issue( $post_id, $post = null ) {
		$post = $post ? $post : get_post( $post_id );
		if ( ! $post || 'sjm_issue' !== $post->post_type || wp_is_post_revision( $post_id ) ) {
			return;
		}

		$journal_post_id = (int) get_post_meta( $post_id, '_sjm_journal_id', true );
		$journal_row     = $journal_post_id ? WJM_Repository::get_journal_by_post( $journal_post_id ) : null;

		global $wpdb;
		$table = WJM_Relational_Schema::table( 'issues' );
		$row   = array(
			'post_id'         => absint( $post_id ),
			'journal_id'      => $journal_row ? (int) $journal_row->id : null,
			'journal_post_id' => $journal_post_id ?: null,
			'title'           => $post->post_title,
			'slug'            => $post->post_name,
			'volume'          => get_post_meta( $post_id, '_sjm_volume', true ) ?: null,
			'number'          => get_post_meta( $post_id, '_sjm_number', true ) ?: null,
			'special_issue'   => '1' === get_post_meta( $post_id, '_sjm_special_issue', true ) ? 1 : 0,
			'guest_editors'   => get_post_meta( $post_id, '_sjm_guest_editors', true ) ?: null,
			'status'          => $post->post_status,
		);

		$existing = WJM_Repository::get_issue_by_post( $post_id );
		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'post_id' => $post_id ) );
		} else {
			$wpdb->insert( $table, $row );
		}
	}

	/**
	 * @param int $post_id Paper post ID.
	 */
	public static function sync_paper( $post_id ) {
		$post = get_post( $post_id );
		if ( ! $post || 'sjm_paper' !== $post->post_type ) {
			return;
		}

		$issue_post_id   = (int) get_post_meta( $post_id, '_sjm_issue_id', true );
		$journal_post_id = (int) get_post_meta( $post_id, '_sjm_journal_id', true );
		$issue_row       = $issue_post_id ? WJM_Repository::get_issue_by_post( $issue_post_id ) : null;

		if ( $issue_row && ! $journal_post_id ) {
			$journal_post_id = (int) $issue_row->journal_post_id;
		}
		if ( $issue_row && ! $journal_post_id && $issue_row->journal_id ) {
			global $wpdb;
			$journal_post_id = (int) $wpdb->get_var(
				$wpdb->prepare(
					'SELECT post_id FROM ' . WJM_Relational_Schema::table( 'journals' ) . ' WHERE id = %d',
					$issue_row->journal_id
				)
			);
		}

		$journal_row = $journal_post_id ? WJM_Repository::get_journal_by_post( $journal_post_id ) : null;

		$doi = get_post_meta( $post_id, '_sjm_doi', true );
		$doi = $doi ? $doi : null;

		global $wpdb;
		$table = WJM_Relational_Schema::table( 'papers' );
		$row   = array(
			'post_id'          => absint( $post_id ),
			'issue_id'         => $issue_row ? (int) $issue_row->id : null,
			'journal_id'       => $journal_row ? (int) $journal_row->id : ( $issue_row ? (int) $issue_row->journal_id : null ),
			'issue_post_id'    => $issue_post_id ?: null,
			'journal_post_id'  => $journal_post_id ?: null,
			'title'            => $post->post_title,
			'slug'             => $post->post_name,
			'doi'              => $doi,
			'abstract'         => get_post_meta( $post_id, '_sjm_abstract', true ) ?: null,
			'paper_type'       => get_post_meta( $post_id, '_sjm_paper_type', true ) ?: null,
			'open_access'      => '1' === get_post_meta( $post_id, '_sjm_open_access', true ) ? 1 : 0,
			'submission_date'  => self::null_date( get_post_meta( $post_id, '_sjm_submission_date', true ) ),
			'acceptance_date'  => self::null_date( get_post_meta( $post_id, '_sjm_acceptance_date', true ) ),
			'page_range'       => get_post_meta( $post_id, '_sjm_page_range', true ) ?: null,
			'funding'          => get_post_meta( $post_id, '_sjm_funding', true ) ?: null,
			'conflicts'        => get_post_meta( $post_id, '_sjm_conflicts', true ) ?: null,
			'ethics'           => get_post_meta( $post_id, '_sjm_ethics', true ) ?: null,
			'data_availability'=> get_post_meta( $post_id, '_sjm_data_availability', true ) ?: null,
			'workflow_status'  => get_post_meta( $post_id, WJM_Workflow::META_STATUS, true ) ?: 'draft',
			'citation_total'   => (int) get_post_meta( $post_id, '_sjm_citation_total', true ),
			'apc_amount'       => get_post_meta( $post_id, '_sjm_apc_amount', true ) !== '' ? get_post_meta( $post_id, '_sjm_apc_amount', true ) : null,
			'apc_status'       => get_post_meta( $post_id, '_sjm_apc_status', true ) ?: 'unpaid',
			'author_user_id'   => (int) $post->post_author,
			'status'           => $post->post_status,
		);

		$existing = WJM_Repository::get_paper_by_post( $post_id );
		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'post_id' => $post_id ) );
		} else {
			$wpdb->insert( $table, $row );
		}
	}

	public static function on_workflow( $paper_id, $from, $to, $note = '' ) {
		unset( $from, $note );
		global $wpdb;
		$wpdb->update(
			WJM_Relational_Schema::table( 'papers' ),
			array( 'workflow_status' => sanitize_key( $to ) ),
			array( 'post_id' => absint( $paper_id ) ),
			array( '%s' ),
			array( '%d' )
		);
	}

	public static function on_doi( $paper_id, $doi ) {
		global $wpdb;
		$wpdb->update(
			WJM_Relational_Schema::table( 'papers' ),
			array( 'doi' => sanitize_text_field( $doi ) ),
			array( 'post_id' => absint( $paper_id ) ),
			array( '%s' ),
			array( '%d' )
		);
	}

	public static function on_delete( $post_id ) {
		$type = get_post_type( $post_id );
		if ( ! in_array( $type, array( 'sjm_journal', 'sjm_issue', 'sjm_paper' ), true ) ) {
			return;
		}
		global $wpdb;
		$key = 'journals';
		if ( 'sjm_issue' === $type ) {
			$key = 'issues';
		} elseif ( 'sjm_paper' === $type ) {
			$key = 'papers';
		}
		$wpdb->delete( WJM_Relational_Schema::table( $key ), array( 'post_id' => absint( $post_id ) ), array( '%d' ) );
	}

	public static function on_status( $new, $old, $post ) {
		if ( ! $post || ! in_array( $post->post_type, array( 'sjm_journal', 'sjm_issue', 'sjm_paper' ), true ) ) {
			return;
		}
		if ( 'sjm_journal' === $post->post_type ) {
			self::sync_journal( $post->ID );
		} elseif ( 'sjm_issue' === $post->post_type ) {
			self::sync_issue( $post->ID, $post );
		} else {
			self::sync_paper( $post->ID );
		}
		unset( $new, $old );
	}

	/**
	 * @param string $date Date string.
	 * @return string|null
	 */
	private static function null_date( $date ) {
		$date = trim( (string) $date );
		if ( ! $date || '0000-00-00' === $date ) {
			return null;
		}
		return $date;
	}
}
