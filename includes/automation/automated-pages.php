<?php
/**
 * Automatic archive / index page helpers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Automated_Pages {

	public static function init() {
		add_action( 'sjm_after_save_journal', array( __CLASS__, 'ensure_journal_index_hint' ) );
	}

	/**
	 * Flag that archive indexes may need refresh after journal saves.
	 *
	 * @param int $journal_id Journal ID.
	 */
	public static function ensure_journal_index_hint( $journal_id ) {
		update_option( 'wjm_indexes_dirty', 1, false );
		unset( $journal_id );
	}

	/**
	 * Create a WordPress page containing journal shortcodes if missing.
	 *
	 * @return int Page ID.
	 */
	public static function ensure_catalog_page() {
		$page_id = (int) get_option( 'wjm_catalog_page_id' );
		if ( $page_id && get_post( $page_id ) ) {
			return $page_id;
		}

		$page_id = wp_insert_post(
			array(
				'post_title'   => __( 'Journals', 'wisdom-journal-manager' ),
				'post_content' => '[journals layout="grid"]' . "\n\n" . '[wjm_search]',
				'post_status'  => 'publish',
				'post_type'    => 'page',
			)
		);

		if ( $page_id && ! is_wp_error( $page_id ) ) {
			update_option( 'wjm_catalog_page_id', $page_id );
		}

		return (int) $page_id;
	}

	/**
	 * Create submission + author dashboard page.
	 *
	 * @return int Page ID.
	 */
	public static function ensure_submit_page() {
		$page_id = (int) get_option( 'wjm_submit_page_id' );
		if ( $page_id && get_post( $page_id ) ) {
			return $page_id;
		}

		$page_id = wp_insert_post(
			array(
				'post_title'   => __( 'Submit Manuscript', 'wisdom-journal-manager' ),
				'post_content' => "[wjm_submit]\n\n<h2>My submissions</h2>\n[wjm_my_submissions]",
				'post_status'  => 'publish',
				'post_type'    => 'page',
			)
		);

		if ( $page_id && ! is_wp_error( $page_id ) ) {
			update_option( 'wjm_submit_page_id', $page_id );
		}

		return (int) $page_id;
	}
}
