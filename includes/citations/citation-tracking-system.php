<?php
/**
 * Citation tracking engine with WP-Cron scheduling.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Citation_Tracking {

	const CRON_HOOK = 'wjm_update_citations';

	public static function init() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run_scheduled_update' ) );
		add_action( 'wp_ajax_wjm_refresh_paper_citations', array( __CLASS__, 'ajax_refresh_paper' ) );
		add_filter( 'cron_schedules', array( __CLASS__, 'cron_schedules' ) );
	}

	public static function cron_schedules( $schedules ) {
		$schedules['wjm_monthly'] = array(
			'interval' => MONTH_IN_SECONDS,
			'display'  => __( 'Once Monthly (WJM)', 'wisdom-journal-manager' ),
		);
		return $schedules;
	}

	/**
	 * Update citations for a single paper across configured sources.
	 *
	 * @param int $paper_id Paper ID.
	 * @return array Results keyed by source.
	 */
	public static function update_paper( $paper_id ) {
		$doi = get_post_meta( $paper_id, '_sjm_doi', true );
		if ( ! $doi ) {
			return array();
		}

		$sources = array( 'crossref', 'semantic_scholar' );
		if ( WJM_Encryption::get_secret( 'wjm_api_scopus' ) ) {
			$sources[] = 'scopus';
		}
		if ( WJM_Encryption::get_secret( 'wjm_api_wos' ) ) {
			$sources[] = 'wos';
		}

		$results = array();
		foreach ( $sources as $source ) {
			$result = self::fetch_with_backoff( $doi, $source );
			if ( is_wp_error( $result ) ) {
				$results[ $source ] = $result;
				continue;
			}
			self::store_metric( $paper_id, $source, $result );
			$results[ $source ] = $result;
		}

		return $results;
	}

	/**
	 * @param string $doi DOI.
	 * @param string $source Source key.
	 * @param int    $attempt Attempt number.
	 * @return array|WP_Error
	 */
	private static function fetch_with_backoff( $doi, $source, $attempt = 1 ) {
		$result = WJM_API_Client::fetch_citations( $doi, $source );
		if ( ! is_wp_error( $result ) || $attempt >= 3 ) {
			return $result;
		}

		// Transient failures: retry with exponential backoff (sleep capped for request context).
		usleep( min( 500000 * $attempt, 1500000 ) );
		return self::fetch_with_backoff( $doi, $source, $attempt + 1 );
	}

	/**
	 * @param int   $paper_id Paper ID.
	 * @param string $source  Source.
	 * @param array  $data    Normalized metrics.
	 */
	public static function store_metric( $paper_id, $source, $data ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'citations' );

		$row = array(
			'paper_id'       => absint( $paper_id ),
			'source'         => sanitize_key( $source ),
			'citation_count' => isset( $data['citation_count'] ) ? (int) $data['citation_count'] : 0,
			'download_count' => isset( $data['download_count'] ) ? (int) $data['download_count'] : 0,
			'altmetric_score'=> isset( $data['altmetric_score'] ) ? (float) $data['altmetric_score'] : null,
			'raw_payload'    => wp_json_encode( isset( $data['raw'] ) ? $data['raw'] : $data ),
			'fetched_at'     => current_time( 'mysql', true ),
		);

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE paper_id = %d AND source = %s",
				$paper_id,
				$source
			)
		);

		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'id' => $existing ) );
		} else {
			$wpdb->insert( $table, $row );
		}

		update_post_meta( $paper_id, '_sjm_citation_total', self::aggregate_count( $paper_id ) );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return int
	 */
	public static function aggregate_count( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'citations' );
		$max   = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT MAX(citation_count) FROM {$table} WHERE paper_id = %d",
				absint( $paper_id )
			)
		);
		return (int) $max;
	}

	public static function run_scheduled_update() {
		$papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'publish',
				'posts_per_page' => 50,
				'meta_key'       => '_sjm_doi',
				'meta_compare'   => 'EXISTS',
				'fields'         => 'ids',
			)
		);

		foreach ( $papers as $paper_id ) {
			self::update_paper( $paper_id );
		}
	}

	public static function ajax_refresh_paper() {
		check_ajax_referer( 'wjm_admin', 'nonce' );
		if ( ! current_user_can( 'edit_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		if ( ! $paper_id ) {
			wp_send_json_error( array( 'message' => 'Missing paper_id' ), 400 );
		}

		$results = self::update_paper( $paper_id );
		wp_send_json_success(
			array(
				'total'   => self::aggregate_count( $paper_id ),
				'results' => $results,
			)
		);
	}
}
