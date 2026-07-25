<?php
/**
 * Aggregated citation metrics and trend helpers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Advanced_Metrics {

	public static function init() {
		add_shortcode( 'wjm_paper_metrics', array( __CLASS__, 'shortcode_metrics' ) );
	}

	/**
	 * Metrics for a paper, broken down by source.
	 *
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function for_paper( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'citations' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY source ASC",
				absint( $paper_id )
			)
		);
	}

	/**
	 * Journal-level citation rollup via child issues/papers.
	 *
	 * @param int $journal_id Journal ID.
	 * @return array
	 */
	public static function for_journal( $journal_id ) {
		global $wpdb;
		$table = WJM_Relational_Schema::table( 'papers' );
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT COUNT(*) AS papers, COALESCE(SUM(citation_total),0) AS citations FROM {$table} WHERE journal_post_id = %d AND status = 'publish'",
				absint( $journal_id )
			)
		);
		if ( $row ) {
			return array(
				'papers'    => (int) $row->papers,
				'citations' => (int) $row->citations,
			);
		}

		return array(
			'papers'    => 0,
			'citations' => 0,
		);
	}

	public static function shortcode_metrics( $atts ) {
		$atts = shortcode_atts(
			array(
				'id' => 0,
			),
			$atts,
			'wjm_paper_metrics'
		);

		$paper_id = absint( $atts['id'] );
		if ( ! $paper_id ) {
			$paper_id = get_the_ID();
		}

		$rows = self::for_paper( $paper_id );
		if ( ! $rows ) {
			return '<p class="wjm-metrics">' . esc_html__( 'No citation data yet.', 'wisdom-journal-manager' ) . '</p>';
		}

		ob_start();
		echo '<ul class="wjm-metrics">';
		foreach ( $rows as $row ) {
			printf(
				'<li><strong>%s:</strong> %d</li>',
				esc_html( $row->source ),
				(int) $row->citation_count
			);
		}
		echo '</ul>';
		return ob_get_clean();
	}
}
