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
		$issue_ids = get_posts(
			array(
				'post_type'      => 'sjm_issue',
				'posts_per_page' => -1,
				'fields'         => 'ids',
				'meta_key'       => '_sjm_journal_id',
				'meta_value'     => absint( $journal_id ),
			)
		);

		if ( ! $issue_ids ) {
			return array(
				'papers'    => 0,
				'citations' => 0,
			);
		}

		$papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => -1,
				'fields'         => 'ids',
				'meta_query'     => array(
					array(
						'key'     => '_sjm_issue_id',
						'value'   => $issue_ids,
						'compare' => 'IN',
					),
				),
			)
		);

		$total = 0;
		foreach ( $papers as $paper_id ) {
			$total += (int) get_post_meta( $paper_id, '_sjm_citation_total', true );
		}

		return array(
			'papers'    => count( $papers ),
			'citations' => $total,
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
