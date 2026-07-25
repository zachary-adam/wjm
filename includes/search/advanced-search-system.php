<?php
/**
 * Faceted search for papers and journals.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Advanced_Search {

	public static function init() {
		add_shortcode( 'wjm_search', array( __CLASS__, 'render_search' ) );
		add_action( 'pre_get_posts', array( __CLASS__, 'filter_main_query' ) );
	}

	/**
	 * Build paper query args from request filters.
	 *
	 * @param array $args Incoming args.
	 * @return array
	 */
	public static function paper_query_args( $args = array() ) {
		$defaults = array(
			'post_type'      => 'sjm_paper',
			'post_status'    => 'publish',
			'posts_per_page' => 20,
		);

		$query_args = array_merge( $defaults, $args );
		$meta_query = array();

		if ( ! empty( $_GET['wjm_keyword'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$query_args['s'] = sanitize_text_field( wp_unslash( $_GET['wjm_keyword'] ) );
		}

		if ( ! empty( $_GET['wjm_paper_type'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$meta_query[] = array(
				'key'   => '_sjm_paper_type',
				'value' => sanitize_text_field( wp_unslash( $_GET['wjm_paper_type'] ) ),
			);
		}

		if ( ! empty( $_GET['wjm_journal_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$journal_id = absint( $_GET['wjm_journal_id'] );
			$issue_ids  = get_posts(
				array(
					'post_type'      => 'sjm_issue',
					'fields'         => 'ids',
					'posts_per_page' => -1,
					'meta_key'       => '_sjm_journal_id',
					'meta_value'     => $journal_id,
				)
			);
			if ( $issue_ids ) {
				$meta_query[] = array(
					'key'     => '_sjm_issue_id',
					'value'   => $issue_ids,
					'compare' => 'IN',
				);
			} else {
				$meta_query[] = array(
					'key'   => '_sjm_issue_id',
					'value' => 0,
				);
			}
		}

		if ( ! empty( $_GET['wjm_year'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$query_args['year'] = absint( $_GET['wjm_year'] );
		}

		if ( $meta_query ) {
			$query_args['meta_query'] = $meta_query;
		}

		/**
		 * Filter paper listing query arguments.
		 *
		 * @param array $query_args Query args.
		 */
		return apply_filters( 'sjm_paper_query_args', $query_args );
	}

	/**
	 * Filter journal query args.
	 *
	 * @param array $args Args.
	 * @return array
	 */
	public static function journal_query_args( $args = array() ) {
		$defaults = array(
			'post_type'      => 'sjm_journal',
			'post_status'    => 'publish',
			'posts_per_page' => 20,
		);
		/**
		 * Filter journal listing query arguments.
		 *
		 * @param array $query_args Query args.
		 */
		return apply_filters( 'sjm_journal_query_args', array_merge( $defaults, $args ) );
	}

	public static function filter_main_query( $query ) {
		if ( is_admin() || ! $query->is_main_query() ) {
			return;
		}
		if ( ! $query->is_post_type_archive( 'sjm_paper' ) ) {
			return;
		}
		foreach ( self::paper_query_args() as $key => $value ) {
			if ( in_array( $key, array( 'post_type', 'post_status' ), true ) ) {
				continue;
			}
			$query->set( $key, $value );
		}
	}

	public static function render_search( $atts ) {
		$journals = get_posts( self::journal_query_args( array( 'posts_per_page' => -1 ) ) );
		$papers   = new WP_Query( self::paper_query_args() );

		ob_start();
		?>
		<form class="wjm-search-form" method="get">
			<input type="text" name="wjm_keyword" value="<?php echo isset( $_GET['wjm_keyword'] ) ? esc_attr( sanitize_text_field( wp_unslash( $_GET['wjm_keyword'] ) ) ) : ''; ?>" placeholder="<?php esc_attr_e( 'Keyword', 'wisdom-journal-manager' ); ?>" />
			<select name="wjm_journal_id">
				<option value=""><?php esc_html_e( 'All journals', 'wisdom-journal-manager' ); ?></option>
				<?php foreach ( $journals as $journal ) : ?>
					<option value="<?php echo esc_attr( $journal->ID ); ?>" <?php selected( isset( $_GET['wjm_journal_id'] ) ? absint( $_GET['wjm_journal_id'] ) : 0, $journal->ID ); ?>>
						<?php echo esc_html( $journal->post_title ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<select name="wjm_paper_type">
				<option value=""><?php esc_html_e( 'All types', 'wisdom-journal-manager' ); ?></option>
				<?php
				$types = array( 'original_research', 'review', 'case_study', 'editorial', 'letter', 'meta_analysis', 'systematic_review' );
				foreach ( $types as $type ) :
					?>
					<option value="<?php echo esc_attr( $type ); ?>" <?php selected( isset( $_GET['wjm_paper_type'] ) ? sanitize_text_field( wp_unslash( $_GET['wjm_paper_type'] ) ) : '', $type ); ?>>
						<?php echo esc_html( ucwords( str_replace( '_', ' ', $type ) ) ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<input type="number" name="wjm_year" min="1900" max="2100" value="<?php echo isset( $_GET['wjm_year'] ) ? esc_attr( absint( $_GET['wjm_year'] ) ) : ''; ?>" placeholder="<?php esc_attr_e( 'Year', 'wisdom-journal-manager' ); ?>" />
			<button type="submit"><?php esc_html_e( 'Search', 'wisdom-journal-manager' ); ?></button>
		</form>
		<ul class="wjm-search-results">
			<?php if ( $papers->have_posts() ) : ?>
				<?php while ( $papers->have_posts() ) : ?>
					<?php $papers->the_post(); ?>
					<li>
						<a href="<?php the_permalink(); ?>"><?php the_title(); ?></a>
						<?php
						$doi = get_post_meta( get_the_ID(), '_sjm_doi', true );
						if ( $doi ) {
							echo ' <span class="wjm-doi">DOI: ' . esc_html( $doi ) . '</span>';
						}
						?>
					</li>
				<?php endwhile; ?>
				<?php wp_reset_postdata(); ?>
			<?php else : ?>
				<li><?php esc_html_e( 'No papers found.', 'wisdom-journal-manager' ); ?></li>
			<?php endif; ?>
		</ul>
		<?php
		return ob_get_clean();
	}
}
