<?php
/**
 * Front-end template overrides for journals / papers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Templates {

	public static function init() {
		add_filter( 'template_include', array( __CLASS__, 'template_include' ) );
		add_filter( 'the_content', array( __CLASS__, 'enhance_content' ) );
	}

	public static function template_include( $template ) {
		if ( is_singular( 'sjm_paper' ) ) {
			$custom = WJM_PLUGIN_DIR . 'templates/single-sjm_paper.php';
			if ( file_exists( $custom ) ) {
				return $custom;
			}
		}
		if ( is_singular( 'sjm_journal' ) ) {
			$custom = WJM_PLUGIN_DIR . 'templates/single-sjm_journal.php';
			if ( file_exists( $custom ) ) {
				return $custom;
			}
		}
		return $template;
	}

	/**
	 * Enrich paper/journal content when theme has no override.
	 *
	 * @param string $content Content.
	 * @return string
	 */
	public static function enhance_content( $content ) {
		if ( ! is_singular( array( 'sjm_paper', 'sjm_journal' ) ) || ! in_the_loop() || ! is_main_query() ) {
			return $content;
		}

		if ( is_singular( 'sjm_paper' ) ) {
			return self::paper_chrome( get_the_ID() ) . $content;
		}

		if ( is_singular( 'sjm_journal' ) ) {
			return $content . self::journal_issues( get_the_ID() );
		}

		return $content;
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return string
	 */
	public static function paper_chrome( $paper_id ) {
		static $done = array();
		$paper_id = absint( $paper_id );
		if ( isset( $done[ $paper_id ] ) ) {
			return '';
		}
		$done[ $paper_id ] = true;

		$doi      = get_post_meta( $paper_id, '_sjm_doi', true );
		$abstract = get_post_meta( $paper_id, '_sjm_abstract', true );
		$authors  = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
		$type     = get_post_meta( $paper_id, '_sjm_paper_type', true );
		$oa       = get_post_meta( $paper_id, '_sjm_open_access', true );
		$cites    = (int) get_post_meta( $paper_id, '_sjm_citation_total', true );

		ob_start();
		?>
		<div class="wjm-paper-header">
			<?php if ( $type ) : ?>
				<p class="wjm-paper-type"><?php echo esc_html( ucwords( str_replace( '_', ' ', $type ) ) ); ?><?php echo $oa ? ' · ' . esc_html__( 'Open Access', 'wisdom-journal-manager' ) : ''; ?></p>
			<?php endif; ?>
			<?php if ( $authors ) : ?>
				<p class="wjm-paper-authors">
					<?php
					$bits = array();
					foreach ( $authors as $author ) {
						$bits[] = esc_html( trim( $author->first_name . ' ' . $author->last_name ) );
					}
					echo implode( ', ', $bits ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>
				</p>
			<?php endif; ?>
			<?php if ( $doi ) : ?>
				<p class="wjm-doi">DOI: <a href="https://doi.org/<?php echo esc_attr( $doi ); ?>"><?php echo esc_html( $doi ); ?></a></p>
			<?php endif; ?>
			<?php if ( $cites ) : ?>
				<p class="wjm-cites"><?php echo esc_html( sprintf( __( 'Citations: %d', 'wisdom-journal-manager' ), $cites ) ); ?></p>
			<?php endif; ?>
			<?php if ( $abstract ) : ?>
				<div class="wjm-abstract">
					<h2><?php esc_html_e( 'Abstract', 'wisdom-journal-manager' ); ?></h2>
					<?php echo wp_kses_post( wpautop( $abstract ) ); ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
		return ob_get_clean();
	}

	/**
	 * @param int $journal_id Journal ID.
	 * @return string
	 */
	public static function journal_issues( $journal_id ) {
		$issues = get_posts(
			array(
				'post_type'      => 'sjm_issue',
				'posts_per_page' => 50,
				'meta_key'       => '_sjm_journal_id',
				'meta_value'     => absint( $journal_id ),
			)
		);
		ob_start();
		echo '<div class="wjm-journal-issues"><h2>' . esc_html__( 'Issues', 'wisdom-journal-manager' ) . '</h2>';
		echo do_shortcode( '[issues journal_id="' . absint( $journal_id ) . '"]' );
		echo '</div>';
		unset( $issues );
		return ob_get_clean();
	}
}
