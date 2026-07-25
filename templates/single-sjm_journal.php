<?php
/**
 * Single journal — Shama Research visual system (detailed).
 *
 * @package WisdomJournalManager
 */

get_header();

$journal_id = get_the_ID();
$jrow       = WJM_Repository::get_journal_by_post( $journal_id );
$issn       = $jrow && $jrow->issn ? $jrow->issn : get_post_meta( $journal_id, '_sjm_issn', true );
$pub        = $jrow && $jrow->publisher ? $jrow->publisher : get_post_meta( $journal_id, '_sjm_publisher', true );
$board      = $jrow && $jrow->editorial_board ? $jrow->editorial_board : get_post_meta( $journal_id, '_sjm_editorial_board', true );
$metrics    = class_exists( 'WJM_Advanced_Metrics' ) ? WJM_Advanced_Metrics::for_journal( $journal_id ) : array( 'papers' => 0, 'citations' => 0 );
$seo        = class_exists( 'WJM_SEO' ) ? WJM_SEO::get_journal_seo( $journal_id ) : array();
$submit_id  = (int) get_option( 'wjm_submit_page_id' );
$show_sub   = ! class_exists( 'WJM_Access' ) || WJM_Access::allowed( 'public_subscriptions' );
$show_search = ! class_exists( 'WJM_Access' ) || WJM_Access::allowed( 'public_search' );
$can_submit = ! class_exists( 'WJM_Access' ) || ! is_wp_error( WJM_Access::can_submit() );
?>
<main class="wjm-single-journal wjm-shama">
	<?php while ( have_posts() ) : ?>
		<?php the_post(); ?>
		<article <?php post_class( 'wjm-journal' ); ?>>

			<header class="wjm-stage">
				<div class="wjm-stage__copy">
					<p class="wjm-eyebrow"><?php esc_html_e( 'Journal', 'wisdom-journal-manager' ); ?></p>
					<h1 class="wjm-stage__title"><?php the_title(); ?></h1>
					<?php if ( $pub || $issn ) : ?>
						<p class="wjm-stage__lead">
							<?php
							$bits = array();
							if ( $pub ) {
								$bits[] = $pub;
							}
							if ( $issn ) {
								$bits[] = 'ISSN ' . $issn;
							}
							echo esc_html( implode( ' · ', $bits ) );
							?>
						</p>
					<?php endif; ?>

					<div class="wjm-meta-strip">
						<div class="wjm-strip-cell">
							<div class="k"><?php esc_html_e( 'Papers', 'wisdom-journal-manager' ); ?></div>
							<div class="v"><?php echo esc_html( (string) ( $metrics['papers'] ?? 0 ) ); ?></div>
						</div>
						<div class="wjm-strip-cell">
							<div class="k"><?php esc_html_e( 'Citations', 'wisdom-journal-manager' ); ?></div>
							<div class="v"><?php echo esc_html( (string) ( $metrics['citations'] ?? 0 ) ); ?></div>
						</div>
						<?php if ( ! empty( $seo['sitemap_include'] ) ) : ?>
							<div class="wjm-strip-cell">
								<div class="k"><?php esc_html_e( 'Sitemap', 'wisdom-journal-manager' ); ?></div>
								<div class="v"><a href="<?php echo esc_url( home_url( '/wjm-sitemap-' . $journal_id . '.xml' ) ); ?>">XML</a></div>
							</div>
						<?php endif; ?>
					</div>

					<?php if ( $can_submit && $submit_id ) : ?>
						<p class="wjm-stage-cta">
							<a class="wjm-btn" href="<?php echo esc_url( add_query_arg( 'journal_id', $journal_id, get_permalink( $submit_id ) ) ); ?>"><?php esc_html_e( 'Submit a manuscript', 'wisdom-journal-manager' ); ?></a>
						</p>
					<?php endif; ?>
				</div>
			</header>

			<div class="wjm-journal-body">
				<?php the_content(); ?>
			</div>

			<?php if ( $board ) : ?>
				<section class="wjm-board">
					<p class="wjm-eyebrow"><?php esc_html_e( 'Editorial board', 'wisdom-journal-manager' ); ?></p>
					<h2 class="wjm-sec-title"><?php esc_html_e( 'Editors', 'wisdom-journal-manager' ); ?></h2>
					<div class="wjm-board-text"><?php echo wp_kses_post( wpautop( $board ) ); ?></div>
				</section>
			<?php endif; ?>

			<?php if ( $show_sub ) : ?>
				<section class="wjm-journal-subscribe">
					<?php echo do_shortcode( '[wjm_subscribe journal_id="' . absint( $journal_id ) . '"]' ); ?>
				</section>
			<?php endif; ?>

			<section class="wjm-journal-issues">
				<p class="wjm-eyebrow"><?php esc_html_e( 'Archives', 'wisdom-journal-manager' ); ?></p>
				<h2 class="wjm-sec-title"><?php esc_html_e( 'Issues', 'wisdom-journal-manager' ); ?></h2>
				<?php echo do_shortcode( '[issues journal_id="' . absint( $journal_id ) . '"]' ); ?>
			</section>

			<section class="wjm-journal-papers">
				<p class="wjm-eyebrow"><?php esc_html_e( 'Recent', 'wisdom-journal-manager' ); ?></p>
				<h2 class="wjm-sec-title"><?php esc_html_e( 'Latest papers', 'wisdom-journal-manager' ); ?></h2>
				<?php
				$recent = get_posts(
					array(
						'post_type'      => 'sjm_paper',
						'posts_per_page' => 8,
						'post_status'    => 'publish',
						'meta_key'       => '_sjm_journal_id',
						'meta_value'     => $journal_id,
						'orderby'        => 'date',
						'order'          => 'DESC',
					)
				);
				if ( $recent ) :
					echo '<ul class="wjm-papers">';
					foreach ( $recent as $rp ) {
						$rtype = get_post_meta( $rp->ID, '_sjm_paper_type', true );
						echo '<li><a href="' . esc_url( get_permalink( $rp->ID ) ) . '">' . esc_html( $rp->post_title ) . '</a>';
						if ( $rtype ) {
							echo ' <span class="description">' . esc_html( ucwords( str_replace( '_', ' ', $rtype ) ) ) . '</span>';
						}
						echo '</li>';
					}
					echo '</ul>';
				else :
					echo '<p class="description">' . esc_html__( 'No published papers yet.', 'wisdom-journal-manager' ) . '</p>';
				endif;
				?>
			</section>

			<?php if ( $show_search ) : ?>
				<section class="wjm-journal-search">
					<p class="wjm-eyebrow"><?php esc_html_e( 'Discover', 'wisdom-journal-manager' ); ?></p>
					<h2 class="wjm-sec-title"><?php esc_html_e( 'Search papers', 'wisdom-journal-manager' ); ?></h2>
					<?php echo do_shortcode( '[wjm_search]' ); ?>
				</section>
			<?php endif; ?>
		</article>
	<?php endwhile; ?>
</main>
<?php
get_footer();
