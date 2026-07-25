<?php
/**
 * Single issue — TOC from assembler.
 *
 * @package WisdomJournalManager
 */

get_header();

$issue_id   = get_the_ID();
$journal_id = (int) get_post_meta( $issue_id, '_sjm_journal_id', true );
$volume     = get_post_meta( $issue_id, '_sjm_volume', true );
$number     = get_post_meta( $issue_id, '_sjm_number', true );
$toc        = class_exists( 'WJM_Issue_Assembler' ) ? WJM_Issue_Assembler::get_toc( $issue_id ) : array();
?>
<main class="wjm-single-issue wjm-shama">
	<?php while ( have_posts() ) : ?>
		<?php the_post(); ?>
		<article <?php post_class( 'wjm-issue' ); ?>>
			<header class="wjm-stage">
				<div class="wjm-stage__copy">
					<p class="wjm-eyebrow">
						<?php
						$bits = array( __( 'Issue', 'wisdom-journal-manager' ) );
						if ( $volume ) {
							$bits[] = 'Vol. ' . $volume;
						}
						if ( $number ) {
							$bits[] = 'No. ' . $number;
						}
						echo esc_html( implode( ' · ', $bits ) );
						?>
					</p>
					<h1 class="wjm-stage__title"><?php the_title(); ?></h1>
					<?php if ( $journal_id ) : ?>
						<p class="wjm-stage__lead"><a href="<?php echo esc_url( get_permalink( $journal_id ) ); ?>"><?php echo esc_html( get_the_title( $journal_id ) ); ?></a></p>
					<?php endif; ?>
				</div>
			</header>

			<div class="wjm-journal-body"><?php the_content(); ?></div>

			<section class="wjm-issue-toc">
				<p class="wjm-eyebrow"><?php esc_html_e( 'Contents', 'wisdom-journal-manager' ); ?></p>
				<h2 class="wjm-sec-title"><?php esc_html_e( 'Table of contents', 'wisdom-journal-manager' ); ?></h2>
				<?php if ( ! $toc ) : ?>
					<p class="description"><?php esc_html_e( 'No papers in this issue yet.', 'wisdom-journal-manager' ); ?></p>
				<?php else : ?>
					<ol class="wjm-papers">
						<?php foreach ( $toc as $pid ) : ?>
							<?php
							$p = get_post( $pid );
							if ( ! $p || 'publish' !== $p->post_status ) {
								continue;
							}
							$pages = get_post_meta( $pid, '_sjm_page_range', true );
							$early = get_post_meta( $pid, '_sjm_early_view', true );
							?>
							<li>
								<a href="<?php echo esc_url( get_permalink( $pid ) ); ?>"><?php echo esc_html( $p->post_title ); ?></a>
								<?php if ( $pages ) : ?>
									<span class="description"> · <?php echo esc_html( $pages ); ?></span>
								<?php endif; ?>
								<?php if ( $early ) : ?>
									<span class="wjm-status-badge"><?php esc_html_e( 'Early view', 'wisdom-journal-manager' ); ?></span>
								<?php endif; ?>
							</li>
						<?php endforeach; ?>
					</ol>
				<?php endif; ?>
			</section>
		</article>
	<?php endwhile; ?>
</main>
<?php
get_footer();
