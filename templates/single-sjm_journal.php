<?php
/**
 * Single journal template.
 *
 * @package WisdomJournalManager
 */

get_header();
?>
<main class="wjm-single-journal">
	<?php while ( have_posts() ) : ?>
		<?php the_post(); ?>
		<article <?php post_class( 'wjm-journal' ); ?>>
			<header class="wjm-hero">
				<h1><?php the_title(); ?></h1>
				<?php
				$issn = get_post_meta( get_the_ID(), '_sjm_issn', true );
				$pub  = get_post_meta( get_the_ID(), '_sjm_publisher', true );
				?>
				<?php if ( $issn || $pub ) : ?>
					<p class="wjm-journal-meta">
						<?php if ( $pub ) : ?><span><?php echo esc_html( $pub ); ?></span><?php endif; ?>
						<?php if ( $issn ) : ?><span>ISSN <?php echo esc_html( $issn ); ?></span><?php endif; ?>
					</p>
				<?php endif; ?>
			</header>
			<div class="wjm-journal-body">
				<?php the_content(); ?>
			</div>
			<?php echo WJM_Templates::journal_issues( get_the_ID() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</article>
	<?php endwhile; ?>
</main>
<?php
get_footer();
