<?php
/**
 * Single paper template.
 *
 * @package WisdomJournalManager
 */

get_header();
?>
<main class="wjm-single-paper">
	<?php while ( have_posts() ) : ?>
		<?php the_post(); ?>
		<article <?php post_class( 'wjm-paper' ); ?>>
			<header class="wjm-hero">
				<h1><?php the_title(); ?></h1>
			</header>
			<?php echo WJM_Templates::paper_chrome( get_the_ID() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<div class="wjm-paper-body">
				<?php the_content(); ?>
			</div>
			<section class="wjm-paper-metrics">
				<h2><?php esc_html_e( 'Citation metrics', 'wisdom-journal-manager' ); ?></h2>
				<?php echo do_shortcode( '[wjm_paper_metrics id="' . get_the_ID() . '"]' ); ?>
			</section>
		</article>
	<?php endwhile; ?>
</main>
<?php
get_footer();
