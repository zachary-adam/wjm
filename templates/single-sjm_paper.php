<?php
/**
 * Single paper — Shama Research visual system (detailed).
 *
 * @package WisdomJournalManager
 */

get_header();

$paper_id   = get_the_ID();
$doi        = WJM_Repository::paper_field( $paper_id, 'doi', '_sjm_doi' );
$type       = WJM_Repository::paper_field( $paper_id, 'paper_type', '_sjm_paper_type' );
$oa         = WJM_Repository::paper_field( $paper_id, 'open_access', '_sjm_open_access' );
$abstract   = WJM_Repository::paper_field( $paper_id, 'abstract', '_sjm_abstract' );
$authors    = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
$cites      = (int) WJM_Repository::paper_field( $paper_id, 'citation_total', '_sjm_citation_total' );
$keywords   = wp_get_post_terms( $paper_id, 'sjm_keyword', array( 'fields' => 'names' ) );
$journal_id = (int) get_post_meta( $paper_id, '_sjm_journal_id', true );
$issue_id   = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
$pages      = get_post_meta( $paper_id, '_sjm_page_range', true );
$sub_date   = get_post_meta( $paper_id, '_sjm_submission_date', true );
$acc_date   = get_post_meta( $paper_id, '_sjm_acceptance_date', true );
$funding    = get_post_meta( $paper_id, '_sjm_funding', true );
$coi        = get_post_meta( $paper_id, '_sjm_conflicts', true );
$ethics     = get_post_meta( $paper_id, '_sjm_ethics', true );
$data_av    = get_post_meta( $paper_id, '_sjm_data_availability', true );
$corr       = get_post_meta( $paper_id, '_sjm_corresponding_email', true );
$preprint   = get_post_meta( $paper_id, '_sjm_preprint_url', true );
$early      = get_post_meta( $paper_id, '_sjm_early_view', true );
$show_metrics = ! class_exists( 'WJM_Access' ) || WJM_Access::allowed( 'public_paper_metrics' );
$show_galleys = ! class_exists( 'WJM_Access' ) || WJM_Access::allowed( 'public_galleys' );

$cite_authors = array();
if ( $authors ) {
	foreach ( $authors as $author ) {
		$cite_authors[] = trim( $author->last_name . ', ' . substr( (string) $author->first_name, 0, 1 ) . '.' );
	}
}
$cite_str = implode( ', ', $cite_authors );
$year     = get_the_date( 'Y' );
$apa      = trim( $cite_str . ( $cite_str ? ' ' : '' ) . '(' . $year . '). ' . get_the_title() . '.' . ( $doi ? ' https://doi.org/' . $doi : '' ) );
?>
<main class="wjm-single-paper wjm-shama">
	<?php while ( have_posts() ) : ?>
		<?php the_post(); ?>
		<article <?php post_class( 'wjm-paper' ); ?>>

			<nav class="wjm-crumbs" aria-label="<?php esc_attr_e( 'Breadcrumb', 'wisdom-journal-manager' ); ?>">
				<?php if ( $journal_id ) : ?>
					<a href="<?php echo esc_url( get_permalink( $journal_id ) ); ?>"><?php echo esc_html( get_the_title( $journal_id ) ); ?></a>
					<span aria-hidden="true"> / </span>
				<?php endif; ?>
				<?php if ( $issue_id ) : ?>
					<a href="<?php echo esc_url( get_permalink( $issue_id ) ); ?>"><?php echo esc_html( get_the_title( $issue_id ) ); ?></a>
					<span aria-hidden="true"> / </span>
				<?php endif; ?>
				<span><?php esc_html_e( 'Article', 'wisdom-journal-manager' ); ?></span>
			</nav>

			<header class="wjm-stage">
				<div class="wjm-stage__copy">
					<p class="wjm-eyebrow">
						<?php
						$bits = array();
						if ( $type ) {
							$bits[] = ucwords( str_replace( '_', ' ', $type ) );
						}
						if ( $oa ) {
							$bits[] = __( 'Open Access', 'wisdom-journal-manager' );
						}
						if ( $early ) {
							$bits[] = __( 'Early view', 'wisdom-journal-manager' );
						}
						echo esc_html( $bits ? implode( ' · ', $bits ) : __( 'Article', 'wisdom-journal-manager' ) );
						?>
					</p>
					<h1 class="wjm-stage__title"><?php the_title(); ?></h1>

					<?php if ( $authors ) : ?>
						<ul class="wjm-author-list">
							<?php foreach ( $authors as $author ) : ?>
								<li>
									<strong><?php echo esc_html( trim( $author->first_name . ' ' . $author->last_name ) ); ?></strong>
									<?php if ( ! empty( $author->affiliation ) ) : ?>
										<span class="wjm-affil"><?php echo esc_html( $author->affiliation ); ?></span>
									<?php endif; ?>
									<?php if ( ! empty( $author->orcid ) ) : ?>
										<a class="wjm-orcid" href="https://orcid.org/<?php echo esc_attr( $author->orcid ); ?>" rel="noopener">ORCID</a>
									<?php endif; ?>
									<?php if ( ! empty( $author->credit_role ) ) : ?>
										<?php
										$roles = class_exists( 'WJM_Author_Profiles' ) ? WJM_Author_Profiles::credit_roles() : array();
										$rl    = isset( $roles[ $author->credit_role ] ) ? $roles[ $author->credit_role ] : $author->credit_role;
										?>
										<span class="wjm-credit"><?php echo esc_html( $rl ); ?></span>
									<?php endif; ?>
								</li>
							<?php endforeach; ?>
						</ul>
						<?php if ( $corr ) : ?>
							<p class="wjm-corr"><?php esc_html_e( 'Corresponding:', 'wisdom-journal-manager' ); ?> <a href="mailto:<?php echo esc_attr( $corr ); ?>"><?php echo esc_html( $corr ); ?></a></p>
						<?php endif; ?>
					<?php endif; ?>

					<div class="wjm-meta-strip">
						<?php if ( $doi ) : ?>
							<div class="wjm-strip-cell">
								<div class="k">DOI</div>
								<div class="v"><a href="https://doi.org/<?php echo esc_attr( $doi ); ?>"><?php echo esc_html( $doi ); ?></a></div>
							</div>
						<?php endif; ?>
						<div class="wjm-strip-cell">
							<div class="k"><?php esc_html_e( 'Published', 'wisdom-journal-manager' ); ?></div>
							<div class="v"><?php echo esc_html( get_the_date() ); ?></div>
						</div>
						<?php if ( $pages ) : ?>
							<div class="wjm-strip-cell">
								<div class="k"><?php esc_html_e( 'Pages', 'wisdom-journal-manager' ); ?></div>
								<div class="v"><?php echo esc_html( $pages ); ?></div>
							</div>
						<?php endif; ?>
						<?php if ( $preprint ) : ?>
							<div class="wjm-strip-cell">
								<div class="k"><?php esc_html_e( 'Preprint', 'wisdom-journal-manager' ); ?></div>
								<div class="v"><a href="<?php echo esc_url( $preprint ); ?>" rel="noopener"><?php esc_html_e( 'View', 'wisdom-journal-manager' ); ?></a></div>
							</div>
						<?php endif; ?>
						<?php if ( $show_metrics && $cites ) : ?>
							<div class="wjm-strip-cell">
								<div class="k"><?php esc_html_e( 'Citations', 'wisdom-journal-manager' ); ?></div>
								<div class="v"><?php echo esc_html( (string) $cites ); ?></div>
							</div>
						<?php endif; ?>
					</div>
				</div>
			</header>

			<?php if ( $sub_date || $acc_date ) : ?>
				<p class="wjm-timeline">
					<?php if ( $sub_date ) : ?>
						<span><?php echo esc_html( sprintf( __( 'Submitted %s', 'wisdom-journal-manager' ), $sub_date ) ); ?></span>
					<?php endif; ?>
					<?php if ( $acc_date ) : ?>
						<span><?php echo esc_html( sprintf( __( 'Accepted %s', 'wisdom-journal-manager' ), $acc_date ) ); ?></span>
					<?php endif; ?>
					<span><?php echo esc_html( sprintf( __( 'Published %s', 'wisdom-journal-manager' ), get_the_date() ) ); ?></span>
				</p>
			<?php endif; ?>

			<?php if ( $show_galleys ) : ?>
				<?php echo WJM_Production::render_public_galleys( $paper_id ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php endif; ?>

			<?php if ( $abstract ) : ?>
				<section class="wjm-abstract">
					<h2><?php esc_html_e( 'Abstract', 'wisdom-journal-manager' ); ?></h2>
					<?php echo wp_kses_post( wpautop( $abstract ) ); ?>
				</section>
			<?php endif; ?>

			<?php if ( $keywords && ! is_wp_error( $keywords ) ) : ?>
				<p class="wjm-keywords">
					<span class="wjm-eyebrow"><?php esc_html_e( 'Keywords', 'wisdom-journal-manager' ); ?></span>
					<?php foreach ( $keywords as $kw ) : ?>
						<span class="wjm-kw"><?php echo esc_html( $kw ); ?></span>
					<?php endforeach; ?>
				</p>
			<?php endif; ?>

			<div class="wjm-paper-body">
				<?php the_content(); ?>
			</div>

			<?php if ( $funding || $coi || $ethics || $data_av ) : ?>
				<section class="wjm-compliance">
					<p class="wjm-eyebrow"><?php esc_html_e( 'Statements', 'wisdom-journal-manager' ); ?></p>
					<h2 class="wjm-sec-title"><?php esc_html_e( 'Ethics & compliance', 'wisdom-journal-manager' ); ?></h2>
					<?php if ( $funding ) : ?>
						<p><strong><?php esc_html_e( 'Funding', 'wisdom-journal-manager' ); ?>:</strong> <?php echo esc_html( $funding ); ?></p>
					<?php endif; ?>
					<?php if ( $coi ) : ?>
						<p><strong><?php esc_html_e( 'Conflicts of interest', 'wisdom-journal-manager' ); ?>:</strong> <?php echo esc_html( $coi ); ?></p>
					<?php endif; ?>
					<?php if ( $ethics ) : ?>
						<p><strong><?php esc_html_e( 'Ethics', 'wisdom-journal-manager' ); ?>:</strong> <?php echo esc_html( $ethics ); ?></p>
					<?php endif; ?>
					<?php if ( $data_av ) : ?>
						<p><strong><?php esc_html_e( 'Data availability', 'wisdom-journal-manager' ); ?>:</strong> <?php echo esc_html( $data_av ); ?></p>
					<?php endif; ?>
				</section>
			<?php endif; ?>

			<section class="wjm-cite-box">
				<p class="wjm-eyebrow"><?php esc_html_e( 'Cite', 'wisdom-journal-manager' ); ?></p>
				<h2 class="wjm-sec-title"><?php esc_html_e( 'How to cite', 'wisdom-journal-manager' ); ?></h2>
				<blockquote class="wjm-apa"><?php echo esc_html( $apa ); ?></blockquote>
				<?php if ( $doi ) : ?>
					<p class="description"><a href="https://doi.org/<?php echo esc_attr( $doi ); ?>"><?php echo esc_html( 'https://doi.org/' . $doi ); ?></a></p>
				<?php endif; ?>
			</section>

			<?php
			if ( class_exists( 'WJM_SEO' ) ) {
				echo WJM_SEO::render_share_kit( $paper_id ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			?>

			<?php if ( $show_metrics ) : ?>
				<section class="wjm-paper-metrics">
					<p class="wjm-eyebrow"><?php esc_html_e( 'Impact', 'wisdom-journal-manager' ); ?></p>
					<h2 class="wjm-sec-title"><?php esc_html_e( 'Citation metrics', 'wisdom-journal-manager' ); ?></h2>
					<?php echo do_shortcode( '[wjm_paper_metrics id="' . $paper_id . '"]' ); ?>
				</section>
			<?php endif; ?>

			<?php echo do_shortcode( '[wjm_pay_apc paper_id="' . $paper_id . '"]' ); ?>
		</article>
	<?php endwhile; ?>
</main>
<?php
get_footer();
