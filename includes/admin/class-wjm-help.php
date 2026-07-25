<?php
/**
 * Help — 3-minute learn path, short answers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Help {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 55 );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Help', 'wisdom-journal-manager' ),
			__( 'Help', 'wisdom-journal-manager' ),
			'edit_posts',
			'wjm-help',
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * @return string
	 */
	public static function url() {
		return admin_url( 'edit.php?post_type=sjm_journal&page=wjm-help' );
	}

	/**
	 * Three short learn steps.
	 *
	 * @return array[]
	 */
	public static function steps() {
		$submit = (int) get_option( 'wjm_submit_page_id' );
		return array(
			array(
				'title' => __( '1. Get a journal', 'wisdom-journal-manager' ),
				'body'  => __( 'Home → Import demo (easiest). Or New journal → title → Publish.', 'wisdom-journal-manager' ),
				'links' => array(
					array( __( 'Home', 'wisdom-journal-manager' ), admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started' ) ),
					array( __( 'New journal', 'wisdom-journal-manager' ), admin_url( 'post-new.php?post_type=sjm_journal' ) ),
				),
			),
			array(
				'title' => __( '2. Let authors submit', 'wisdom-journal-manager' ),
				'body'  => __( 'Create the public submit page. Access → who can submit. Authors never need wp-admin.', 'wisdom-journal-manager' ),
				'links' => array(
					array( __( 'Access', 'wisdom-journal-manager' ), admin_url( 'edit.php?post_type=sjm_journal&page=wjm-access' ) ),
					array(
						$submit ? __( 'Submit page', 'wisdom-journal-manager' ) : __( 'Create submit page', 'wisdom-journal-manager' ),
						$submit ? get_permalink( $submit ) : wp_nonce_url( admin_url( 'admin-post.php?action=wjm_quick_setup' ), 'wjm_quick_setup' ),
					),
				),
			),
			array(
				'title' => __( '3. Inbox → review → publish', 'wisdom-journal-manager' ),
				'body'  => __( 'Open Inbox, claim a paper, assign reviewers, Accept / Revision / Reject, then publish. Money and DOI later if you want.', 'wisdom-journal-manager' ),
				'links' => array(
					array( __( 'Inbox', 'wisdom-journal-manager' ), admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ),
					array( __( 'Issues', 'wisdom-journal-manager' ), admin_url( 'edit.php?post_type=sjm_issue' ) ),
				),
			),
		);
	}

	/**
	 * @return array[]
	 */
	public static function faq() {
		return array(
			array(
				'q' => __( 'What do I do every day?', 'wisdom-journal-manager' ),
				'a' => __( 'Open Inbox. Work papers. Publish when ready. That is the whole core loop.', 'wisdom-journal-manager' ),
			),
			array(
				'q' => __( 'Do authors need wp-admin?', 'wisdom-journal-manager' ),
				'a' => __( 'No. Share the public submit page only.', 'wisdom-journal-manager' ),
			),
			array(
				'q' => __( 'Must I use Money or DOI?', 'wisdom-journal-manager' ),
				'a' => __( 'No. Skip until you need them. They live under Advanced and need your vendor keys.', 'wisdom-journal-manager' ),
			),
			array(
				'q' => __( 'Advanced menu vs paper extras?', 'wisdom-journal-manager' ),
				'a' => __( 'Advanced is a toolbox of optional pages (Money, DOI, ORCID…). “Show paper extras” only adds extra boxes on paper/journal screens. They are separate.', 'wisdom-journal-manager' ),
			),
			array(
				'q' => __( 'Will integrity flags auto-reject?', 'wisdom-journal-manager' ),
				'a' => __( 'Never. Flags help you decide — you always choose.', 'wisdom-journal-manager' ),
			),
			array(
				'q' => __( 'Does WJM write peer-review credit to ORCID?', 'wisdom-journal-manager' ),
				'a' => __( 'No. ORCID Public API is for lookup / connect / import works. Recognition emails ask reviewers to add credit in their own ORCID account.', 'wisdom-journal-manager' ),
			),
		);
	}

	public static function render() {
		if ( ! current_user_can( 'edit_posts' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$steps   = self::steps();
		$faq     = self::faq();
		$pending = class_exists( 'WJM_Editor_Inbox' ) ? WJM_Editor_Inbox::count_pending() : 0;
		$next    = class_exists( 'WJM_Getting_Started' ) ? WJM_Getting_Started::next_action() : null;
		?>
		<div class="wrap wjm-simple wjm-help">
			<div class="wjm-home-hero">
				<div class="wjm-brand-lockup">
					<img src="<?php echo esc_url( WJM_PLUGIN_URL . 'assets/brand/wjm-mark-dark.svg' ); ?>" alt="" width="44" height="44" />
					<div>
						<span class="wjm-wordmark">WJM</span>
						<span class="wjm-wordmark-sub"><?php esc_html_e( 'Wisdom Journal Manager', 'wisdom-journal-manager' ); ?></span>
					</div>
				</div>
				<p class="wjm-learn-kicker"><?php esc_html_e( '3-minute Help', 'wisdom-journal-manager' ); ?></p>
				<h2><?php esc_html_e( 'Learn one loop', 'wisdom-journal-manager' ); ?></h2>
				<p class="wjm-lead" style="margin:0;">
					<?php esc_html_e( 'Journal → submit → Inbox → publish. Everything else is optional.', 'wisdom-journal-manager' ); ?>
				</p>
				<div class="wjm-home-actions">
					<?php if ( $next && ! empty( $next['primary']['form'] ) && 'demo' === $next['primary']['form'] ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
							<input type="hidden" name="action" value="wjm_import_demo" />
							<?php wp_nonce_field( 'wjm_import_demo' ); ?>
							<button type="submit" class="button button-primary button-hero"><?php echo esc_html( $next['primary']['label'] ); ?></button>
						</form>
					<?php elseif ( $next ) : ?>
						<a class="button button-primary button-hero" href="<?php echo esc_url( $next['primary']['url'] ); ?>"><?php echo esc_html( $next['primary']['label'] ); ?></a>
					<?php else : ?>
						<a class="button button-primary button-hero" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started' ) ); ?>"><?php esc_html_e( 'Go to Home', 'wisdom-journal-manager' ); ?></a>
					<?php endif; ?>
					<a class="button button-hero" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ); ?>">
						<?php
						echo esc_html__( 'Inbox', 'wisdom-journal-manager' );
						if ( $pending ) {
							echo ' (' . (int) $pending . ')';
						}
						?>
					</a>
				</div>
			</div>

			<ol class="wjm-help-steps">
				<?php foreach ( $steps as $step ) : ?>
					<li class="wjm-help-step">
						<strong class="wjm-help-step-title"><?php echo esc_html( $step['title'] ); ?></strong>
						<p><?php echo esc_html( $step['body'] ); ?></p>
						<?php if ( ! empty( $step['links'] ) ) : ?>
							<p class="wjm-help-links">
								<?php foreach ( $step['links'] as $link ) : ?>
									<a class="button button-small" href="<?php echo esc_url( $link[1] ); ?>"<?php echo ( 0 === strpos( (string) $link[1], home_url() ) && false === strpos( (string) $link[1], 'wp-admin' ) ) ? ' target="_blank" rel="noopener"' : ''; ?>><?php echo esc_html( $link[0] ); ?></a>
								<?php endforeach; ?>
							</p>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ol>

			<details class="wjm-details-calm" open>
				<summary><?php esc_html_e( 'Quick answers', 'wisdom-journal-manager' ); ?></summary>
				<div class="wjm-help-faq">
					<?php foreach ( $faq as $row ) : ?>
						<details class="wjm-help-faq-item">
							<summary><?php echo esc_html( $row['q'] ); ?></summary>
							<p><?php echo esc_html( $row['a'] ); ?></p>
						</details>
					<?php endforeach; ?>
				</div>
			</details>

			<details class="wjm-details-calm">
				<summary><?php esc_html_e( 'Later: Stripe, DOI, ORCID, DOAJ, double-blind', 'wisdom-journal-manager' ); ?></summary>
				<div class="wjm-help-faq">
					<details class="wjm-help-faq-item">
						<summary><?php esc_html_e( 'Double-blind files', 'wisdom-journal-manager' ); ?></summary>
						<p><?php esc_html_e( 'Access → require anonymized manuscript + title page. Reviewers get the anonymized file only.', 'wisdom-journal-manager' ); ?></p>
					</details>
					<details class="wjm-help-faq-item">
						<summary><?php esc_html_e( 'ORCID', 'wisdom-journal-manager' ); ?></summary>
						<p><?php esc_html_e( 'Public API: lookup / connect with free Client ID + Secret. WJM does not write peer-review credit to ORCID — recognition emails help reviewers add it themselves.', 'wisdom-journal-manager' ); ?></p>
					</details>
					<details class="wjm-help-faq-item">
						<summary><?php esc_html_e( 'DOAJ', 'wisdom-journal-manager' ); ?></summary>
						<p><?php esc_html_e( 'Advanced → DOAJ readiness, then apply at doaj.org. Only DOAJ accepts journals.', 'wisdom-journal-manager' ); ?></p>
					</details>
					<details class="wjm-help-faq-item">
						<summary><?php esc_html_e( 'Stripe / DOI / iThenticate', 'wisdom-journal-manager' ); ?></summary>
						<p><?php esc_html_e( 'Already in the plugin. Paste your vendor keys to Enable — otherwise leave off or use Manual / Local.', 'wisdom-journal-manager' ); ?></p>
					</details>
				</div>
			</details>

			<details class="wjm-details-calm">
				<summary><?php esc_html_e( 'Word meanings', 'wisdom-journal-manager' ); ?></summary>
				<ul class="wjm-help-glossary">
					<li><strong><?php esc_html_e( 'Journal', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'Your publication.', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'Issue', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'A numbered group of papers.', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'Paper', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'One manuscript.', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'Inbox', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'Where you work papers.', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'Galley', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'Final PDF readers download.', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'APC / DOI', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'Fee / identifier — optional.', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'Advanced', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'Optional toolbox pages (Money, DOI, ORCID…).', 'wisdom-journal-manager' ); ?></li>
					<li><strong><?php esc_html_e( 'Paper extras', 'wisdom-journal-manager' ); ?></strong> — <?php esc_html_e( 'Extra boxes on paper screens only — not the sidebar.', 'wisdom-journal-manager' ); ?></li>
				</ul>
			</details>

			<p class="description" style="margin-top:1.5rem;"><?php echo esc_html( 'Wisdom Journal Manager v' . WJM_VERSION ); ?></p>
		</div>
		<?php
	}
}
