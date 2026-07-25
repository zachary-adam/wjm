<?php
/**
 * Home dashboard — one next step, short learn path, extras hidden.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Getting_Started {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 5 );
		add_action( 'admin_init', array( __CLASS__, 'maybe_redirect' ) );
		add_action( 'admin_post_wjm_quick_setup', array( __CLASS__, 'handle_quick_setup' ) );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Home', 'wisdom-journal-manager' ),
			__( 'Home', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-getting-started',
			array( __CLASS__, 'render' )
		);
	}

	public static function maybe_redirect() {
		if ( ! get_transient( 'wjm_activation_redirect' ) ) {
			return;
		}
		delete_transient( 'wjm_activation_redirect' );
		if ( is_network_admin() || isset( $_GET['activate-multi'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started' ) );
		exit;
	}

	public static function handle_quick_setup() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_quick_setup' );

		WJM_Automated_Pages::ensure_catalog_page();
		WJM_Automated_Pages::ensure_submit_page();
		WJM_Roles::ensure_roles();

		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started&setup=1' ) );
		exit;
	}

	/**
	 * Single “do this next” action for learning.
	 *
	 * @return array{title:string,body:string,primary:array{label:string,url:string,form?:string},secondary?:array{label:string,url:string}}
	 */
	public static function next_action() {
		$blank   = class_exists( 'WJM_Simple_UI' ) ? ! WJM_Simple_UI::has_journal() : ( (int) wp_count_posts( 'sjm_journal' )->publish < 1 );
		$submit  = (int) get_option( 'wjm_submit_page_id' );
		$pending = class_exists( 'WJM_Editor_Inbox' ) ? WJM_Editor_Inbox::count_pending() : 0;
		$access  = class_exists( 'WJM_Access' ) && WJM_Access::allowed( 'public_submissions' );

		if ( $blank ) {
			return array(
				'title'     => __( 'Step 1 — Get a journal', 'wisdom-journal-manager' ),
				'body'      => __( 'Import a sample (fastest) or create a blank one. Then you can click Inbox → review → publish.', 'wisdom-journal-manager' ),
				'primary'   => array(
					'label' => __( 'Import demo (recommended)', 'wisdom-journal-manager' ),
					'form'  => 'demo',
				),
				'secondary' => array(
					'label' => __( 'New blank journal', 'wisdom-journal-manager' ),
					'url'   => admin_url( 'post-new.php?post_type=sjm_journal' ),
				),
			);
		}

		if ( ! $submit ) {
			return array(
				'title'   => __( 'Step 2 — Make a submit page', 'wisdom-journal-manager' ),
				'body'    => __( 'Authors use a public page — they never need wp-admin.', 'wisdom-journal-manager' ),
				'primary' => array(
					'label' => __( 'Create submit page', 'wisdom-journal-manager' ),
					'url'   => wp_nonce_url( admin_url( 'admin-post.php?action=wjm_quick_setup' ), 'wjm_quick_setup' ),
				),
			);
		}

		if ( ! $access ) {
			return array(
				'title'   => __( 'Step 2 — Open submissions', 'wisdom-journal-manager' ),
				'body'    => __( 'Turn on public submissions so authors can send papers.', 'wisdom-journal-manager' ),
				'primary' => array(
					'label' => __( 'Open Access settings', 'wisdom-journal-manager' ),
					'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-access' ),
				),
			);
		}

		if ( $pending > 0 ) {
			return array(
				'title'   => __( 'Step 3 — Work your Inbox', 'wisdom-journal-manager' ),
				'body'    => sprintf(
					/* translators: %d: pending count */
					_n( 'You have %d paper waiting. Open it, decide, then publish.', 'You have %d papers waiting. Open one, decide, then publish.', $pending, 'wisdom-journal-manager' ),
					$pending
				),
				'primary' => array(
					'label' => sprintf(
						/* translators: %d: pending */
						__( 'Open Inbox (%d)', 'wisdom-journal-manager' ),
						$pending
					),
					'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ),
				),
			);
		}

		return array(
			'title'     => __( "You're set — run the loop", 'wisdom-journal-manager' ),
			'body'      => __( 'Share the submit page with an author (or submit a test yourself). Then Inbox → review → publish. Money and DOI stay optional.', 'wisdom-journal-manager' ),
			'primary'   => array(
				'label' => __( 'Open Inbox', 'wisdom-journal-manager' ),
				'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ),
			),
			'secondary' => array(
				'label' => __( 'Author submit page', 'wisdom-journal-manager' ),
				'url'   => get_permalink( $submit ),
			),
		);
	}

	public static function render() {
		$checks   = self::checklist();
		$required = array_filter(
			$checks,
			static function ( $row ) {
				return empty( $row['optional'] );
			}
		);
		$done     = count( array_filter( wp_list_pluck( $required, 'ok' ) ) );
		$total    = count( $required );
		$catalog  = (int) get_option( 'wjm_catalog_page_id' );
		$submit   = (int) get_option( 'wjm_submit_page_id' );
		$advanced = class_exists( 'WJM_Simple_UI' ) && WJM_Simple_UI::is_advanced_mode();
		$progress = class_exists( 'WJM_Product_Guard' ) ? WJM_Product_Guard::dry_run_progress() : array( 'done' => 0, 'total' => 0, 'pct' => 0, 'all_ok' => false );
		$proven   = class_exists( 'WJM_Product_Guard' ) && WJM_Product_Guard::is_cycle_proven();
		$dry      = class_exists( 'WJM_Product_Guard' ) ? WJM_Product_Guard::dry_run_checks() : array();
		$blank    = class_exists( 'WJM_Simple_UI' ) ? ! WJM_Simple_UI::has_journal() : ( (int) wp_count_posts( 'sjm_journal' )->publish < 1 );
		$next     = self::next_action();
		$learn_n  = $blank ? 1 : ( ! $submit ? 2 : 3 );

		if ( ! empty( $_GET['setup'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Public pages and roles are ready.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		if ( ! empty( $_GET['demo'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$jid   = isset( $_GET['journal'] ) ? absint( $_GET['journal'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$pid   = isset( $_GET['paper'] ) ? absint( $_GET['paper'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$links = array();
			if ( $pid ) {
				$links[] = '<a href="' . esc_url( get_edit_post_link( $pid, 'raw' ) ) . '">' . esc_html__( 'Open a sample paper', 'wisdom-journal-manager' ) . '</a>';
			}
			$links[] = '<a href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ) . '">' . esc_html__( 'Open Inbox', 'wisdom-journal-manager' ) . '</a>';
			if ( $jid ) {
				$links[] = '<a href="' . esc_url( get_permalink( $jid ) ) . '" target="_blank" rel="noopener">' . esc_html__( 'View journal', 'wisdom-journal-manager' ) . '</a>';
			}
			$msg = __( 'Demo ready. Try this next:', 'wisdom-journal-manager' );
			$msg .= ' ' . implode( ' · ', $links );
			echo '<div class="notice notice-success is-dismissible"><p>' . wp_kses_post( $msg ) . '</p></div>';
		}
		if ( ! empty( $_GET['mode'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$m = sanitize_key( wp_unslash( $_GET['mode'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( 'advanced' === $m ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Paper extras ON — extra boxes on papers. Journals menu unchanged.', 'wisdom-journal-manager' ) . '</p></div>';
			} elseif ( 'basic' === $m ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Paper extras OFF. Optional tools stay under Advanced.', 'wisdom-journal-manager' ) . '</p></div>';
			}
		}
		if ( isset( $_GET['proven'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$p = sanitize_key( wp_unslash( $_GET['proven'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( '1' === $p ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'First cycle marked proven.', 'wisdom-journal-manager' ) . '</p></div>';
			} elseif ( 'incomplete' === $p ) {
				echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'Finish the practice checks before marking proven.', 'wisdom-journal-manager' ) . '</p></div>';
			}
		}
		?>
		<div class="wrap wjm-simple">
			<div class="wjm-home-hero<?php echo $blank ? ' is-blank' : ''; ?>">
				<div class="wjm-brand-lockup">
					<img src="<?php echo esc_url( WJM_PLUGIN_URL . 'assets/brand/wjm-mark-dark.svg' ); ?>" alt="" width="44" height="44" />
					<div>
						<span class="wjm-wordmark">WJM</span>
						<span class="wjm-wordmark-sub"><?php esc_html_e( 'Wisdom Journal Manager', 'wisdom-journal-manager' ); ?></span>
					</div>
				</div>
				<p class="wjm-learn-kicker"><?php esc_html_e( 'Learn the journal loop', 'wisdom-journal-manager' ); ?></p>
				<h2><?php echo esc_html( $next['title'] ); ?></h2>
				<p class="wjm-lead" style="margin:0;"><?php echo esc_html( $next['body'] ); ?></p>
				<div class="wjm-home-actions">
					<?php if ( ! empty( $next['primary']['form'] ) && 'demo' === $next['primary']['form'] ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
							<input type="hidden" name="action" value="wjm_import_demo" />
							<?php wp_nonce_field( 'wjm_import_demo' ); ?>
							<button type="submit" class="button button-primary button-hero"><?php echo esc_html( $next['primary']['label'] ); ?></button>
						</form>
					<?php else : ?>
						<a class="button button-primary button-hero" href="<?php echo esc_url( $next['primary']['url'] ); ?>"><?php echo esc_html( $next['primary']['label'] ); ?></a>
					<?php endif; ?>
					<?php if ( ! empty( $next['secondary'] ) ) : ?>
						<a class="button button-hero" href="<?php echo esc_url( $next['secondary']['url'] ); ?>"<?php echo ( false === strpos( (string) $next['secondary']['url'], 'wp-admin' ) ) ? ' target="_blank" rel="noopener"' : ''; ?>><?php echo esc_html( $next['secondary']['label'] ); ?></a>
					<?php endif; ?>
					<a class="button button-hero" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-help' ) ); ?>"><?php esc_html_e( '3-minute Help', 'wisdom-journal-manager' ); ?></a>
				</div>
			</div>

			<ol class="wjm-learn-path" aria-label="<?php esc_attr_e( 'Three steps to learn', 'wisdom-journal-manager' ); ?>">
				<li class="<?php echo 1 === $learn_n ? 'is-now' : ( $learn_n > 1 ? 'is-done' : '' ); ?>">
					<span class="n">1</span>
					<span class="t"><?php esc_html_e( 'Journal', 'wisdom-journal-manager' ); ?></span>
					<span class="d"><?php esc_html_e( 'Demo or new', 'wisdom-journal-manager' ); ?></span>
				</li>
				<li class="<?php echo 2 === $learn_n ? 'is-now' : ( $learn_n > 2 ? 'is-done' : '' ); ?>">
					<span class="n">2</span>
					<span class="t"><?php esc_html_e( 'Submit page', 'wisdom-journal-manager' ); ?></span>
					<span class="d"><?php esc_html_e( 'Authors send papers', 'wisdom-journal-manager' ); ?></span>
				</li>
				<li class="<?php echo 3 === $learn_n ? 'is-now' : ''; ?>">
					<span class="n">3</span>
					<span class="t"><?php esc_html_e( 'Inbox → publish', 'wisdom-journal-manager' ); ?></span>
					<span class="d"><?php esc_html_e( 'Review & decide', 'wisdom-journal-manager' ); ?></span>
				</li>
			</ol>

			<p class="wjm-learn-mantra"><?php esc_html_e( 'Remember: Authors submit → Inbox → review → publish. Money, DOI, Stripe, and DOAJ are optional add-ons — not day one.', 'wisdom-journal-manager' ); ?></p>

			<details class="wjm-details-calm">
				<summary>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: done 2: total */
							__( 'Setup checklist (%1$d of %2$d)', 'wisdom-journal-manager' ),
							$done,
							$total
						)
					);
					?>
				</summary>
				<ul class="wjm-check-list">
					<?php foreach ( $checks as $row ) : ?>
						<li>
							<span class="mark <?php echo ! empty( $row['ok'] ) ? 'ok' : ( ! empty( $row['optional'] ) ? 'skip' : 'no' ); ?>"><?php echo ! empty( $row['ok'] ) ? '✓' : ( ! empty( $row['optional'] ) ? '–' : '·' ); ?></span>
							<div class="body">
								<strong><?php echo esc_html( $row['label'] ); ?></strong>
								<?php if ( ! empty( $row['hint'] ) ) : ?>
									<span><?php echo esc_html( $row['hint'] ); ?></span>
								<?php endif; ?>
							</div>
							<?php if ( ! empty( $row['action'] ) && empty( $row['ok'] ) ) : ?>
								<?php echo wp_kses_post( $row['action'] ); ?>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			</details>

			<details class="wjm-details-calm">
				<summary>
					<?php esc_html_e( 'Practice path', 'wisdom-journal-manager' ); ?>
					<?php if ( $proven ) : ?>
						<span class="description"> — <?php esc_html_e( 'done', 'wisdom-journal-manager' ); ?></span>
					<?php elseif ( ! empty( $progress['all_ok'] ) ) : ?>
						<span class="description"> — <?php esc_html_e( 'ready to finish', 'wisdom-journal-manager' ); ?></span>
					<?php else : ?>
						<span class="description"> — <?php echo esc_html( sprintf( /* translators: 1: done 2: total */ __( '%1$d of %2$d', 'wisdom-journal-manager' ), $progress['done'], $progress['total'] ) ); ?></span>
					<?php endif; ?>
				</summary>
				<div class="wjm-dry-run-box">
					<p class="wjm-dry-lead"><?php esc_html_e( 'Try the loop once on this site. Checks turn green as you go.', 'wisdom-journal-manager' ); ?></p>
					<ul class="wjm-check-list">
						<?php foreach ( $dry as $row ) : ?>
							<li>
								<span class="mark <?php echo $row['ok'] ? 'ok' : 'no'; ?>"><?php echo $row['ok'] ? '✓' : '·'; ?></span>
								<div class="body">
									<strong><?php echo esc_html( $row['label'] ); ?></strong>
									<?php if ( ! empty( $row['hint'] ) ) : ?>
										<span><?php echo esc_html( $row['hint'] ); ?></span>
									<?php endif; ?>
								</div>
								<?php if ( ! empty( $row['action'] ) && empty( $row['ok'] ) ) : ?>
									<?php echo wp_kses_post( $row['action'] ); ?>
								<?php endif; ?>
							</li>
						<?php endforeach; ?>
					</ul>
					<?php if ( $progress['all_ok'] && ! $proven ) : ?>
						<p><?php esc_html_e( 'All steps look good. Save that so Home stays calm.', 'wisdom-journal-manager' ); ?></p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<input type="hidden" name="action" value="wjm_mark_cycle_proven" />
							<?php wp_nonce_field( 'wjm_mark_cycle_proven' ); ?>
							<?php submit_button( __( 'Mark practice complete', 'wisdom-journal-manager' ), 'primary', 'submit', false ); ?>
						</form>
					<?php elseif ( $proven ) : ?>
						<p class="description"><?php esc_html_e( 'Practice complete on this site.', 'wisdom-journal-manager' ); ?></p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<input type="hidden" name="action" value="wjm_clear_cycle_proven" />
							<?php wp_nonce_field( 'wjm_clear_cycle_proven' ); ?>
							<?php submit_button( __( 'Reset practice', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
						</form>
					<?php else : ?>
						<p class="description"><?php esc_html_e( 'Tip: Import demo → open a paper in Inbox → Accept or Revision → publish.', 'wisdom-journal-manager' ); ?></p>
					<?php endif; ?>
				</div>
			</details>

			<details class="wjm-details-calm">
				<summary><?php esc_html_e( 'More (demo, extras, later tools)', 'wisdom-journal-manager' ); ?></summary>
				<div style="margin-top:0.75rem;">
					<?php if ( ! $blank ) : ?>
						<p>
							<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_quick_setup' ), 'wjm_quick_setup' ) ); ?>"><?php esc_html_e( 'Recreate submit + catalog pages', 'wisdom-journal-manager' ); ?></a>
						</p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0.75rem 0 1rem;">
							<input type="hidden" name="action" value="wjm_import_demo" />
							<?php wp_nonce_field( 'wjm_import_demo' ); ?>
							<?php submit_button( __( 'Import / re-import demo journal', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
						</form>
					<?php endif; ?>

					<div class="wjm-mode-box" style="padding:1rem 0;border-top:1px solid var(--wjm-line,#c3c4c7);">
						<p style="margin-top:0;">
							<strong><?php esc_html_e( 'Paper extras', 'wisdom-journal-manager' ); ?></strong>
							<?php
							echo $advanced
								? esc_html__( ' — ON. Extra boxes on papers only. Journals menu stays calm.', 'wisdom-journal-manager' )
								: esc_html__( ' — OFF (recommended). Open tools from the Advanced hub when needed — that menu is separate.', 'wisdom-journal-manager' );
							?>
						</p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<input type="hidden" name="action" value="wjm_toggle_advanced_mode" />
							<?php wp_nonce_field( 'wjm_toggle_advanced_mode' ); ?>
							<?php if ( $advanced ) : ?>
								<input type="hidden" name="advanced_mode" value="0" />
								<?php submit_button( __( 'Hide paper extras', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
							<?php else : ?>
								<input type="hidden" name="advanced_mode" value="1" />
								<?php submit_button( __( 'Show paper extras', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
							<?php endif; ?>
							<a class="button" style="margin-left:0.5rem;" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-advanced' ) ); ?>"><?php esc_html_e( 'Advanced hub', 'wisdom-journal-manager' ); ?></a>
						</form>
					</div>

					<p class="description" style="margin-top:1rem;">
						<?php esc_html_e( 'Stripe, DOI, and iThenticate: paste your vendor keys under Advanced to Enable. DOAJ: checklist here, apply on doaj.org. ORCID: Public lookup / connect — WJM does not write peer-review credit to ORCID.', 'wisdom-journal-manager' ); ?>
						<a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-help' ) ); ?>"><?php esc_html_e( 'See Help', 'wisdom-journal-manager' ); ?></a>
					</p>
				</div>
			</details>

			<?php if ( $catalog ) : ?>
				<p class="description" style="margin-top:1.25rem;"><a href="<?php echo esc_url( get_permalink( $catalog ) ); ?>"><?php esc_html_e( 'Public journals catalog', 'wisdom-journal-manager' ); ?></a></p>
			<?php endif; ?>
			<p class="description"><?php echo esc_html( 'Wisdom Journal Manager v' . WJM_VERSION ); ?></p>
		</div>
		<?php
	}

	/**
	 * @return array[]
	 */
	private static function checklist() {
		$journals = (int) wp_count_posts( 'sjm_journal' )->publish;
		$pay      = class_exists( 'WJM_Payments' ) ? WJM_Payments::settings() : array();
		$stripe   = class_exists( 'WJM_Encryption' ) && (bool) WJM_Encryption::get_secret( 'wjm_stripe_secret' );

		return array(
			array(
				'label'  => __( 'Create your first journal', 'wisdom-journal-manager' ),
				'hint'   => __( 'Import demo is fastest.', 'wisdom-journal-manager' ),
				'ok'     => $journals > 0,
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'post-new.php?post_type=sjm_journal' ) ) . '">' . esc_html__( 'Add journal', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'label'  => __( 'Author submit page', 'wisdom-journal-manager' ),
				'hint'   => __( 'Public form — no wp-admin for authors.', 'wisdom-journal-manager' ),
				'ok'     => (bool) get_option( 'wjm_submit_page_id' ),
				'action' => '<a class="button button-small" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_quick_setup' ), 'wjm_quick_setup' ) ) . '">' . esc_html__( 'Create page', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'label'  => __( 'Editor + Reviewer roles', 'wisdom-journal-manager' ),
				'hint'   => __( 'Auto-created on activate.', 'wisdom-journal-manager' ),
				'ok'     => (bool) get_role( 'sjm_editor' ) && (bool) get_role( 'sjm_reviewer' ),
				'action' => '',
			),
			array(
				'label'  => __( 'Payments (optional)', 'wisdom-journal-manager' ),
				'hint'   => __( 'Skip unless you charge fees.', 'wisdom-journal-manager' ),
				'ok'     => empty( $pay['enabled'] ) || ( ! empty( $pay['enabled'] ) && ( 'manual' === $pay['provider'] || $stripe ) ),
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-advanced' ) ) . '">' . esc_html__( 'Later', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'label'    => __( 'DOI (optional)', 'wisdom-journal-manager' ),
				'hint'     => __( 'Skip for now.', 'wisdom-journal-manager' ),
				'ok'       => false,
				'optional' => true,
				'action'   => '<a class="button button-small" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-advanced' ) ) . '">' . esc_html__( 'Later', 'wisdom-journal-manager' ) . '</a>',
			),
		);
	}
}
