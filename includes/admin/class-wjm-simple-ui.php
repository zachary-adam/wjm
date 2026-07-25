<?php
/**
 * Zero-complexity admin UX: Basic sidebar + Advanced hub toolbox.
 *
 * Sidebar stays calm always. Power tools open from the Advanced hub (grouped).
 * "Show paper extras" only unlocks extra paper/journal meta boxes — it never changes the menu.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Simple_UI {

	/**
	 * Submenu slugs always removed from the Journals sidebar (reachable via Advanced hub).
	 *
	 * @return string[]
	 */
	public static function advanced_slugs() {
		$slugs = array(
			'wjm-doi',
			'wjm-database',
			'wjm-automation',
			'wjm-diagnostics',
			'wjm-security',
			'wjm-settings',
			'wjm-analytics',
			'wjm-decision-letters',
			'wjm-webhooks',
			'wjm-doaj',
			'wjm-waivers',
			'wjm-orcid',
			'wjm-recognition',
			'wjm-deals',
			'wjm-ithenticate',
			'edit-tags.php?taxonomy=sjm_subject&amp;post_type=sjm_journal',
			'edit-tags.php?taxonomy=sjm_subject&post_type=sjm_journal',
		);
		return apply_filters( 'wjm_simple_ui_advanced_slugs', $slugs );
	}

	/**
	 * Whether paper/journal “extras” meta boxes are visible.
	 *
	 * @return bool
	 */
	public static function is_advanced_mode() {
		return (bool) get_option( 'wjm_advanced_mode', 0 );
	}

	/**
	 * Alias — clearer name for the same option.
	 *
	 * @return bool
	 */
	public static function paper_extras_on() {
		return self::is_advanced_mode();
	}

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'register_advanced' ), 60 );
		add_action( 'admin_menu', array( __CLASS__, 'simplify_menus' ), 999 );
		add_action( 'add_meta_boxes', array( __CLASS__, 'hide_basic_paper_noise' ), 999 );
		add_action( 'admin_post_wjm_toggle_advanced_mode', array( __CLASS__, 'handle_toggle' ) );
	}

	/**
	 * @return bool
	 */
	public static function has_journal() {
		$c = wp_count_posts( 'sjm_journal' );
		return (int) ( $c->publish ?? 0 ) > 0;
	}

	/**
	 * Meta boxes hidden on papers/journals while Basic mode is on.
	 *
	 * @return string[]
	 */
	public static function basic_hidden_metaboxes() {
		return array(
			'wjm_extensions_meta',
			'wjm_ithenticate',
			'wjm_jats',
			'wjm_paper_seo',
			'wjm_journal_seo',
			'wjm_apc',
			'wjm_institution',
			'wjm_paper_compliance',
			'wjm_subscription',
		);
	}

	/**
	 * Essentials-first: strip power meta boxes unless “Show paper extras” is on.
	 */
	public static function hide_basic_paper_noise() {
		if ( self::paper_extras_on() ) {
			return;
		}
		foreach ( self::basic_hidden_metaboxes() as $id ) {
			remove_meta_box( $id, 'sjm_paper', 'normal' );
			remove_meta_box( $id, 'sjm_paper', 'side' );
			remove_meta_box( $id, 'sjm_journal', 'normal' );
			remove_meta_box( $id, 'sjm_journal', 'side' );
		}
	}

	public static function handle_toggle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_toggle_advanced_mode' );
		$on = ! empty( $_POST['advanced_mode'] );
		update_option( 'wjm_advanced_mode', $on ? 1 : 0 );
		$redirect = wp_get_referer() ? wp_get_referer() : admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started' );
		wp_safe_redirect( add_query_arg( 'mode', $on ? 'advanced' : 'basic', remove_query_arg( array( 'mode', 'demo', 'setup' ), $redirect ) ) );
		exit;
	}

	public static function register_advanced() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Advanced', 'wisdom-journal-manager' ),
			__( 'Advanced', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-advanced',
			array( __CLASS__, 'render_advanced' )
		);
	}

	/**
	 * Hide power-user screens from the Journals menu.
	 * Tools stay reachable from the Advanced hub — never flood the daily sidebar.
	 */
	public static function simplify_menus() {
		$parent = 'edit.php?post_type=sjm_journal';

		foreach ( self::advanced_slugs() as $slug ) {
			remove_submenu_page( $parent, $slug );
		}

		global $submenu;
		if ( empty( $submenu[ $parent ] ) || ! is_array( $submenu[ $parent ] ) ) {
			return;
		}

		$renames = array(
			'wjm-getting-started' => __( 'Home', 'wisdom-journal-manager' ),
			'wjm-payments'        => __( 'Money', 'wisdom-journal-manager' ),
			'wjm-access'          => __( 'Access', 'wisdom-journal-manager' ),
			'wjm-inbox'           => __( 'Inbox', 'wisdom-journal-manager' ),
			'wjm-my-reviews'      => __( 'Reviews', 'wisdom-journal-manager' ),
			'wjm-authors'         => __( 'Authors', 'wisdom-journal-manager' ),
			'wjm-help'            => __( 'Help', 'wisdom-journal-manager' ),
			'wjm-advanced'        => __( 'Advanced', 'wisdom-journal-manager' ),
			'wjm-doi'             => __( 'DOI', 'wisdom-journal-manager' ),
			'wjm-database'        => __( 'Database', 'wisdom-journal-manager' ),
			'wjm-automation'      => __( 'Automation', 'wisdom-journal-manager' ),
			'wjm-settings'        => __( 'API keys', 'wisdom-journal-manager' ),
			'wjm-analytics'       => __( 'Analytics', 'wisdom-journal-manager' ),
			'wjm-diagnostics'     => __( 'Diagnostics', 'wisdom-journal-manager' ),
			'wjm-security'        => __( 'Security', 'wisdom-journal-manager' ),
		);

		foreach ( $submenu[ $parent ] as $i => $item ) {
			$slug = isset( $item[2] ) ? $item[2] : '';
			if ( isset( $renames[ $slug ] ) ) {
				if ( 'wjm-inbox' === $slug && false !== strpos( (string) $item[0], 'awaiting-mod' ) ) {
					$submenu[ $parent ][ $i ][0] = $renames[ $slug ] . ' ' . substr( $item[0], strpos( $item[0], '<span' ) );
				} else {
					$submenu[ $parent ][ $i ][0] = $renames[ $slug ];
				}
			}
		}

		$order = array(
			'wjm-getting-started',
			'edit.php?post_type=sjm_journal',
			'post-new.php?post_type=sjm_journal',
			'edit.php?post_type=sjm_issue',
			'edit.php?post_type=sjm_paper',
			'wjm-inbox',
			'wjm-my-reviews',
			'wjm-payments',
			'wjm-access',
			'wjm-authors',
			'wjm-help',
			'wjm-advanced',
		);

		$by_slug = array();
		$rest    = array();
		foreach ( $submenu[ $parent ] as $item ) {
			$slug = $item[2];
			if ( in_array( $slug, $order, true ) ) {
				$by_slug[ $slug ] = $item;
			} else {
				$rest[] = $item;
			}
		}

		$sorted = array();
		foreach ( $order as $slug ) {
			if ( isset( $by_slug[ $slug ] ) ) {
				$sorted[] = $by_slug[ $slug ];
			}
		}
		$submenu[ $parent ] = array_merge( $sorted, $rest );
	}

	/**
	 * Grouped Advanced hub catalog — open what you need; sidebar stays calm.
	 *
	 * @return array[]
	 */
	public static function hub_groups() {
		return array(
			array(
				'key'     => 'common',
				'title'   => __( 'Often needed', 'wisdom-journal-manager' ),
				'blurb'   => __( 'Start here — money, letters, identifiers, identity.', 'wisdom-journal-manager' ),
				'open'    => true,
				'links'   => array(
					array(
						'title' => __( 'Money', 'wisdom-journal-manager' ),
						'desc'  => __( 'APC / Stripe — optional.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-payments' ),
					),
					array(
						'title' => __( 'Decision letters', 'wisdom-journal-manager' ),
						'desc'  => __( 'Accept / revision / reject email templates.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-decision-letters' ),
					),
					array(
						'title' => __( 'DOI Manager', 'wisdom-journal-manager' ),
						'desc'  => __( 'Prefixes, CrossRef / DataCite, batch DOI.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' ),
					),
					array(
						'title' => __( 'ORCID', 'wisdom-journal-manager' ),
						'desc'  => __( 'OAuth connect, login, and public iD auto-fill.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-orcid' ),
					),
					array(
						'title' => __( 'Analytics', 'wisdom-journal-manager' ),
						'desc'  => __( 'Journal / paper counts and citations.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-analytics' ),
					),
				),
			),
			array(
				'key'     => 'publishing',
				'title'   => __( 'Publishing & discovery', 'wisdom-journal-manager' ),
				'blurb'   => __( 'Indexing readiness and harvest extras.', 'wisdom-journal-manager' ),
				'open'    => false,
				'links'   => array(
					array(
						'title' => __( 'DOAJ readiness', 'wisdom-journal-manager' ),
						'desc'  => __( 'Completeness checklist for open-access indexing.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doaj' ),
					),
					array(
						'title' => __( 'Subjects', 'wisdom-journal-manager' ),
						'desc'  => __( 'Subject taxonomy for journals/papers.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit-tags.php?taxonomy=sjm_subject&post_type=sjm_journal' ),
					),
					array(
						'title' => __( 'Reviewer recognition', 'wisdom-journal-manager' ),
						'desc'  => __( 'Certificates, CSV export, thank-you emails.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-recognition' ),
					),
				),
			),
			array(
				'key'     => 'money_extra',
				'title'   => __( 'Money extras', 'wisdom-journal-manager' ),
				'blurb'   => __( 'Only if you charge fees or have deals.', 'wisdom-journal-manager' ),
				'open'    => false,
				'links'   => array(
					array(
						'title' => __( 'Waiver codes', 'wisdom-journal-manager' ),
						'desc'  => __( 'APC discount / full-waiver codes.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-waivers' ),
					),
					array(
						'title' => __( 'VAT & R&P', 'wisdom-journal-manager' ),
						'desc'  => __( 'VAT percent and institutional email-domain deals.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-deals' ),
					),
				),
			),
			array(
				'key'     => 'integrations',
				'title'   => __( 'Integrations', 'wisdom-journal-manager' ),
				'blurb'   => __( 'Keys and vendor APIs — skip until you need them.', 'wisdom-journal-manager' ),
				'open'    => false,
				'links'   => array(
					array(
						'title' => __( 'API keys', 'wisdom-journal-manager' ),
						'desc'  => __( 'Semantic Scholar, Scopus, Crossref mailto. (Web of Science counts not wired.)', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-settings' ),
					),
					array(
						'title' => __( 'iThenticate', 'wisdom-journal-manager' ),
						'desc'  => __( 'Turnitin Core API — similarity % only.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-ithenticate' ),
					),
					array(
						'title' => __( 'Webhooks', 'wisdom-journal-manager' ),
						'desc'  => __( 'POST events once to Zapier / Slack / Make — no retries.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-webhooks' ),
					),
					array(
						'title' => __( 'Automation', 'wisdom-journal-manager' ),
						'desc'  => __( 'Citation cron, catalog & submit pages.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-automation' ),
					),
				),
			),
			array(
				'key'     => 'ops',
				'title'   => __( 'Site health', 'wisdom-journal-manager' ),
				'blurb'   => __( 'Rare — diagnostics and logs.', 'wisdom-journal-manager' ),
				'open'    => false,
				'links'   => array(
					array(
						'title' => __( 'Database', 'wisdom-journal-manager' ),
						'desc'  => __( 'Relational tables health and re-sync.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-database' ),
					),
					array(
						'title' => __( 'Plugin Verification', 'wisdom-journal-manager' ),
						'desc'  => __( 'Integrity checks for tables and Stripe.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-diagnostics' ),
					),
					array(
						'title' => __( 'Security Logs', 'wisdom-journal-manager' ),
						'desc'  => __( 'Audit trail of sensitive actions.', 'wisdom-journal-manager' ),
						'url'   => admin_url( 'edit.php?post_type=sjm_journal&page=wjm-security' ),
					),
				),
			),
		);
	}

	/**
	 * Short “what ships” map — plain language, no merge-tag junk.
	 *
	 * @return array[]
	 */
	public static function roadmap() {
		return array(
			array(
				'group' => __( 'Editorial tools', 'wisdom-journal-manager' ),
				'items' => array(
					array( 'status' => 'live', 'title' => __( 'Decision letters', 'wisdom-journal-manager' ), 'desc' => __( 'Accept, revision, and reject templates for authors.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Revision rounds', 'wisdom-journal-manager' ), 'desc' => __( 'R1/R2 badges, author response, revised files, due dates.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Desk reject + Inbox', 'wisdom-journal-manager' ), 'desc' => __( 'Desk-reject status and letter; board, timers, claim.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Conflict checks', 'wisdom-journal-manager' ), 'desc' => __( 'Warn when authors and reviewers may overlap.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Double-blind files', 'wisdom-journal-manager' ), 'desc' => __( 'Anonymized manuscript for reviewers; title page for editors.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Similarity %', 'wisdom-journal-manager' ), 'desc' => __( 'Manual or API score on a paper — never auto-rejects.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Appeals', 'wisdom-journal-manager' ), 'desc' => __( 'Editor-side status + email — no author appeal form yet.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Integrity assist', 'wisdom-journal-manager' ), 'desc' => __( 'Soft keyword / length flags only — you always decide.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'iThenticate (optional)', 'wisdom-journal-manager' ), 'desc' => __( 'Needs your API keys; or enter similarity % by hand.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Easy Home + Help', 'wisdom-journal-manager' ), 'desc' => __( 'Demo-first Home and a 3-minute tutorial.', 'wisdom-journal-manager' ) ),
				),
			),
			array(
				'group' => __( 'Reviewers', 'wisdom-journal-manager' ),
				'items' => array(
					array( 'status' => 'live', 'title' => __( 'Invite links', 'wisdom-journal-manager' ), 'desc' => __( 'Accept or decline without a WordPress login first.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Review forms', 'wisdom-journal-manager' ), 'desc' => __( 'Recommendation, score, editor-only notes, author comments.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Reminders', 'wisdom-journal-manager' ), 'desc' => __( 'Automatic nudges before and after the due date.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Expertise tags', 'wisdom-journal-manager' ), 'desc' => __( 'Shown when you assign reviewers.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Recognition', 'wisdom-journal-manager' ), 'desc' => __( 'Thank-you email, certificate, CSV export. Reviewers add ORCID credit themselves.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Smart matching', 'wisdom-journal-manager' ), 'desc' => __( 'Suggest reviewers by expertise tags and open load — not a full matching engine.', 'wisdom-journal-manager' ) ),
				),
			),
			array(
				'group' => __( 'Authors', 'wisdom-journal-manager' ),
				'items' => array(
					array( 'status' => 'live', 'title' => __( 'Public submit', 'wisdom-journal-manager' ), 'desc' => __( 'Sectioned form; authors never need wp-admin.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Save draft', 'wisdom-journal-manager' ), 'desc' => __( 'Resume later; upload the manuscript on final submit.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Co-author confirm', 'wisdom-journal-manager' ), 'desc' => __( 'Email each co-author a confirm link.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Preprint + CRediT', 'wisdom-journal-manager' ), 'desc' => __( 'Optional preprint URL and CRediT role picker.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'ORCID (Public API)', 'wisdom-journal-manager' ), 'desc' => __( 'Lookup, connect, import works. Does not write peer-review credit to ORCID.', 'wisdom-journal-manager' ) ),
				),
			),
			array(
				'group' => __( 'Publish', 'wisdom-journal-manager' ),
				'items' => array(
					array( 'status' => 'live', 'title' => __( 'Copyedit + galleys', 'wisdom-journal-manager' ), 'desc' => __( 'Checklist, PDF/HTML/XML galleys, public toggle.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'Issues + early view', 'wisdom-journal-manager' ), 'desc' => __( 'Assemble TOC; flag papers published without an issue.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'JATS export', 'wisdom-journal-manager' ), 'desc' => __( 'Minimal article XML — not full archival JATS.', 'wisdom-journal-manager' ) ),
				),
			),
			array(
				'group' => __( 'Optional add-ons', 'wisdom-journal-manager' ),
				'items' => array(
					array( 'status' => 'live', 'title' => __( 'Money / DOI / Stripe', 'wisdom-journal-manager' ), 'desc' => __( 'Off until you add credentials under Advanced.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'DOAJ readiness', 'wisdom-journal-manager' ), 'desc' => __( 'Checklist only — you still apply on doaj.org.', 'wisdom-journal-manager' ) ),
					array( 'status' => 'live', 'title' => __( 'REST, OAI, webhooks', 'wisdom-journal-manager' ), 'desc' => __( 'Minimal OAI-DC; webhooks fire once (no retries). Citation counts: Crossref / Semantic Scholar / Scopus — not Web of Science.', 'wisdom-journal-manager' ) ),
				),
			),
		);
	}

	public static function render_advanced() {
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'manage_sjm_settings' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$advanced = self::is_advanced_mode();
		$groups   = self::hub_groups();
		?>
		<div class="wrap wjm-simple">
			<div class="wjm-brand-lockup wjm-brand-lockup--light" style="margin:1rem 0 0.5rem;">
				<img src="<?php echo esc_url( WJM_PLUGIN_URL . 'assets/brand/wjm-mark-primary.svg' ); ?>" alt="" width="40" height="40" />
				<div>
					<span class="wjm-wordmark">WJM</span>
					<span class="wjm-wordmark-sub"><?php esc_html_e( 'Wisdom Journal Manager', 'wisdom-journal-manager' ); ?></span>
				</div>
			</div>
			<h1><?php esc_html_e( 'Advanced', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead">
				<?php esc_html_e( 'Optional tools. Learn the Inbox loop first — open these only when you need money, DOI, or integrations.', 'wisdom-journal-manager' ); ?>
				<a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-help' ) ); ?>"><?php esc_html_e( '3-minute Help', 'wisdom-journal-manager' ); ?></a>
			</p>

			<div class="wjm-adv-mode-box" style="margin:1rem 0 1.5rem;padding:1.1rem 1.25rem;border:1px solid var(--wjm-line,#c3c4c7);background:<?php echo $advanced ? '#edf7f1' : '#fff'; ?>;">
				<p style="margin-top:0;">
					<strong><?php esc_html_e( 'Paper extras', 'wisdom-journal-manager' ); ?></strong>
					<?php
					echo $advanced
						? esc_html__( ' — ON. Discovery, integrity, SEO, APC, JATS, and similar boxes show on papers. This does not change the Journals menu.', 'wisdom-journal-manager' )
						: esc_html__( ' — OFF (recommended). Papers stay essentials-first. The Advanced menu below is a separate toolbox — open cards when you need them.', 'wisdom-journal-manager' );
					?>
				</p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
					<input type="hidden" name="action" value="wjm_toggle_advanced_mode" />
					<?php wp_nonce_field( 'wjm_toggle_advanced_mode' ); ?>
					<?php if ( $advanced ) : ?>
						<input type="hidden" name="advanced_mode" value="0" />
						<?php submit_button( __( 'Hide paper extras', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
					<?php else : ?>
						<input type="hidden" name="advanced_mode" value="1" />
						<?php submit_button( __( 'Show paper extras', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
					<?php endif; ?>
				</form>
			</div>

			<?php foreach ( $groups as $group ) : ?>
				<details class="wjm-details-calm wjm-hub-group" <?php echo ! empty( $group['open'] ) ? 'open' : ''; ?>>
					<summary>
						<?php echo esc_html( $group['title'] ); ?>
						<span class="description"> — <?php echo esc_html( $group['blurb'] ); ?></span>
					</summary>
					<div class="wjm-card-grid">
						<?php foreach ( $group['links'] as $link ) : ?>
							<a class="wjm-card" href="<?php echo esc_url( $link['url'] ); ?>">
								<strong><?php echo esc_html( $link['title'] ); ?></strong>
								<span><?php echo esc_html( $link['desc'] ); ?></span>
							</a>
						<?php endforeach; ?>
					</div>
				</details>
			<?php endforeach; ?>

			<details class="wjm-details-calm" style="margin-top:1.5rem;">
				<summary><?php esc_html_e( 'What already ships (optional)', 'wisdom-journal-manager' ); ?>
					<span class="description"> — <?php esc_html_e( 'Reference only — not a to-do list', 'wisdom-journal-manager' ); ?></span>
				</summary>
				<p class="description" style="margin:0.75rem 0 0;"><?php esc_html_e( 'Skip this unless you want a plain list of built-in tools. Day-to-day work stays on Home and Inbox.', 'wisdom-journal-manager' ); ?></p>
				<?php foreach ( self::roadmap() as $block ) : ?>
					<h3 style="margin-top:1rem;font-family:var(--wjm-serif,Georgia,serif);"><?php echo esc_html( $block['group'] ); ?></h3>
					<ul class="wjm-check-list" style="list-style:none;margin:0;padding:0;">
						<?php foreach ( $block['items'] as $item ) : ?>
							<li style="border-bottom:1px solid var(--wjm-line,#dcdcde);padding:0.55rem 0;display:block;background:transparent;border-left:0;border-right:0;border-top:0;margin:0;">
								<strong><?php echo esc_html( $item['title'] ); ?></strong>
								<span class="description"> — <?php echo esc_html( $item['desc'] ); ?></span>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php endforeach; ?>
			</details>

			<p class="description" style="margin-top:1.5rem;"><?php echo esc_html( 'Wisdom Journal Manager v' . WJM_VERSION ); ?></p>
		</div>
		<?php
	}
}

