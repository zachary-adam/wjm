<?php
/**
 * Product guard — keep Basic calm, set honest limits, prove the first cycle.
 *
 * Addresses: ambition vs calm, WordPress ceiling, live-proof maturity.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Product_Guard {

	const OPT_PROVEN = 'wjm_first_cycle_proven_at';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'enforce_basic_allowlist' ), 1000 );
		add_action( 'admin_post_wjm_mark_cycle_proven', array( __CLASS__, 'handle_mark_proven' ) );
		add_action( 'admin_post_wjm_clear_cycle_proven', array( __CLASS__, 'handle_clear_proven' ) );
	}

	/**
	 * Menus allowed in Basic mode — progressive until a journal exists.
	 *
	 * @return string[]
	 */
	public static function basic_allowlist() {
		$core = array(
			'wjm-getting-started',
			'edit.php?post_type=sjm_journal',
			'post-new.php?post_type=sjm_journal',
			'wjm-access',
			'wjm-help',
			'wjm-advanced',
		);

		$has_journal = class_exists( 'WJM_Simple_UI' ) ? WJM_Simple_UI::has_journal() : ( (int) wp_count_posts( 'sjm_journal' )->publish > 0 );
		if ( ! $has_journal ) {
			return $core;
		}

		$core = array_merge(
			$core,
			array(
				'edit.php?post_type=sjm_issue',
				'edit.php?post_type=sjm_paper',
				'wjm-inbox',
				'wjm-my-reviews',
				'wjm-authors',
			)
		);

		$pay = class_exists( 'WJM_Payments' ) ? WJM_Payments::settings() : array();
		if ( ! empty( $pay['enabled'] ) ) {
			$core[] = 'wjm-payments';
		}

		return $core;
	}

	/**
	 * Pages that live under Advanced (not in Basic sidebar).
	 * Still reachable from the Advanced hub cards — menus stay calm.
	 *
	 * @return string[]
	 */
	public static function advanced_only_pages() {
		return array(
			'wjm-doi',
			'wjm-database',
			'wjm-automation',
			'wjm-diagnostics',
			'wjm-security',
			'wjm-settings',
			'wjm-analytics',
			'wjm-decision-letters',
		);
	}

	/**
	 * Hard allowlist — keep Basic sidebar calm. Paper extras (meta boxes) do not affect menus.
	 */
	public static function enforce_basic_allowlist() {
		if ( ! class_exists( 'WJM_Simple_UI' ) ) {
			return;
		}

		$parent = 'edit.php?post_type=sjm_journal';
		global $submenu;
		if ( empty( $submenu[ $parent ] ) || ! is_array( $submenu[ $parent ] ) ) {
			return;
		}

		$allow = self::basic_allowlist();
		$kept  = array();
		foreach ( $submenu[ $parent ] as $item ) {
			$slug = isset( $item[2] ) ? $item[2] : '';
			if ( in_array( $slug, $allow, true ) ) {
				$kept[] = $item;
			}
		}
		$submenu[ $parent ] = $kept;
	}

	/**
	 * @return bool
	 */
	public static function is_cycle_proven() {
		return (bool) get_option( self::OPT_PROVEN );
	}

	/**
	 * First-cycle dry-run checks — prove the path on this install.
	 *
	 * @return array[]
	 */
	public static function dry_run_checks() {
		$journals = (int) wp_count_posts( 'sjm_journal' )->publish;
		$papers   = wp_count_posts( 'sjm_paper' );
		$paper_n  = (int) ( $papers->publish ?? 0 ) + (int) ( $papers->private ?? 0 ) + (int) ( $papers->draft ?? 0 );
		$submit   = (int) get_option( 'wjm_submit_page_id' );
		$roles_ok = (bool) get_role( 'sjm_editor' ) && (bool) get_role( 'sjm_reviewer' );

		$has_submitted = false;
		$has_decision  = false;
		$has_published = false;
		$sample        = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => 50,
				'post_status'    => array( 'publish', 'private', 'draft', 'pending' ),
				'fields'         => 'ids',
			)
		);
		foreach ( $sample as $pid ) {
			$st = WJM_Workflow::get_status( $pid );
			if ( in_array( $st, array( 'submitted', 'screening', 'under_review', 'revision', 'resubmitted', 'accepted', 'published' ), true ) ) {
				$has_submitted = true;
			}
			if ( in_array( $st, array( 'accepted', 'rejected', 'revision', 'published' ), true ) || get_post_meta( $pid, '_sjm_decision_letter', true ) ) {
				$has_decision = true;
			}
			if ( 'published' === $st || 'publish' === get_post_status( $pid ) ) {
				$has_published = true;
			}
		}

		global $wpdb;
		$a_table = WJM_Database_Schema::table( 'assignments' );
		$token_col = false;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$cols = $wpdb->get_col( "DESCRIBE {$a_table}", 0 );
		if ( is_array( $cols ) ) {
			$token_col = in_array( 'invite_token', $cols, true );
		}

		$access_ok = class_exists( 'WJM_Access' ) && WJM_Access::allowed( 'public_submissions' );

		return array(
			array(
				'id'     => 'journal',
				'label'  => __( 'You have a journal', 'wisdom-journal-manager' ),
				'hint'   => __( 'Import demo or create one.', 'wisdom-journal-manager' ),
				'ok'     => $journals > 0,
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'post-new.php?post_type=sjm_journal' ) ) . '">' . esc_html__( 'Add journal', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'id'     => 'submit_page',
				'label'  => __( 'Authors can submit', 'wisdom-journal-manager' ),
				'hint'   => __( 'A public submit page exists.', 'wisdom-journal-manager' ),
				'ok'     => (bool) $submit,
				'action' => '<a class="button button-small" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_quick_setup' ), 'wjm_quick_setup' ) ) . '">' . esc_html__( 'Create page', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'id'     => 'roles',
				'label'  => __( 'Editor and Reviewer roles ready', 'wisdom-journal-manager' ),
				'hint'   => __( 'Added when you activate the plugin.', 'wisdom-journal-manager' ),
				'ok'     => $roles_ok,
				'action' => '',
			),
			array(
				'id'     => 'submissions_open',
				'label'  => __( 'Submissions are open', 'wisdom-journal-manager' ),
				'hint'   => __( 'Access allows public submissions.', 'wisdom-journal-manager' ),
				'ok'     => $access_ok,
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-access' ) ) . '">' . esc_html__( 'Access', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'id'     => 'invite_schema',
				'label'  => __( 'Reviewer invites work', 'wisdom-journal-manager' ),
				'hint'   => __( 'Reviewers can accept without logging in first.', 'wisdom-journal-manager' ),
				'ok'     => $token_col,
				'action' => '<span class="description">' . esc_html__( 'Deactivate and reactivate the plugin once if this stays incomplete.', 'wisdom-journal-manager' ) . '</span>',
			),
			array(
				'id'     => 'has_paper',
				'label'  => __( 'You have at least one paper', 'wisdom-journal-manager' ),
				'hint'   => __( 'From demo import or a real submission.', 'wisdom-journal-manager' ),
				'ok'     => $paper_n > 0,
				'action' => '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline;">'
					. '<input type="hidden" name="action" value="wjm_import_demo" />'
					. wp_nonce_field( 'wjm_import_demo', '_wpnonce', true, false )
					. '<button type="submit" class="button button-small">' . esc_html__( 'Import demo', 'wisdom-journal-manager' ) . '</button></form>',
			),
			array(
				'id'     => 'workflow_touch',
				'label'  => __( 'A paper is in the Inbox path', 'wisdom-journal-manager' ),
				'hint'   => __( 'Submitted or under review.', 'wisdom-journal-manager' ),
				'ok'     => $has_submitted,
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ) . '">' . esc_html__( 'Inbox', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'id'     => 'decision',
				'label'  => __( 'You made a decision', 'wisdom-journal-manager' ),
				'hint'   => __( 'Accept, ask for revision, or reject.', 'wisdom-journal-manager' ),
				'ok'     => $has_decision,
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_paper' ) ) . '">' . esc_html__( 'Papers', 'wisdom-journal-manager' ) . '</a>',
			),
			array(
				'id'     => 'published',
				'label'  => __( 'You published a paper', 'wisdom-journal-manager' ),
				'hint'   => __( 'Full loop: submit → decide → publish.', 'wisdom-journal-manager' ),
				'ok'     => $has_published,
				'action' => '<a class="button button-small" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_paper' ) ) . '">' . esc_html__( 'Papers', 'wisdom-journal-manager' ) . '</a>',
			),
		);
	}

	/**
	 * @return array{done:int,total:int,pct:int,all_ok:bool}
	 */
	public static function dry_run_progress() {
		$checks = self::dry_run_checks();
		$done   = count( array_filter( wp_list_pluck( $checks, 'ok' ) ) );
		$total  = count( $checks );
		return array(
			'done'   => $done,
			'total'  => $total,
			'pct'    => $total ? (int) round( ( $done / $total ) * 100 ) : 0,
			'all_ok' => $done === $total,
		);
	}

	public static function handle_mark_proven() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_mark_cycle_proven' );
		$progress = self::dry_run_progress();
		if ( ! $progress['all_ok'] ) {
			wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started&proven=incomplete' ) );
			exit;
		}
		update_option( self::OPT_PROVEN, current_time( 'mysql', true ) );
		WJM_Audit::log( 'info', 'first_cycle_proven', 'Editor marked first journal cycle as proven on this install.' );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started&proven=1' ) );
		exit;
	}

	public static function handle_clear_proven() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_clear_cycle_proven' );
		delete_option( self::OPT_PROVEN );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started&proven=0' ) );
		exit;
	}

	/**
	 * Honest ceiling — who this is for / not for.
	 *
	 * @return array{for:string[],not:string[]}
	 */
	public static function positioning() {
		return array(
			'for' => array(
				__( 'Campus / society / diamond OA journals', 'wisdom-journal-manager' ),
				__( 'Small editorial boards on WordPress hosting', 'wisdom-journal-manager' ),
				__( 'Submit → review → decide → publish without enterprise software', 'wisdom-journal-manager' ),
			),
			'not' => array(
				__( 'Not a ScholarOne / Editorial Manager replacement for mega-publishers', 'wisdom-journal-manager' ),
				__( 'Not multi-press SSO, complex consortia contracts, or 50-journal ops out of the box', 'wisdom-journal-manager' ),
				__( 'Not “turn on every Advanced card” — sidebar stays calm on purpose', 'wisdom-journal-manager' ),
			),
		);
	}
}
