<?php
/**
 * Next-batch features: preprint, early view, appeals, plagiarism %, webhooks,
 * co-author confirm, reviewer expertise, DOAJ checklist, waiver codes.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Extensions {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_boxes' ) );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'save_paper' ), 25, 2 );
		add_action( 'sjm_workflow_transition', array( __CLASS__, 'fire_webhook' ), 40, 4 );
		add_action( 'sjm_after_save_paper', array( __CLASS__, 'maybe_send_coauthor_confirms' ) );
		add_action( 'admin_post_nopriv_wjm_coauthor_confirm', array( __CLASS__, 'handle_coauthor_confirm' ) );
		add_action( 'admin_post_wjm_coauthor_confirm', array( __CLASS__, 'handle_coauthor_confirm' ) );
		add_action( 'admin_post_wjm_save_webhooks', array( __CLASS__, 'handle_save_webhooks' ) );
		add_action( 'admin_post_wjm_save_waiver_codes', array( __CLASS__, 'handle_save_waivers' ) );
		add_action( 'admin_menu', array( __CLASS__, 'menus' ), 57 );
		add_action( 'show_user_profile', array( __CLASS__, 'render_expertise_field' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_expertise_field' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'save_expertise_field' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save_expertise_field' ) );
		add_filter( 'wjm_apc_amount', array( __CLASS__, 'apply_waiver_code' ), 10, 2 );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_coauthor_page' ) );
	}

	public static function menus() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Webhooks', 'wisdom-journal-manager' ),
			__( 'Webhooks', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-webhooks',
			array( __CLASS__, 'render_webhooks' )
		);
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'DOAJ readiness', 'wisdom-journal-manager' ),
			__( 'DOAJ readiness', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-doaj',
			array( __CLASS__, 'render_doaj' )
		);
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Waiver codes', 'wisdom-journal-manager' ),
			__( 'Waiver codes', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-waivers',
			array( __CLASS__, 'render_waivers' )
		);
	}

	public static function meta_boxes() {
		add_meta_box(
			'wjm_extensions_meta',
			__( 'Discovery & integrity', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_paper_box' ),
			'sjm_paper',
			'normal',
			'default'
		);
		add_meta_box(
			'wjm_appeals',
			__( 'Appeals & corrections', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_appeals_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	public static function render_paper_box( $post ) {
		$preprint = get_post_meta( $post->ID, '_sjm_preprint_url', true );
		$early    = get_post_meta( $post->ID, '_sjm_early_view', true );
		$sim      = get_post_meta( $post->ID, '_sjm_similarity_pct', true );
		$sim_src  = get_post_meta( $post->ID, '_sjm_similarity_source', true );
		$rights   = get_post_meta( $post->ID, '_sjm_access_rights', true );
		$grant    = get_post_meta( $post->ID, '_sjm_funding_grant', true );
		$funder   = get_post_meta( $post->ID, '_sjm_funder_name', true );
		$project  = get_post_meta( $post->ID, '_sjm_project_id', true );
		?>
		<p>
			<label><strong><?php esc_html_e( 'Preprint URL', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="url" class="widefat" name="sjm_preprint_url" value="<?php echo esc_attr( $preprint ); ?>" placeholder="https://..." />
		</p>
		<p>
			<label>
				<input type="checkbox" name="sjm_early_view" value="1" <?php checked( $early, '1' ); ?> />
				<?php esc_html_e( 'Early view / ahead-of-print (online first)', 'wisdom-journal-manager' ); ?>
			</label>
		</p>
		<p>
			<label><strong><?php esc_html_e( 'Similarity % (plagiarism check)', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="number" min="0" max="100" step="0.1" name="sjm_similarity_pct" value="<?php echo esc_attr( $sim ); ?>" style="width:6rem;" />
			<input type="text" name="sjm_similarity_source" value="<?php echo esc_attr( $sim_src ); ?>" placeholder="<?php esc_attr_e( 'Source e.g. iThenticate', 'wisdom-journal-manager' ); ?>" class="regular-text" />
		</p>
		<p class="description"><?php esc_html_e( 'Optional manual or API-fed score — never auto-rejects.', 'wisdom-journal-manager' ); ?></p>
		<hr />
		<p><strong><?php esc_html_e( 'OpenAIRE / access', 'wisdom-journal-manager' ); ?></strong></p>
		<p>
			<label><?php esc_html_e( 'Access rights', 'wisdom-journal-manager' ); ?></label><br />
			<select name="sjm_access_rights" class="widefat">
				<option value=""><?php esc_html_e( '— Default —', 'wisdom-journal-manager' ); ?></option>
				<option value="openAccess" <?php selected( $rights, 'openAccess' ); ?>><?php esc_html_e( 'openAccess', 'wisdom-journal-manager' ); ?></option>
				<option value="embargoedAccess" <?php selected( $rights, 'embargoedAccess' ); ?>><?php esc_html_e( 'embargoedAccess', 'wisdom-journal-manager' ); ?></option>
				<option value="restrictedAccess" <?php selected( $rights, 'restrictedAccess' ); ?>><?php esc_html_e( 'restrictedAccess', 'wisdom-journal-manager' ); ?></option>
				<option value="metadataOnlyAccess" <?php selected( $rights, 'metadataOnlyAccess' ); ?>><?php esc_html_e( 'metadataOnlyAccess', 'wisdom-journal-manager' ); ?></option>
			</select>
		</p>
		<p>
			<label><?php esc_html_e( 'Funder name', 'wisdom-journal-manager' ); ?></label><br />
			<input type="text" class="widefat" name="sjm_funder_name" value="<?php echo esc_attr( $funder ); ?>" />
		</p>
		<p>
			<label><?php esc_html_e( 'Grant / award id', 'wisdom-journal-manager' ); ?></label><br />
			<input type="text" class="widefat" name="sjm_funding_grant" value="<?php echo esc_attr( $grant ); ?>" placeholder="info:eu-repo/grantAgreement/EC/H2020/…" />
		</p>
		<p>
			<label><?php esc_html_e( 'Project id (OpenAIRE)', 'wisdom-journal-manager' ); ?></label><br />
			<input type="text" class="widefat" name="sjm_project_id" value="<?php echo esc_attr( $project ); ?>" />
		</p>
		<?php
	}

	public static function render_appeals_box( $post ) {
		$appeal = get_post_meta( $post->ID, '_sjm_appeal_status', true );
		$note   = get_post_meta( $post->ID, '_sjm_appeal_note', true );
		$ctype  = get_post_meta( $post->ID, '_sjm_correction_type', true );
		$decided = get_post_meta( $post->ID, '_sjm_appeal_decided_at', true );
		$status = class_exists( 'WJM_Workflow' ) ? WJM_Workflow::get_status( $post->ID ) : '';
		?>
		<p class="description"><?php esc_html_e( 'Opens notify editors; upheld/denied emails the author. Upheld can reopen desk/peer rejects.', 'wisdom-journal-manager' ); ?></p>
		<p>
			<label><?php esc_html_e( 'Appeal', 'wisdom-journal-manager' ); ?></label>
			<select name="sjm_appeal_status" class="widefat">
				<option value=""><?php esc_html_e( '— None —', 'wisdom-journal-manager' ); ?></option>
				<option value="open" <?php selected( $appeal, 'open' ); ?>><?php esc_html_e( 'Open', 'wisdom-journal-manager' ); ?></option>
				<option value="under_review" <?php selected( $appeal, 'under_review' ); ?>><?php esc_html_e( 'Under review', 'wisdom-journal-manager' ); ?></option>
				<option value="upheld" <?php selected( $appeal, 'upheld' ); ?>><?php esc_html_e( 'Upheld (reopen)', 'wisdom-journal-manager' ); ?></option>
				<option value="denied" <?php selected( $appeal, 'denied' ); ?>><?php esc_html_e( 'Denied', 'wisdom-journal-manager' ); ?></option>
			</select>
		</p>
		<p>
			<textarea name="sjm_appeal_note" class="widefat" rows="3" placeholder="<?php esc_attr_e( 'Appeal / decision notes (emailed)', 'wisdom-journal-manager' ); ?>"><?php echo esc_textarea( $note ); ?></textarea>
		</p>
		<?php if ( $decided ) : ?>
			<p class="description"><?php echo esc_html( sprintf( __( 'Last decided: %s', 'wisdom-journal-manager' ), $decided ) ); ?></p>
		<?php endif; ?>
		<?php if ( in_array( $status, array( 'desk_reject', 'rejected' ), true ) && ! in_array( $appeal, array( 'open', 'under_review' ), true ) ) : ?>
			<p class="description"><?php esc_html_e( 'Tip: set Appeal to Open, save, then decide upheld/denied.', 'wisdom-journal-manager' ); ?></p>
		<?php endif; ?>
		<p>
			<label><?php esc_html_e( 'Correction type', 'wisdom-journal-manager' ); ?></label>
			<select name="sjm_correction_type" class="widefat">
				<option value=""><?php esc_html_e( '— None —', 'wisdom-journal-manager' ); ?></option>
				<option value="corrigendum" <?php selected( $ctype, 'corrigendum' ); ?>><?php esc_html_e( 'Corrigendum', 'wisdom-journal-manager' ); ?></option>
				<option value="erratum" <?php selected( $ctype, 'erratum' ); ?>><?php esc_html_e( 'Erratum', 'wisdom-journal-manager' ); ?></option>
				<option value="retraction" <?php selected( $ctype, 'retraction' ); ?>><?php esc_html_e( 'Retraction', 'wisdom-journal-manager' ); ?></option>
				<option value="expression_of_concern" <?php selected( $ctype, 'expression_of_concern' ); ?>><?php esc_html_e( 'Expression of concern', 'wisdom-journal-manager' ); ?></option>
			</select>
		</p>
		<?php
	}

	public static function save_paper( $post_id, $post ) {
		if ( wp_is_post_revision( $post_id ) || ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		if ( isset( $_POST['sjm_preprint_url'] ) ) {
			update_post_meta( $post_id, '_sjm_preprint_url', esc_url_raw( wp_unslash( $_POST['sjm_preprint_url'] ) ) );
		}
		update_post_meta( $post_id, '_sjm_early_view', ! empty( $_POST['sjm_early_view'] ) ? '1' : '0' );
		if ( isset( $_POST['sjm_similarity_pct'] ) ) {
			update_post_meta( $post_id, '_sjm_similarity_pct', sanitize_text_field( wp_unslash( $_POST['sjm_similarity_pct'] ) ) );
		}
		if ( isset( $_POST['sjm_similarity_source'] ) ) {
			update_post_meta( $post_id, '_sjm_similarity_source', sanitize_text_field( wp_unslash( $_POST['sjm_similarity_source'] ) ) );
		}
		if ( isset( $_POST['sjm_access_rights'] ) ) {
			update_post_meta( $post_id, '_sjm_access_rights', sanitize_text_field( wp_unslash( $_POST['sjm_access_rights'] ) ) );
		}
		if ( isset( $_POST['sjm_funder_name'] ) ) {
			update_post_meta( $post_id, '_sjm_funder_name', sanitize_text_field( wp_unslash( $_POST['sjm_funder_name'] ) ) );
		}
		if ( isset( $_POST['sjm_funding_grant'] ) ) {
			update_post_meta( $post_id, '_sjm_funding_grant', sanitize_text_field( wp_unslash( $_POST['sjm_funding_grant'] ) ) );
		}
		if ( isset( $_POST['sjm_project_id'] ) ) {
			update_post_meta( $post_id, '_sjm_project_id', sanitize_text_field( wp_unslash( $_POST['sjm_project_id'] ) ) );
		}
		if ( isset( $_POST['sjm_appeal_note'] ) ) {
			update_post_meta( $post_id, '_sjm_appeal_note', sanitize_textarea_field( wp_unslash( $_POST['sjm_appeal_note'] ) ) );
		}
		if ( isset( $_POST['sjm_correction_type'] ) ) {
			update_post_meta( $post_id, '_sjm_correction_type', sanitize_key( wp_unslash( $_POST['sjm_correction_type'] ) ) );
		}
		if ( isset( $_POST['sjm_appeal_status'] ) ) {
			$prev = get_post_meta( $post_id, '_sjm_appeal_status', true );
			$next = sanitize_key( wp_unslash( $_POST['sjm_appeal_status'] ) );
			update_post_meta( $post_id, '_sjm_appeal_status', $next );
			if ( $next && $next !== $prev ) {
				self::handle_appeal_change( $post_id, $prev, $next );
			}
		}
		unset( $post );
	}

	/**
	 * Notify + optional reopen when appeal status changes.
	 *
	 * @param int    $paper_id Paper ID.
	 * @param string $from     Previous appeal status.
	 * @param string $to       New appeal status.
	 */
	public static function handle_appeal_change( $paper_id, $from, $to ) {
		$note = (string) get_post_meta( $paper_id, '_sjm_appeal_note', true );
		if ( class_exists( 'WJM_Audit' ) ) {
			WJM_Audit::log(
				'info',
				'appeal_' . $to,
				sprintf( 'Appeal %s → %s on paper %d', $from ? $from : 'none', $to, $paper_id ),
				array( 'paper_id' => $paper_id )
			);
		}

		if ( ! class_exists( 'WJM_Email' ) ) {
			return;
		}

		if ( in_array( $to, array( 'open', 'under_review' ), true ) && ! in_array( $from, array( 'open', 'under_review' ), true ) ) {
			WJM_Email::notify_editors( $paper_id, 'appeal_opened', array( 'note' => $note ) );
		}

		if ( in_array( $to, array( 'upheld', 'denied' ), true ) ) {
			update_post_meta( $paper_id, '_sjm_appeal_decided_at', current_time( 'mysql', true ) );
			$author_id = (int) get_post_field( 'post_author', $paper_id );
			$extra     = array(
				'note'          => $note,
				'appeal_status' => $to,
			);
			if ( $author_id ) {
				WJM_Email::send_template( $author_id, 'appeal_decided', $paper_id, $extra );
			} else {
				$guest = get_post_meta( $paper_id, '_sjm_corresponding_email', true );
				if ( is_email( $guest ) ) {
					WJM_Email::send_template( 0, 'appeal_decided', $paper_id, $extra, $guest );
				}
			}

			if ( 'upheld' === $to && class_exists( 'WJM_Workflow' ) ) {
				$wf = WJM_Workflow::get_status( $paper_id );
				if ( 'desk_reject' === $wf ) {
					WJM_Workflow::transition( $paper_id, 'screening', $note ? $note : __( 'Appeal upheld — reopened to screening.', 'wisdom-journal-manager' ) );
				} elseif ( 'rejected' === $wf ) {
					WJM_Workflow::transition( $paper_id, 'under_review', $note ? $note : __( 'Appeal upheld — reopened to peer review.', 'wisdom-journal-manager' ) );
				}
			}
		}
	}

	public static function fire_webhook( $paper_id, $from, $to, $note ) {
		$url = get_option( 'wjm_webhook_url', '' );
		if ( ! $url || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			return;
		}
		$events = get_option( 'wjm_webhook_events', array( 'submitted', 'accepted', 'rejected', 'revision', 'published' ) );
		if ( ! is_array( $events ) ) {
			$events = array();
		}
		if ( $events && ! in_array( $to, $events, true ) ) {
			return;
		}
		$payload = array(
			'event'    => 'workflow_transition',
			'paper_id' => (int) $paper_id,
			'title'    => get_the_title( $paper_id ),
			'from'     => $from,
			'to'       => $to,
			'note'     => $note,
			'url'      => get_permalink( $paper_id ),
			'site'     => home_url( '/' ),
			'time'     => gmdate( 'c' ),
		);
		wp_remote_post(
			$url,
			array(
				'timeout'  => 8,
				'blocking' => false,
				'headers'  => array( 'Content-Type' => 'application/json' ),
				'body'     => wp_json_encode( $payload ),
			)
		);
	}

	public static function render_webhooks() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$url    = get_option( 'wjm_webhook_url', '' );
		$events = get_option( 'wjm_webhook_events', array( 'submitted', 'accepted', 'rejected', 'revision', 'published' ) );
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Webhooks saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'Activity webhooks', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'POST JSON to Slack/Zapier/Make on workflow events. Empty URL = off.', 'wisdom-journal-manager' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_webhooks" />
				<?php wp_nonce_field( 'wjm_save_webhooks' ); ?>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Webhook URL', 'wisdom-journal-manager' ); ?></th>
						<td><input type="url" class="large-text" name="webhook_url" value="<?php echo esc_attr( $url ); ?>" placeholder="https://hooks.zapier.com/..." /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Events', 'wisdom-journal-manager' ); ?></th>
						<td>
							<?php foreach ( array( 'submitted', 'under_review', 'revision', 'accepted', 'rejected', 'published' ) as $ev ) : ?>
								<label style="display:block;"><input type="checkbox" name="events[]" value="<?php echo esc_attr( $ev ); ?>" <?php checked( in_array( $ev, (array) $events, true ) ); ?> /> <?php echo esc_html( $ev ); ?></label>
							<?php endforeach; ?>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save webhooks', 'wisdom-journal-manager' ) ); ?>
			</form>
		</div>
		<?php
	}

	public static function handle_save_webhooks() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_webhooks' );
		update_option( 'wjm_webhook_url', isset( $_POST['webhook_url'] ) ? esc_url_raw( wp_unslash( $_POST['webhook_url'] ) ) : '' );
		$events = isset( $_POST['events'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['events'] ) ) : array();
		update_option( 'wjm_webhook_events', $events );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-webhooks&saved=1' ) );
		exit;
	}

	public static function render_doaj() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$checks = self::doaj_checks();
		$done   = count( array_filter( wp_list_pluck( $checks, 'ok' ) ) );
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'DOAJ / ROAD readiness', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php echo esc_html( sprintf( __( 'Completeness %1$d / %2$d — guidance only, not an official application.', 'wisdom-journal-manager' ), $done, count( $checks ) ) ); ?></p>
			<p>
				<a class="button button-primary" href="https://doaj.org/apply/" target="_blank" rel="noopener"><?php esc_html_e( 'Apply at DOAJ (official)', 'wisdom-journal-manager' ); ?></a>
				<a class="button" href="https://doaj.org/apply/guide/" target="_blank" rel="noopener"><?php esc_html_e( 'DOAJ application guide', 'wisdom-journal-manager' ); ?></a>
			</p>
			<ol class="wjm-help-steps" style="max-width:none;line-height:1.55;">
				<li><?php esc_html_e( 'Tick every item below that you can (ISSN, license, board, OA papers, OAI).', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Publish a clear APC / no-APC policy page on your site.', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Confirm peer review and open access statements are public.', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Submit the official DOAJ form — only DOAJ staff can accept you.', 'wisdom-journal-manager' ); ?></li>
			</ol>
			<ul class="wjm-check-list">
				<?php foreach ( $checks as $row ) : ?>
					<li>
						<span class="mark <?php echo $row['ok'] ? 'ok' : 'no'; ?>"><?php echo $row['ok'] ? '✓' : '·'; ?></span>
						<div class="body">
							<strong><?php echo esc_html( $row['label'] ); ?></strong>
							<span><?php echo esc_html( $row['hint'] ); ?></span>
						</div>
					</li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php
	}

	/**
	 * @return array[]
	 */
	public static function doaj_checks() {
		$journals = (int) wp_count_posts( 'sjm_journal' )->publish;
		$j        = $journals ? get_posts( array( 'post_type' => 'sjm_journal', 'posts_per_page' => 1, 'post_status' => 'publish' ) ) : array();
		$jid      = $j ? $j[0]->ID : 0;
		$issn     = $jid ? get_post_meta( $jid, '_sjm_issn', true ) : '';
		$board    = $jid ? get_post_meta( $jid, '_sjm_editorial_board', true ) : '';
		$publisher = $jid ? get_post_meta( $jid, '_sjm_publisher', true ) : '';
		$license  = $jid ? get_post_meta( $jid, '_sjm_license', true ) : '';
		$oa_papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => 1,
				'post_status'    => 'publish',
				'meta_key'       => '_sjm_open_access',
				'meta_value'     => '1',
				'fields'         => 'ids',
			)
		);
		$pub_count = (int) wp_count_posts( 'sjm_paper' )->publish;
		$doi_paper = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'publish',
				'posts_per_page' => 1,
				'meta_key'       => '_sjm_doi',
				'meta_compare'   => '!=',
				'meta_value'     => '',
				'fields'         => 'ids',
			)
		);
		$access    = get_option( 'wjm_access_settings' );
		$access_ok = is_array( $access ) && array_key_exists( 'public_submissions', $access );
		$oai_ok    = class_exists( 'WJM_OAI' );
		$oai_hint  = $oai_ok ? WJM_OAI::base_url() . '?verb=Identify' : '';
		$pay       = class_exists( 'WJM_Payments' ) ? WJM_Payments::settings() : array();
		$apc_stated = empty( $pay['enabled'] ) || ! empty( $pay['default_apc'] ) || ! empty( $pay['enabled'] );

		return array(
			array( 'label' => __( 'At least one journal', 'wisdom-journal-manager' ), 'hint' => '', 'ok' => $journals > 0 ),
			array( 'label' => __( 'ISSN set', 'wisdom-journal-manager' ), 'hint' => __( 'Journal meta', 'wisdom-journal-manager' ), 'ok' => (bool) $issn ),
			array( 'label' => __( 'Publisher name set', 'wisdom-journal-manager' ), 'hint' => '', 'ok' => (bool) $publisher ),
			array( 'label' => __( 'Editorial board listed', 'wisdom-journal-manager' ), 'hint' => '', 'ok' => (bool) $board ),
			array( 'label' => __( 'License on journal', 'wisdom-journal-manager' ), 'hint' => __( 'Journal Details → License (e.g. CC BY 4.0)', 'wisdom-journal-manager' ), 'ok' => (bool) $license ),
			array( 'label' => __( 'Public submit page', 'wisdom-journal-manager' ), 'hint' => '', 'ok' => (bool) get_option( 'wjm_submit_page_id' ) ),
			array( 'label' => __( 'Access policy saved', 'wisdom-journal-manager' ), 'hint' => __( 'Who can submit is configured', 'wisdom-journal-manager' ), 'ok' => $access_ok ),
			array( 'label' => __( 'Peer-review path proven', 'wisdom-journal-manager' ), 'hint' => __( 'At least one paper reached under_review or beyond', 'wisdom-journal-manager' ), 'ok' => self::doaj_has_reviewed_paper() ),
			array( 'label' => __( '≥ 5 published papers', 'wisdom-journal-manager' ), 'hint' => __( 'DOAJ often expects a publishing track record', 'wisdom-journal-manager' ), 'ok' => $pub_count >= 5 ),
			array( 'label' => __( 'Open-access paper published', 'wisdom-journal-manager' ), 'hint' => '', 'ok' => (bool) $oa_papers ),
			array( 'label' => __( 'DOI on a published paper', 'wisdom-journal-manager' ), 'hint' => __( 'Optional but strengthens applications', 'wisdom-journal-manager' ), 'ok' => (bool) $doi_paper ),
			array( 'label' => __( 'APC policy stated (or fees off)', 'wisdom-journal-manager' ), 'hint' => __( 'Money settings', 'wisdom-journal-manager' ), 'ok' => $apc_stated ),
			array( 'label' => __( 'OAI-PMH endpoint registered', 'wisdom-journal-manager' ), 'hint' => $oai_hint, 'ok' => $oai_ok ),
			array( 'label' => __( 'OpenAIRE metadata fields available', 'wisdom-journal-manager' ), 'hint' => __( 'Access rights / funder on papers + oai_openaire', 'wisdom-journal-manager' ), 'ok' => $oai_ok ),
		);
	}

	/**
	 * @return bool
	 */
	private static function doaj_has_reviewed_paper() {
		$ids = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => 20,
				'post_status'    => array( 'publish', 'private', 'draft', 'pending' ),
				'fields'         => 'ids',
			)
		);
		foreach ( $ids as $id ) {
			$st = class_exists( 'WJM_Workflow' ) ? WJM_Workflow::get_status( $id ) : '';
			if ( in_array( $st, array( 'under_review', 'revision', 'resubmitted', 'accepted', 'copyediting', 'production', 'published', 'rejected' ), true ) ) {
				return true;
			}
		}
		return false;
	}

	public static function render_waivers() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$codes = get_option( 'wjm_waiver_codes', array() );
		if ( ! is_array( $codes ) ) {
			$codes = array();
		}
		$text = '';
		foreach ( $codes as $code => $pct ) {
			$text .= $code . '=' . $pct . "\n";
		}
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Waiver codes saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'APC waiver codes', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'One per line: CODE=percent (100 = full waiver). Authors enter the code on the pay shortcode.', 'wisdom-journal-manager' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_waiver_codes" />
				<?php wp_nonce_field( 'wjm_save_waiver_codes' ); ?>
				<textarea name="codes" class="large-text" rows="8" placeholder="WAIVE100=100&#10;LOW50=50"><?php echo esc_textarea( $text ); ?></textarea>
				<?php submit_button( __( 'Save codes', 'wisdom-journal-manager' ) ); ?>
			</form>
		</div>
		<?php
	}

	public static function handle_save_waivers() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_waiver_codes' );
		$raw  = isset( $_POST['codes'] ) ? sanitize_textarea_field( wp_unslash( $_POST['codes'] ) ) : '';
		$out  = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $line ) {
			$line = trim( $line );
			if ( ! $line || false === strpos( $line, '=' ) ) {
				continue;
			}
			list( $code, $pct ) = array_map( 'trim', explode( '=', $line, 2 ) );
			$code = strtoupper( sanitize_key( $code ) );
			$pct  = max( 0, min( 100, (float) $pct ) );
			if ( $code ) {
				$out[ $code ] = $pct;
			}
		}
		update_option( 'wjm_waiver_codes', $out );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-waivers&saved=1' ) );
		exit;
	}

	/**
	 * @param float $amount Amount.
	 * @param int   $paper_id Paper ID.
	 * @return float
	 */
	public static function apply_waiver_code( $amount, $paper_id ) {
		$code = '';
		if ( ! empty( $_REQUEST['wjm_waiver'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$code = strtoupper( sanitize_key( wp_unslash( $_REQUEST['wjm_waiver'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$stored = get_post_meta( $paper_id, '_sjm_waiver_code', true );
		if ( $code ) {
			update_post_meta( $paper_id, '_sjm_waiver_code', $code );
		} elseif ( $stored ) {
			$code = strtoupper( sanitize_key( $stored ) );
		}
		if ( ! $code ) {
			return $amount;
		}
		$codes = get_option( 'wjm_waiver_codes', array() );
		if ( empty( $codes[ $code ] ) ) {
			return $amount;
		}
		$pct = (float) $codes[ $code ];
		$new = round( $amount * ( 1 - ( $pct / 100 ) ), 2 );
		if ( $pct >= 100 ) {
			update_post_meta( $paper_id, WJM_Payments::META_STATUS, 'waived' );
		}
		return max( 0, $new );
	}

	public static function render_expertise_field( $user ) {
		$tags = get_user_meta( $user->ID, '_wjm_expertise_tags', true );
		?>
		<h2><?php esc_html_e( 'Reviewer expertise (WJM)', 'wisdom-journal-manager' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><label for="wjm_expertise_tags"><?php esc_html_e( 'Expertise tags', 'wisdom-journal-manager' ); ?></label></th>
				<td>
					<input type="text" class="regular-text" name="wjm_expertise_tags" id="wjm_expertise_tags" value="<?php echo esc_attr( $tags ); ?>" />
					<p class="description"><?php esc_html_e( 'Comma-separated subjects for reviewer matching.', 'wisdom-journal-manager' ); ?></p>
				</td>
			</tr>
		</table>
		<?php
	}

	public static function save_expertise_field( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		if ( isset( $_POST['wjm_expertise_tags'] ) ) {
			update_user_meta( $user_id, '_wjm_expertise_tags', sanitize_text_field( wp_unslash( $_POST['wjm_expertise_tags'] ) ) );
		}
	}

	/**
	 * After paper save from submit: email co-authors with confirm tokens.
	 *
	 * @param int $paper_id Paper ID.
	 */
	public static function maybe_send_coauthor_confirms( $paper_id ) {
		$text = get_post_meta( $paper_id, '_sjm_authors_confirm_queue', true );
		if ( ! $text ) {
			return;
		}
		delete_post_meta( $paper_id, '_sjm_authors_confirm_queue' );
		$lines = array_filter( array_map( 'trim', explode( "\n", (string) $text ) ) );
		$pending = array();
		foreach ( $lines as $line ) {
			$parts = array_map( 'trim', explode( ';', $line ) );
			$name  = $parts[0] ?? '';
			$email = '';
			foreach ( $parts as $part ) {
				if ( is_email( $part ) ) {
					$email = $part;
					break;
				}
			}
			if ( ! $email ) {
				continue;
			}
			$token = wp_generate_password( 32, false, false );
			$pending[ $token ] = array(
				'email' => $email,
				'name'  => $name,
				'status'=> 'pending',
			);
			$link = add_query_arg(
				array(
					'wjm_coauthor' => $token,
					'paper'       => $paper_id,
				),
				home_url( '/' )
			);
			wp_mail(
				$email,
				sprintf( '[%s] Confirm co-authorship: %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), get_the_title( $paper_id ) ),
				sprintf( "Dear %s,\n\nPlease confirm you are a co-author of \"%s\":\n%s\n", $name ? $name : 'Colleague', get_the_title( $paper_id ), $link )
			);
		}
		if ( $pending ) {
			update_post_meta( $paper_id, '_sjm_coauthor_confirms', $pending );
		}
	}

	public static function maybe_coauthor_page() {
		if ( empty( $_GET['wjm_coauthor'] ) || empty( $_GET['paper'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$token    = sanitize_text_field( wp_unslash( $_GET['wjm_coauthor'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$paper_id = absint( $_GET['paper'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map      = get_post_meta( $paper_id, '_sjm_coauthor_confirms', true );
		if ( ! is_array( $map ) || empty( $map[ $token ] ) ) {
			return;
		}
		status_header( 200 );
		get_header();
		echo '<main class="wjm-shama" style="max-width:36rem;margin:2rem auto;padding:0 1rem;">';
		echo '<h1>' . esc_html__( 'Confirm co-authorship', 'wisdom-journal-manager' ) . '</h1>';
		echo '<p>' . esc_html( get_the_title( $paper_id ) ) . '</p>';
		if ( 'confirmed' === $map[ $token ]['status'] ) {
			echo '<p class="wjm-notice wjm-notice-success">' . esc_html__( 'Already confirmed. Thank you.', 'wisdom-journal-manager' ) . '</p>';
		} else {
			?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_coauthor_confirm" />
				<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
				<input type="hidden" name="paper_id" value="<?php echo esc_attr( $paper_id ); ?>" />
				<?php wp_nonce_field( 'wjm_coauthor_confirm_' . $token ); ?>
				<button type="submit" class="wjm-btn"><?php esc_html_e( 'I confirm I am a co-author', 'wisdom-journal-manager' ); ?></button>
			</form>
			<?php
		}
		echo '</main>';
		get_footer();
		exit;
	}

	public static function handle_coauthor_confirm() {
		$token    = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		check_admin_referer( 'wjm_coauthor_confirm_' . $token );
		$map = get_post_meta( $paper_id, '_sjm_coauthor_confirms', true );
		if ( is_array( $map ) && isset( $map[ $token ] ) ) {
			$map[ $token ]['status'] = 'confirmed';
			$map[ $token ]['at']     = current_time( 'mysql', true );
			update_post_meta( $paper_id, '_sjm_coauthor_confirms', $map );
			WJM_Audit::log( 'info', 'coauthor_confirmed', sprintf( 'Co-author confirmed for paper %d', $paper_id ), array( 'paper_id' => $paper_id ) );
		}
		wp_safe_redirect( add_query_arg( array( 'wjm_coauthor' => $token, 'paper' => $paper_id ), home_url( '/' ) ) );
		exit;
	}
}
