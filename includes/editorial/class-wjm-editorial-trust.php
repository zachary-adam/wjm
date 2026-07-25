<?php
/**
 * Editorial trust layer: decision letters, revision rounds, paper activity trail.
 * Keeps Basic calm — these are paper-level tools editors need for real journals.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Editorial_Trust {

	const META_ROUND          = '_sjm_revision_round';
	const META_LETTER         = '_sjm_decision_letter';
	const META_LETTER_TYPE    = '_sjm_decision_type';
	const META_LETTER_AT      = '_sjm_decision_at';
	const META_AUTHOR_RESPONSE = '_sjm_author_response';
	const OPT_TEMPLATES       = 'wjm_decision_templates';

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_boxes' ) );
		add_action( 'sjm_workflow_transition', array( __CLASS__, 'on_transition' ), 5, 4 );
		add_action( 'admin_post_wjm_save_decision_templates', array( __CLASS__, 'handle_save_templates' ) );
		add_action( 'admin_post_wjm_author_resubmit', array( __CLASS__, 'handle_author_resubmit' ) );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 56 );
	}

	/**
	 * @return array
	 */
	public static function default_templates() {
		return array(
			'accepted' => __( "Dear Author,\n\nWe are pleased to accept your manuscript \"{title}\" for publication, pending final production checks.\n\n{note}\n\nSincerely,\nThe Editorial Office", 'wisdom-journal-manager' ),
			'revision' => __( "Dear Author,\n\nThank you for submitting \"{title}\". After peer review we request a revision (round {round}).\n\nPlease address the comments below and resubmit with a point-by-point response.\n\n{note}\n\nSincerely,\nThe Editorial Office", 'wisdom-journal-manager' ),
			'rejected'    => __( "Dear Author,\n\nThank you for submitting \"{title}\". After careful consideration we are unable to accept this manuscript for publication.\n\n{note}\n\nSincerely,\nThe Editorial Office", 'wisdom-journal-manager' ),
			'desk_reject' => __( "Dear Author,\n\nThank you for submitting \"{title}\". After desk screening we are unable to send this manuscript for peer review.\n\n{note}\n\nSincerely,\nThe Editorial Office", 'wisdom-journal-manager' ),
		);
	}

	/**
	 * @return array
	 */
	public static function templates() {
		$stored = get_option( self::OPT_TEMPLATES, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::default_templates(), $stored );
	}

	/**
	 * @param string   $type           accepted|revision|rejected.
	 * @param int      $paper_id       Paper ID.
	 * @param string   $note           Editor note.
	 * @param int|null $round_override Force round number (after increment).
	 * @return string
	 */
	public static function render_letter( $type, $paper_id, $note = '', $round_override = null ) {
		$templates = self::templates();
		$body      = isset( $templates[ $type ] ) ? $templates[ $type ] : '';
		$current   = (int) get_post_meta( $paper_id, self::META_ROUND, true );
		if ( null !== $round_override ) {
			$round = max( 1, (int) $round_override );
		} elseif ( 'revision' === $type ) {
			$round = $current + 1;
		} else {
			$round = max( 1, $current );
		}
		$map = array(
			'{title}' => get_the_title( $paper_id ),
			'{note}'  => $note,
			'{round}' => (string) $round,
			'{site}'  => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
		);
		return strtr( $body, $map );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return int
	 */
	public static function get_round( $paper_id ) {
		return (int) get_post_meta( $paper_id, self::META_ROUND, true );
	}

	public static function on_transition( $paper_id, $from, $to, $note ) {
		$paper_id = absint( $paper_id );

		if ( 'revision' === $to ) {
			$round = self::get_round( $paper_id ) + 1;
			update_post_meta( $paper_id, self::META_ROUND, $round );
			WJM_Audit::log(
				'info',
				'revision_requested',
				sprintf( 'Revision round R%d requested for paper %d', $round, $paper_id ),
				array( 'paper_id' => $paper_id, 'round' => $round )
			);
		}

		if ( in_array( $to, array( 'accepted', 'rejected', 'desk_reject', 'revision' ), true ) ) {
			$letter_type = $to;
			$letter      = $note ? $note : self::render_letter( $letter_type, $paper_id, '', self::get_round( $paper_id ) );
			update_post_meta( $paper_id, self::META_LETTER, $letter );
			update_post_meta( $paper_id, self::META_LETTER_TYPE, $letter_type );
			update_post_meta( $paper_id, self::META_LETTER_AT, current_time( 'mysql', true ) );

			if ( class_exists( 'WJM_Email' ) ) {
				$author_id = (int) get_post_field( 'post_author', $paper_id );
				$extra     = array(
					'letter'      => $letter,
					'from_status' => $from,
					'to_status'   => $to,
					'note'        => $note,
					'round'       => (string) self::get_round( $paper_id ),
				);
				if ( $author_id ) {
					WJM_Email::send_template( $author_id, 'decision_letter', $paper_id, $extra );
				} else {
					$guest = get_post_meta( $paper_id, '_sjm_corresponding_email', true );
					if ( is_email( $guest ) ) {
						WJM_Email::send_template( 0, 'decision_letter', $paper_id, $extra, $guest );
					}
				}
			}
		}

		if ( 'resubmitted' === $to ) {
			WJM_Audit::log(
				'info',
				'revision_resubmitted',
				sprintf( 'Author resubmitted paper %d (R%d)', $paper_id, self::get_round( $paper_id ) ),
				array( 'paper_id' => $paper_id, 'round' => self::get_round( $paper_id ) )
			);
		}
	}

	public static function meta_boxes() {
		add_meta_box(
			'wjm_paper_activity',
			__( 'Activity trail', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_activity' ),
			'sjm_paper',
			'normal',
			'default'
		);
		add_meta_box(
			'wjm_decision_letter',
			__( 'Decision letter', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_decision_box' ),
			'sjm_paper',
			'normal',
			'high'
		);
	}

	public static function render_decision_box( $post ) {
		$can = current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' );
		$is_author = (int) $post->post_author === get_current_user_id();
		$status = WJM_Workflow::get_status( $post->ID );
		$round  = self::get_round( $post->ID );
		$letter = get_post_meta( $post->ID, self::META_LETTER, true );
		$response = get_post_meta( $post->ID, self::META_AUTHOR_RESPONSE, true );

		if ( $round ) {
			echo '<p><strong>' . esc_html( sprintf( /* translators: %d round */ __( 'Revision round: R%d', 'wisdom-journal-manager' ), $round ) ) . '</strong></p>';
		}
		$rev_due = get_post_meta( $post->ID, '_sjm_revision_due', true );
		if ( $rev_due && 'revision' === $status ) {
			echo '<p class="description">' . esc_html( sprintf( __( 'Author revision due: %s', 'wisdom-journal-manager' ), $rev_due ) ) . '</p>';
		}

		if ( $letter ) {
			$type = get_post_meta( $post->ID, self::META_LETTER_TYPE, true );
			$at   = get_post_meta( $post->ID, self::META_LETTER_AT, true );
			echo '<p class="description">' . esc_html( sprintf( __( 'Last decision (%1$s) · %2$s', 'wisdom-journal-manager' ), $type, $at ) ) . '</p>';
			echo '<div class="wjm-letter-preview" style="white-space:pre-wrap;border:1px solid #c3c4c7;padding:0.85rem;background:#fff;margin:0.5rem 0 1rem;">' . esc_html( $letter ) . '</div>';
		}

		if ( $can ) {
			$templates = self::templates();
			?>
			<p class="description"><?php esc_html_e( 'When you Accept / Ask for revision / Reject, the note field becomes the decision letter emailed to the author. Load a template first if helpful.', 'wisdom-journal-manager' ); ?></p>
			<p>
				<select id="wjm_letter_template">
					<option value=""><?php esc_html_e( '— Load template —', 'wisdom-journal-manager' ); ?></option>
					<option value="accepted"><?php esc_html_e( 'Accept letter', 'wisdom-journal-manager' ); ?></option>
					<option value="revision"><?php esc_html_e( 'Revision letter', 'wisdom-journal-manager' ); ?></option>
					<option value="desk_reject"><?php esc_html_e( 'Desk reject letter', 'wisdom-journal-manager' ); ?></option>
					<option value="rejected"><?php esc_html_e( 'Reject letter', 'wisdom-journal-manager' ); ?></option>
				</select>
				<button type="button" class="button" id="wjm_load_letter"><?php esc_html_e( 'Load into note', 'wisdom-journal-manager' ); ?></button>
			</p>
			<script type="application/json" id="wjm-letter-json"><?php echo wp_json_encode( array( 'accepted' => self::render_letter( 'accepted', $post->ID, '' ), 'revision' => self::render_letter( 'revision', $post->ID, '' ), 'desk_reject' => self::render_letter( 'desk_reject', $post->ID, '' ), 'rejected' => self::render_letter( 'rejected', $post->ID, '' ) ) ); ?></script>
			<?php
			unset( $templates );
		}

		if ( $response ) {
			echo '<h4>' . esc_html__( 'Author response (latest)', 'wisdom-journal-manager' ) . '</h4>';
			echo '<div style="white-space:pre-wrap;border:1px solid #c3c4c7;padding:0.85rem;background:#f6f7f7;">' . esc_html( $response ) . '</div>';
		}

		if ( $is_author && 'revision' === $status ) {
			?>
			<hr />
			<h4><?php echo esc_html( sprintf( __( 'Resubmit revision R%d', 'wisdom-journal-manager' ), max( 1, $round ) ) ); ?></h4>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
				<input type="hidden" name="action" value="wjm_author_resubmit" />
				<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
				<?php wp_nonce_field( 'wjm_author_resubmit_' . $post->ID ); ?>
				<p>
					<label><?php esc_html_e( 'Point-by-point response', 'wisdom-journal-manager' ); ?></label>
					<textarea name="author_response" class="widefat" rows="5" required></textarea>
				</p>
				<p>
					<label><?php esc_html_e( 'Revised manuscript (optional)', 'wisdom-journal-manager' ); ?></label>
					<input type="file" name="revised_manuscript" accept=".pdf,.doc,.docx" />
				</p>
				<?php submit_button( __( 'Resubmit revision', 'wisdom-journal-manager' ), 'primary', 'submit', false ); ?>
			</form>
			<?php
		}
	}

	public static function render_activity( $post ) {
		if ( ! current_user_can( 'edit_post', $post->ID ) && ! current_user_can( 'manage_options' ) ) {
			echo '<p>' . esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) . '</p>';
			return;
		}

		$workflow = WJM_Workflow::history( $post->ID );
		$emails   = self::emails_for_paper( $post->ID );
		$audit    = WJM_Audit::for_paper( $post->ID, 40 );
		?>
		<div class="wjm-activity-trail">
			<h4><?php esc_html_e( 'Workflow', 'wisdom-journal-manager' ); ?></h4>
			<ul class="wjm-workflow-history">
				<?php if ( ! $workflow ) : ?>
					<li><?php esc_html_e( 'No status changes yet.', 'wisdom-journal-manager' ); ?></li>
				<?php else : ?>
					<?php foreach ( $workflow as $row ) : ?>
						<li>
							<strong><?php echo esc_html( $row->from_status . ' → ' . $row->to_status ); ?></strong>
							· <small><?php echo esc_html( $row->created_at ); ?></small>
							<?php if ( $row->note ) : ?>
								<br /><span class="description"><?php echo esc_html( wp_trim_words( $row->note, 40 ) ); ?></span>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>

			<h4><?php esc_html_e( 'Emails', 'wisdom-journal-manager' ); ?></h4>
			<ul>
				<?php if ( ! $emails ) : ?>
					<li><?php esc_html_e( 'No emails logged for this paper.', 'wisdom-journal-manager' ); ?></li>
				<?php else : ?>
					<?php foreach ( $emails as $mail ) : ?>
						<li>
							<code><?php echo esc_html( $mail->template_key ); ?></code>
							→ <?php echo esc_html( $mail->to_email ); ?>
							· <?php echo esc_html( $mail->status ); ?>
							· <small><?php echo esc_html( $mail->created_at ); ?></small>
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>

			<h4><?php esc_html_e( 'Audit', 'wisdom-journal-manager' ); ?></h4>
			<ul>
				<?php if ( ! $audit ) : ?>
					<li><?php esc_html_e( 'No audit events for this paper.', 'wisdom-journal-manager' ); ?></li>
				<?php else : ?>
					<?php foreach ( $audit as $ev ) : ?>
						<li>
							<span class="wjm-status-badge"><?php echo esc_html( $ev->event_type ); ?></span>
							<?php echo esc_html( $ev->message ); ?>
							· <small><?php echo esc_html( $ev->created_at ); ?></small>
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
		</div>
		<?php
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function emails_for_paper( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'email_log' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY created_at DESC LIMIT 40",
				absint( $paper_id )
			)
		);
	}

	public static function handle_author_resubmit() {
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		check_admin_referer( 'wjm_author_resubmit_' . $paper_id );

		if ( (int) get_post_field( 'post_author', $paper_id ) !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		if ( 'revision' !== WJM_Workflow::get_status( $paper_id ) ) {
			wp_die( esc_html__( 'Paper is not awaiting revision.', 'wisdom-journal-manager' ) );
		}

		$response = isset( $_POST['author_response'] ) ? sanitize_textarea_field( wp_unslash( $_POST['author_response'] ) ) : '';
		if ( ! $response ) {
			wp_die( esc_html__( 'Response letter is required.', 'wisdom-journal-manager' ) );
		}
		update_post_meta( $paper_id, self::META_AUTHOR_RESPONSE, $response );

		if ( ! empty( $_FILES['revised_manuscript']['name'] ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			require_once ABSPATH . 'wp-admin/includes/media.php';
			require_once ABSPATH . 'wp-admin/includes/image.php';
			$att = media_handle_upload( 'revised_manuscript', $paper_id );
			if ( ! is_wp_error( $att ) && class_exists( 'WJM_Submissions' ) ) {
				$round = max( 1, self::get_round( $paper_id ) );
				WJM_Submissions::attach_file( $paper_id, $att, 'revision', 'R' . $round );
			}
		}

		$result = WJM_Workflow::transition( $paper_id, 'resubmitted', $response );
		if ( is_wp_error( $result ) ) {
			wp_die( esc_html( $result->get_error_message() ) );
		}

		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::notify_editors( $paper_id, 'revision_resubmitted', array( 'note' => $response ) );
		}

		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Decision letters', 'wisdom-journal-manager' ),
			__( 'Decision letters', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-decision-letters',
			array( __CLASS__, 'render_templates_page' )
		);
	}

	public static function render_templates_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$t = self::templates();
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Templates saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'Decision letter templates', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Used when Accept / Ask for revision / Desk reject / Reject. Tokens: {title} {note} {round} {site}', 'wisdom-journal-manager' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_decision_templates" />
				<?php wp_nonce_field( 'wjm_save_decision_templates' ); ?>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Accept', 'wisdom-journal-manager' ); ?></th>
						<td><textarea name="accepted" class="large-text" rows="8"><?php echo esc_textarea( $t['accepted'] ); ?></textarea></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Revision', 'wisdom-journal-manager' ); ?></th>
						<td><textarea name="revision" class="large-text" rows="8"><?php echo esc_textarea( $t['revision'] ); ?></textarea></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Desk reject', 'wisdom-journal-manager' ); ?></th>
						<td><textarea name="desk_reject" class="large-text" rows="8"><?php echo esc_textarea( isset( $t['desk_reject'] ) ? $t['desk_reject'] : '' ); ?></textarea></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Reject (after review)', 'wisdom-journal-manager' ); ?></th>
						<td><textarea name="rejected" class="large-text" rows="8"><?php echo esc_textarea( $t['rejected'] ); ?></textarea></td>
					</tr>
				</table>
				<?php submit_button( __( 'Save templates', 'wisdom-journal-manager' ) ); ?>
			</form>
		</div>
		<?php
	}

	public static function handle_save_templates() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_decision_templates' );
		update_option(
			self::OPT_TEMPLATES,
			array(
				'accepted'    => isset( $_POST['accepted'] ) ? sanitize_textarea_field( wp_unslash( $_POST['accepted'] ) ) : '',
				'revision'    => isset( $_POST['revision'] ) ? sanitize_textarea_field( wp_unslash( $_POST['revision'] ) ) : '',
				'desk_reject' => isset( $_POST['desk_reject'] ) ? sanitize_textarea_field( wp_unslash( $_POST['desk_reject'] ) ) : '',
				'rejected'    => isset( $_POST['rejected'] ) ? sanitize_textarea_field( wp_unslash( $_POST['rejected'] ) ) : '',
			)
		);
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-decision-letters&saved=1' ) );
		exit;
	}
}
