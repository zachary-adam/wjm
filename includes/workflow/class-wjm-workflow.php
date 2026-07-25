<?php
/**
 * Editorial workflow state machine for papers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Workflow {

	const META_STATUS = '_sjm_workflow_status';

	/**
	 * Ordered editorial statuses.
	 *
	 * @return array
	 */
	public static function statuses() {
		return array(
			'draft'            => __( 'Draft', 'wisdom-journal-manager' ),
			'submitted'        => __( 'Submitted', 'wisdom-journal-manager' ),
			'screening'        => __( 'Desk Screening', 'wisdom-journal-manager' ),
			'under_review'     => __( 'Under Review', 'wisdom-journal-manager' ),
			'revision'         => __( 'Revision Requested', 'wisdom-journal-manager' ),
			'resubmitted'      => __( 'Resubmitted', 'wisdom-journal-manager' ),
			'accepted'         => __( 'Accepted', 'wisdom-journal-manager' ),
			'copyediting'      => __( 'Copyediting', 'wisdom-journal-manager' ),
			'production'       => __( 'Production', 'wisdom-journal-manager' ),
			'published'        => __( 'Published', 'wisdom-journal-manager' ),
			'desk_reject'      => __( 'Desk Rejected', 'wisdom-journal-manager' ),
			'rejected'         => __( 'Rejected', 'wisdom-journal-manager' ),
			'withdrawn'        => __( 'Withdrawn', 'wisdom-journal-manager' ),
		);
	}

	/**
	 * Allowed transitions: from => to[].
	 *
	 * @return array
	 */
	public static function transitions() {
		return array(
			'draft'        => array( 'submitted', 'withdrawn' ),
			'submitted'    => array( 'screening', 'under_review', 'desk_reject', 'withdrawn' ),
			'screening'    => array( 'under_review', 'desk_reject', 'withdrawn' ),
			'under_review' => array( 'revision', 'accepted', 'rejected', 'under_review' ),
			'revision'     => array( 'resubmitted', 'withdrawn' ),
			'resubmitted'  => array( 'under_review', 'accepted', 'rejected' ),
			'accepted'     => array( 'copyediting', 'production', 'rejected' ),
			'copyediting'  => array( 'production' ),
			'production'   => array( 'published' ),
			'published'    => array(),
			'desk_reject'  => array( 'screening' ), // appeal upheld can reopen
			'rejected'     => array( 'under_review' ), // appeal upheld can reopen
			'withdrawn'    => array(),
		);
	}

	/**
	 * Simple happy-path buttons: status => [ to => label ].
	 *
	 * @param string $status Current status.
	 * @return array
	 */
	public static function simple_actions( $status ) {
		$map = array(
			'draft'        => array( 'submitted' => __( 'Submit for review', 'wisdom-journal-manager' ) ),
			'submitted'    => array(
				'under_review' => __( 'Send to peer review', 'wisdom-journal-manager' ),
				'desk_reject'  => __( 'Desk reject', 'wisdom-journal-manager' ),
			),
			'screening'    => array(
				'under_review' => __( 'Send to peer review', 'wisdom-journal-manager' ),
				'desk_reject'  => __( 'Desk reject', 'wisdom-journal-manager' ),
			),
			'under_review' => array(
				'accepted' => __( 'Accept', 'wisdom-journal-manager' ),
				'revision' => __( 'Ask for revision', 'wisdom-journal-manager' ),
				'rejected' => __( 'Reject', 'wisdom-journal-manager' ),
			),
			'revision'     => array( 'resubmitted' => __( 'Resubmit revision', 'wisdom-journal-manager' ) ),
			'resubmitted'  => array(
				'under_review' => __( 'Send back to review', 'wisdom-journal-manager' ),
				'accepted'     => __( 'Accept', 'wisdom-journal-manager' ),
			),
			'accepted'     => array( 'production' => __( 'Start production', 'wisdom-journal-manager' ) ),
			'copyediting'  => array( 'production' => __( 'To production', 'wisdom-journal-manager' ) ),
			'production'   => array( 'published' => __( 'Publish', 'wisdom-journal-manager' ) ),
		);
		return isset( $map[ $status ] ) ? $map[ $status ] : array();
	}

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'ensure_default_status' ), 5, 2 );
		add_action( 'wp_ajax_wjm_transition_status', array( __CLASS__, 'ajax_transition' ) );
		add_filter( 'manage_sjm_paper_posts_columns', array( __CLASS__, 'columns' ) );
		add_action( 'manage_sjm_paper_posts_custom_column', array( __CLASS__, 'column_content' ), 10, 2 );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return string
	 */
	public static function get_status( $paper_id ) {
		$status = get_post_meta( $paper_id, self::META_STATUS, true );
		return $status ? $status : 'draft';
	}

	/**
	 * @param int    $paper_id Paper ID.
	 * @param string $to       Target status.
	 * @param string $note     Optional note.
	 * @param string $extra    Optional JSON/extra (revision due date).
	 * @return true|WP_Error
	 */
	public static function transition( $paper_id, $to, $note = '', $extra = array() ) {
		$paper_id = absint( $paper_id );
		$to       = sanitize_key( $to );
		$from     = self::get_status( $paper_id );
		$allowed  = self::transitions();
		if ( ! is_array( $extra ) ) {
			$extra = array();
		}

		if ( ! isset( self::statuses()[ $to ] ) ) {
			return new WP_Error( 'wjm_bad_status', __( 'Unknown status.', 'wisdom-journal-manager' ) );
		}

		if ( $from === $to ) {
			return true;
		}

		if ( empty( $allowed[ $from ] ) || ! in_array( $to, $allowed[ $from ], true ) ) {
			return new WP_Error(
				'wjm_bad_transition',
				sprintf(
					/* translators: 1: from status, 2: to status */
					__( 'Cannot move from %1$s to %2$s.', 'wisdom-journal-manager' ),
					$from,
					$to
				)
			);
		}

		if ( ! current_user_can( 'edit_post', $paper_id ) && ! current_user_can( 'manage_options' ) ) {
			// Authors may submit/withdraw/resubmit their own papers.
			$author_ok = ( (int) get_post_field( 'post_author', $paper_id ) === get_current_user_id() )
				&& in_array( $to, array( 'submitted', 'resubmitted', 'withdrawn' ), true );
			if ( ! $author_ok ) {
				return new WP_Error( 'wjm_forbidden', __( 'Unauthorized transition.', 'wisdom-journal-manager' ) );
			}
		}

		update_post_meta( $paper_id, self::META_STATUS, $to );

		global $wpdb;
		$wpdb->insert(
			WJM_Database_Schema::table( 'workflow' ),
			array(
				'paper_id'    => $paper_id,
				'from_status' => $from,
				'to_status'   => $to,
				'user_id'     => get_current_user_id() ? get_current_user_id() : null,
				'note'        => sanitize_textarea_field( $note ),
				'created_at'  => current_time( 'mysql', true ),
			),
			array( '%d', '%s', '%s', '%d', '%s', '%s' )
		);

		if ( 'published' === $to && 'publish' !== get_post_status( $paper_id ) ) {
			wp_update_post(
				array(
					'ID'          => $paper_id,
					'post_status' => 'publish',
				)
			);
		}

		// Ahead-of-print: published without an issue → early view.
		if ( 'published' === $to ) {
			$issue_id = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
			if ( ! $issue_id ) {
				update_post_meta( $paper_id, '_sjm_early_view', '1' );
			}
		}

		/**
		 * Fires after a workflow status change.
		 *
		 * @param int    $paper_id Paper ID.
		 * @param string $from     Previous status.
		 * @param string $to       New status.
		 * @param string $note     Note.
		 */
		do_action( 'sjm_workflow_transition', $paper_id, $from, $to, $note );

		if ( 'revision' === $to && ! empty( $extra['revision_due'] ) ) {
			update_post_meta( $paper_id, '_sjm_revision_due', sanitize_text_field( $extra['revision_due'] ) );
		}

		WJM_Audit::log(
			'info',
			'workflow_transition',
			"Paper {$paper_id}: {$from} → {$to}",
			array(
				'paper_id' => $paper_id,
				'from'     => $from,
				'to'       => $to,
			)
		);

		if ( class_exists( 'WJM_Email' ) ) {
			// Decision letters (accept/revision/reject) are sent by WJM_Editorial_Trust.
			if ( ! in_array( $to, array( 'accepted', 'rejected', 'desk_reject', 'revision' ), true ) ) {
				WJM_Email::notify_transition( $paper_id, $from, $to, $note );
			}
		}

		return true;
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function history( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'workflow' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY created_at DESC LIMIT 100",
				absint( $paper_id )
			)
		);
	}

	public static function ensure_default_status( $post_id, $post ) {
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( ! get_post_meta( $post_id, self::META_STATUS, true ) ) {
			update_post_meta( $post_id, self::META_STATUS, 'draft' );
		}
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_workflow',
			__( 'Next step', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_meta_box' ),
			'sjm_paper',
			'side',
			'high'
		);
	}

	public static function render_meta_box( $post ) {
		$status   = self::get_status( $post->ID );
		$statuses = self::statuses();
		$next     = isset( self::transitions()[ $status ] ) ? self::transitions()[ $status ] : array();
		$simple   = self::simple_actions( $status );
		$history  = self::history( $post->ID );
		$can      = current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' ) || (int) $post->post_author === get_current_user_id();
		$round    = class_exists( 'WJM_Editorial_Trust' ) ? WJM_Editorial_Trust::get_round( $post->ID ) : 0;
		?>
		<p>
			<span class="wjm-status-badge wjm-status-<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $statuses[ $status ] ); ?></span>
			<?php if ( $round ) : ?>
				<span class="wjm-status-badge"><?php echo esc_html( 'R' . $round ); ?></span>
			<?php endif; ?>
		</p>
		<?php if ( $can && $simple ) : ?>
			<div class="wjm-flow-btns">
				<?php foreach ( $simple as $to => $label ) : ?>
					<?php
					$is_bad = in_array( $to, array( 'rejected', 'desk_reject', 'withdrawn' ), true );
					$class  = $is_bad ? 'button' : 'button button-primary';
					?>
					<button type="button" class="<?php echo esc_attr( $class ); ?> wjm-quick-transition" data-paper-id="<?php echo esc_attr( $post->ID ); ?>" data-to="<?php echo esc_attr( $to ); ?>">
						<?php echo esc_html( $label ); ?>
					</button>
				<?php endforeach; ?>
			</div>
			<p>
				<textarea id="wjm_transition_note" class="widefat" rows="4" placeholder="<?php esc_attr_e( 'Decision letter / note to author (required for accept, revision, desk reject, reject)', 'wisdom-journal-manager' ); ?>"></textarea>
			</p>
			<p>
				<label for="wjm_revision_due"><?php esc_html_e( 'Revision due (if asking revision)', 'wisdom-journal-manager' ); ?></label>
				<input type="date" id="wjm_revision_due" class="widefat" />
			</p>
		<?php endif; ?>
		<?php if ( $can && $next ) : ?>
			<details style="margin-top:0.75rem;">
				<summary><?php esc_html_e( 'More statuses', 'wisdom-journal-manager' ); ?></summary>
				<p>
					<select id="wjm_next_status" class="widefat">
						<?php foreach ( $next as $key ) : ?>
							<option value="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $statuses[ $key ] ); ?></option>
						<?php endforeach; ?>
					</select>
				</p>
				<p>
					<button type="button" class="button wjm-transition-btn" data-paper-id="<?php echo esc_attr( $post->ID ); ?>">
						<?php esc_html_e( 'Update status', 'wisdom-journal-manager' ); ?>
					</button>
				</p>
			</details>
		<?php endif; ?>
		<?php if ( $history ) : ?>
			<details style="margin-top:0.5rem;">
				<summary><?php esc_html_e( 'History', 'wisdom-journal-manager' ); ?></summary>
				<ul class="wjm-workflow-history">
					<?php foreach ( array_slice( $history, 0, 8 ) as $row ) : ?>
						<li>
							<code><?php echo esc_html( $row->from_status . ' → ' . $row->to_status ); ?></code>
							<br /><small><?php echo esc_html( $row->created_at ); ?></small>
						</li>
					<?php endforeach; ?>
				</ul>
			</details>
		<?php endif; ?>
		<?php
	}

	public static function ajax_transition() {
		check_ajax_referer( 'wjm_admin', 'nonce' );
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		$to       = isset( $_POST['to'] ) ? sanitize_key( wp_unslash( $_POST['to'] ) ) : '';
		$note     = isset( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : '';
		$extra    = array();
		if ( ! empty( $_POST['revision_due'] ) ) {
			$extra['revision_due'] = sanitize_text_field( wp_unslash( $_POST['revision_due'] ) );
		}

		$result = self::transition( $paper_id, $to, $note, $extra );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
		}

		wp_send_json_success(
			array(
				'status' => $to,
				'label'  => self::statuses()[ $to ],
			)
		);
	}

	public static function columns( $columns ) {
		$columns['wjm_status'] = __( 'Workflow', 'wisdom-journal-manager' );
		return $columns;
	}

	public static function column_content( $column, $post_id ) {
		if ( 'wjm_status' !== $column ) {
			return;
		}
		$status   = self::get_status( $post_id );
		$statuses = self::statuses();
		echo '<span class="wjm-status-badge wjm-status-' . esc_attr( $status ) . '">' . esc_html( isset( $statuses[ $status ] ) ? $statuses[ $status ] : $status ) . '</span>';
	}
}
