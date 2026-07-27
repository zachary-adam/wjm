<?php
/**
 * Peer review: assignments, blind review, structured recommendations.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Peer_Review {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_boxes' ) );
		add_action( 'admin_menu', array( __CLASS__, 'menus' ) );
		add_action( 'admin_post_wjm_assign_reviewer', array( __CLASS__, 'handle_assign' ) );
		add_action( 'admin_post_wjm_submit_review', array( __CLASS__, 'handle_submit_review' ) );
		add_action( 'admin_post_wjm_respond_invitation', array( __CLASS__, 'handle_invitation' ) );
	}

	public static function menus() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'My Reviews', 'wisdom-journal-manager' ),
			__( 'My Reviews', 'wisdom-journal-manager' ),
			'read',
			'wjm-my-reviews',
			array( __CLASS__, 'render_my_reviews' )
		);
	}

	public static function meta_boxes() {
		add_meta_box(
			'wjm_peer_review',
			__( 'Peer Review', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_editor_box' ),
			'sjm_paper',
			'normal',
			'high'
		);
	}

	/**
	 * Recommendations.
	 *
	 * @return array
	 */
	public static function recommendations() {
		return array(
			'accept'             => __( 'Accept', 'wisdom-journal-manager' ),
			'minor_revision'     => __( 'Minor Revision', 'wisdom-journal-manager' ),
			'major_revision'     => __( 'Major Revision', 'wisdom-journal-manager' ),
			'reject'             => __( 'Reject', 'wisdom-journal-manager' ),
			'reject_resubmit'    => __( 'Reject & Resubmit', 'wisdom-journal-manager' ),
		);
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function get_assignments( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'assignments' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY created_at DESC",
				absint( $paper_id )
			)
		);
	}

	/**
	 * @param int $user_id Reviewer user ID.
	 * @return object[]
	 */
	public static function get_assignments_for_user( $user_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'assignments' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE reviewer_user_id = %d ORDER BY created_at DESC",
				absint( $user_id )
			)
		);
	}

	/**
	 * Assign a reviewer (double-blind by default).
	 *
	 * @param int    $paper_id   Paper ID.
	 * @param int    $reviewer_id User ID.
	 * @param string $due_date   Y-m-d.
	 * @param string $blind_type single|double|open.
	 * @return int|WP_Error Assignment ID.
	 */
	public static function assign( $paper_id, $reviewer_id, $due_date = '', $blind_type = 'double' ) {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'wjm_forbidden', __( 'Only editors can assign reviewers.', 'wisdom-journal-manager' ) );
		}

		$paper_id    = absint( $paper_id );
		$reviewer_id = absint( $reviewer_id );
		if ( ! $paper_id || ! $reviewer_id || ! get_userdata( $reviewer_id ) ) {
			return new WP_Error( 'wjm_bad_args', __( 'Invalid paper or reviewer.', 'wisdom-journal-manager' ) );
		}

		// Blind integrity: reviewer cannot be paper author.
		if ( (int) get_post_field( 'post_author', $paper_id ) === $reviewer_id ) {
			return new WP_Error( 'wjm_conflict', __( 'Author cannot review their own paper.', 'wisdom-journal-manager' ) );
		}

		global $wpdb;
		$table = WJM_Database_Schema::table( 'assignments' );
		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE paper_id = %d AND reviewer_user_id = %d",
				$paper_id,
				$reviewer_id
			)
		);
		if ( $existing ) {
			return new WP_Error( 'wjm_exists', __( 'Reviewer already assigned.', 'wisdom-journal-manager' ) );
		}

		$wpdb->insert(
			$table,
			array(
				'paper_id'          => $paper_id,
				'reviewer_user_id'  => $reviewer_id,
				'assigned_by'       => get_current_user_id(),
				'status'            => 'invited',
				'due_date'          => $due_date ? sanitize_text_field( $due_date ) : null,
				'blind_type'        => in_array( $blind_type, array( 'single', 'double', 'open' ), true ) ? $blind_type : 'double',
				'created_at'        => current_time( 'mysql', true ),
			),
			array( '%d', '%d', '%d', '%s', '%s', '%s', '%s' )
		);

		$id = (int) $wpdb->insert_id;

		$status = WJM_Workflow::get_status( $paper_id );
		if ( in_array( $status, array( 'submitted', 'screening', 'resubmitted' ), true ) ) {
			WJM_Workflow::transition( $paper_id, 'under_review', __( 'Reviewer assigned', 'wisdom-journal-manager' ) );
		}

		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::send_template(
				$reviewer_id,
				'reviewer_invitation',
				$paper_id,
				array(
					'due_date' => $due_date,
				)
			);
		}

		WJM_Audit::log( 'info', 'reviewer_assigned', "Reviewer {$reviewer_id} assigned to paper {$paper_id}" );
		return $id;
	}

	/**
	 * Submit a structured review.
	 *
	 * @param int   $assignment_id Assignment ID.
	 * @param array $data          Review fields.
	 * @return true|WP_Error
	 */
	public static function submit_review( $assignment_id, $data ) {
		global $wpdb;
		$a_table = WJM_Database_Schema::table( 'assignments' );
		$r_table = WJM_Database_Schema::table( 'reviews' );

		$assignment = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$a_table} WHERE id = %d", absint( $assignment_id ) )
		);
		if ( ! $assignment ) {
			return new WP_Error( 'wjm_missing', __( 'Assignment not found.', 'wisdom-journal-manager' ) );
		}

		if ( (int) $assignment->reviewer_user_id !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'wjm_forbidden', __( 'Not your assignment.', 'wisdom-journal-manager' ) );
		}

		if ( ! in_array( $assignment->status, array( 'invited', 'accepted', 'in_progress' ), true ) ) {
			return new WP_Error( 'wjm_closed', __( 'Assignment is closed.', 'wisdom-journal-manager' ) );
		}

		$rec = isset( $data['recommendation'] ) ? sanitize_key( $data['recommendation'] ) : '';
		if ( ! isset( self::recommendations()[ $rec ] ) ) {
			return new WP_Error( 'wjm_rec', __( 'Invalid recommendation.', 'wisdom-journal-manager' ) );
		}

		$wpdb->insert(
			$r_table,
			array(
				'assignment_id'     => (int) $assignment->id,
				'paper_id'          => (int) $assignment->paper_id,
				'reviewer_user_id'  => (int) $assignment->reviewer_user_id,
				'recommendation'    => $rec,
				'score'             => isset( $data['score'] ) ? min( 10, max( 1, absint( $data['score'] ) ) ) : null,
				'comments_editor'   => sanitize_textarea_field( $data['comments_editor'] ?? '' ),
				'comments_author'   => sanitize_textarea_field( $data['comments_author'] ?? '' ),
				'is_blind'          => 'open' === $assignment->blind_type ? 0 : 1,
				'submitted_at'      => current_time( 'mysql', true ),
			),
			array( '%d', '%d', '%d', '%s', '%d', '%s', '%s', '%d', '%s' )
		);

		$wpdb->update(
			$a_table,
			array( 'status' => 'completed' ),
			array( 'id' => (int) $assignment->id ),
			array( '%s' ),
			array( '%d' )
		);

		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::notify_editors( $assignment->paper_id, 'review_submitted', array( 'recommendation' => $rec ) );
		}

		return true;
	}

	public static function render_editor_box( $post ) {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			echo '<p>' . esc_html__( 'Editor access required to manage peer review.', 'wisdom-journal-manager' ) . '</p>';
			return;
		}

		$assignments = self::get_assignments( $post->ID );
		$users       = get_users(
			array(
				'role__in' => array( 'sjm_researcher', 'sjm_editor', 'sjm_reviewer', 'administrator' ),
				'orderby'  => 'display_name',
				'number'   => 200,
			)
		);
		$reviews = self::get_reviews_for_paper( $post->ID );
		?>
		<div class="wjm-peer-review-admin">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wjm-assign-form">
				<input type="hidden" name="action" value="wjm_assign_reviewer" />
				<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
				<?php wp_nonce_field( 'wjm_assign_reviewer' ); ?>
				<p>
					<label><strong><?php esc_html_e( 'Assign reviewer', 'wisdom-journal-manager' ); ?></strong></label><br />
					<select name="reviewer_user_id" required>
						<option value=""><?php esc_html_e( '— Select user —', 'wisdom-journal-manager' ); ?></option>
						<?php foreach ( $users as $user ) : ?>
							<option value="<?php echo esc_attr( $user->ID ); ?>"><?php echo esc_html( $user->display_name . ' (' . $user->user_email . ')' ); ?></option>
						<?php endforeach; ?>
					</select>
					<input type="date" name="due_date" />
					<select name="blind_type">
						<option value="double"><?php esc_html_e( 'Double-blind', 'wisdom-journal-manager' ); ?></option>
						<option value="single"><?php esc_html_e( 'Single-blind', 'wisdom-journal-manager' ); ?></option>
						<option value="open"><?php esc_html_e( 'Open', 'wisdom-journal-manager' ); ?></option>
					</select>
					<?php submit_button( __( 'Invite', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
				</p>
			</form>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Reviewer', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Blind', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Due', 'wisdom-journal-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( ! $assignments ) : ?>
					<tr><td colspan="4"><?php esc_html_e( 'No reviewers assigned yet.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $assignments as $a ) : ?>
						<?php $u = get_userdata( $a->reviewer_user_id ); ?>
						<tr>
							<td><?php echo esc_html( $u ? $u->display_name : '#' . $a->reviewer_user_id ); ?></td>
							<td><?php echo esc_html( $a->status ); ?></td>
							<td><?php echo esc_html( $a->blind_type ); ?></td>
							<td><?php echo esc_html( $a->due_date ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>

			<?php if ( $reviews ) : ?>
				<h3><?php esc_html_e( 'Submitted reviews', 'wisdom-journal-manager' ); ?></h3>
				<?php foreach ( $reviews as $review ) : ?>
					<div class="wjm-review-card">
						<p>
							<strong><?php echo esc_html( self::recommendations()[ $review->recommendation ] ?? $review->recommendation ); ?></strong>
							<?php if ( $review->score ) : ?>
								— <?php echo esc_html( sprintf( __( 'Score: %d/10', 'wisdom-journal-manager' ), (int) $review->score ) ); ?>
							<?php endif; ?>
							<?php if ( ! $review->is_blind ) : ?>
								— <?php echo esc_html( get_the_author_meta( 'display_name', $review->reviewer_user_id ) ); ?>
							<?php else : ?>
								— <em><?php esc_html_e( 'Blind reviewer', 'wisdom-journal-manager' ); ?></em>
							<?php endif; ?>
						</p>
						<?php if ( $review->comments_editor ) : ?>
							<p><strong><?php esc_html_e( 'To editor:', 'wisdom-journal-manager' ); ?></strong> <?php echo esc_html( $review->comments_editor ); ?></p>
						<?php endif; ?>
						<?php if ( $review->comments_author ) : ?>
							<p><strong><?php esc_html_e( 'To author:', 'wisdom-journal-manager' ); ?></strong> <?php echo esc_html( $review->comments_author ); ?></p>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function get_reviews_for_paper( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'reviews' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY submitted_at DESC",
				absint( $paper_id )
			)
		);
	}

	/**
	 * Author-safe comments (no reviewer identity for blind).
	 *
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function get_author_visible_reviews( $paper_id ) {
		$reviews = self::get_reviews_for_paper( $paper_id );
		foreach ( $reviews as $review ) {
			if ( $review->is_blind ) {
				$review->reviewer_user_id = 0;
				$review->comments_editor  = '';
			}
		}
		return $reviews;
	}

	public static function render_my_reviews() {
		$assignments = self::get_assignments_for_user( get_current_user_id() );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'My Reviews', 'wisdom-journal-manager' ); ?></h1>
			<?php if ( ! $assignments ) : ?>
				<p><?php esc_html_e( 'You have no review invitations.', 'wisdom-journal-manager' ); ?></p>
			<?php endif; ?>
			<?php foreach ( $assignments as $a ) : ?>
				<?php
				$paper = get_post( $a->paper_id );
				if ( ! $paper ) {
					continue;
				}
				$hide_authors = in_array( $a->blind_type, array( 'single', 'double' ), true );
				?>
				<div class="wjm-review-panel">
					<h2>
						<?php echo esc_html( $paper->post_title ); ?>
						<small>(<?php echo esc_html( $a->status ); ?>)</small>
					</h2>
					<?php if ( ! $hide_authors ) : ?>
						<p><?php esc_html_e( 'Authors visible (open review).', 'wisdom-journal-manager' ); ?></p>
					<?php else : ?>
						<p><em><?php esc_html_e( 'Blind review — author identity hidden.', 'wisdom-journal-manager' ); ?></em></p>
					<?php endif; ?>
					<p><?php echo esc_html( wp_trim_words( get_post_meta( $paper->ID, '_sjm_abstract', true ), 60 ) ); ?></p>
					<?php
					$files = WJM_Submissions::get_files( $paper->ID );
					if ( $files ) :
						?>
						<p><strong><?php esc_html_e( 'Manuscript files', 'wisdom-journal-manager' ); ?></strong></p>
						<ul>
							<?php foreach ( $files as $file ) : ?>
								<?php $url = wp_get_attachment_url( $file->attachment_id ); ?>
								<?php if ( $url ) : ?>
									<li><a href="<?php echo esc_url( $url ); ?>" target="_blank" rel="noopener"><?php echo esc_html( $file->file_role . ( $file->version_label ? ' (' . $file->version_label . ')' : '' ) ); ?></a></li>
								<?php endif; ?>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>

					<?php if ( 'invited' === $a->status ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
							<input type="hidden" name="action" value="wjm_respond_invitation" />
							<input type="hidden" name="assignment_id" value="<?php echo esc_attr( $a->id ); ?>" />
							<input type="hidden" name="response" value="accepted" />
							<?php wp_nonce_field( 'wjm_respond_invitation' ); ?>
							<?php submit_button( __( 'Accept invitation', 'wisdom-journal-manager' ), 'primary', 'submit', false ); ?>
						</form>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
							<input type="hidden" name="action" value="wjm_respond_invitation" />
							<input type="hidden" name="assignment_id" value="<?php echo esc_attr( $a->id ); ?>" />
							<input type="hidden" name="response" value="declined" />
							<?php wp_nonce_field( 'wjm_respond_invitation' ); ?>
							<?php submit_button( __( 'Decline', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
						</form>
					<?php elseif ( in_array( $a->status, array( 'accepted', 'in_progress' ), true ) ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<input type="hidden" name="action" value="wjm_submit_review" />
							<input type="hidden" name="assignment_id" value="<?php echo esc_attr( $a->id ); ?>" />
							<?php wp_nonce_field( 'wjm_submit_review' ); ?>
							<table class="form-table">
								<tr>
									<th><?php esc_html_e( 'Recommendation', 'wisdom-journal-manager' ); ?></th>
									<td>
										<select name="recommendation" required>
											<?php foreach ( self::recommendations() as $key => $label ) : ?>
												<option value="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label ); ?></option>
											<?php endforeach; ?>
										</select>
									</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Score (1–10)', 'wisdom-journal-manager' ); ?></th>
									<td><input type="number" name="score" min="1" max="10" value="7" /></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Comments to editor', 'wisdom-journal-manager' ); ?></th>
									<td><textarea name="comments_editor" class="large-text" rows="4"></textarea></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Comments to author', 'wisdom-journal-manager' ); ?></th>
									<td><textarea name="comments_author" class="large-text" rows="5" required></textarea></td>
								</tr>
							</table>
							<?php submit_button( __( 'Submit review', 'wisdom-journal-manager' ) ); ?>
						</form>
					<?php else : ?>
						<p><?php esc_html_e( 'This assignment is closed.', 'wisdom-journal-manager' ); ?></p>
					<?php endif; ?>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	public static function handle_assign() {
		check_admin_referer( 'wjm_assign_reviewer' );
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		$result   = self::assign(
			$paper_id,
			isset( $_POST['reviewer_user_id'] ) ? absint( $_POST['reviewer_user_id'] ) : 0,
			isset( $_POST['due_date'] ) ? sanitize_text_field( wp_unslash( $_POST['due_date'] ) ) : '',
			isset( $_POST['blind_type'] ) ? sanitize_key( wp_unslash( $_POST['blind_type'] ) ) : 'double'
		);
		$args = is_wp_error( $result ) ? array( 'wjm_err' => rawurlencode( $result->get_error_message() ) ) : array( 'wjm_reviewer' => 1 );
		wp_safe_redirect( add_query_arg( $args, get_edit_post_link( $paper_id, 'raw' ) ) );
		exit;
	}

	public static function handle_submit_review() {
		check_admin_referer( 'wjm_submit_review' );
		$id     = isset( $_POST['assignment_id'] ) ? absint( $_POST['assignment_id'] ) : 0;
		$result = self::submit_review( $id, wp_unslash( $_POST ) );
		$url    = admin_url( 'admin.php?page=wjm-my-reviews' );
		if ( is_wp_error( $result ) ) {
			$url = add_query_arg( 'wjm_err', rawurlencode( $result->get_error_message() ), $url );
		} else {
			$url = add_query_arg( 'wjm_ok', '1', $url );
		}
		wp_safe_redirect( $url );
		exit;
	}

	public static function handle_invitation() {
		check_admin_referer( 'wjm_respond_invitation' );
		global $wpdb;
		$id       = isset( $_POST['assignment_id'] ) ? absint( $_POST['assignment_id'] ) : 0;
		$response = isset( $_POST['response'] ) ? sanitize_key( wp_unslash( $_POST['response'] ) ) : '';
		$table    = WJM_Database_Schema::table( 'assignments' );
		$row      = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ) );

		if ( $row && (int) $row->reviewer_user_id === get_current_user_id() && in_array( $response, array( 'accepted', 'declined' ), true ) ) {
			$wpdb->update(
				$table,
				array( 'status' => $response ),
				array( 'id' => $id ),
				array( '%s' ),
				array( '%d' )
			);
		}

		wp_safe_redirect( admin_url( 'admin.php?page=wjm-my-reviews' ) );
		exit;
	}
}
