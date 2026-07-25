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
		add_action( 'admin_post_nopriv_wjm_invite_respond', array( __CLASS__, 'handle_token_respond' ) );
		add_action( 'admin_post_wjm_invite_respond', array( __CLASS__, 'handle_token_respond' ) );
		add_action( 'admin_post_wjm_reviewer_file', array( __CLASS__, 'handle_reviewer_file' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_render_invite_page' ) );
		add_action( 'init', array( __CLASS__, 'schedule_reminders' ) );
		add_action( 'wjm_reviewer_reminders', array( __CLASS__, 'run_reminders' ) );
	}

	/**
	 * Blind-safe manuscript URL for an assignment (gated download).
	 *
	 * @param object $assignment Assignment row.
	 * @param object $file       File row.
	 * @return string
	 */
	public static function reviewer_file_url( $assignment, $file ) {
		return wp_nonce_url(
			admin_url(
				'admin-post.php?action=wjm_reviewer_file&assignment_id=' . absint( $assignment->id ) . '&file_id=' . absint( $file->id )
			),
			'wjm_reviewer_file_' . absint( $assignment->id ) . '_' . absint( $file->id )
		);
	}

	/**
	 * Serve manuscript only to the assigned reviewer; hide cover letters in double-blind.
	 */
	public static function handle_reviewer_file() {
		$assignment_id = isset( $_GET['assignment_id'] ) ? absint( $_GET['assignment_id'] ) : 0;
		$file_id       = isset( $_GET['file_id'] ) ? absint( $_GET['file_id'] ) : 0;
		check_admin_referer( 'wjm_reviewer_file_' . $assignment_id . '_' . $file_id );

		if ( ! is_user_logged_in() ) {
			auth_redirect();
		}

		global $wpdb;
		$assignment = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . WJM_Database_Schema::table( 'assignments' ) . ' WHERE id = %d',
				$assignment_id
			)
		);
		if ( ! $assignment || (int) $assignment->reviewer_id !== get_current_user_id() ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ), 403 );
		}
		if ( ! in_array( $assignment->status, array( 'invited', 'accepted', 'in_progress', 'completed' ), true ) ) {
			wp_die( esc_html__( 'Assignment closed.', 'wisdom-journal-manager' ), 403 );
		}

		$file = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . WJM_Database_Schema::table( 'manuscripts' ) . ' WHERE id = %d AND paper_id = %d',
				$file_id,
				(int) $assignment->paper_id
			)
		);
		if ( ! $file ) {
			wp_die( esc_html__( 'File not found.', 'wisdom-journal-manager' ), 404 );
		}

		// Double-blind: do not serve cover letters / title pages / author identity packs.
		if ( 'double' === $assignment->blind_type && in_array( $file->file_role, array( 'cover_letter', 'author_identity', 'title_page' ), true ) ) {
			wp_die( esc_html__( 'This file is withheld for double-blind review.', 'wisdom-journal-manager' ), 403 );
		}
		if ( 'double' === $assignment->blind_type && 'manuscript' === $file->file_role ) {
			$anon = $wpdb->get_var(
				$wpdb->prepare(
					'SELECT id FROM ' . WJM_Database_Schema::table( 'manuscripts' ) . ' WHERE paper_id = %d AND file_role = %s LIMIT 1',
					(int) $assignment->paper_id,
					'anonymized_manuscript'
				)
			);
			if ( $anon ) {
				wp_die( esc_html__( 'Use the anonymized manuscript for this review.', 'wisdom-journal-manager' ), 403 );
			}
		}

		$path = get_attached_file( (int) $file->attachment_id );
		$url  = wp_get_attachment_url( (int) $file->attachment_id );
		if ( $path && file_exists( $path ) ) {
			$mime = get_post_mime_type( (int) $file->attachment_id );
			nocache_headers();
			header( 'Content-Type: ' . ( $mime ? $mime : 'application/octet-stream' ) );
			header( 'Content-Disposition: inline; filename="' . basename( $path ) . '"' );
			header( 'X-WJM-Blind: ' . sanitize_key( $assignment->blind_type ) );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
			readfile( $path );
			exit;
		}
		if ( $url ) {
			wp_safe_redirect( $url );
			exit;
		}
		wp_die( esc_html__( 'File not available.', 'wisdom-journal-manager' ), 404 );
	}

	public static function schedule_reminders() {
		if ( ! wp_next_scheduled( 'wjm_reviewer_reminders' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'wjm_reviewer_reminders' );
		}
	}

	/**
	 * Daily: remind invited/accepted reviewers 3 days before due and when overdue.
	 */
	public static function run_reminders() {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'assignments' );
		$rows  = $wpdb->get_results(
			"SELECT * FROM {$table} WHERE status IN ('invited','accepted','in_progress') AND due_date IS NOT NULL AND due_date != ''"
		);
		if ( ! $rows ) {
			return;
		}
		$today = gmdate( 'Y-m-d' );
		foreach ( $rows as $row ) {
			$due = $row->due_date;
			$diff = (int) ( ( strtotime( $due . ' UTC' ) - strtotime( $today . ' UTC' ) ) / DAY_IN_SECONDS );
			$bucket = '';
			if ( 0 === $diff || 3 === $diff ) {
				$bucket = ( 3 === $diff ) ? 'before' : 'due_today';
			} elseif ( $diff < 0 && in_array( abs( $diff ), array( 1, 3, 7 ), true ) ) {
				$bucket = 'overdue';
			}
			if ( ! $bucket ) {
				continue;
			}
			$flag_key = '_wjm_remind_' . $row->id . '_' . $bucket . '_' . $due;
			if ( get_option( $flag_key ) ) {
				continue;
			}
			$invite = ! empty( $row->invite_token )
				? add_query_arg( 'wjm_invite', $row->invite_token, home_url( '/' ) )
				: admin_url( 'edit.php?post_type=sjm_journal&page=wjm-my-reviews' );
			$note = 'before' === $bucket ? __( 'due in 3 days', 'wisdom-journal-manager' ) : ( 'due_today' === $bucket ? __( 'due today', 'wisdom-journal-manager' ) : __( 'overdue', 'wisdom-journal-manager' ) );
			if ( class_exists( 'WJM_Email' ) ) {
				WJM_Email::send_template(
					(int) $row->reviewer_user_id,
					'reviewer_reminder',
					(int) $row->paper_id,
					array(
						'due_date'    => $due,
						'invite_link' => $invite,
						'note'        => $note,
					)
				);
			}
			update_option( $flag_key, current_time( 'mysql', true ), false );
			WJM_Audit::log(
				'info',
				'reviewer_reminded',
				sprintf( 'Reminded reviewer %d for paper %d (%s)', (int) $row->reviewer_user_id, (int) $row->paper_id, $bucket ),
				array(
					'paper_id'      => (int) $row->paper_id,
					'assignment_id' => (int) $row->id,
				)
			);
		}
	}

	/**
	 * COI warnings (soft — never blocks assign).
	 *
	 * @param int $paper_id    Paper ID.
	 * @param int $reviewer_id User ID.
	 * @return string[]
	 */
	public static function coi_warnings( $paper_id, $reviewer_id ) {
		$warnings = array();
		$reviewer = get_userdata( $reviewer_id );
		if ( ! $reviewer ) {
			return $warnings;
		}
		$author_id = (int) get_post_field( 'post_author', $paper_id );
		if ( $author_id === $reviewer_id ) {
			$warnings[] = __( 'Reviewer is the submitting WordPress author.', 'wisdom-journal-manager' );
		}
		$corr = strtolower( (string) get_post_meta( $paper_id, '_sjm_corresponding_email', true ) );
		if ( $corr && strtolower( $reviewer->user_email ) === $corr ) {
			$warnings[] = __( 'Reviewer email matches corresponding author email.', 'wisdom-journal-manager' );
		}
		$suggested = strtolower( (string) get_post_meta( $paper_id, '_sjm_suggested_reviewers', true ) );
		if ( $suggested && false !== strpos( $suggested, strtolower( $reviewer->user_email ) ) ) {
			$warnings[] = __( 'Reviewer appears in author-suggested reviewers list.', 'wisdom-journal-manager' );
		}
		if ( class_exists( 'WJM_Author_Profiles' ) ) {
			$authors = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
			$rev_aff = '';
			// Best-effort: match display name fragments against author names.
			foreach ( $authors as $a ) {
				$full = strtolower( trim( $a->first_name . ' ' . $a->last_name ) );
				if ( $full && false !== stripos( $reviewer->display_name, $a->last_name ) ) {
					$warnings[] = __( 'Reviewer name overlaps an author name — check carefully.', 'wisdom-journal-manager' );
					break;
				}
				if ( ! empty( $a->email ) && strtolower( $a->email ) === strtolower( $reviewer->user_email ) ) {
					$warnings[] = __( 'Reviewer email matches a listed co-author.', 'wisdom-journal-manager' );
					break;
				}
				unset( $rev_aff );
			}
		}
		return array_unique( $warnings );
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

		$token = wp_generate_password( 48, false, false );

		$wpdb->insert(
			$table,
			array(
				'paper_id'         => $paper_id,
				'reviewer_user_id' => $reviewer_id,
				'assigned_by'      => get_current_user_id(),
				'status'           => 'invited',
				'due_date'         => $due_date ? sanitize_text_field( $due_date ) : null,
				'blind_type'       => in_array( $blind_type, array( 'single', 'double', 'open' ), true ) ? $blind_type : 'double',
				'invite_token'     => $token,
				'created_at'       => current_time( 'mysql', true ),
			),
			array( '%d', '%d', '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		$id = (int) $wpdb->insert_id;

		$status = WJM_Workflow::get_status( $paper_id );
		if ( in_array( $status, array( 'submitted', 'screening', 'resubmitted' ), true ) ) {
			WJM_Workflow::transition( $paper_id, 'under_review', __( 'Reviewer assigned', 'wisdom-journal-manager' ) );
		}

		$invite_link = add_query_arg( 'wjm_invite', rawurlencode( $token ), home_url( '/' ) );

		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::send_template(
				$reviewer_id,
				'reviewer_invitation',
				$paper_id,
				array(
					'due_date'    => $due_date,
					'invite_link' => $invite_link,
				)
			);
		}

		WJM_Audit::log(
			'info',
			'reviewer_assigned',
			"Reviewer {$reviewer_id} assigned to paper {$paper_id}",
			array(
				'paper_id'    => $paper_id,
				'reviewer_id' => $reviewer_id,
			)
		);
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

	/**
	 * Suggest reviewers by expertise overlap + open assignment load.
	 *
	 * @param int $paper_id Paper ID.
	 * @param int $limit Max suggestions.
	 * @return array[] {user_id,name,email,expertise,score,load,coi}
	 */
	public static function suggest_reviewers( $paper_id, $limit = 8 ) {
		$paper_id = absint( $paper_id );
		$needles  = array();
		$keywords = wp_get_post_terms( $paper_id, 'sjm_keyword', array( 'fields' => 'names' ) );
		if ( ! is_wp_error( $keywords ) ) {
			foreach ( $keywords as $kw ) {
				$needles[] = strtolower( trim( $kw ) );
			}
		}
		$subjects = wp_get_post_terms( $paper_id, 'sjm_subject', array( 'fields' => 'names' ) );
		if ( ! is_wp_error( $subjects ) ) {
			foreach ( $subjects as $s ) {
				$needles[] = strtolower( trim( $s ) );
			}
		}
		$jid = (int) get_post_meta( $paper_id, '_sjm_journal_id', true );
		if ( $jid ) {
			$jsub = wp_get_post_terms( $jid, 'sjm_subject', array( 'fields' => 'names' ) );
			if ( ! is_wp_error( $jsub ) ) {
				foreach ( $jsub as $s ) {
					$needles[] = strtolower( trim( $s ) );
				}
			}
		}
		$title = strtolower( get_the_title( $paper_id ) );
		$needles = array_values( array_unique( array_filter( $needles ) ) );

		$assigned = array();
		foreach ( self::get_assignments( $paper_id ) as $a ) {
			$assigned[ (int) $a->reviewer_user_id ] = true;
		}

		$users = get_users(
			array(
				'role__in' => array( 'sjm_researcher', 'sjm_editor', 'sjm_reviewer', 'administrator' ),
				'number'   => 300,
				'fields'   => array( 'ID', 'display_name', 'user_email' ),
			)
		);

		global $wpdb;
		$table = WJM_Database_Schema::table( 'assignments' );
		$loads = array();
		$load_rows = $wpdb->get_results(
			"SELECT reviewer_user_id, COUNT(*) AS c FROM {$table}
			WHERE status IN ('invited','accepted','in_progress')
			GROUP BY reviewer_user_id"
		);
		foreach ( (array) $load_rows as $lr ) {
			$loads[ (int) $lr->reviewer_user_id ] = (int) $lr->c;
		}

		$scored = array();
		foreach ( $users as $user ) {
			$uid = (int) $user->ID;
			if ( isset( $assigned[ $uid ] ) ) {
				continue;
			}
			$exp_raw = (string) get_user_meta( $uid, '_wjm_expertise_tags', true );
			$exp     = array_filter( array_map( 'trim', explode( ',', strtolower( $exp_raw ) ) ) );
			$score   = 0;
			foreach ( $needles as $n ) {
				foreach ( $exp as $e ) {
					if ( $e && ( false !== strpos( $e, $n ) || false !== strpos( $n, $e ) ) ) {
						$score += 3;
					}
				}
				if ( $n && false !== strpos( $title, $n ) && $exp ) {
					// slight boost already counted via keywords.
				}
			}
			// Prefer people with any expertise tags even without keyword match (low score).
			if ( ! $score && $exp ) {
				$score = 1;
			}
			if ( ! $score && ! $needles ) {
				$score = 1; // no keywords: still list lightest load.
			}
			if ( $score < 1 ) {
				continue;
			}
			$coi  = self::coi_warnings( $paper_id, $uid );
			$load = isset( $loads[ $uid ] ) ? $loads[ $uid ] : 0;
			if ( $coi ) {
				$score -= 2;
			}
			$scored[] = array(
				'user_id'   => $uid,
				'name'      => $user->display_name,
				'email'     => $user->user_email,
				'expertise' => $exp_raw,
				'score'     => $score,
				'load'      => $load,
				'coi'       => $coi,
			);
		}

		usort(
			$scored,
			function ( $a, $b ) {
				if ( $a['score'] !== $b['score'] ) {
					return $b['score'] - $a['score'];
				}
				return $a['load'] - $b['load'];
			}
		);

		return array_slice( $scored, 0, absint( $limit ) );
	}

	public static function render_editor_box( $post ) {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			echo '<p>' . esc_html__( 'Editor access required to manage peer review.', 'wisdom-journal-manager' ) . '</p>';
			return;
		}

		$assignments = self::get_assignments( $post->ID );
		$journal_id  = (int) get_post_meta( $post->ID, '_sjm_journal_id', true );
		$default_blind = $journal_id ? get_post_meta( $journal_id, '_sjm_default_blind', true ) : 'double';
		if ( ! in_array( $default_blind, array( 'single', 'double', 'open' ), true ) ) {
			$default_blind = 'double';
		}
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
							<?php
							$coi  = self::coi_warnings( $post->ID, $user->ID );
							$tag  = $coi ? ' ⚠' : '';
							$exp  = get_user_meta( $user->ID, '_wjm_expertise_tags', true );
							$exp_s = $exp ? ' · ' . $exp : '';
							?>
							<option value="<?php echo esc_attr( $user->ID ); ?>"><?php echo esc_html( $user->display_name . ' (' . $user->user_email . ')' . $exp_s . $tag ); ?></option>
						<?php endforeach; ?>
					</select>
					<input type="date" name="due_date" />
					<select name="blind_type">
						<option value="double" <?php selected( $default_blind, 'double' ); ?>><?php esc_html_e( 'Double-blind', 'wisdom-journal-manager' ); ?></option>
						<option value="single" <?php selected( $default_blind, 'single' ); ?>><?php esc_html_e( 'Single-blind', 'wisdom-journal-manager' ); ?></option>
						<option value="open" <?php selected( $default_blind, 'open' ); ?>><?php esc_html_e( 'Open', 'wisdom-journal-manager' ); ?></option>
					</select>
					<?php submit_button( __( 'Invite', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
				</p>
				<p class="description"><?php esc_html_e( '⚠ in the list = possible COI. Assign still works — you decide.', 'wisdom-journal-manager' ); ?></p>
			</form>

			<?php
			$suggestions = self::suggest_reviewers( $post->ID, 6 );
			if ( $suggestions ) :
				?>
				<h4><?php esc_html_e( 'Suggested (expertise + load)', 'wisdom-journal-manager' ); ?></h4>
				<ul class="wjm-reviewer-suggestions" style="margin:0.5rem 0 1rem;padding-left:1.2rem;">
					<?php foreach ( $suggestions as $s ) : ?>
						<li>
							<strong><?php echo esc_html( $s['name'] ); ?></strong>
							<?php if ( $s['expertise'] ) : ?>
								— <em><?php echo esc_html( $s['expertise'] ); ?></em>
							<?php endif; ?>
							<span class="description">
								(<?php echo esc_html( sprintf( __( 'match %1$d · open %2$d', 'wisdom-journal-manager' ), $s['score'], $s['load'] ) ); ?><?php echo $s['coi'] ? ' · ⚠ COI' : ''; ?>)
							</span>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;margin-left:0.35rem;">
								<input type="hidden" name="action" value="wjm_assign_reviewer" />
								<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
								<input type="hidden" name="reviewer_user_id" value="<?php echo esc_attr( $s['user_id'] ); ?>" />
								<input type="hidden" name="blind_type" value="<?php echo esc_attr( $default_blind ); ?>" />
								<?php wp_nonce_field( 'wjm_assign_reviewer' ); ?>
								<button type="submit" class="button button-small"><?php esc_html_e( 'Invite', 'wisdom-journal-manager' ); ?></button>
							</form>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="description"><?php esc_html_e( 'Ranked by keyword/subject overlap with expertise tags, then fewest open assignments.', 'wisdom-journal-manager' ); ?></p>
			<?php endif; ?>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Reviewer', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Blind', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Due', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Invite link', 'wisdom-journal-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( ! $assignments ) : ?>
					<tr><td colspan="5"><?php esc_html_e( 'No reviewers assigned yet.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $assignments as $a ) : ?>
						<?php $u = get_userdata( $a->reviewer_user_id ); ?>
						<tr>
							<td><?php echo esc_html( $u ? $u->display_name : '#' . $a->reviewer_user_id ); ?></td>
							<td><?php echo esc_html( $a->status ); ?></td>
							<td><?php echo esc_html( $a->blind_type ); ?></td>
							<td><?php echo esc_html( $a->due_date ); ?></td>
							<td>
								<?php if ( ! empty( $a->invite_token ) && 'invited' === $a->status ) : ?>
									<code style="font-size:11px;"><?php echo esc_html( add_query_arg( 'wjm_invite', $a->invite_token, home_url( '/' ) ) ); ?></code>
								<?php else : ?>
									—
								<?php endif; ?>
							</td>
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
						<p><em><?php esc_html_e( 'Blind review — author names hidden here. Files download through a gated link; cover letters withheld in double-blind.', 'wisdom-journal-manager' ); ?></em></p>
						<?php if ( 'double' === $a->blind_type ) : ?>
							<p class="description"><?php esc_html_e( 'Note: the manuscript PDF itself may still contain identity — editors should upload an anonymized file when possible.', 'wisdom-journal-manager' ); ?></p>
						<?php endif; ?>
					<?php endif; ?>
					<p><?php echo esc_html( wp_trim_words( get_post_meta( $paper->ID, '_sjm_abstract', true ), 60 ) ); ?></p>
					<?php
					$files = WJM_Submissions::get_files( $paper->ID );
					if ( $files ) :
						$has_anon = false;
						foreach ( $files as $f ) {
							if ( 'anonymized_manuscript' === $f->file_role ) {
								$has_anon = true;
								break;
							}
						}
						?>
						<p><strong><?php esc_html_e( 'Manuscript files', 'wisdom-journal-manager' ); ?></strong></p>
						<ul>
							<?php foreach ( $files as $file ) : ?>
								<?php
								if ( 'double' === $a->blind_type && in_array( $file->file_role, array( 'cover_letter', 'author_identity', 'title_page' ), true ) ) {
									continue;
								}
								// Prefer anonymized file for double-blind; hide full manuscript if anon exists.
								if ( 'double' === $a->blind_type && $has_anon && 'manuscript' === $file->file_role ) {
									continue;
								}
								$url = self::reviewer_file_url( $a, $file );
								?>
								<li><a href="<?php echo esc_url( $url ); ?>" target="_blank" rel="noopener"><?php echo esc_html( $file->file_role . ( $file->version_label ? ' (' . $file->version_label . ')' : '' ) ); ?></a></li>
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
		$paper_id    = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		$reviewer_id = isset( $_POST['reviewer_user_id'] ) ? absint( $_POST['reviewer_user_id'] ) : 0;
		$coi         = self::coi_warnings( $paper_id, $reviewer_id );
		if ( $coi ) {
			WJM_Audit::log(
				'warning',
				'coi_flag',
				implode( ' ', $coi ),
				array(
					'paper_id'    => $paper_id,
					'reviewer_id' => $reviewer_id,
					'warnings'    => $coi,
				)
			);
		}
		$result = self::assign(
			$paper_id,
			$reviewer_id,
			isset( $_POST['due_date'] ) ? sanitize_text_field( wp_unslash( $_POST['due_date'] ) ) : '',
			isset( $_POST['blind_type'] ) ? sanitize_key( wp_unslash( $_POST['blind_type'] ) ) : 'double'
		);
		$args = is_wp_error( $result ) ? array( 'wjm_err' => rawurlencode( $result->get_error_message() ) ) : array( 'wjm_reviewer' => 1 );
		if ( $coi && ! is_wp_error( $result ) ) {
			$args['wjm_coi'] = 1;
		}
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
			WJM_Audit::log(
				'info',
				'reviewer_' . $response,
				sprintf( 'Reviewer %d %s invite for paper %d', get_current_user_id(), $response, (int) $row->paper_id ),
				array(
					'paper_id'       => (int) $row->paper_id,
					'assignment_id'  => $id,
				)
			);
		}

		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-my-reviews' ) );
		exit;
	}

	/**
	 * Public invite page: ?wjm_invite=TOKEN
	 */
	public static function maybe_render_invite_page() {
		if ( empty( $_GET['wjm_invite'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$token = sanitize_text_field( wp_unslash( $_GET['wjm_invite'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$row   = self::get_by_token( $token );
		status_header( 200 );
		nocache_headers();
		get_header();
		echo '<main class="wjm-invite-page wjm-shama" style="max-width:36rem;margin:2rem auto;padding:0 1rem;">';
		if ( ! $row ) {
			echo '<h1>' . esc_html__( 'Invitation not found', 'wisdom-journal-manager' ) . '</h1>';
			echo '<p>' . esc_html__( 'This link is invalid or expired.', 'wisdom-journal-manager' ) . '</p>';
			echo '</main>';
			get_footer();
			exit;
		}

		$paper = get_post( $row->paper_id );
		$title = $paper ? $paper->post_title : __( 'Manuscript', 'wisdom-journal-manager' );

		if ( 'invited' !== $row->status ) {
			echo '<h1>' . esc_html__( 'Already responded', 'wisdom-journal-manager' ) . '</h1>';
			echo '<p>' . esc_html( sprintf( __( 'Status: %s', 'wisdom-journal-manager' ), $row->status ) ) . '</p>';
			if ( 'accepted' === $row->status && is_user_logged_in() ) {
				echo '<p><a class="wjm-btn" href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-my-reviews' ) ) . '">' . esc_html__( 'Open My Reviews', 'wisdom-journal-manager' ) . '</a></p>';
			} elseif ( 'accepted' === $row->status ) {
				echo '<p><a href="' . esc_url( wp_login_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-my-reviews' ) ) ) . '">' . esc_html__( 'Log in to submit your review', 'wisdom-journal-manager' ) . '</a></p>';
			}
			echo '</main>';
			get_footer();
			exit;
		}

		$msg = isset( $_GET['wjm_invite_ok'] ) ? sanitize_key( wp_unslash( $_GET['wjm_invite_ok'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		?>
		<p class="wjm-eyebrow"><?php esc_html_e( 'Peer review', 'wisdom-journal-manager' ); ?></p>
		<h1><?php esc_html_e( 'Review invitation', 'wisdom-journal-manager' ); ?></h1>
		<p><?php echo esc_html( sprintf( __( 'You are invited to review: %s', 'wisdom-journal-manager' ), $title ) ); ?></p>
		<?php if ( $row->due_date ) : ?>
			<p><?php echo esc_html( sprintf( __( 'Due: %s', 'wisdom-journal-manager' ), $row->due_date ) ); ?></p>
		<?php endif; ?>
		<?php if ( $msg ) : ?>
			<p class="wjm-notice wjm-notice-success"><?php echo esc_html( 'accepted' === $msg ? __( 'Invitation accepted. Log in to submit your review.', 'wisdom-journal-manager' ) : __( 'Invitation declined. Thank you.', 'wisdom-journal-manager' ) ); ?></p>
		<?php else : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:0.5rem;">
				<input type="hidden" name="action" value="wjm_invite_respond" />
				<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
				<input type="hidden" name="response" value="accepted" />
				<?php wp_nonce_field( 'wjm_invite_respond_' . $token ); ?>
				<button type="submit" class="wjm-btn"><?php esc_html_e( 'Accept invitation', 'wisdom-journal-manager' ); ?></button>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;">
				<input type="hidden" name="action" value="wjm_invite_respond" />
				<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
				<input type="hidden" name="response" value="declined" />
				<?php wp_nonce_field( 'wjm_invite_respond_' . $token ); ?>
				<button type="submit" class="button"><?php esc_html_e( 'Decline', 'wisdom-journal-manager' ); ?></button>
			</form>
		<?php endif; ?>
		</main>
		<?php
		get_footer();
		exit;
	}

	/**
	 * @param string $token Token.
	 * @return object|null
	 */
	public static function get_by_token( $token ) {
		global $wpdb;
		if ( ! $token ) {
			return null;
		}
		$table = WJM_Database_Schema::table( 'assignments' );
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE invite_token = %s LIMIT 1",
				$token
			)
		);
	}

	public static function handle_token_respond() {
		$token    = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		$response = isset( $_POST['response'] ) ? sanitize_key( wp_unslash( $_POST['response'] ) ) : '';
		check_admin_referer( 'wjm_invite_respond_' . $token );

		$row = self::get_by_token( $token );
		if ( ! $row || 'invited' !== $row->status || ! in_array( $response, array( 'accepted', 'declined' ), true ) ) {
			wp_safe_redirect( add_query_arg( 'wjm_invite', rawurlencode( $token ), home_url( '/' ) ) );
			exit;
		}

		global $wpdb;
		$wpdb->update(
			WJM_Database_Schema::table( 'assignments' ),
			array( 'status' => $response ),
			array( 'id' => (int) $row->id ),
			array( '%s' ),
			array( '%d' )
		);

		WJM_Audit::log(
			'info',
			'reviewer_' . $response,
			sprintf( 'Token invite %s for paper %d', $response, (int) $row->paper_id ),
			array(
				'paper_id'      => (int) $row->paper_id,
				'assignment_id' => (int) $row->id,
				'via'           => 'token',
			)
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'wjm_invite'    => rawurlencode( $token ),
					'wjm_invite_ok' => $response,
				),
				home_url( '/' )
			)
		);
		exit;
	}
}
