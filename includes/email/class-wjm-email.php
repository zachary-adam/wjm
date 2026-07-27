<?php
/**
 * Transactional email notifications for editorial events.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Email {

	public static function init() {
		add_action( 'sjm_workflow_transition', array( __CLASS__, 'on_transition' ), 10, 4 );
	}

	/**
	 * Template catalog.
	 *
	 * @return array
	 */
	public static function templates() {
		return array(
			'submission_received'  => array(
				'subject' => '[{site}] Submission received: {title}',
				'body'    => "Dear {name},\n\nWe received your manuscript \"{title}\". Current status: {status}.\n\nThank you,\n{site}",
			),
			'new_submission'       => array(
				'subject' => '[{site}] New submission: {title}',
				'body'    => "A new manuscript was submitted.\n\nTitle: {title}\nStatus: {status}\nEdit: {edit_link}\n",
			),
			'reviewer_invitation'  => array(
				'subject' => '[{site}] Review invitation: {title}',
				'body'    => "Dear {name},\n\nYou are invited to review \"{title}\". Due: {due_date}.\n\nRespond here: {reviews_link}\n\n{site}",
			),
			'review_submitted'     => array(
				'subject' => '[{site}] Review submitted: {title}',
				'body'    => "A review was submitted for \"{title}\".\nRecommendation: {recommendation}\nEdit: {edit_link}\n",
			),
			'status_changed'       => array(
				'subject' => '[{site}] Status update: {title}',
				'body'    => "Dear {name},\n\nYour manuscript \"{title}\" moved from {from_status} to {to_status}.\n\nNote: {note}\n\n{site}",
			),
		);
	}

	/**
	 * @param int    $user_id      Recipient user ID or 0.
	 * @param string $template_key Template key.
	 * @param int    $paper_id     Paper ID.
	 * @param array  $extra        Extra tokens.
	 * @param string $to_email     Optional direct email.
	 * @return bool
	 */
	public static function send_template( $user_id, $template_key, $paper_id = 0, $extra = array(), $to_email = '' ) {
		$templates = self::templates();
		if ( ! isset( $templates[ $template_key ] ) ) {
			return false;
		}

		$user = $user_id ? get_userdata( $user_id ) : null;
		if ( ! $to_email && $user ) {
			$to_email = $user->user_email;
		}
		if ( ! $to_email || ! is_email( $to_email ) ) {
			return false;
		}

		$tokens = self::tokens( $paper_id, $user, $extra );
		$subject = self::replace( $templates[ $template_key ]['subject'], $tokens );
		$body    = self::replace( $templates[ $template_key ]['body'], $tokens );

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );
		$sent    = wp_mail( $to_email, $subject, $body, $headers );

		global $wpdb;
		$wpdb->insert(
			WJM_Database_Schema::table( 'email_log' ),
			array(
				'paper_id'     => $paper_id ? absint( $paper_id ) : null,
				'to_email'     => $to_email,
				'subject'      => $subject,
				'template_key' => $template_key,
				'status'       => $sent ? 'sent' : 'failed',
				'created_at'   => current_time( 'mysql', true ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		return (bool) $sent;
	}

	/**
	 * Notify all editors/admins.
	 *
	 * @param int    $paper_id Paper ID.
	 * @param string $template Template key.
	 * @param array  $extra    Extra tokens.
	 */
	public static function notify_editors( $paper_id, $template, $extra = array() ) {
		$users = get_users(
			array(
				'role__in' => array( 'sjm_editor', 'administrator' ),
				'fields'   => array( 'ID', 'user_email' ),
			)
		);
		foreach ( $users as $user ) {
			self::send_template( $user->ID, $template, $paper_id, $extra );
		}
	}

	/**
	 * @param int    $paper_id Paper ID.
	 * @param string $from     From status.
	 * @param string $to       To status.
	 * @param string $note     Note.
	 */
	public static function notify_transition( $paper_id, $from, $to, $note = '' ) {
		$author_id = (int) get_post_field( 'post_author', $paper_id );
		if ( $author_id ) {
			self::send_template(
				$author_id,
				'status_changed',
				$paper_id,
				array(
					'from_status' => $from,
					'to_status'   => $to,
					'note'        => $note,
				)
			);
		}
	}

	public static function on_transition( $paper_id, $from, $to, $note ) {
		// notify_transition is called from workflow already; keep hook for extensions.
		unset( $paper_id, $from, $to, $note );
	}

	/**
	 * @param int          $paper_id Paper ID.
	 * @param WP_User|null $user     User.
	 * @param array        $extra    Extra.
	 * @return array
	 */
	private static function tokens( $paper_id, $user, $extra ) {
		$title  = $paper_id ? get_the_title( $paper_id ) : '';
		$status = $paper_id ? WJM_Workflow::get_status( $paper_id ) : '';
		$labels = WJM_Workflow::statuses();

		$tokens = array(
			'site'         => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'name'         => $user ? $user->display_name : __( 'Colleague', 'wisdom-journal-manager' ),
			'title'        => $title,
			'status'       => isset( $labels[ $status ] ) ? $labels[ $status ] : $status,
			'edit_link'    => $paper_id ? get_edit_post_link( $paper_id, 'raw' ) : '',
			'reviews_link' => admin_url( 'admin.php?page=wjm-my-reviews' ),
			'due_date'     => '',
			'from_status'  => '',
			'to_status'    => '',
			'note'         => '',
			'recommendation' => '',
		);

		return array_merge( $tokens, $extra );
	}

	/**
	 * @param string $text   Template.
	 * @param array  $tokens Tokens.
	 * @return string
	 */
	private static function replace( $text, $tokens ) {
		foreach ( $tokens as $key => $value ) {
			$text = str_replace( '{' . $key . '}', (string) $value, $text );
		}
		return $text;
	}
}
