<?php
/**
 * Centralized security audit logging.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Audit {

	public static function init() {
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ) );
	}

	/**
	 * Write an audit event.
	 *
	 * @param string $severity  info|warning|critical
	 * @param string $event_type Event key.
	 * @param string $message    Human-readable message.
	 * @param array  $context    Optional context.
	 */
	public static function log( $severity, $event_type, $message, $context = array() ) {
		global $wpdb;

		$wpdb->insert(
			WJM_Database_Schema::table( 'audit' ),
			array(
				'severity'   => sanitize_key( $severity ),
				'event_type' => sanitize_key( $event_type ),
				'message'    => sanitize_text_field( $message ),
				'user_id'    => get_current_user_id() ? get_current_user_id() : null,
				'ip_address' => self::client_ip(),
				'context'    => wp_json_encode( $context ),
				'created_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		/**
		 * Fires when a security event is logged.
		 *
		 * @param string $severity
		 * @param string $event_type
		 * @param string $message
		 * @param array  $context
		 */
		do_action( 'sjm_security_event_logged', $severity, $event_type, $message, $context );
	}

	public static function on_login_failed( $username ) {
		self::log( 'warning', 'login_failed', 'Failed login attempt.', array( 'username' => $username ) );
	}

	/**
	 * Recent audit rows for admin UI.
	 *
	 * @param int $limit Limit.
	 * @return array
	 */
	public static function recent( $limit = 50 ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'audit' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} ORDER BY created_at DESC LIMIT %d",
				absint( $limit )
			)
		);
	}

	private static function client_ip() {
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}
		return '';
	}
}
