<?php
/**
 * Submit draft save / resume (logged-in user meta or guest token).
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Drafts {

	const USER_META = '_wjm_submit_draft';
	const COOKIE    = 'wjm_draft';

	public static function init() {
		add_action( 'admin_post_wjm_save_draft', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_nopriv_wjm_save_draft', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_wjm_clear_draft', array( __CLASS__, 'handle_clear' ) );
		add_action( 'admin_post_nopriv_wjm_clear_draft', array( __CLASS__, 'handle_clear' ) );
	}

	/**
	 * @return array
	 */
	public static function get_draft() {
		if ( is_user_logged_in() ) {
			$d = get_user_meta( get_current_user_id(), self::USER_META, true );
			return is_array( $d ) ? $d : array();
		}
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( ! $token && isset( $_GET['draft'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$token = sanitize_text_field( wp_unslash( $_GET['draft'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		if ( ! $token ) {
			return array();
		}
		$d = get_transient( 'wjm_draft_' . $token );
		return is_array( $d ) ? $d : array();
	}

	/**
	 * @param array $data Draft fields.
	 * @return string Token for guests.
	 */
	public static function save_draft( $data ) {
		$payload = array(
			'journal_id'            => isset( $data['journal_id'] ) ? absint( $data['journal_id'] ) : 0,
			'paper_type'            => isset( $data['paper_type'] ) ? sanitize_key( $data['paper_type'] ) : '',
			'title'                 => isset( $data['title'] ) ? sanitize_text_field( $data['title'] ) : '',
			'abstract'              => isset( $data['abstract'] ) ? sanitize_textarea_field( $data['abstract'] ) : '',
			'keywords'              => isset( $data['keywords'] ) ? sanitize_text_field( $data['keywords'] ) : '',
			'authors_text'          => isset( $data['authors_text'] ) ? sanitize_textarea_field( $data['authors_text'] ) : '',
			'corresponding_email'   => isset( $data['corresponding_email'] ) ? sanitize_email( $data['corresponding_email'] ) : '',
			'funding'               => isset( $data['funding'] ) ? sanitize_textarea_field( $data['funding'] ) : '',
			'conflicts'             => isset( $data['conflicts'] ) ? sanitize_textarea_field( $data['conflicts'] ) : '',
			'ethics'                => isset( $data['ethics'] ) ? sanitize_textarea_field( $data['ethics'] ) : '',
			'data_availability'     => isset( $data['data_availability'] ) ? sanitize_textarea_field( $data['data_availability'] ) : '',
			'cover_letter'          => isset( $data['cover_letter'] ) ? sanitize_textarea_field( $data['cover_letter'] ) : '',
			'suggested_reviewers'   => isset( $data['suggested_reviewers'] ) ? sanitize_textarea_field( $data['suggested_reviewers'] ) : '',
			'preprint_url'          => isset( $data['preprint_url'] ) ? esc_url_raw( $data['preprint_url'] ) : '',
			'guest_email'           => isset( $data['guest_email'] ) ? sanitize_email( $data['guest_email'] ) : '',
			'guest_name'            => isset( $data['guest_name'] ) ? sanitize_text_field( $data['guest_name'] ) : '',
			'saved_at'              => current_time( 'mysql', true ),
		);

		if ( is_user_logged_in() ) {
			update_user_meta( get_current_user_id(), self::USER_META, $payload );
			return '';
		}

		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( ! $token ) {
			$token = wp_generate_password( 32, false, false );
		}
		set_transient( 'wjm_draft_' . $token, $payload, WEEK_IN_SECONDS );
		if ( ! headers_sent() ) {
			setcookie( self::COOKIE, $token, time() + WEEK_IN_SECONDS, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), true );
		}
		return $token;
	}

	public static function clear_draft() {
		if ( is_user_logged_in() ) {
			delete_user_meta( get_current_user_id(), self::USER_META );
		}
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( $token ) {
			delete_transient( 'wjm_draft_' . $token );
		}
		if ( ! headers_sent() ) {
			setcookie( self::COOKIE, '', time() - YEAR_IN_SECONDS, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), true );
		}
	}

	public static function handle_save() {
		check_admin_referer( 'wjm_submit_paper' );
		$token = self::save_draft( wp_unslash( $_POST ) );
		$redirect = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		$args     = array( 'wjm_draft_saved' => '1' );
		if ( $token ) {
			$args['draft'] = $token;
		}
		wp_safe_redirect( add_query_arg( $args, $redirect ) );
		exit;
	}

	public static function handle_clear() {
		check_admin_referer( 'wjm_clear_draft' );
		self::clear_draft();
		$redirect = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_draft_cleared', '1', $redirect ) );
		exit;
	}

	/**
	 * @param string $key Field key.
	 * @param string $default Default.
	 * @return string
	 */
	public static function val( $key, $default = '' ) {
		$d = self::get_draft();
		return isset( $d[ $key ] ) ? (string) $d[ $key ] : $default;
	}
}
