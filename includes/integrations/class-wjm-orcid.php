<?php
/**
 * ORCID connect, login, and public-record auto-fill.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_ORCID {

	const META_ID    = '_wjm_orcid';
	const META_NAME  = '_wjm_orcid_name';
	const META_AFFIL = '_wjm_orcid_affiliation';
	const META_EMAIL = '_wjm_orcid_email';
	const OPT        = 'wjm_orcid_settings';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 57 );
		add_action( 'admin_post_wjm_save_orcid', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wjm_orcid_start', array( __CLASS__, 'handle_start' ) );
		add_action( 'admin_post_nopriv_wjm_orcid_start', array( __CLASS__, 'handle_start' ) );
		add_action( 'admin_post_wjm_orcid_callback', array( __CLASS__, 'handle_callback' ) );
		add_action( 'admin_post_nopriv_wjm_orcid_callback', array( __CLASS__, 'handle_callback' ) );
		add_action( 'admin_post_wjm_orcid_disconnect', array( __CLASS__, 'handle_disconnect' ) );
		add_action( 'wp_ajax_wjm_orcid_lookup', array( __CLASS__, 'ajax_lookup' ) );
		add_action( 'wp_ajax_nopriv_wjm_orcid_lookup', array( __CLASS__, 'ajax_lookup' ) );
		add_action( 'wp_ajax_wjm_orcid_works', array( __CLASS__, 'ajax_works' ) );
		add_action( 'wp_ajax_nopriv_wjm_orcid_works', array( __CLASS__, 'ajax_works' ) );
		add_action( 'show_user_profile', array( __CLASS__, 'render_profile' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_profile' ) );
		add_action( 'login_form', array( __CLASS__, 'render_login_button' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue_public' ) );
	}

	/**
	 * @return array
	 */
	public static function defaults() {
		return array(
			'enabled'           => 0,
			'client_id'         => '',
			'sandbox'           => 0,
			'allow_login'       => 1,
			'allow_create_user' => 1,
		);
	}

	/**
	 * @return array
	 */
	public static function settings() {
		$stored = get_option( self::OPT, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * @return bool
	 */
	public static function is_enabled() {
		return ! empty( self::settings()['enabled'] );
	}

	/**
	 * @return bool
	 */
	public static function oauth_ready() {
		$s = self::settings();
		return self::is_enabled() && ! empty( $s['client_id'] ) && (bool) self::get_secret();
	}

	/**
	 * @return string
	 */
	public static function get_secret() {
		return class_exists( 'WJM_Encryption' ) ? WJM_Encryption::get_secret( 'wjm_orcid_secret' ) : (string) get_option( 'wjm_orcid_secret', '' );
	}

	/**
	 * @return string
	 */
	public static function redirect_uri() {
		return admin_url( 'admin-post.php?action=wjm_orcid_callback' );
	}

	/**
	 * @return string
	 */
	private static function auth_base() {
		return ! empty( self::settings()['sandbox'] ) ? 'https://sandbox.orcid.org' : 'https://orcid.org';
	}

	/**
	 * @return string
	 */
	private static function api_base() {
		return ! empty( self::settings()['sandbox'] ) ? 'https://pub.sandbox.orcid.org/v3.0' : 'https://pub.orcid.org/v3.0';
	}

	/**
	 * Normalize ORCID iD to XXXX-XXXX-XXXX-XXXX.
	 *
	 * @param string $raw Raw ORCID.
	 * @return string
	 */
	public static function normalize( $raw ) {
		$raw = strtoupper( trim( (string) $raw ) );
		$raw = preg_replace( '#^https?://(sandbox\.)?orcid\.org/#i', '', $raw );
		$raw = preg_replace( '/[^0-9X]/', '', $raw );
		if ( 16 !== strlen( $raw ) ) {
			return '';
		}
		return substr( $raw, 0, 4 ) . '-' . substr( $raw, 4, 4 ) . '-' . substr( $raw, 8, 4 ) . '-' . substr( $raw, 12, 4 );
	}

	/**
	 * @param int $user_id User ID.
	 * @return string
	 */
	public static function user_orcid( $user_id = 0 ) {
		$user_id = $user_id ? absint( $user_id ) : get_current_user_id();
		if ( ! $user_id ) {
			return '';
		}
		return (string) get_user_meta( $user_id, self::META_ID, true );
	}

	/**
	 * Profile fields for auto-fill (connected user or lookup).
	 *
	 * @param int $user_id User ID.
	 * @return array
	 */
	public static function profile_for_user( $user_id = 0 ) {
		$user_id = $user_id ? absint( $user_id ) : get_current_user_id();
		if ( ! $user_id ) {
			return array();
		}
		$orcid = self::user_orcid( $user_id );
		if ( ! $orcid ) {
			return array();
		}
		$name  = (string) get_user_meta( $user_id, self::META_NAME, true );
		$affil = (string) get_user_meta( $user_id, self::META_AFFIL, true );
		$email = (string) get_user_meta( $user_id, self::META_EMAIL, true );
		$user  = get_userdata( $user_id );
		if ( ! $email && $user ) {
			$email = $user->user_email;
		}
		if ( ! $name && $user ) {
			$name = $user->display_name;
		}
		return array(
			'orcid'       => $orcid,
			'name'        => $name,
			'affiliation' => $affil,
			'email'       => $email,
			'author_line' => self::author_line( $name, $affil, $orcid, $email ),
		);
	}

	/**
	 * @param string $name Name.
	 * @param string $affil Affiliation.
	 * @param string $orcid ORCID.
	 * @param string $email Email.
	 * @return string
	 */
	public static function author_line( $name, $affil = '', $orcid = '', $email = '' ) {
		return trim( (string) $name ) . '; ' . trim( (string) $affil ) . '; ' . trim( (string) $orcid ) . '; ; ' . trim( (string) $email );
	}

	/**
	 * Fetch public person record.
	 *
	 * @param string $orcid ORCID iD.
	 * @return array|WP_Error
	 */
	public static function fetch_public( $orcid ) {
		$orcid = self::normalize( $orcid );
		if ( ! $orcid ) {
			return new WP_Error( 'wjm_orcid', __( 'Invalid ORCID iD.', 'wisdom-journal-manager' ) );
		}

		$url  = trailingslashit( self::api_base() ) . $orcid . '/person';
		$res  = wp_remote_get(
			$url,
			array(
				'timeout' => 15,
				'headers' => array(
					'Accept' => 'application/json',
				),
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$code = wp_remote_retrieve_response_code( $res );
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( 200 !== $code || ! is_array( $body ) ) {
			return new WP_Error( 'wjm_orcid', __( 'ORCID record not found or not public.', 'wisdom-journal-manager' ) );
		}

		$name = '';
		if ( ! empty( $body['name']['credit-name']['value'] ) ) {
			$name = $body['name']['credit-name']['value'];
		} else {
			$given  = $body['name']['given-names']['value'] ?? '';
			$family = $body['name']['family-name']['value'] ?? '';
			$name   = trim( $given . ' ' . $family );
		}

		$affil = '';
		$emp_res = wp_remote_get(
			trailingslashit( self::api_base() ) . $orcid . '/employments',
			array(
				'timeout' => 12,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);
		if ( ! is_wp_error( $emp_res ) && 200 === wp_remote_retrieve_response_code( $emp_res ) ) {
			$emp_body = json_decode( wp_remote_retrieve_body( $emp_res ), true );
			$groups   = $emp_body['affiliation-group'] ?? array();
			if ( $groups ) {
				$summary = $groups[0]['summaries'][0]['employment-summary'] ?? array();
				$affil   = $summary['organization']['name'] ?? '';
			}
		}

		$email = '';
		$emails = $body['emails']['email'] ?? array();
		foreach ( (array) $emails as $row ) {
			if ( ! empty( $row['email'] ) && ! empty( $row['visibility'] ) && 'public' === $row['visibility'] ) {
				$email = $row['email'];
				break;
			}
			if ( ! empty( $row['email'] ) && empty( $email ) ) {
				$email = $row['email'];
			}
		}

		return array(
			'orcid'       => $orcid,
			'name'        => sanitize_text_field( $name ),
			'affiliation' => sanitize_text_field( $affil ),
			'email'       => sanitize_email( $email ),
			'author_line' => self::author_line( $name, $affil, $orcid, $email ),
		);
	}

	/**
	 * Recent public works for an ORCID iD.
	 *
	 * @param string $orcid ORCID.
	 * @param int    $limit Max works.
	 * @return array|WP_Error List of {title,doi,year,url,type}.
	 */
	public static function fetch_works( $orcid, $limit = 12 ) {
		$orcid = self::normalize( $orcid );
		if ( ! $orcid ) {
			return new WP_Error( 'wjm_orcid', __( 'Invalid ORCID iD.', 'wisdom-journal-manager' ) );
		}
		$res = wp_remote_get(
			trailingslashit( self::api_base() ) . $orcid . '/works',
			array(
				'timeout' => 20,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return new WP_Error( 'wjm_orcid', __( 'Could not load ORCID works.', 'wisdom-journal-manager' ) );
		}
		$body   = json_decode( wp_remote_retrieve_body( $res ), true );
		$groups = $body['group'] ?? array();
		$out    = array();
		foreach ( $groups as $group ) {
			$summary = $group['work-summary'][0] ?? null;
			if ( ! $summary ) {
				continue;
			}
			$title = $summary['title']['title']['value'] ?? '';
			if ( ! $title ) {
				continue;
			}
			$doi  = '';
			$exts = $summary['external-ids']['external-id'] ?? array();
			foreach ( (array) $exts as $ext ) {
				if ( isset( $ext['external-id-type'] ) && 'doi' === strtolower( $ext['external-id-type'] ) ) {
					$doi = $ext['external-id-value'] ?? '';
					break;
				}
			}
			$year = $summary['publication-date']['year']['value'] ?? '';
			$type = $summary['type'] ?? '';
			$url  = $doi ? 'https://doi.org/' . $doi : ( 'https://orcid.org/' . $orcid );
			$out[] = array(
				'title' => sanitize_text_field( $title ),
				'doi'   => sanitize_text_field( $doi ),
				'year'  => sanitize_text_field( (string) $year ),
				'type'  => sanitize_key( str_replace( array( ' ', '_' ), '-', (string) $type ) ),
				'url'   => esc_url_raw( $url ),
			);
			if ( count( $out ) >= absint( $limit ) ) {
				break;
			}
		}
		return $out;
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'ORCID', 'wisdom-journal-manager' ),
			__( 'ORCID', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-orcid',
			array( __CLASS__, 'render_settings' )
		);
	}

	public static function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$s = self::settings();
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'ORCID settings saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'ORCID', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Connect ORCID for login and submit auto-fill. Public iD lookup works without OAuth; connect/login needs a free ORCID API client.', 'wisdom-journal-manager' ); ?></p>
			<div class="notice notice-info inline">
				<p><strong><?php esc_html_e( 'What works today (Public API):', 'wisdom-journal-manager' ); ?></strong>
				<?php esc_html_e( 'Lookup ORCID iD, import public works titles, Sign in / Connect with Client ID + Secret.', 'wisdom-journal-manager' ); ?></p>
				<p><strong><?php esc_html_e( 'Peer-review credit on ORCID:', 'wisdom-journal-manager' ); ?></strong>
				<?php esc_html_e( 'WJM does not write reviews to ORCID. Use Reviewer Recognition to thank reviewers and email certificate details — they add the review in their own ORCID account.', 'wisdom-journal-manager' ); ?>
				<a href="https://info.orcid.org/documentation/features/peer-review/" target="_blank" rel="noopener"><?php esc_html_e( 'About ORCID peer review', 'wisdom-journal-manager' ); ?></a></p>
			</div>
			<ol>
				<li><?php esc_html_e( 'Register an app at orcid.org/developer-tools (or sandbox).', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Set redirect URI exactly to:', 'wisdom-journal-manager' ); ?> <code><?php echo esc_html( self::redirect_uri() ); ?></code></li>
				<li><?php esc_html_e( 'Paste Client ID + Secret below. Scope used: /authenticate', 'wisdom-journal-manager' ); ?></li>
			</ol>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_orcid" />
				<?php wp_nonce_field( 'wjm_save_orcid' ); ?>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Enable ORCID', 'wisdom-journal-manager' ); ?></th>
						<td><label><input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $s['enabled'] ) ); ?> /> <?php esc_html_e( 'Show connect / lookup on submit and profiles', 'wisdom-journal-manager' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Sandbox', 'wisdom-journal-manager' ); ?></th>
						<td><label><input type="checkbox" name="sandbox" value="1" <?php checked( ! empty( $s['sandbox'] ) ); ?> /> <?php esc_html_e( 'Use sandbox.orcid.org', 'wisdom-journal-manager' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Client ID', 'wisdom-journal-manager' ); ?></th>
						<td><input type="text" class="regular-text" name="client_id" value="<?php echo esc_attr( $s['client_id'] ); ?>" autocomplete="off" /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Client secret', 'wisdom-journal-manager' ); ?></th>
						<td>
							<input type="password" class="regular-text" name="client_secret" value="" placeholder="<?php echo self::get_secret() ? esc_attr__( '•••• saved — leave blank to keep', 'wisdom-journal-manager' ) : ''; ?>" autocomplete="new-password" />
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Login', 'wisdom-journal-manager' ); ?></th>
						<td>
							<label style="display:block;"><input type="checkbox" name="allow_login" value="1" <?php checked( ! empty( $s['allow_login'] ) ); ?> /> <?php esc_html_e( 'Allow Sign in with ORCID', 'wisdom-journal-manager' ); ?></label>
							<label style="display:block;margin-top:0.35rem;"><input type="checkbox" name="allow_create_user" value="1" <?php checked( ! empty( $s['allow_create_user'] ) ); ?> /> <?php esc_html_e( 'Create a WP user on first ORCID login', 'wisdom-journal-manager' ); ?></label>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save ORCID settings', 'wisdom-journal-manager' ) ); ?>
			</form>
			<p class="description"><?php echo self::oauth_ready() ? esc_html__( 'OAuth is ready.', 'wisdom-journal-manager' ) : esc_html__( 'OAuth needs Client ID + Secret. Public lookup still works when Enable is on.', 'wisdom-journal-manager' ); ?></p>
		</div>
		<?php
	}

	public static function handle_save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_orcid' );
		$prev = self::settings();
		update_option(
			self::OPT,
			array(
				'enabled'           => ! empty( $_POST['enabled'] ) ? 1 : 0,
				'client_id'         => isset( $_POST['client_id'] ) ? sanitize_text_field( wp_unslash( $_POST['client_id'] ) ) : '',
				'sandbox'           => ! empty( $_POST['sandbox'] ) ? 1 : 0,
				'allow_login'       => ! empty( $_POST['allow_login'] ) ? 1 : 0,
				'allow_create_user' => ! empty( $_POST['allow_create_user'] ) ? 1 : 0,
			)
		);
		if ( ! empty( $_POST['client_secret'] ) ) {
			$secret = sanitize_text_field( wp_unslash( $_POST['client_secret'] ) );
			if ( class_exists( 'WJM_Encryption' ) ) {
				WJM_Encryption::set_secret( 'wjm_orcid_secret', $secret );
			} else {
				update_option( 'wjm_orcid_secret', $secret );
			}
		}
		unset( $prev );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-orcid&saved=1' ) );
		exit;
	}

	/**
	 * Start OAuth authorize.
	 */
	public static function handle_start() {
		if ( ! self::oauth_ready() ) {
			wp_die( esc_html__( 'ORCID OAuth is not configured.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_orcid_start' );
		$return = isset( $_REQUEST['return'] ) ? esc_url_raw( wp_unslash( $_REQUEST['return'] ) ) : home_url( '/' );
		$mode   = isset( $_REQUEST['mode'] ) ? sanitize_key( wp_unslash( $_REQUEST['mode'] ) ) : 'connect';
		$state  = wp_generate_password( 24, false, false );
		set_transient(
			'wjm_orcid_state_' . $state,
			array(
				'return'  => $return,
				'mode'    => $mode,
				'user_id' => get_current_user_id(),
			),
			15 * MINUTE_IN_SECONDS
		);
		$s    = self::settings();
		$url  = add_query_arg(
			array(
				'client_id'     => $s['client_id'],
				'response_type' => 'code',
				'scope'         => '/authenticate',
				'redirect_uri'  => self::redirect_uri(),
				'state'         => $state,
			),
			trailingslashit( self::auth_base() ) . 'oauth/authorize'
		);
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- ORCID host
		exit;
	}

	public static function handle_callback() {
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$pack  = $state ? get_transient( 'wjm_orcid_state_' . $state ) : false;
		if ( ! $code || ! is_array( $pack ) ) {
			wp_die( esc_html__( 'ORCID authorization failed or expired. Try again.', 'wisdom-journal-manager' ) );
		}
		delete_transient( 'wjm_orcid_state_' . $state );

		$token = self::exchange_code( $code );
		if ( is_wp_error( $token ) ) {
			wp_die( esc_html( $token->get_error_message() ) );
		}

		$orcid = self::normalize( $token['orcid'] ?? '' );
		$name  = sanitize_text_field( $token['name'] ?? '' );
		if ( ! $orcid ) {
			wp_die( esc_html__( 'ORCID did not return an iD.', 'wisdom-journal-manager' ) );
		}

		$public = self::fetch_public( $orcid );
		$affil  = is_array( $public ) ? ( $public['affiliation'] ?? '' ) : '';
		$email  = is_array( $public ) ? ( $public['email'] ?? '' ) : '';
		if ( ! $name && is_array( $public ) ) {
			$name = $public['name'] ?? '';
		}

		$user_id = ! empty( $pack['user_id'] ) ? absint( $pack['user_id'] ) : 0;
		$mode    = $pack['mode'] ?? 'connect';
		$s       = self::settings();

		if ( 'login' === $mode || ( ! $user_id && ! empty( $s['allow_login'] ) ) ) {
			$user_id = self::find_or_create_user( $orcid, $name, $email );
			if ( is_wp_error( $user_id ) ) {
				wp_die( esc_html( $user_id->get_error_message() ) );
			}
			wp_set_current_user( $user_id );
			wp_set_auth_cookie( $user_id, true );
		}

		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}
		if ( $user_id ) {
			self::store_on_user( $user_id, $orcid, $name, $affil, $email );
			if ( class_exists( 'WJM_Audit' ) ) {
				WJM_Audit::log( 'info', 'orcid_connected', sprintf( 'ORCID %s linked to user %d', $orcid, $user_id ), array( 'user_id' => $user_id ) );
			}
		}

		$return = ! empty( $pack['return'] ) ? $pack['return'] : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_orcid', 'connected', $return ) );
		exit;
	}

	/**
	 * @param string $code Auth code.
	 * @return array|WP_Error
	 */
	private static function exchange_code( $code ) {
		$s    = self::settings();
		$res  = wp_remote_post(
			trailingslashit( self::auth_base() ) . 'oauth/token',
			array(
				'timeout' => 20,
				'headers' => array(
					'Accept' => 'application/json',
				),
				'body'    => array(
					'client_id'     => $s['client_id'],
					'client_secret' => self::get_secret(),
					'grant_type'    => 'authorization_code',
					'code'          => $code,
					'redirect_uri'  => self::redirect_uri(),
				),
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( empty( $body['orcid'] ) ) {
			$msg = $body['error_description'] ?? $body['error'] ?? __( 'Token exchange failed.', 'wisdom-journal-manager' );
			return new WP_Error( 'wjm_orcid', $msg );
		}
		return $body;
	}

	/**
	 * @param int    $user_id User ID.
	 * @param string $orcid ORCID.
	 * @param string $name Name.
	 * @param string $affil Affiliation.
	 * @param string $email Email.
	 */
	public static function store_on_user( $user_id, $orcid, $name = '', $affil = '', $email = '' ) {
		update_user_meta( $user_id, self::META_ID, self::normalize( $orcid ) );
		if ( $name ) {
			update_user_meta( $user_id, self::META_NAME, sanitize_text_field( $name ) );
			wp_update_user(
				array(
					'ID'           => $user_id,
					'display_name' => sanitize_text_field( $name ),
				)
			);
		}
		if ( $affil ) {
			update_user_meta( $user_id, self::META_AFFIL, sanitize_text_field( $affil ) );
		}
		if ( $email ) {
			update_user_meta( $user_id, self::META_EMAIL, sanitize_email( $email ) );
		}

		// Sync into WJM author row when possible.
		if ( class_exists( 'WJM_Author_Profiles' ) ) {
			global $wpdb;
			$table    = WJM_Database_Schema::table( 'authors' );
			$existing = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE orcid = %s LIMIT 1", self::normalize( $orcid ) ) );
			$parts    = preg_split( '/\s+/', trim( $name ), 2 );
			WJM_Author_Profiles::save_author(
				array(
					'user_id'     => $user_id,
					'first_name'  => $parts[0] ?? $name,
					'last_name'   => $parts[1] ?? '',
					'orcid'       => $orcid,
					'email'       => $email,
					'affiliation' => $affil,
				),
				$existing
			);
		}
	}

	/**
	 * @param string $orcid ORCID.
	 * @param string $name Name.
	 * @param string $email Email.
	 * @return int|WP_Error
	 */
	private static function find_or_create_user( $orcid, $name, $email ) {
		$users = get_users(
			array(
				'meta_key'   => self::META_ID,
				'meta_value' => $orcid,
				'number'     => 1,
				'fields'     => 'ID',
			)
		);
		if ( $users ) {
			return (int) $users[0];
		}
		if ( $email && is_email( $email ) ) {
			$by_email = get_user_by( 'email', $email );
			if ( $by_email ) {
				return (int) $by_email->ID;
			}
		}
		$s = self::settings();
		if ( empty( $s['allow_create_user'] ) ) {
			return new WP_Error( 'wjm_orcid', __( 'No WordPress account linked to this ORCID. Log in first, then Connect ORCID.', 'wisdom-journal-manager' ) );
		}
		$login = 'orcid_' . strtolower( str_replace( '-', '', $orcid ) );
		if ( username_exists( $login ) ) {
			$login .= '_' . wp_generate_password( 4, false );
		}
		if ( ! $email || ! is_email( $email ) ) {
			$email = $login . '@orcid.local';
		}
		$uid = wp_create_user( $login, wp_generate_password( 24, true ), $email );
		if ( is_wp_error( $uid ) ) {
			return $uid;
		}
		wp_update_user(
			array(
				'ID'           => $uid,
				'display_name' => $name ? $name : $login,
				'role'         => 'sjm_researcher',
			)
		);
		return (int) $uid;
	}

	public static function handle_disconnect() {
		if ( ! is_user_logged_in() ) {
			auth_redirect();
		}
		check_admin_referer( 'wjm_orcid_disconnect' );
		$uid = get_current_user_id();
		delete_user_meta( $uid, self::META_ID );
		delete_user_meta( $uid, self::META_NAME );
		delete_user_meta( $uid, self::META_AFFIL );
		delete_user_meta( $uid, self::META_EMAIL );
		$return = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_orcid', 'disconnected', $return ) );
		exit;
	}

	public static function ajax_lookup() {
		check_ajax_referer( 'wjm_orcid_lookup', 'nonce' );
		if ( ! self::is_enabled() ) {
			wp_send_json_error( array( 'message' => __( 'ORCID is disabled.', 'wisdom-journal-manager' ) ), 403 );
		}
		$orcid = isset( $_POST['orcid'] ) ? sanitize_text_field( wp_unslash( $_POST['orcid'] ) ) : '';
		$data  = self::fetch_public( $orcid );
		if ( is_wp_error( $data ) ) {
			wp_send_json_error( array( 'message' => $data->get_error_message() ) );
		}
		wp_send_json_success( $data );
	}

	public static function ajax_works() {
		check_ajax_referer( 'wjm_orcid_lookup', 'nonce' );
		if ( ! self::is_enabled() ) {
			wp_send_json_error( array( 'message' => __( 'ORCID is disabled.', 'wisdom-journal-manager' ) ), 403 );
		}
		$orcid = isset( $_POST['orcid'] ) ? sanitize_text_field( wp_unslash( $_POST['orcid'] ) ) : '';
		if ( ! $orcid && is_user_logged_in() ) {
			$orcid = self::user_orcid();
		}
		$works = self::fetch_works( $orcid );
		if ( is_wp_error( $works ) ) {
			wp_send_json_error( array( 'message' => $works->get_error_message() ) );
		}
		wp_send_json_success( array( 'works' => $works, 'orcid' => self::normalize( $orcid ) ) );
	}

	public static function enqueue_public() {
		if ( ! self::is_enabled() ) {
			return;
		}
		global $post;
		$need = is_singular() && $post instanceof WP_Post && (
			has_shortcode( $post->post_content, 'wjm_submit' )
			|| false !== strpos( $post->post_content, '[wjm_submit' )
		);
		if ( ! $need ) {
			return;
		}
		wp_enqueue_script(
			'wjm-orcid',
			WJM_PLUGIN_URL . 'assets/js/orcid.js',
			array(),
			WJM_VERSION,
			true
		);
		wp_localize_script(
			'wjm-orcid',
			'wjmOrcid',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'wjm_orcid_lookup' ),
			)
		);
	}

	/**
	 * Markup for submit form / shortcode.
	 *
	 * @return string
	 */
	public static function render_submit_panel() {
		if ( ! self::is_enabled() ) {
			return '';
		}
		$profile = is_user_logged_in() ? self::profile_for_user() : array();
		$return  = ( is_ssl() ? 'https://' : 'http://' ) . ( $_SERVER['HTTP_HOST'] ?? '' ) . ( $_SERVER['REQUEST_URI'] ?? '/' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$return  = esc_url_raw( $return );
		ob_start();
		?>
		<div class="wjm-orcid-panel" data-wjm-orcid>
			<p class="wjm-eyebrow"><?php esc_html_e( 'ORCID', 'wisdom-journal-manager' ); ?></p>
			<?php if ( ! empty( $profile['orcid'] ) ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s ORCID iD */
							__( 'Connected: %s', 'wisdom-journal-manager' ),
							$profile['orcid']
						)
					);
					?>
					<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-orcid-fill
						data-name="<?php echo esc_attr( $profile['name'] ); ?>"
						data-email="<?php echo esc_attr( $profile['email'] ); ?>"
						data-line="<?php echo esc_attr( $profile['author_line'] ); ?>"
					><?php esc_html_e( 'Fill author from ORCID', 'wisdom-journal-manager' ); ?></button>
					<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-orcid-works data-orcid="<?php echo esc_attr( $profile['orcid'] ); ?>">
						<?php esc_html_e( 'Import works', 'wisdom-journal-manager' ); ?>
					</button>
				</p>
			<?php elseif ( self::oauth_ready() ) : ?>
				<p>
					<a class="wjm-btn wjm-btn-secondary" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_orcid_start&mode=connect&return=' . rawurlencode( $return ) ), 'wjm_orcid_start' ) ); ?>">
						<?php esc_html_e( 'Connect ORCID', 'wisdom-journal-manager' ); ?>
					</a>
				</p>
			<?php endif; ?>
			<p class="wjm-orcid-lookup">
				<label for="wjm_orcid_lookup"><?php esc_html_e( 'Or look up a public ORCID iD', 'wisdom-journal-manager' ); ?></label>
				<input type="text" id="wjm_orcid_lookup" placeholder="0000-0000-0000-0000" value="<?php echo esc_attr( ! empty( $profile['orcid'] ) ? $profile['orcid'] : '' ); ?>" />
				<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-orcid-lookup><?php esc_html_e( 'Look up', 'wisdom-journal-manager' ); ?></button>
				<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-orcid-works><?php esc_html_e( 'Works', 'wisdom-journal-manager' ); ?></button>
			</p>
			<ul class="wjm-orcid-works" data-wjm-orcid-works-list hidden></ul>
			<p class="description wjm-orcid-msg" hidden></p>
		</div>
		<?php
		return ob_get_clean();
	}

	public static function render_profile( $user ) {
		if ( ! self::is_enabled() ) {
			return;
		}
		$orcid = self::user_orcid( $user->ID );
		?>
		<h2><?php esc_html_e( 'ORCID (WJM)', 'wisdom-journal-manager' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'ORCID iD', 'wisdom-journal-manager' ); ?></th>
				<td>
					<?php if ( $orcid ) : ?>
						<a href="https://orcid.org/<?php echo esc_attr( $orcid ); ?>" target="_blank" rel="noopener"><?php echo esc_html( $orcid ); ?></a>
						<?php if ( (int) $user->ID === get_current_user_id() ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;margin-left:0.75rem;">
								<input type="hidden" name="action" value="wjm_orcid_disconnect" />
								<?php wp_nonce_field( 'wjm_orcid_disconnect' ); ?>
								<button type="submit" class="button-link-delete"><?php esc_html_e( 'Disconnect', 'wisdom-journal-manager' ); ?></button>
							</form>
						<?php endif; ?>
					<?php elseif ( (int) $user->ID === get_current_user_id() && self::oauth_ready() ) : ?>
						<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_orcid_start&mode=connect&return=' . rawurlencode( get_edit_profile_url() ) ), 'wjm_orcid_start' ) ); ?>">
							<?php esc_html_e( 'Connect ORCID', 'wisdom-journal-manager' ); ?>
						</a>
					<?php else : ?>
						<span class="description"><?php esc_html_e( 'Not connected.', 'wisdom-journal-manager' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	public static function render_login_button() {
		$s = self::settings();
		if ( ! self::oauth_ready() || empty( $s['allow_login'] ) ) {
			return;
		}
		$return = wp_get_referer() ? wp_get_referer() : admin_url();
		$url    = wp_nonce_url(
			admin_url( 'admin-post.php?action=wjm_orcid_start&mode=login&return=' . rawurlencode( $return ) ),
			'wjm_orcid_start'
		);
		echo '<p class="wjm-orcid-login" style="margin:1rem 0;"><a class="button button-secondary" href="' . esc_url( $url ) . '">' . esc_html__( 'Sign in with ORCID', 'wisdom-journal-manager' ) . '</a></p>';
	}
}
