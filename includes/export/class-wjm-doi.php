<?php
/**
 * OJS-style automatic DOI generator + CrossRef / DataCite deposit.
 *
 * Pattern tokens (like OJS):
 *   %p  = DOI prefix (10.xxxx)
 *   %j  = journal acronym
 *   %v  = volume
 *   %i  = issue number
 *   %a  = article / paper ID (or sequential article number)
 *   %Y  = year
 *   %m  = month
 *   %x  = custom article number meta (_sjm_article_number)
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_DOI {

	const META_DOI           = '_sjm_doi';
	const META_STATUS        = '_sjm_doi_deposit_status';
	const META_ERROR         = '_sjm_doi_deposit_error';
	const META_REGISTERED_AT = '_sjm_doi_registered_at';
	const META_ARTICLE_NUM   = '_sjm_article_number';

	public static function init() {
		add_action( 'admin_post_wjm_register_doi', array( __CLASS__, 'handle_register' ) );
		add_action( 'admin_post_wjm_preview_doi', array( __CLASS__, 'handle_preview' ) );
		add_action( 'admin_post_wjm_retry_doi_deposit', array( __CLASS__, 'handle_retry_deposit' ) );
		add_action( 'admin_post_wjm_batch_doi_issue', array( __CLASS__, 'handle_batch_issue' ) );
		add_action( 'admin_post_wjm_save_doi_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wjm_test_doi_connection', array( __CLASS__, 'handle_test_connection' ) );
		add_action( 'sjm_workflow_transition', array( __CLASS__, 'on_workflow' ), 20, 4 );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'add_meta_boxes', array( __CLASS__, 'journal_meta_box' ) );
		add_action( 'save_post_sjm_journal', array( __CLASS__, 'save_journal_doi_meta' ), 20, 2 );
	}

	/**
	 * Whether current user can manage DOI credentials / settings.
	 *
	 * @return bool
	 */
	public static function can_manage() {
		return current_user_can( 'manage_options' ) || current_user_can( 'manage_sjm_settings' ) || current_user_can( 'manage_sjm_api_keys' );
	}

	/**
	 * Credential presence status for UI (never exposes secrets).
	 *
	 * @return array
	 */
	public static function credential_status() {
		$cr_user = WJM_Encryption::get_secret( 'wjm_crossref_user' );
		$cr_pass = WJM_Encryption::get_secret( 'wjm_crossref_pass' );
		$dc_user = WJM_Encryption::get_secret( 'wjm_datacite_user' );
		$dc_pass = WJM_Encryption::get_secret( 'wjm_datacite_pass' );
		$s       = self::settings();

		return array(
			'prefix'           => ! empty( $s['prefix'] ) && preg_match( '/^10\.\d{4,9}$/', $s['prefix'] ),
			'crossref'         => ( '' !== $cr_user && '' !== $cr_pass ),
			'crossref_user'    => $cr_user ? self::mask_user( $cr_user ) : '',
			'datacite'         => ( '' !== $dc_user && '' !== $dc_pass ),
			'datacite_user'    => $dc_user ? self::mask_user( $dc_user ) : '',
			'agency'           => $s['agency'],
			'test_mode'        => ! empty( $s['test_mode'] ),
			'last_test'        => get_option( 'wjm_doi_last_connection_test', array() ),
		);
	}

	/**
	 * @param string $user Username.
	 * @return string
	 */
	private static function mask_user( $user ) {
		$len = strlen( $user );
		if ( $len <= 3 ) {
			return str_repeat( '*', $len );
		}
		return substr( $user, 0, 2 ) . str_repeat( '*', max( 3, $len - 4 ) ) . substr( $user, -2 );
	}

	/**
	 * Test CrossRef or DataCite login without depositing a real article.
	 *
	 * @param string $agency crossref|datacite
	 * @return true|WP_Error
	 */
	public static function test_connection( $agency = 'crossref' ) {
		$settings = self::settings();
		$agency   = in_array( $agency, array( 'crossref', 'datacite' ), true ) ? $agency : 'crossref';

		if ( 'datacite' === $agency ) {
			$user = WJM_Encryption::get_secret( 'wjm_datacite_user' );
			$pass = WJM_Encryption::get_secret( 'wjm_datacite_pass' );
			if ( ! $user || ! $pass ) {
				return new WP_Error( 'wjm_no_creds', __( 'Save DataCite username and password first.', 'wisdom-journal-manager' ) );
			}
			$base = ! empty( $settings['test_mode'] ) ? 'https://mds.test.datacite.org' : 'https://mds.datacite.org';
			$response = wp_remote_get(
				$base . '/heartbeat',
				array(
					'timeout' => 20,
					'headers' => array(
						'Authorization' => 'Basic ' . base64_encode( $user . ':' . $pass ),
					),
				)
			);
		} else {
			$user = WJM_Encryption::get_secret( 'wjm_crossref_user' );
			$pass = WJM_Encryption::get_secret( 'wjm_crossref_pass' );
			if ( ! $user || ! $pass ) {
				return new WP_Error( 'wjm_no_creds', __( 'Save CrossRef username and password first.', 'wisdom-journal-manager' ) );
			}
			// Lightweight auth check against CrossRef deposit servlet.
			$endpoint = ! empty( $settings['test_mode'] )
				? 'https://test.crossref.org/servlet/deposit'
				: 'https://doi.crossref.org/servlet/deposit';
			$response = wp_remote_post(
				$endpoint,
				array(
					'timeout' => 25,
					'body'    => array(
						'operation'    => 'doQueryStatus',
						'login_id'     => $user,
						'login_passwd' => $pass,
					),
				)
			);
		}

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		// CrossRef returns various codes; 401/403 = bad auth. 200–399 usually OK for query.
		if ( in_array( $code, array( 401, 403 ), true ) || false !== stripos( $body, 'bad login' ) || false !== stripos( $body, 'unauthorized' ) ) {
			return new WP_Error( 'wjm_auth_fail', __( 'Login failed. Check username/password and test mode.', 'wisdom-journal-manager' ) );
		}
		if ( $code >= 500 ) {
			return new WP_Error( 'wjm_agency_down', sprintf( __( 'Agency error (HTTP %d). Try again later.', 'wisdom-journal-manager' ), $code ) );
		}

		$ok = array(
			'agency'  => $agency,
			'ok'      => 1,
			'code'    => $code,
			'tested'  => current_time( 'mysql' ),
			'test_mode' => ! empty( $settings['test_mode'] ) ? 1 : 0,
		);
		update_option( 'wjm_doi_last_connection_test', $ok, false );
		return true;
	}

	/**
	 * Default options.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'prefix'           => '',
			'pattern'          => '%p/%j.%Y.%a',
			'auto_assign'      => 'published', // never|accepted|published
			'agency'           => 'crossref',  // crossref|datacite|local
			'test_mode'        => 1,
			'depositor_name'   => '',
			'depositor_email'  => '',
			'registrant'       => '',
		);
	}

	/**
	 * Merged settings.
	 *
	 * @return array
	 */
	public static function settings() {
		$stored = get_option( 'wjm_doi_settings', array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		$settings = array_merge( self::defaults(), $stored );

		// Back-compat with older single option.
		if ( empty( $settings['prefix'] ) ) {
			$settings['prefix'] = (string) get_option( 'wjm_doi_prefix', '' );
		}
		return $settings;
	}

	/**
	 * Save DOI settings from admin form.
	 *
	 * @param array $input Raw POST.
	 */
	public static function save_settings( $input ) {
		$current = self::settings();
		$next    = array(
			'prefix'          => isset( $input['wjm_doi_prefix'] ) ? sanitize_text_field( $input['wjm_doi_prefix'] ) : $current['prefix'],
			'pattern'         => isset( $input['wjm_doi_pattern'] ) ? sanitize_text_field( $input['wjm_doi_pattern'] ) : $current['pattern'],
			'auto_assign'     => isset( $input['wjm_doi_auto_assign'] ) ? sanitize_key( $input['wjm_doi_auto_assign'] ) : $current['auto_assign'],
			'agency'          => isset( $input['wjm_doi_agency'] ) ? sanitize_key( $input['wjm_doi_agency'] ) : $current['agency'],
			'test_mode'       => ! empty( $input['wjm_doi_test_mode'] ) ? 1 : 0,
			'depositor_name'  => isset( $input['wjm_doi_depositor_name'] ) ? sanitize_text_field( $input['wjm_doi_depositor_name'] ) : $current['depositor_name'],
			'depositor_email' => isset( $input['wjm_doi_depositor_email'] ) ? sanitize_email( $input['wjm_doi_depositor_email'] ) : $current['depositor_email'],
			'registrant'      => isset( $input['wjm_doi_registrant'] ) ? sanitize_text_field( $input['wjm_doi_registrant'] ) : $current['registrant'],
		);

		if ( ! in_array( $next['auto_assign'], array( 'never', 'accepted', 'published' ), true ) ) {
			$next['auto_assign'] = 'published';
		}
		if ( ! in_array( $next['agency'], array( 'crossref', 'datacite', 'local' ), true ) ) {
			$next['agency'] = 'crossref';
		}

		// Normalize prefix: strip https://doi.org/ if pasted.
		$next['prefix'] = preg_replace( '#^https?://(dx\.)?doi\.org/#i', '', $next['prefix'] );
		$next['prefix'] = rtrim( trim( $next['prefix'] ), '/' );

		update_option( 'wjm_doi_settings', $next );
		update_option( 'wjm_doi_prefix', $next['prefix'] ); // back-compat
	}

	/**
	 * Build a DOI string from the configured pattern (does not save).
	 *
	 * @param int $paper_id Paper ID.
	 * @return string|WP_Error
	 */
	public static function generate( $paper_id ) {
		$paper_id = absint( $paper_id );
		$settings = self::settings();
		$prefix   = $settings['prefix'];

		if ( ! $prefix || ! preg_match( '/^10\.\d{4,9}$/', $prefix ) ) {
			return new WP_Error(
				'wjm_doi_prefix',
				__( 'Set a valid DOI prefix (e.g. 10.12345) under Journals → DOI Manager.', 'wisdom-journal-manager' )
			);
		}

		$issue_id   = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
		$journal_id = $issue_id ? (int) get_post_meta( $issue_id, '_sjm_journal_id', true ) : (int) get_post_meta( $paper_id, '_sjm_journal_id', true );

		// Per-journal prefix override.
		if ( $journal_id ) {
			$j_prefix = get_post_meta( $journal_id, '_sjm_doi_prefix', true );
			if ( $j_prefix && preg_match( '/^10\.\d{4,9}$/', $j_prefix ) ) {
				$prefix = $j_prefix;
			}
		}

		$acronym = '';
		if ( $journal_id ) {
			$acronym = get_post_meta( $journal_id, '_sjm_doi_acronym', true );
			if ( ! $acronym ) {
				$acronym = sanitize_title( get_the_title( $journal_id ) );
				$acronym = substr( preg_replace( '/[^a-z0-9]/i', '', $acronym ), 0, 12 );
			}
		}
		if ( ! $acronym ) {
			$acronym = 'wjm';
		}

		$volume = $issue_id ? (string) get_post_meta( $issue_id, '_sjm_volume', true ) : '';
		$issue  = $issue_id ? (string) get_post_meta( $issue_id, '_sjm_number', true ) : '';
		$year   = get_the_date( 'Y', $paper_id );
		$month  = get_the_date( 'm', $paper_id );
		// Preview-safe: do not consume sequence counter here.
		$article_num = get_post_meta( $paper_id, self::META_ARTICLE_NUM, true );
		if ( ! $article_num ) {
			$key         = $journal_id ? 'wjm_doi_seq_' . absint( $journal_id ) : 'wjm_doi_seq_global';
			$article_num = (int) get_option( $key, 0 ) + 1;
		}

		$tokens = array(
			'%p' => $prefix,
			'%j' => strtolower( $acronym ),
			'%v' => $volume ? $volume : '0',
			'%i' => $issue ? $issue : '0',
			'%a' => (string) $paper_id,
			'%Y' => $year ? $year : gmdate( 'Y' ),
			'%m' => $month ? $month : gmdate( 'm' ),
			'%x' => (string) $article_num,
		);

		$pattern = $settings['pattern'] ? $settings['pattern'] : '%p/%j.%Y.%a';
		// If pattern doesn't start with prefix token, prepend prefix/.
		if ( false === strpos( $pattern, '%p' ) ) {
			$pattern = '%p/' . ltrim( $pattern, '/' );
		}

		$doi = strtr( $pattern, $tokens );
		$doi = preg_replace( '#/+#', '/', $doi );
		$doi = preg_replace( '/\s+/', '', $doi );
		$doi = strtolower( $doi );

		if ( ! preg_match( '#^10\.\d{4,9}/.+#', $doi ) ) {
			return new WP_Error( 'wjm_doi_pattern', __( 'Generated DOI is invalid. Check your pattern.', 'wisdom-journal-manager' ) );
		}

		// Ensure uniqueness across papers.
		$conflict = self::find_paper_by_doi( $doi );
		if ( $conflict && (int) $conflict !== $paper_id ) {
			$doi .= '.' . substr( md5( $paper_id . microtime() ), 0, 4 );
		}

		return $doi;
	}

	/**
	 * Sequential article counter per journal (or global).
	 *
	 * @param int $journal_id Journal ID.
	 * @return int
	 */
	public static function next_article_number( $journal_id = 0 ) {
		$key = $journal_id ? 'wjm_doi_seq_' . absint( $journal_id ) : 'wjm_doi_seq_global';
		$n   = (int) get_option( $key, 0 );
		$n++;
		update_option( $key, $n, false );
		return $n;
	}

	/**
	 * @param string $doi DOI.
	 * @return int Paper ID or 0.
	 */
	public static function find_paper_by_doi( $doi ) {
		$q = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'any',
				'posts_per_page' => 1,
				'fields'         => 'ids',
				'meta_key'       => self::META_DOI,
				'meta_value'     => $doi,
			)
		);
		return $q ? (int) $q[0] : 0;
	}

	/**
	 * Assign DOI (generate + save) and optionally deposit with agency.
	 *
	 * @param int  $paper_id Paper ID.
	 * @param bool $deposit  Whether to deposit with CrossRef/DataCite.
	 * @return string|WP_Error
	 */
	public static function register( $paper_id, $deposit = true ) {
		$paper_id = absint( $paper_id );
		$existing = get_post_meta( $paper_id, self::META_DOI, true );
		if ( $existing ) {
			if ( $deposit && 'submitted' !== get_post_meta( $paper_id, self::META_STATUS, true ) && 'registered' !== get_post_meta( $paper_id, self::META_STATUS, true ) ) {
				$dep = self::deposit( $existing, $paper_id );
				if ( is_wp_error( $dep ) ) {
					return $dep;
				}
			}
			return $existing;
		}

		$settings = self::settings();
		if ( false !== strpos( $settings['pattern'], '%x' ) && ! get_post_meta( $paper_id, self::META_ARTICLE_NUM, true ) ) {
			$issue_id   = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
			$journal_id = $issue_id ? (int) get_post_meta( $issue_id, '_sjm_journal_id', true ) : (int) get_post_meta( $paper_id, '_sjm_journal_id', true );
			$num        = self::next_article_number( $journal_id ? $journal_id : 0 );
			update_post_meta( $paper_id, self::META_ARTICLE_NUM, $num );
		}

		$doi = self::generate( $paper_id );
		if ( is_wp_error( $doi ) ) {
			return $doi;
		}

		update_post_meta( $paper_id, self::META_DOI, $doi );
		update_post_meta( $paper_id, self::META_REGISTERED_AT, current_time( 'mysql', true ) );
		update_post_meta( $paper_id, self::META_STATUS, 'assigned' );

		if ( $deposit ) {
			$result = self::deposit( $doi, $paper_id );
			if ( is_wp_error( $result ) ) {
				update_post_meta( $paper_id, self::META_ERROR, $result->get_error_message() );
				WJM_Audit::log( 'warning', 'doi_deposit_failed', $result->get_error_message(), array( 'doi' => $doi ) );
				// Keep assigned DOI; editor can retry deposit.
			}
		} else {
			update_post_meta( $paper_id, self::META_STATUS, 'local_only' );
		}

		WJM_Audit::log( 'info', 'doi_assigned', "DOI {$doi} for paper {$paper_id}" );
		do_action( 'sjm_doi_registered', $paper_id, $doi );
		return $doi;
	}

	/**
	 * Deposit with configured agency.
	 *
	 * @param string $doi      DOI.
	 * @param int    $paper_id Paper ID.
	 * @return true|WP_Error
	 */
	public static function deposit( $doi, $paper_id ) {
		$settings = self::settings();
		$agency   = $settings['agency'];

		if ( 'local' === $agency ) {
			update_post_meta( $paper_id, self::META_STATUS, 'local_only' );
			delete_post_meta( $paper_id, self::META_ERROR );
			return true;
		}

		if ( 'datacite' === $agency ) {
			$result = self::deposit_datacite( $doi, $paper_id );
		} else {
			$result = self::deposit_crossref( $doi, $paper_id );
		}

		if ( is_wp_error( $result ) ) {
			update_post_meta( $paper_id, self::META_STATUS, 'failed' );
			update_post_meta( $paper_id, self::META_ERROR, $result->get_error_message() );
			return $result;
		}

		update_post_meta( $paper_id, self::META_STATUS, 'submitted' );
		delete_post_meta( $paper_id, self::META_ERROR );
		return true;
	}

	/**
	 * CrossRef UNIXREF deposit (production or test).
	 *
	 * @param string $doi      DOI.
	 * @param int    $paper_id Paper ID.
	 * @return true|WP_Error
	 */
	private static function deposit_crossref( $doi, $paper_id ) {
		$user = WJM_Encryption::get_secret( 'wjm_crossref_user' );
		$pass = WJM_Encryption::get_secret( 'wjm_crossref_pass' );
		if ( ! $user || ! $pass ) {
			return new WP_Error(
				'wjm_crossref_creds',
				__( 'Add CrossRef deposit username/password in DOI Manager (same credentials as your CrossRef membership / OJS plugin).', 'wisdom-journal-manager' )
			);
		}

		$settings = self::settings();
		$xml      = self::build_crossref_xml( $doi, $paper_id );
		$endpoint = ! empty( $settings['test_mode'] )
			? 'https://test.crossref.org/servlet/deposit'
			: 'https://doi.crossref.org/servlet/deposit';

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 60,
				'body'    => array(
					'operation'    => 'doMDUpload',
					'login_id'     => $user,
					'login_passwd' => $pass,
					'fname'        => $xml,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'wjm_crossref_http', 'CrossRef HTTP ' . $code . ': ' . wp_strip_all_tags( substr( $body, 0, 500 ) ) );
		}

		update_post_meta( $paper_id, '_sjm_doi_deposit_response', substr( $body, 0, 2000 ) );
		update_post_meta( $paper_id, '_sjm_doi_test_mode', ! empty( $settings['test_mode'] ) ? '1' : '0' );
		return true;
	}

	/**
	 * Richer CrossRef deposit XML with journal + authors.
	 *
	 * @param string $doi      DOI.
	 * @param int    $paper_id Paper ID.
	 * @return string
	 */
	public static function build_crossref_xml( $doi, $paper_id ) {
		$settings   = self::settings();
		$paper      = get_post( $paper_id );
		$issue_id   = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
		$journal_id = $issue_id ? (int) get_post_meta( $issue_id, '_sjm_journal_id', true ) : (int) get_post_meta( $paper_id, '_sjm_journal_id', true );
		$journal    = $journal_id ? get_the_title( $journal_id ) : get_bloginfo( 'name' );
		$issn       = $journal_id ? get_post_meta( $journal_id, '_sjm_issn', true ) : '';
		$volume     = $issue_id ? get_post_meta( $issue_id, '_sjm_volume', true ) : '';
		$number     = $issue_id ? get_post_meta( $issue_id, '_sjm_number', true ) : '';
		$pages      = get_post_meta( $paper_id, '_sjm_page_range', true );
		$authors    = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
		$url        = get_permalink( $paper_id );
		$year       = get_the_date( 'Y', $paper_id );
		$month      = get_the_date( 'n', $paper_id );
		$day        = get_the_date( 'j', $paper_id );

		$depositor = $settings['depositor_name'] ? $settings['depositor_name'] : WJM_Encryption::get_secret( 'wjm_crossref_user' );
		$email     = $settings['depositor_email'] ? $settings['depositor_email'] : get_option( 'admin_email' );
		$reg       = $settings['registrant'] ? $settings['registrant'] : get_bloginfo( 'name' );

		$contribs = '';
		$seq      = 1;
		foreach ( $authors as $author ) {
			$contribs .= '<person_name sequence="' . ( 1 === $seq ? 'first' : 'additional' ) . '" contributor_role="author">'
				. '<given_name>' . self::x( $author->first_name ) . '</given_name>'
				. '<surname>' . self::x( $author->last_name ) . '</surname>';
			if ( $author->orcid ) {
				$contribs .= '<ORCID authenticated="false">https://orcid.org/' . self::x( $author->orcid ) . '</ORCID>';
			}
			$contribs .= '</person_name>';
			$seq++;
		}

		$pages_xml = '';
		if ( $pages && preg_match( '/(\d+)\s*-\s*(\d+)/', $pages, $m ) ) {
			$pages_xml = '<pages><first_page>' . self::x( $m[1] ) . '</first_page><last_page>' . self::x( $m[2] ) . '</last_page></pages>';
		}

		$issn_xml = $issn ? '<issn media_type="electronic">' . self::x( $issn ) . '</issn>' : '';

		return '<?xml version="1.0" encoding="UTF-8"?>'
			. '<doi_batch version="4.4.2" xmlns="http://www.crossref.org/schema/4.4.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.crossref.org/schema/4.4.2 https://www.crossref.org/schemas/crossref4.4.2.xsd">'
			. '<head>'
			. '<doi_batch_id>wjm-' . (int) $paper_id . '-' . time() . '</doi_batch_id>'
			. '<timestamp>' . time() . '</timestamp>'
			. '<depositor><depositor_name>' . self::x( $depositor ) . '</depositor_name><email_address>' . self::x( $email ) . '</email_address></depositor>'
			. '<registrant>' . self::x( $reg ) . '</registrant>'
			. '</head><body><journal>'
			. '<journal_metadata language="en">'
			. '<full_title>' . self::x( $journal ) . '</full_title>'
			. $issn_xml
			. '</journal_metadata>'
			. '<journal_issue>'
			. '<publication_date media_type="online"><month>' . self::x( $month ) . '</month><day>' . self::x( $day ) . '</day><year>' . self::x( $year ) . '</year></publication_date>'
			. ( $volume ? '<journal_volume><volume>' . self::x( $volume ) . '</volume></journal_volume>' : '' )
			. ( $number ? '<issue>' . self::x( $number ) . '</issue>' : '' )
			. '</journal_issue>'
			. '<journal_article publication_type="full_text">'
			. '<titles><title>' . self::x( $paper->post_title ) . '</title></titles>'
			. ( $contribs ? '<contributors>' . $contribs . '</contributors>' : '' )
			. '<publication_date media_type="online"><month>' . self::x( $month ) . '</month><day>' . self::x( $day ) . '</day><year>' . self::x( $year ) . '</year></publication_date>'
			. $pages_xml
			. '<doi_data><doi>' . self::x( $doi ) . '</doi><resource>' . self::x( $url ) . '</resource></doi_data>'
			. '</journal_article></journal></body></doi_batch>';
	}

	/**
	 * DataCite MDS API deposit (requires DataCite membership credentials).
	 *
	 * @param string $doi      DOI.
	 * @param int    $paper_id Paper ID.
	 * @return true|WP_Error
	 */
	private static function deposit_datacite( $doi, $paper_id ) {
		$user = WJM_Encryption::get_secret( 'wjm_datacite_user' );
		$pass = WJM_Encryption::get_secret( 'wjm_datacite_pass' );
		if ( ! $user || ! $pass ) {
			return new WP_Error( 'wjm_datacite_creds', __( 'Add DataCite username/password in DOI Manager.', 'wisdom-journal-manager' ) );
		}

		$settings = self::settings();
		$base     = ! empty( $settings['test_mode'] ) ? 'https://mds.test.datacite.org' : 'https://mds.datacite.org';
		$url      = get_permalink( $paper_id );
		$title    = get_the_title( $paper_id );
		$authors  = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
		$creator  = 'Unknown';
		if ( $authors ) {
			$creator = trim( $authors[0]->last_name . ', ' . $authors[0]->first_name );
		}

		$xml = '<?xml version="1.0" encoding="UTF-8"?>'
			. '<resource xmlns="http://datacite.org/schema/kernel-4">'
			. '<identifier identifierType="DOI">' . self::x( $doi ) . '</identifier>'
			. '<creators><creator><creatorName>' . self::x( $creator ) . '</creatorName></creator></creators>'
			. '<titles><title>' . self::x( $title ) . '</title></titles>'
			. '<publisher>' . self::x( get_bloginfo( 'name' ) ) . '</publisher>'
			. '<publicationYear>' . self::x( get_the_date( 'Y', $paper_id ) ) . '</publicationYear>'
			. '<resourceType resourceTypeGeneral="JournalArticle">JournalArticle</resourceType>'
			. '</resource>';

		// Upload metadata.
		$meta = wp_remote_request(
			$base . '/metadata/' . rawurlencode( $doi ),
			array(
				'method'  => 'PUT',
				'timeout' => 45,
				'headers' => array(
					'Content-Type'  => 'application/xml;charset=UTF-8',
					'Authorization' => 'Basic ' . base64_encode( $user . ':' . $pass ),
				),
				'body'    => $xml,
			)
		);
		if ( is_wp_error( $meta ) ) {
			return $meta;
		}
		$code = wp_remote_retrieve_response_code( $meta );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'wjm_datacite_meta', 'DataCite metadata HTTP ' . $code . ': ' . wp_remote_retrieve_body( $meta ) );
		}

		// Mint URL.
		$mint = wp_remote_request(
			$base . '/doi/' . rawurlencode( $doi ),
			array(
				'method'  => 'PUT',
				'timeout' => 45,
				'headers' => array(
					'Content-Type'  => 'text/plain;charset=UTF-8',
					'Authorization' => 'Basic ' . base64_encode( $user . ':' . $pass ),
				),
				'body'    => 'doi=' . $doi . "\nurl=" . $url,
			)
		);
		if ( is_wp_error( $mint ) ) {
			return $mint;
		}
		$code = wp_remote_retrieve_response_code( $mint );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'wjm_datacite_mint', 'DataCite mint HTTP ' . $code . ': ' . wp_remote_retrieve_body( $mint ) );
		}

		return true;
	}

	/**
	 * Auto-assign on workflow transitions (OJS-like).
	 *
	 * @param int    $paper_id Paper ID.
	 * @param string $from     From.
	 * @param string $to       To.
	 * @param string $note     Note.
	 */
	public static function on_workflow( $paper_id, $from, $to, $note = '' ) {
		unset( $from, $note );
		$settings = self::settings();
		$trigger  = $settings['auto_assign'];
		if ( 'never' === $trigger ) {
			return;
		}
		if ( 'accepted' === $trigger && 'accepted' !== $to ) {
			return;
		}
		if ( 'published' === $trigger && 'published' !== $to ) {
			return;
		}
		if ( get_post_meta( $paper_id, self::META_DOI, true ) ) {
			return;
		}

		$result = self::register( $paper_id, true );
		if ( is_wp_error( $result ) ) {
			WJM_Audit::log( 'warning', 'doi_auto_failed', $result->get_error_message(), array( 'paper_id' => $paper_id ) );
		}
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'DOI Manager', 'wisdom-journal-manager' ),
			__( 'DOI Manager', 'wisdom-journal-manager' ),
			'manage_sjm_settings',
			'wjm-doi',
			array( __CLASS__, 'render_page' )
		);
	}

	public static function render_page() {
		if ( ! self::can_manage() ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		settings_errors( 'wjm' );
		$s      = self::settings();
		$status = self::credential_status();
		$example_preview = '10.12345/myjournal.2026.42';

		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'DOI settings & credentials saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		if ( ! empty( $_GET['batch'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( sprintf( __( 'Assigned DOIs to %d papers.', 'wisdom-journal-manager' ), absint( $_GET['batch'] ) ) ) . '</p></div>';
		}
		if ( isset( $_GET['test'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( '1' === $_GET['test'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Connection test succeeded. Credentials look good.', 'wisdom-journal-manager' ) . '</p></div>';
			} else {
				$msg = isset( $_GET['test_msg'] ) ? sanitize_text_field( wp_unslash( $_GET['test_msg'] ) ) : __( 'Connection test failed.', 'wisdom-journal-manager' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
			}
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'DOI Manager', 'wisdom-journal-manager' ); ?></h1>
			<p><?php esc_html_e( 'Let each journal publisher add their own CrossRef or DataCite membership credentials — same workflow as OJS — then auto-generate and deposit DOIs for papers.', 'wisdom-journal-manager' ); ?></p>

			<div class="wjm-doi-status-cards">
				<div class="wjm-doi-card <?php echo $status['prefix'] ? 'is-ok' : 'is-warn'; ?>">
					<strong><?php esc_html_e( 'DOI prefix', 'wisdom-journal-manager' ); ?></strong>
					<span><?php echo $status['prefix'] ? esc_html( $s['prefix'] ) : esc_html__( 'Not set', 'wisdom-journal-manager' ); ?></span>
				</div>
				<div class="wjm-doi-card <?php echo $status['crossref'] ? 'is-ok' : 'is-warn'; ?>">
					<strong><?php esc_html_e( 'CrossRef credentials', 'wisdom-journal-manager' ); ?></strong>
					<span>
						<?php
						echo $status['crossref']
							? esc_html( sprintf( __( 'Saved (%s)', 'wisdom-journal-manager' ), $status['crossref_user'] ) )
							: esc_html__( 'Not added yet', 'wisdom-journal-manager' );
						?>
					</span>
				</div>
				<div class="wjm-doi-card <?php echo $status['datacite'] ? 'is-ok' : 'is-muted'; ?>">
					<strong><?php esc_html_e( 'DataCite credentials', 'wisdom-journal-manager' ); ?></strong>
					<span>
						<?php
						echo $status['datacite']
							? esc_html( sprintf( __( 'Saved (%s)', 'wisdom-journal-manager' ), $status['datacite_user'] ) )
							: esc_html__( 'Optional', 'wisdom-journal-manager' );
						?>
					</span>
				</div>
				<div class="wjm-doi-card is-muted">
					<strong><?php esc_html_e( 'Active agency', 'wisdom-journal-manager' ); ?></strong>
					<span><?php echo esc_html( ucfirst( $status['agency'] ) ); ?><?php echo $status['test_mode'] ? ' · ' . esc_html__( 'TEST mode', 'wisdom-journal-manager' ) : ''; ?></span>
				</div>
			</div>

			<p>
				<?php
				$test_cr = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_test_doi_connection&agency=crossref' ), 'wjm_test_doi' );
				$test_dc = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_test_doi_connection&agency=datacite' ), 'wjm_test_doi' );
				?>
				<a class="button" href="<?php echo esc_url( $test_cr ); ?>"><?php esc_html_e( 'Test CrossRef connection', 'wisdom-journal-manager' ); ?></a>
				<a class="button" href="<?php echo esc_url( $test_dc ); ?>"><?php esc_html_e( 'Test DataCite connection', 'wisdom-journal-manager' ); ?></a>
			</p>

			<div class="notice notice-info inline">
				<p>
					<strong><?php esc_html_e( 'For publishers using this plugin:', 'wisdom-journal-manager' ); ?></strong>
					<?php esc_html_e( '1) Get a CrossRef (or DataCite) membership and prefix. 2) Paste username/password below. 3) Set pattern + auto-assign. 4) Publish a paper — DOI is generated and deposited automatically.', 'wisdom-journal-manager' ); ?>
					<a href="https://www.crossref.org/membership/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'CrossRef membership', 'wisdom-journal-manager' ); ?></a>
					·
					<a href="https://datacite.org/" target="_blank" rel="noopener noreferrer">DataCite</a>
				</p>
			</div>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_doi_settings" />
				<?php wp_nonce_field( 'wjm_save_doi_settings' ); ?>

				<h2><?php esc_html_e( '1. Add your credentials', 'wisdom-journal-manager' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Stored with AES-256-CBC encryption (WordPress salts). Leave a password field blank to keep the existing value.', 'wisdom-journal-manager' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Registration agency', 'wisdom-journal-manager' ); ?></th>
						<td>
							<select name="wjm_doi_agency">
								<option value="crossref" <?php selected( $s['agency'], 'crossref' ); ?>>CrossRef <?php esc_html_e( '(recommended for journals, same as OJS)', 'wisdom-journal-manager' ); ?></option>
								<option value="datacite" <?php selected( $s['agency'], 'datacite' ); ?>>DataCite</option>
								<option value="local" <?php selected( $s['agency'], 'local' ); ?>><?php esc_html_e( 'Local only — generate DOIs without depositing', 'wisdom-journal-manager' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Test mode', 'wisdom-journal-manager' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wjm_doi_test_mode" value="1" <?php checked( ! empty( $s['test_mode'] ) ); ?> />
								<?php esc_html_e( 'Use test servers (safe while setting up; turn off for production)', 'wisdom-journal-manager' ); ?>
							</label>
						</td>
					</tr>
					<tr><th><?php esc_html_e( 'CrossRef username / role', 'wisdom-journal-manager' ); ?></th><td><input type="text" class="regular-text" name="wjm_crossref_user" autocomplete="off" placeholder="<?php echo $status['crossref'] ? esc_attr( $status['crossref_user'] ) : ''; ?>" /></td></tr>
					<tr><th><?php esc_html_e( 'CrossRef password', 'wisdom-journal-manager' ); ?></th><td><input type="password" class="regular-text" name="wjm_crossref_pass" autocomplete="new-password" /></td></tr>
					<tr><th><?php esc_html_e( 'Depositor name', 'wisdom-journal-manager' ); ?></th><td><input type="text" class="regular-text" name="wjm_doi_depositor_name" value="<?php echo esc_attr( $s['depositor_name'] ); ?>" /></td></tr>
					<tr><th><?php esc_html_e( 'Depositor email', 'wisdom-journal-manager' ); ?></th><td><input type="email" class="regular-text" name="wjm_doi_depositor_email" value="<?php echo esc_attr( $s['depositor_email'] ); ?>" /></td></tr>
					<tr><th><?php esc_html_e( 'Registrant organization', 'wisdom-journal-manager' ); ?></th><td><input type="text" class="regular-text" name="wjm_doi_registrant" value="<?php echo esc_attr( $s['registrant'] ); ?>" /></td></tr>
					<tr><th><?php esc_html_e( 'DataCite username (optional)', 'wisdom-journal-manager' ); ?></th><td><input type="text" class="regular-text" name="wjm_datacite_user" autocomplete="off" /></td></tr>
					<tr><th><?php esc_html_e( 'DataCite password (optional)', 'wisdom-journal-manager' ); ?></th><td><input type="password" class="regular-text" name="wjm_datacite_pass" autocomplete="new-password" /></td></tr>
				</table>

				<h2><?php esc_html_e( '2. DOI generator', 'wisdom-journal-manager' ); ?></h2>
				<table class="form-table">
					<tr>
						<th><label for="wjm_doi_prefix"><?php esc_html_e( 'DOI prefix', 'wisdom-journal-manager' ); ?></label></th>
						<td>
							<input type="text" class="regular-text" id="wjm_doi_prefix" name="wjm_doi_prefix" value="<?php echo esc_attr( $s['prefix'] ); ?>" placeholder="10.12345" />
							<p class="description"><?php esc_html_e( 'Assigned by CrossRef/DataCite with your membership (same as OJS).', 'wisdom-journal-manager' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><label for="wjm_doi_pattern"><?php esc_html_e( 'DOI pattern', 'wisdom-journal-manager' ); ?></label></th>
						<td>
							<input type="text" class="regular-text" id="wjm_doi_pattern" name="wjm_doi_pattern" value="<?php echo esc_attr( $s['pattern'] ); ?>" />
							<p class="description">
								<?php esc_html_e( 'Tokens:', 'wisdom-journal-manager' ); ?>
								<code>%p</code> prefix,
								<code>%j</code> journal acronym,
								<code>%v</code> volume,
								<code>%i</code> issue,
								<code>%a</code> paper ID,
								<code>%x</code> sequential article #,
								<code>%Y</code> year,
								<code>%m</code> month.
								<br /><?php esc_html_e( 'Examples:', 'wisdom-journal-manager' ); ?>
								<code>%p/%j.%Y.%a</code> → <?php echo esc_html( $example_preview ); ?> ·
								<code>%p/%j.v%vi%i.%x</code>
							</p>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Auto-assign when', 'wisdom-journal-manager' ); ?></th>
						<td>
							<select name="wjm_doi_auto_assign">
								<option value="published" <?php selected( $s['auto_assign'], 'published' ); ?>><?php esc_html_e( 'Published (recommended)', 'wisdom-journal-manager' ); ?></option>
								<option value="accepted" <?php selected( $s['auto_assign'], 'accepted' ); ?>><?php esc_html_e( 'Accepted', 'wisdom-journal-manager' ); ?></option>
								<option value="never" <?php selected( $s['auto_assign'], 'never' ); ?>><?php esc_html_e( 'Never (manual only)', 'wisdom-journal-manager' ); ?></option>
							</select>
						</td>
					</tr>
				</table>

				<?php submit_button( __( 'Save credentials & DOI settings', 'wisdom-journal-manager' ) ); ?>
			</form>

			<hr />
			<h2><?php esc_html_e( '3. Batch assign for an issue', 'wisdom-journal-manager' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_batch_doi_issue" />
				<?php wp_nonce_field( 'wjm_batch_doi_issue' ); ?>
				<?php
				$issues = get_posts(
					array(
						'post_type'      => 'sjm_issue',
						'posts_per_page' => 100,
						'post_status'    => 'publish',
						'orderby'        => 'title',
						'order'          => 'ASC',
					)
				);
				?>
				<select name="issue_id" required>
					<option value=""><?php esc_html_e( '— Select issue —', 'wisdom-journal-manager' ); ?></option>
					<?php foreach ( $issues as $issue ) : ?>
						<option value="<?php echo esc_attr( $issue->ID ); ?>"><?php echo esc_html( $issue->post_title ); ?></option>
					<?php endforeach; ?>
				</select>
				<label><input type="checkbox" name="deposit" value="1" checked /> <?php esc_html_e( 'Also deposit with agency', 'wisdom-journal-manager' ); ?></label>
				<?php submit_button( __( 'Generate DOIs for all papers in issue', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
			</form>

			<hr />
			<h2><?php esc_html_e( 'Recent DOIs', 'wisdom-journal-manager' ); ?></h2>
			<?php self::render_recent_table(); ?>
		</div>
		<?php
	}

	private static function render_recent_table() {
		$papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'any',
				'posts_per_page' => 25,
				'meta_key'       => self::META_DOI,
				'meta_compare'   => 'EXISTS',
				'orderby'        => 'modified',
				'order'          => 'DESC',
			)
		);
		echo '<table class="widefat striped"><thead><tr><th>Paper</th><th>DOI</th><th>Status</th><th></th></tr></thead><tbody>';
		if ( ! $papers ) {
			echo '<tr><td colspan="4">' . esc_html__( 'No DOIs assigned yet.', 'wisdom-journal-manager' ) . '</td></tr>';
		}
		foreach ( $papers as $paper ) {
			$doi    = get_post_meta( $paper->ID, self::META_DOI, true );
			$status = get_post_meta( $paper->ID, self::META_STATUS, true );
			$err    = get_post_meta( $paper->ID, self::META_ERROR, true );
			$retry  = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_retry_doi_deposit&paper_id=' . $paper->ID ), 'wjm_retry_doi_' . $paper->ID );
			echo '<tr>';
			echo '<td><a href="' . esc_url( get_edit_post_link( $paper->ID ) ) . '">' . esc_html( $paper->post_title ) . '</a></td>';
			echo '<td><a href="https://doi.org/' . esc_attr( $doi ) . '" target="_blank" rel="noopener">' . esc_html( $doi ) . '</a></td>';
			echo '<td>' . esc_html( $status ? $status : '—' );
			if ( $err ) {
				echo '<br /><small style="color:#b32d2e;">' . esc_html( $err ) . '</small>';
			}
			echo '</td>';
			echo '<td><a href="' . esc_url( $retry ) . '">' . esc_html__( 'Retry deposit', 'wisdom-journal-manager' ) . '</a></td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	public static function journal_meta_box() {
		add_meta_box(
			'wjm_journal_doi',
			__( 'DOI settings', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_journal_doi_box' ),
			'sjm_journal',
			'side',
			'default'
		);
	}

	public static function render_journal_doi_box( $post ) {
		$prefix   = get_post_meta( $post->ID, '_sjm_doi_prefix', true );
		$acronym  = get_post_meta( $post->ID, '_sjm_doi_acronym', true );
		wp_nonce_field( 'wjm_journal_doi', 'wjm_journal_doi_nonce' );
		?>
		<p>
			<label for="sjm_doi_acronym"><strong><?php esc_html_e( 'Journal acronym (%j)', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" class="widefat" id="sjm_doi_acronym" name="sjm_doi_acronym" value="<?php echo esc_attr( $acronym ); ?>" placeholder="wjm" />
		</p>
		<p>
			<label for="sjm_doi_prefix"><strong><?php esc_html_e( 'Prefix override', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" class="widefat" id="sjm_doi_prefix" name="sjm_doi_prefix" value="<?php echo esc_attr( $prefix ); ?>" placeholder="10.12345" />
			<span class="description"><?php esc_html_e( 'Optional. Leave blank to use global prefix.', 'wisdom-journal-manager' ); ?></span>
		</p>
		<?php
	}

	public static function save_journal_doi_meta( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_journal_doi_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_journal_doi_nonce'] ) ), 'wjm_journal_doi' ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		update_post_meta( $post_id, '_sjm_doi_acronym', isset( $_POST['sjm_doi_acronym'] ) ? sanitize_title( wp_unslash( $_POST['sjm_doi_acronym'] ) ) : '' );
		$prefix = isset( $_POST['sjm_doi_prefix'] ) ? sanitize_text_field( wp_unslash( $_POST['sjm_doi_prefix'] ) ) : '';
		update_post_meta( $post_id, '_sjm_doi_prefix', $prefix );
		unset( $post );
	}

	public static function handle_register() {
		$paper_id = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_register_doi_' . $paper_id );
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$result = self::register( $paper_id, true );
		$args   = is_wp_error( $result )
			? array( 'wjm_err' => rawurlencode( $result->get_error_message() ) )
			: array( 'wjm_doi' => rawurlencode( $result ) );
		wp_safe_redirect( add_query_arg( $args, get_edit_post_link( $paper_id, 'raw' ) ) );
		exit;
	}

	public static function handle_retry_deposit() {
		$paper_id = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_retry_doi_' . $paper_id );
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'edit_others_sjm_papers' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$doi = get_post_meta( $paper_id, self::META_DOI, true );
		if ( ! $doi ) {
			self::register( $paper_id, true );
		} else {
			self::deposit( $doi, $paper_id );
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi&retried=1' ) );
		exit;
	}

	public static function handle_batch_issue() {
		check_admin_referer( 'wjm_batch_doi_issue' );
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'edit_others_sjm_papers' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$issue_id = isset( $_POST['issue_id'] ) ? absint( $_POST['issue_id'] ) : 0;
		$deposit  = ! empty( $_POST['deposit'] );
		$papers   = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'any',
				'posts_per_page' => -1,
				'fields'         => 'ids',
				'meta_key'       => '_sjm_issue_id',
				'meta_value'     => $issue_id,
			)
		);
		$ok = 0;
		foreach ( $papers as $pid ) {
			$r = self::register( $pid, $deposit );
			if ( ! is_wp_error( $r ) ) {
				$ok++;
			}
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi&batch=' . $ok ) );
		exit;
	}

	public static function handle_preview() {
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' ) );
		exit;
	}

	public static function handle_save_settings() {
		if ( ! self::can_manage() ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_doi_settings' );

		self::save_settings( wp_unslash( $_POST ) );

		$secrets = array(
			'wjm_crossref_user' => 'wjm_crossref_user',
			'wjm_crossref_pass' => 'wjm_crossref_pass',
			'wjm_datacite_user' => 'wjm_datacite_user',
			'wjm_datacite_pass' => 'wjm_datacite_pass',
		);
		foreach ( $secrets as $field => $option ) {
			if ( ! empty( $_POST[ $field ] ) ) {
				WJM_Encryption::set_secret( $option, sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) );
			}
		}

		WJM_Audit::log( 'info', 'doi_settings_updated', 'DOI manager settings saved.' );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi&saved=1' ) );
		exit;
	}

	public static function handle_test_connection() {
		if ( ! self::can_manage() ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_test_doi' );
		$agency = isset( $_GET['agency'] ) ? sanitize_key( wp_unslash( $_GET['agency'] ) ) : 'crossref';
		$result = self::test_connection( $agency );
		if ( is_wp_error( $result ) ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'test'     => '0',
						'test_msg' => rawurlencode( $result->get_error_message() ),
					),
					admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' )
				)
			);
			exit;
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi&test=1' ) );
		exit;
	}

	/**
	 * Enhance paper Export/DOI metabox content via filter-friendly helper.
	 *
	 * @param int $paper_id Paper ID.
	 * @return string HTML.
	 */
	public static function paper_panel_html( $paper_id ) {
		$doi     = get_post_meta( $paper_id, self::META_DOI, true );
		$status  = get_post_meta( $paper_id, self::META_STATUS, true );
		$error   = get_post_meta( $paper_id, self::META_ERROR, true );
		$preview = self::generate( $paper_id );
		$preview_s = is_wp_error( $preview ) ? $preview->get_error_message() : $preview;

		ob_start();
		echo '<div class="wjm-doi-panel">';
		if ( $doi ) {
			echo '<p><strong>DOI:</strong> <a href="https://doi.org/' . esc_attr( $doi ) . '" target="_blank" rel="noopener">' . esc_html( $doi ) . '</a></p>';
			echo '<p><strong>' . esc_html__( 'Deposit', 'wisdom-journal-manager' ) . ':</strong> ' . esc_html( $status ? $status : '—' ) . '</p>';
			if ( $error ) {
				echo '<p style="color:#b32d2e;"><small>' . esc_html( $error ) . '</small></p>';
			}
			$retry = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_retry_doi_deposit&paper_id=' . $paper_id ), 'wjm_retry_doi_' . $paper_id );
			echo '<p><a class="button" href="' . esc_url( $retry ) . '">' . esc_html__( 'Retry deposit', 'wisdom-journal-manager' ) . '</a></p>';
		} else {
			echo '<p><strong>' . esc_html__( 'Preview', 'wisdom-journal-manager' ) . ':</strong><br /><code>' . esc_html( $preview_s ) . '</code></p>';
			$url = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_register_doi&paper_id=' . $paper_id ), 'wjm_register_doi_' . $paper_id );
			echo '<p><a class="button button-primary" href="' . esc_url( $url ) . '">' . esc_html__( 'Generate & register DOI', 'wisdom-journal-manager' ) . '</a></p>';
		}
		echo '<p class="description"><a href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' ) ) . '">' . esc_html__( 'DOI Manager settings', 'wisdom-journal-manager' ) . '</a></p>';
		echo '</div>';
		return ob_get_clean();
	}

	/**
	 * @param string $text Text.
	 * @return string
	 */
	private static function x( $text ) {
		return htmlspecialchars( (string) $text, ENT_XML1 | ENT_COMPAT, 'UTF-8' );
	}
}
