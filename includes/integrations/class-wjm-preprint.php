<?php
/**
 * Preprint URL / DOI transfer-in (bioRxiv, medRxiv, Crossref, OSF).
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Preprint {

	public static function init() {
		add_action( 'wp_ajax_wjm_preprint_lookup', array( __CLASS__, 'ajax_lookup' ) );
		add_action( 'wp_ajax_nopriv_wjm_preprint_lookup', array( __CLASS__, 'ajax_lookup' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
	}

	public static function enqueue() {
		global $post;
		$need = is_singular() && $post instanceof WP_Post && (
			has_shortcode( $post->post_content, 'wjm_submit' )
			|| false !== strpos( $post->post_content, '[wjm_submit' )
		);
		if ( ! $need ) {
			return;
		}
		wp_enqueue_script(
			'wjm-preprint',
			WJM_PLUGIN_URL . 'assets/js/preprint.js',
			array(),
			WJM_VERSION,
			true
		);
		wp_localize_script(
			'wjm-preprint',
			'wjmPreprint',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'wjm_preprint_lookup' ),
			)
		);
	}

	public static function ajax_lookup() {
		check_ajax_referer( 'wjm_preprint_lookup', 'nonce' );
		$input = isset( $_POST['url'] ) ? sanitize_text_field( wp_unslash( $_POST['url'] ) ) : '';
		$data  = self::lookup( $input );
		if ( is_wp_error( $data ) ) {
			wp_send_json_error( array( 'message' => $data->get_error_message() ) );
		}
		wp_send_json_success( $data );
	}

	/**
	 * @param string $input URL or DOI.
	 * @return array|WP_Error
	 */
	public static function lookup( $input ) {
		$input = trim( (string) $input );
		if ( ! $input ) {
			return new WP_Error( 'wjm_preprint', __( 'Enter a preprint URL or DOI.', 'wisdom-journal-manager' ) );
		}

		$doi = self::extract_doi( $input );
		$url = ( 0 === stripos( $input, 'http' ) ) ? esc_url_raw( $input ) : '';

		// bioRxiv / medRxiv content API.
		if ( $doi && ( false !== stripos( $input, 'biorxiv' ) || false !== stripos( $input, 'medrxiv' ) || self::looks_biorxiv_doi( $doi ) ) ) {
			$server = ( false !== stripos( $input, 'medrxiv' ) || 0 === stripos( $doi, '10.1101' ) && false !== stripos( $input, 'med' ) ) ? 'medrxiv' : 'biorxiv';
			if ( false !== stripos( $input, 'medrxiv' ) ) {
				$server = 'medrxiv';
			}
			$bx = self::fetch_biorxiv( $doi, $server );
			if ( ! is_wp_error( $bx ) ) {
				return $bx;
			}
		}

		// OSF preprints.
		if ( $url && ( false !== stripos( $url, 'osf.io' ) || false !== stripos( $url, 'osf.io/preprints' ) ) ) {
			$osf = self::fetch_osf( $url );
			if ( ! is_wp_error( $osf ) ) {
				return $osf;
			}
		}

		if ( $doi ) {
			$cr = self::fetch_crossref( $doi );
			if ( ! is_wp_error( $cr ) ) {
				return $cr;
			}
			return $cr;
		}

		return new WP_Error( 'wjm_preprint', __( 'Could not resolve preprint metadata. Try a DOI.', 'wisdom-journal-manager' ) );
	}

	/**
	 * @param string $input Input.
	 * @return string
	 */
	public static function extract_doi( $input ) {
		$input = trim( $input );
		if ( preg_match( '#(10\.\d{4,9}/[-._;()/:A-Z0-9]+)#i', $input, $m ) ) {
			return rtrim( $m[1], '.)],' );
		}
		if ( preg_match( '#doi\.org/(10\.[^\s]+)#i', $input, $m ) ) {
			return rtrim( $m[1], '.)],' );
		}
		return '';
	}

	/**
	 * @param string $doi DOI.
	 * @return bool
	 */
	private static function looks_biorxiv_doi( $doi ) {
		return 0 === stripos( $doi, '10.1101/' );
	}

	/**
	 * @param string $doi DOI.
	 * @param string $server biorxiv|medrxiv.
	 * @return array|WP_Error
	 */
	private static function fetch_biorxiv( $doi, $server = 'biorxiv' ) {
		$server = 'medrxiv' === $server ? 'medrxiv' : 'biorxiv';
		$api    = sprintf( 'https://api.biorxiv.org/details/%s/%s', $server, rawurlencode( $doi ) );
		$res    = wp_remote_get( $api, array( 'timeout' => 15 ) );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		$row  = $body['collection'][0] ?? null;
		if ( ! is_array( $row ) ) {
			return new WP_Error( 'wjm_preprint', __( 'bioRxiv/medRxiv record not found.', 'wisdom-journal-manager' ) );
		}
		$authors = array();
		if ( ! empty( $row['authors'] ) ) {
			foreach ( preg_split( '/\s*;\s*/', $row['authors'] ) as $a ) {
				$a = trim( $a );
				if ( $a ) {
					$authors[] = $a . '; ; ; ;';
				}
			}
		}
		$abs = $row['abstract'] ?? '';
		return array(
			'title'       => sanitize_text_field( $row['title'] ?? '' ),
			'abstract'    => sanitize_textarea_field( wp_strip_all_tags( $abs ) ),
			'doi'         => sanitize_text_field( $row['doi'] ?? $doi ),
			'preprint_url'=> esc_url_raw( sprintf( 'https://www.%s.org/content/%s', $server, $doi ) ),
			'authors_text'=> implode( "\n", $authors ),
			'source'      => $server,
		);
	}

	/**
	 * @param string $doi DOI.
	 * @return array|WP_Error
	 */
	private static function fetch_crossref( $doi ) {
		$api = 'https://api.crossref.org/works/' . rawurlencode( $doi );
		$res = wp_remote_get(
			$api,
			array(
				'timeout' => 15,
				'headers' => array(
					'User-Agent' => 'WisdomJournalManager/' . WJM_VERSION . ' (mailto:editors@example.com)',
				),
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return new WP_Error( 'wjm_preprint', __( 'Crossref record not found.', 'wisdom-journal-manager' ) );
		}
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		$msg  = $body['message'] ?? array();
		if ( ! $msg ) {
			return new WP_Error( 'wjm_preprint', __( 'Crossref record empty.', 'wisdom-journal-manager' ) );
		}
		$title = is_array( $msg['title'] ?? null ) ? ( $msg['title'][0] ?? '' ) : (string) ( $msg['title'] ?? '' );
		$abs   = '';
		if ( ! empty( $msg['abstract'] ) ) {
			$abs = wp_strip_all_tags( $msg['abstract'] );
		}
		$authors = array();
		foreach ( (array) ( $msg['author'] ?? array() ) as $a ) {
			$name = trim( ( $a['given'] ?? '' ) . ' ' . ( $a['family'] ?? '' ) );
			$orcid = '';
			if ( ! empty( $a['ORCID'] ) ) {
				$orcid = preg_replace( '#.*/#', '', $a['ORCID'] );
			}
			if ( $name ) {
				$authors[] = $name . '; ; ' . $orcid . '; ;';
			}
		}
		$url = '';
		if ( ! empty( $msg['URL'] ) ) {
			$url = $msg['URL'];
		} elseif ( ! empty( $msg['resource']['primary']['URL'] ) ) {
			$url = $msg['resource']['primary']['URL'];
		} else {
			$url = 'https://doi.org/' . $doi;
		}
		return array(
			'title'        => sanitize_text_field( $title ),
			'abstract'     => sanitize_textarea_field( $abs ),
			'doi'          => sanitize_text_field( $doi ),
			'preprint_url' => esc_url_raw( $url ),
			'authors_text' => implode( "\n", $authors ),
			'source'       => 'crossref',
		);
	}

	/**
	 * @param string $url OSF URL.
	 * @return array|WP_Error
	 */
	private static function fetch_osf( $url ) {
		$path = wp_parse_url( $url, PHP_URL_PATH );
		$id   = '';
		if ( preg_match( '#/([a-z0-9]{5,})/?$#i', (string) $path, $m ) ) {
			$id = $m[1];
		}
		if ( ! $id ) {
			return new WP_Error( 'wjm_preprint', __( 'Could not parse OSF preprint id.', 'wisdom-journal-manager' ) );
		}
		$api = 'https://api.osf.io/v2/preprints/' . rawurlencode( $id ) . '/';
		$res = wp_remote_get( $api, array( 'timeout' => 15 ) );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		$attrs = $body['data']['attributes'] ?? null;
		if ( ! is_array( $attrs ) ) {
			return new WP_Error( 'wjm_preprint', __( 'OSF preprint not found.', 'wisdom-journal-manager' ) );
		}
		$doi = $attrs['doi'] ?? '';
		if ( $doi ) {
			$cr = self::fetch_crossref( self::extract_doi( $doi ) ?: $doi );
			if ( ! is_wp_error( $cr ) ) {
				$cr['preprint_url'] = esc_url_raw( $url );
				$cr['source']       = 'osf';
				return $cr;
			}
		}
		return array(
			'title'        => sanitize_text_field( $attrs['title'] ?? '' ),
			'abstract'     => sanitize_textarea_field( wp_strip_all_tags( $attrs['description'] ?? '' ) ),
			'doi'          => sanitize_text_field( $doi ),
			'preprint_url' => esc_url_raw( $url ),
			'authors_text' => '',
			'source'       => 'osf',
		);
	}
}
