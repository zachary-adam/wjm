<?php
/**
 * Scholarly API client — CrossRef, Semantic Scholar, arXiv, Scopus.
 * Web of Science citation counts are intentionally not wired.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_API_Client {

	/**
	 * Fetch citation-ish metrics for a DOI from a source.
	 *
	 * @param string $doi    DOI.
	 * @param string $source crossref|semantic_scholar|scopus|wos|arxiv
	 * @return array|WP_Error
	 */
	public static function fetch_citations( $doi, $source = 'crossref' ) {
		$check = WJM_Rate_Limiter::check( 'fetch' );
		if ( is_wp_error( $check ) ) {
			return $check;
		}

		$doi = trim( $doi );
		if ( '' === $doi ) {
			return new WP_Error( 'wjm_no_doi', __( 'DOI is required.', 'wisdom-journal-manager' ) );
		}

		switch ( $source ) {
			case 'semantic_scholar':
				return self::semantic_scholar( $doi );
			case 'scopus':
				return self::scopus( $doi );
			case 'wos':
				return self::web_of_science( $doi );
			case 'arxiv':
				return self::arxiv( $doi );
			case 'crossref':
			default:
				return self::crossref( $doi );
		}
	}

	private static function crossref( $doi ) {
		$url  = 'https://api.crossref.org/works/' . rawurlencode( $doi );
		$data = self::get_json( $url );
		if ( is_wp_error( $data ) ) {
			return $data;
		}

		$message = isset( $data['message'] ) ? $data['message'] : array();
		return array(
			'source'         => 'crossref',
			'citation_count' => isset( $message['is-referenced-by-count'] ) ? (int) $message['is-referenced-by-count'] : 0,
			'title'          => isset( $message['title'][0] ) ? $message['title'][0] : '',
			'raw'            => $message,
		);
	}

	private static function semantic_scholar( $doi ) {
		$url  = 'https://api.semanticscholar.org/graph/v1/paper/DOI:' . rawurlencode( $doi ) . '?fields=title,citationCount,influentialCitationCount';
		$headers = array();
		$key = WJM_Encryption::get_secret( 'wjm_api_semantic_scholar' );
		if ( $key ) {
			$headers['x-api-key'] = $key;
		}

		$data = self::get_json( $url, $headers );
		if ( is_wp_error( $data ) ) {
			return $data;
		}

		return array(
			'source'         => 'semantic_scholar',
			'citation_count' => isset( $data['citationCount'] ) ? (int) $data['citationCount'] : 0,
			'title'          => isset( $data['title'] ) ? $data['title'] : '',
			'raw'            => $data,
		);
	}

	private static function scopus( $doi ) {
		$key = WJM_Encryption::get_secret( 'wjm_api_scopus' );
		if ( ! $key ) {
			return new WP_Error( 'wjm_no_key', __( 'Scopus API key not configured.', 'wisdom-journal-manager' ) );
		}

		$url  = 'https://api.elsevier.com/content/abstract/doi/' . rawurlencode( $doi );
		$data = self::get_json(
			$url,
			array(
				'Accept' => 'application/json',
				'X-ELS-APIKey' => $key,
			)
		);
		if ( is_wp_error( $data ) ) {
			return $data;
		}

		$count = 0;
		if ( isset( $data['abstracts-retrieval-response']['coredata']['citedby-count'] ) ) {
			$count = (int) $data['abstracts-retrieval-response']['coredata']['citedby-count'];
		}

		return array(
			'source'         => 'scopus',
			'citation_count' => $count,
			'raw'            => $data,
		);
	}

	private static function web_of_science( $doi ) {
		unset( $doi );
		// Clarivate citation counts are not parsed in this release — refuse rather than return a fake 0.
		return new WP_Error(
			'wjm_wos_unsupported',
			__( 'Web of Science citation counts are not wired in this version. Use Crossref, Semantic Scholar, or Scopus.', 'wisdom-journal-manager' )
		);
	}

	private static function arxiv( $id ) {
		$url = 'http://export.arxiv.org/api/query?id_list=' . rawurlencode( $id );
		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$body = wp_remote_retrieve_body( $response );
		return array(
			'source'         => 'arxiv',
			'citation_count' => 0,
			'raw'            => $body,
		);
	}

	/**
	 * @param string $url     Request URL.
	 * @param array  $headers Optional headers.
	 * @return array|WP_Error
	 */
	private static function get_json( $url, $headers = array() ) {
		$check = WJM_Rate_Limiter::check( 'api' );
		if ( is_wp_error( $check ) ) {
			return $check;
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 25,
				'headers' => array_merge(
					array(
						'User-Agent' => 'WisdomJournalManager/' . WJM_VERSION . ' (mailto:zadam@aethexweb.com)',
					),
					$headers
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'wjm_api_http', sprintf( 'API HTTP %d', $code ), array( 'body' => $body ) );
		}

		$data = json_decode( $body, true );
		if ( null === $data ) {
			return new WP_Error( 'wjm_api_json', __( 'Invalid JSON from API.', 'wisdom-journal-manager' ) );
		}

		return $data;
	}
}
