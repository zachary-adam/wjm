<?php
/**
 * JATS XML export for indexing / interchange.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_JATS {

	public static function init() {
		add_action( 'admin_post_wjm_export_jats', array( __CLASS__, 'download' ) );
		add_filter( 'post_row_actions', array( __CLASS__, 'row_action' ), 10, 2 );
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_jats',
			__( 'Export / DOI', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	public static function render_box( $post ) {
		$url = wp_nonce_url(
			admin_url( 'admin-post.php?action=wjm_export_jats&paper_id=' . $post->ID ),
			'wjm_export_jats_' . $post->ID
		);
		echo '<p><a class="button" href="' . esc_url( $url ) . '">' . esc_html__( 'Download JATS XML', 'wisdom-journal-manager' ) . '</a></p>';

		if ( current_user_can( 'manage_options' ) || current_user_can( 'edit_others_sjm_papers' ) ) {
			echo WJM_DOI::paper_panel_html( $post->ID ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
	}

	public static function row_action( $actions, $post ) {
		if ( 'sjm_paper' === $post->post_type ) {
			$url = wp_nonce_url(
				admin_url( 'admin-post.php?action=wjm_export_jats&paper_id=' . $post->ID ),
				'wjm_export_jats_' . $post->ID
			);
			$actions['wjm_jats'] = '<a href="' . esc_url( $url ) . '">JATS</a>';
		}
		return $actions;
	}

	public static function download() {
		$paper_id = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_export_jats_' . $paper_id );

		if ( ! $paper_id || ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$xml = self::export_paper( $paper_id );
		$slug = sanitize_title( get_the_title( $paper_id ) );

		nocache_headers();
		header( 'Content-Type: application/xml; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="jats-' . $slug . '.xml"' );
		echo $xml; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	/**
	 * Build a minimal JATS article XML document.
	 *
	 * @param int $paper_id Paper ID.
	 * @return string
	 */
	public static function export_paper( $paper_id ) {
		$paper    = get_post( $paper_id );
		$doi      = get_post_meta( $paper_id, '_sjm_doi', true );
		$abstract = get_post_meta( $paper_id, '_sjm_abstract', true );
		$authors  = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
		$keywords = wp_get_post_terms( $paper_id, 'sjm_keyword', array( 'fields' => 'names' ) );

		$issue_id   = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
		$journal_id = $issue_id ? (int) get_post_meta( $issue_id, '_sjm_journal_id', true ) : (int) get_post_meta( $paper_id, '_sjm_journal_id', true );
		$journal    = $journal_id ? get_the_title( $journal_id ) : get_bloginfo( 'name' );
		$issn       = $journal_id ? get_post_meta( $journal_id, '_sjm_issn', true ) : '';
		$volume     = $issue_id ? get_post_meta( $issue_id, '_sjm_volume', true ) : '';
		$number     = $issue_id ? get_post_meta( $issue_id, '_sjm_number', true ) : '';

		$dom  = new DOMDocument( '1.0', 'UTF-8' );
		$dom->formatOutput = true;

		$article = $dom->createElement( 'article' );
		$article->setAttribute( 'xmlns:xlink', 'http://www.w3.org/1999/xlink' );
		$article->setAttribute( 'article-type', 'research-article' );
		$article->setAttribute( 'dtd-version', '1.3' );
		$dom->appendChild( $article );

		$front = $dom->createElement( 'front' );
		$article->appendChild( $front );

		$jm = $dom->createElement( 'journal-meta' );
		$front->appendChild( $jm );
		$jm->appendChild( $dom->createElement( 'journal-title-group' ) )->appendChild( $dom->createElement( 'journal-title', self::xml( $journal ) ) );
		if ( $issn ) {
			$issn_el = $dom->createElement( 'issn', self::xml( $issn ) );
			$issn_el->setAttribute( 'publication-format', 'electronic' );
			$jm->appendChild( $issn_el );
		}

		$am = $dom->createElement( 'article-meta' );
		$front->appendChild( $am );

		if ( $doi ) {
			$aid = $dom->createElement( 'article-id', self::xml( $doi ) );
			$aid->setAttribute( 'pub-id-type', 'doi' );
			$am->appendChild( $aid );
		}

		$tg = $dom->createElement( 'title-group' );
		$tg->appendChild( $dom->createElement( 'article-title', self::xml( $paper->post_title ) ) );
		$am->appendChild( $tg );

		$cg = $dom->createElement( 'contrib-group' );
		foreach ( $authors as $author ) {
			$contrib = $dom->createElement( 'contrib' );
			$contrib->setAttribute( 'contrib-type', 'author' );
			$name = $dom->createElement( 'name' );
			$name->appendChild( $dom->createElement( 'surname', self::xml( $author->last_name ) ) );
			$name->appendChild( $dom->createElement( 'given-names', self::xml( $author->first_name ) ) );
			$contrib->appendChild( $name );
			if ( $author->orcid ) {
				$cid = $dom->createElement( 'contrib-id', self::xml( $author->orcid ) );
				$cid->setAttribute( 'contrib-id-type', 'orcid' );
				$contrib->appendChild( $cid );
			}
			if ( $author->affiliation ) {
				$contrib->appendChild( $dom->createElement( 'aff', self::xml( $author->affiliation ) ) );
			}
			$cg->appendChild( $contrib );
		}
		$am->appendChild( $cg );

		if ( $volume || $number ) {
			if ( $volume ) {
				$am->appendChild( $dom->createElement( 'volume', self::xml( $volume ) ) );
			}
			if ( $number ) {
				$am->appendChild( $dom->createElement( 'issue', self::xml( $number ) ) );
			}
		}

		if ( $abstract ) {
			$abs = $dom->createElement( 'abstract' );
			$abs->appendChild( $dom->createElement( 'p', self::xml( $abstract ) ) );
			$am->appendChild( $abs );
		}

		if ( $keywords && ! is_wp_error( $keywords ) ) {
			$kwd_group = $dom->createElement( 'kwd-group' );
			foreach ( $keywords as $kw ) {
				$kwd_group->appendChild( $dom->createElement( 'kwd', self::xml( $kw ) ) );
			}
			$am->appendChild( $kwd_group );
		}

		$body = $dom->createElement( 'body' );
		$sec  = $dom->createElement( 'sec' );
		$sec->appendChild( $dom->createElement( 'title', 'Article' ) );
		$sec->appendChild( $dom->createElement( 'p', self::xml( wp_strip_all_tags( $paper->post_content ) ) ) );
		$body->appendChild( $sec );
		$article->appendChild( $body );

		return $dom->saveXML();
	}

	/**
	 * Escape for text nodes (DOMDocument handles most; keep simple).
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private static function xml( $text ) {
		return htmlspecialchars( (string) $text, ENT_XML1 | ENT_COMPAT, 'UTF-8' );
	}
}
