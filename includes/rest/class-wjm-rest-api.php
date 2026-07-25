<?php
/**
 * REST API for headless frontends and integrations.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_REST_API {

	const NS = 'wjm/v1';

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	public static function register_routes() {
		register_rest_route(
			self::NS,
			'/journals',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'journals' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NS,
			'/papers',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'papers' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NS,
			'/papers/(?P<id>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'paper' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NS,
			'/papers/(?P<id>\d+)/jats',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'paper_jats' ),
				'permission_callback' => function () {
					return current_user_can( 'edit_sjm_papers' ) || current_user_can( 'manage_options' );
				},
			)
		);

		register_rest_route(
			self::NS,
			'/papers/(?P<id>\d+)/status',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'set_status' ),
				'permission_callback' => function () {
					return current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' );
				},
			)
		);

		register_rest_route(
			self::NS,
			'/authors/(?P<id>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'author' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NS,
			'/stats',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'stats' ),
				'permission_callback' => function () {
					return current_user_can( 'view_sjm_analytics' ) || current_user_can( 'manage_options' );
				},
			)
		);
	}

	public static function journals( $request ) {
		$q = new WP_Query(
			apply_filters(
				'sjm_journal_query_args',
				array(
					'post_type'      => 'sjm_journal',
					'post_status'    => 'publish',
					'posts_per_page' => 100,
				)
			)
		);
		$data = array();
		foreach ( $q->posts as $post ) {
			$data[] = self::format_journal( $post );
		}
		return rest_ensure_response( $data );
	}

	public static function papers( $request ) {
		$args = array(
			'post_type'      => 'sjm_paper',
			'post_status'    => 'publish',
			'posts_per_page' => min( 100, absint( $request->get_param( 'per_page' ) ? $request->get_param( 'per_page' ) : 20 ) ),
			'paged'          => max( 1, absint( $request->get_param( 'page' ) ) ),
		);
		if ( $request->get_param( 'search' ) ) {
			$args['s'] = sanitize_text_field( $request->get_param( 'search' ) );
		}
		$args = apply_filters( 'sjm_paper_query_args', $args );
		$q    = new WP_Query( $args );
		$data = array();
		foreach ( $q->posts as $post ) {
			$data[] = self::format_paper( $post );
		}
		return rest_ensure_response(
			array(
				'items' => $data,
				'total' => (int) $q->found_posts,
				'pages' => (int) $q->max_num_pages,
			)
		);
	}

	public static function paper( $request ) {
		$post = get_post( absint( $request['id'] ) );
		if ( ! $post || 'sjm_paper' !== $post->post_type ) {
			return new WP_Error( 'wjm_not_found', 'Paper not found', array( 'status' => 404 ) );
		}
		if ( 'publish' !== $post->post_status && ! current_user_can( 'edit_post', $post->ID ) ) {
			return new WP_Error( 'wjm_forbidden', 'Forbidden', array( 'status' => 403 ) );
		}
		return rest_ensure_response( self::format_paper( $post, true ) );
	}

	public static function paper_jats( $request ) {
		$paper_id = absint( $request['id'] );
		return new WP_REST_Response( WJM_JATS::export_paper( $paper_id ), 200, array( 'Content-Type' => 'application/xml' ) );
	}

	public static function set_status( $request ) {
		$paper_id = absint( $request['id'] );
		$to       = sanitize_key( $request->get_param( 'status' ) );
		$note     = sanitize_textarea_field( (string) $request->get_param( 'note' ) );
		$result   = WJM_Workflow::transition( $paper_id, $to, $note );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return rest_ensure_response(
			array(
				'id'     => $paper_id,
				'status' => WJM_Workflow::get_status( $paper_id ),
			)
		);
	}

	public static function author( $request ) {
		$author = WJM_Author_Profiles::get_author( absint( $request['id'] ) );
		if ( ! $author ) {
			return new WP_Error( 'wjm_not_found', 'Author not found', array( 'status' => 404 ) );
		}
		return rest_ensure_response(
			array(
				'id'          => (int) $author->id,
				'first_name'  => $author->first_name,
				'last_name'   => $author->last_name,
				'orcid'       => $author->orcid,
				'affiliation' => $author->affiliation,
				'h_index'     => $author->h_index,
				'bio'         => $author->bio,
			)
		);
	}

	public static function stats() {
		return rest_ensure_response( WJM_Analytics_Dashboard::collect() );
	}

	private static function format_journal( $post ) {
		$row = WJM_Repository::get_journal_by_post( $post->ID );
		return array(
			'id'          => $post->ID,
			'entity_id'   => $row ? (int) $row->id : null,
			'title'       => $row ? $row->title : get_the_title( $post ),
			'link'        => get_permalink( $post ),
			'issn'        => $row ? $row->issn : get_post_meta( $post->ID, '_sjm_issn', true ),
			'publisher'   => $row ? $row->publisher : get_post_meta( $post->ID, '_sjm_publisher', true ),
			'excerpt'     => get_the_excerpt( $post ),
		);
	}

	private static function format_paper( $post, $detailed = false ) {
		$row  = WJM_Repository::get_paper_by_post( $post->ID );
		$data = array(
			'id'          => $post->ID,
			'entity_id'   => $row ? (int) $row->id : null,
			'journal_id'  => $row ? (int) $row->journal_post_id : (int) get_post_meta( $post->ID, '_sjm_journal_id', true ),
			'issue_id'    => $row ? (int) $row->issue_post_id : (int) get_post_meta( $post->ID, '_sjm_issue_id', true ),
			'title'       => $row ? $row->title : get_the_title( $post ),
			'link'        => get_permalink( $post ),
			'doi'         => $row ? $row->doi : get_post_meta( $post->ID, '_sjm_doi', true ),
			'type'        => $row ? $row->paper_type : get_post_meta( $post->ID, '_sjm_paper_type', true ),
			'status'      => $row ? $row->workflow_status : WJM_Workflow::get_status( $post->ID ),
			'citations'   => $row ? (int) $row->citation_total : (int) get_post_meta( $post->ID, '_sjm_citation_total', true ),
			'open_access' => $row ? (bool) $row->open_access : (bool) get_post_meta( $post->ID, '_sjm_open_access', true ),
			'date'        => get_the_date( 'c', $post ),
		);
		if ( $detailed ) {
			$data['abstract'] = $row ? $row->abstract : get_post_meta( $post->ID, '_sjm_abstract', true );
			$data['authors']  = array_map(
				function ( $a ) {
					return array(
						'id'         => (int) $a->id,
						'name'       => trim( $a->first_name . ' ' . $a->last_name ),
						'orcid'      => $a->orcid,
						'affiliation'=> $a->affiliation,
					);
				},
				WJM_Author_Profiles::get_authors_for_paper( $post->ID )
			);
			$data['keywords'] = wp_get_post_terms( $post->ID, 'sjm_keyword', array( 'fields' => 'names' ) );
			$data['metrics']  = WJM_Advanced_Metrics::for_paper( $post->ID );
		}
		return $data;
	}
}
