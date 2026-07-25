<?php
/**
 * Custom post types: Journal, Issue, Paper.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Post_Types {

	/**
	 * Register CPTs and taxonomies.
	 */
	public static function register() {
		self::register_journal();
		self::register_issue();
		self::register_paper();
		self::register_taxonomies();
	}

	private static function register_journal() {
		register_post_type(
			'sjm_journal',
			array(
				'labels'              => array(
					'name'          => __( 'Journals', 'wisdom-journal-manager' ),
					'singular_name' => __( 'Journal', 'wisdom-journal-manager' ),
					'add_new_item'  => __( 'Add New Journal', 'wisdom-journal-manager' ),
					'edit_item'     => __( 'Edit Journal', 'wisdom-journal-manager' ),
					'menu_name'     => __( 'Journals', 'wisdom-journal-manager' ),
				),
				'public'              => true,
				'has_archive'         => true,
				'show_in_rest'        => true,
				'menu_icon'           => 'dashicons-book-alt',
				'menu_position'       => 25,
				'supports'            => array( 'title', 'editor', 'thumbnail', 'excerpt', 'revisions' ),
				'rewrite'             => array( 'slug' => 'journals' ),
				'capability_type'     => array( 'sjm_journal', 'sjm_journals' ),
				'map_meta_cap'        => true,
			)
		);
	}

	private static function register_issue() {
		register_post_type(
			'sjm_issue',
			array(
				'labels'              => array(
					'name'          => __( 'Issues', 'wisdom-journal-manager' ),
					'singular_name' => __( 'Issue', 'wisdom-journal-manager' ),
					'add_new_item'  => __( 'Add New Issue', 'wisdom-journal-manager' ),
					'edit_item'     => __( 'Edit Issue', 'wisdom-journal-manager' ),
				),
				'public'              => true,
				'has_archive'         => true,
				'show_in_rest'        => true,
				'show_in_menu'        => 'edit.php?post_type=sjm_journal',
				'supports'            => array( 'title', 'editor', 'thumbnail', 'excerpt' ),
				'rewrite'             => array( 'slug' => 'issues' ),
				'capability_type'     => array( 'sjm_issue', 'sjm_issues' ),
				'map_meta_cap'        => true,
			)
		);
	}

	private static function register_paper() {
		register_post_type(
			'sjm_paper',
			array(
				'labels'              => array(
					'name'          => __( 'Papers', 'wisdom-journal-manager' ),
					'singular_name' => __( 'Paper', 'wisdom-journal-manager' ),
					'add_new_item'  => __( 'Add New Paper', 'wisdom-journal-manager' ),
					'edit_item'     => __( 'Edit Paper', 'wisdom-journal-manager' ),
				),
				'public'              => true,
				'has_archive'         => true,
				'show_in_rest'        => true,
				'show_in_menu'        => 'edit.php?post_type=sjm_journal',
				'supports'            => array( 'title', 'editor', 'thumbnail', 'excerpt', 'revisions' ),
				'rewrite'             => array( 'slug' => 'papers' ),
				'capability_type'     => array( 'sjm_paper', 'sjm_papers' ),
				'map_meta_cap'        => true,
			)
		);
	}

	private static function register_taxonomies() {
		register_taxonomy(
			'sjm_subject',
			array( 'sjm_journal', 'sjm_paper' ),
			array(
				'labels'       => array(
					'name'          => __( 'Subjects', 'wisdom-journal-manager' ),
					'singular_name' => __( 'Subject', 'wisdom-journal-manager' ),
				),
				'public'       => true,
				'hierarchical' => true,
				'show_in_rest' => true,
				'rewrite'      => array( 'slug' => 'subject' ),
			)
		);

		register_taxonomy(
			'sjm_keyword',
			'sjm_paper',
			array(
				'labels'       => array(
					'name'          => __( 'Keywords', 'wisdom-journal-manager' ),
					'singular_name' => __( 'Keyword', 'wisdom-journal-manager' ),
				),
				'public'       => true,
				'hierarchical' => false,
				'show_in_rest' => true,
				'rewrite'      => array( 'slug' => 'keyword' ),
			)
		);
	}
}
