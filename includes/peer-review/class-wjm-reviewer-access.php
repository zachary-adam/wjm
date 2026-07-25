<?php
/**
 * Allow assigned reviewers to read private manuscripts + files.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Reviewer_Access {

	public static function init() {
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), 10, 4 );
		add_filter( 'user_has_cap', array( __CLASS__, 'user_has_cap' ), 10, 4 );
	}

	/**
	 * @param int $user_id  User ID.
	 * @param int $paper_id Paper ID.
	 * @return bool
	 */
	public static function is_assigned( $user_id, $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'assignments' );
		$id    = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE paper_id = %d AND reviewer_user_id = %d AND status IN ('invited','accepted','in_progress','completed') LIMIT 1",
				absint( $paper_id ),
				absint( $user_id )
			)
		);
		return ! empty( $id );
	}

	/**
	 * @param string[] $caps    Required caps.
	 * @param string   $cap     Capability.
	 * @param int      $user_id User ID.
	 * @param array    $args    Args.
	 * @return string[]
	 */
	public static function map_meta_cap( $caps, $cap, $user_id, $args ) {
		if ( ! in_array( $cap, array( 'read_post', 'read_sjm_paper' ), true ) || empty( $args[0] ) ) {
			return $caps;
		}

		$post = get_post( $args[0] );
		if ( ! $post || 'sjm_paper' !== $post->post_type ) {
			return $caps;
		}

		if ( self::is_assigned( $user_id, $post->ID ) ) {
			return array( 'read' );
		}

		return $caps;
	}

	/**
	 * Grant read_private_sjm_papers dynamically for assigned reviewers.
	 *
	 * @param array   $allcaps All caps.
	 * @param array   $caps    Requested.
	 * @param array   $args    Args.
	 * @param WP_User $user    User.
	 * @return array
	 */
	public static function user_has_cap( $allcaps, $caps, $args, $user ) {
		if ( empty( $args[0] ) || 'read_post' !== $args[0] || empty( $args[2] ) ) {
			// Also allow listing private papers in My Reviews context via read_private.
			if ( in_array( 'read_private_sjm_papers', $caps, true ) ) {
				// Don't grant globally — keep map_meta_cap path.
				return $allcaps;
			}
			return $allcaps;
		}

		$post = get_post( $args[2] );
		if ( $post && 'sjm_paper' === $post->post_type && self::is_assigned( $user->ID, $post->ID ) ) {
			$allcaps['read_post'] = true;
			$allcaps[ 'read_sjm_paper' ] = true;
			$allcaps['read_private_sjm_papers'] = true;
		}

		return $allcaps;
	}
}
