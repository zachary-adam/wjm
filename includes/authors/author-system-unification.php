<?php
/**
 * Author identity unification across papers and affiliations.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Author_Unification {

	public static function init() {
		add_action( 'admin_post_wjm_merge_authors', array( __CLASS__, 'handle_merge' ) );
	}

	/**
	 * Find potential duplicate authors by ORCID or name+email.
	 *
	 * @return array[]
	 */
	public static function find_duplicates() {
		$authors = WJM_Author_Profiles::get_all_authors();
		$groups  = array();

		foreach ( $authors as $author ) {
			$key = '';
			if ( ! empty( $author->orcid ) ) {
				$key = 'orcid:' . strtolower( $author->orcid );
			} elseif ( ! empty( $author->email ) ) {
				$key = 'email:' . strtolower( $author->email );
			} else {
				$key = 'name:' . strtolower( $author->last_name . '|' . $author->first_name );
			}
			$groups[ $key ][] = $author;
		}

		return array_values(
			array_filter(
				$groups,
				function ( $group ) {
					return count( $group ) > 1;
				}
			)
		);
	}

	/**
	 * Merge source author into target, reassigning paper links.
	 *
	 * @param int $target_id Canonical author.
	 * @param int $source_id Duplicate to absorb.
	 * @return bool
	 */
	public static function merge( $target_id, $source_id ) {
		$target_id = absint( $target_id );
		$source_id = absint( $source_id );
		if ( ! $target_id || ! $source_id || $target_id === $source_id ) {
			return false;
		}

		global $wpdb;
		$link = WJM_Database_Schema::table( 'paper_authors' );
		$authors = WJM_Database_Schema::table( 'authors' );

		$source_links = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$link} WHERE author_id = %d", $source_id )
		);

		foreach ( $source_links as $row ) {
			$exists = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT id FROM {$link} WHERE paper_id = %d AND author_id = %d",
					$row->paper_id,
					$target_id
				)
			);
			if ( $exists ) {
				$wpdb->delete( $link, array( 'id' => $row->id ), array( '%d' ) );
			} else {
				$wpdb->update( $link, array( 'author_id' => $target_id ), array( 'id' => $row->id ), array( '%d' ), array( '%d' ) );
			}
		}

		$source = WJM_Author_Profiles::get_author( $source_id );
		$target = WJM_Author_Profiles::get_author( $target_id );
		if ( $source && $target ) {
			$update = array();
			if ( empty( $target->orcid ) && ! empty( $source->orcid ) ) {
				$update['orcid'] = $source->orcid;
			}
			if ( empty( $target->affiliation ) && ! empty( $source->affiliation ) ) {
				$update['affiliation'] = $source->affiliation;
			}
			if ( empty( $target->bio ) && ! empty( $source->bio ) ) {
				$update['bio'] = $source->bio;
			}
			if ( null === $target->h_index && null !== $source->h_index ) {
				$update['h_index'] = $source->h_index;
			}
			if ( $update ) {
				$wpdb->update( $authors, $update, array( 'id' => $target_id ) );
			}
		}

		$wpdb->delete( $authors, array( 'id' => $source_id ), array( '%d' ) );
		WJM_Audit::log( 'info', 'author_merged', sprintf( 'Merged author %d into %d.', $source_id, $target_id ) );
		return true;
	}

	public static function handle_merge() {
		if ( ! current_user_can( 'manage_sjm_authors' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_merge_authors' );

		$target = isset( $_POST['target_id'] ) ? absint( $_POST['target_id'] ) : 0;
		$source = isset( $_POST['source_id'] ) ? absint( $_POST['source_id'] ) : 0;
		self::merge( $target, $source );

		wp_safe_redirect( admin_url( 'admin.php?page=wjm-authors&merged=1' ) );
		exit;
	}
}
