<?php
/**
 * Role-based access control — Student, Researcher, Editor, Administrator.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Roles {

	/**
	 * Register custom roles and grant capabilities.
	 */
	/**
	 * Primitive capabilities for a CPT capability_type pair.
	 *
	 * @param string $singular Singular type, e.g. sjm_paper.
	 * @param string $plural   Plural type, e.g. sjm_papers.
	 * @return string[]
	 */
	private static function cpt_caps( $singular, $plural ) {
		return array(
			"edit_{$singular}",
			"read_{$singular}",
			"delete_{$singular}",
			"edit_{$plural}",
			"edit_others_{$plural}",
			"publish_{$plural}",
			"read_private_{$plural}",
			"delete_{$plural}",
			"delete_private_{$plural}",
			"delete_published_{$plural}",
			"delete_others_{$plural}",
			"edit_private_{$plural}",
			"edit_published_{$plural}",
			"create_{$plural}",
		);
	}

	public static function register_roles() {
		$student_caps = array(
			'read' => true,
		);

		$researcher_caps = $student_caps;
		foreach ( self::cpt_caps( 'sjm_paper', 'sjm_papers' ) as $cap ) {
			// Researchers may create/edit their own papers; others-caps granted to editors.
			if ( false !== strpos( $cap, 'others' ) || false !== strpos( $cap, 'private' ) || false !== strpos( $cap, 'delete' ) ) {
				continue;
			}
			$researcher_caps[ $cap ] = true;
		}
		$researcher_caps['upload_files'] = true;

		$editor_caps = $researcher_caps;
		foreach ( array( array( 'sjm_journal', 'sjm_journals' ), array( 'sjm_issue', 'sjm_issues' ), array( 'sjm_paper', 'sjm_papers' ) ) as $pair ) {
			foreach ( self::cpt_caps( $pair[0], $pair[1] ) as $cap ) {
				$editor_caps[ $cap ] = true;
			}
		}
		$editor_caps['manage_sjm_authors'] = true;
		$editor_caps['view_sjm_analytics'] = true;
		$editor_caps['manage_sjm_reviews'] = true;

		$reviewer_caps = array(
			'read'              => true,
			'upload_files'      => true,
			'read_sjm_papers'   => true,
		);

		remove_role( 'sjm_student' );
		remove_role( 'sjm_researcher' );
		remove_role( 'sjm_editor' );
		remove_role( 'sjm_reviewer' );

		add_role( 'sjm_student', __( 'WJM Student', 'wisdom-journal-manager' ), $student_caps );
		add_role( 'sjm_researcher', __( 'WJM Researcher', 'wisdom-journal-manager' ), $researcher_caps );
		add_role( 'sjm_editor', __( 'WJM Editor', 'wisdom-journal-manager' ), $editor_caps );
		add_role( 'sjm_reviewer', __( 'WJM Reviewer', 'wisdom-journal-manager' ), $reviewer_caps );

		$admin = get_role( 'administrator' );
		if ( $admin ) {
			foreach ( array_keys( $editor_caps ) as $cap ) {
				$admin->add_cap( $cap );
			}
			$admin->add_cap( 'manage_sjm_settings' );
			$admin->add_cap( 'view_sjm_security_logs' );
			$admin->add_cap( 'manage_sjm_api_keys' );
		}
	}

	/**
	 * Ensure roles exist after upgrades.
	 */
	public static function ensure_roles() {
		if ( ! get_role( 'sjm_editor' ) || ! get_role( 'sjm_reviewer' ) ) {
			self::register_roles();
			return;
		}

		$admin = get_role( 'administrator' );
		if ( $admin && ! $admin->has_cap( 'manage_sjm_settings' ) ) {
			self::register_roles();
		}

		// Ensure admins can always open DOI Manager even on older installs.
		if ( $admin ) {
			$admin->add_cap( 'manage_sjm_settings' );
			$admin->add_cap( 'manage_sjm_api_keys' );
		}
	}

	/**
	 * Rate-limit quotas by role (API calls / data fetches per hour).
	 *
	 * @param int $user_id User ID.
	 * @return array{api:int,fetch:int}
	 */
	public static function rate_limits_for_user( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return array( 'api' => 20, 'fetch' => 10 );
		}

		if ( user_can( $user, 'manage_options' ) || user_can( $user, 'manage_sjm_settings' ) ) {
			return array( 'api' => 500, 'fetch' => 300 );
		}
		if ( in_array( 'sjm_editor', (array) $user->roles, true ) || user_can( $user, 'edit_others_sjm_papers' ) ) {
			return array( 'api' => 200, 'fetch' => 120 );
		}
		if ( in_array( 'sjm_researcher', (array) $user->roles, true ) ) {
			return array( 'api' => 100, 'fetch' => 60 );
		}
		return array( 'api' => 50, 'fetch' => 30 );
	}

	/**
	 * Capability check helper.
	 *
	 * @param string $cap Capability.
	 * @return bool
	 */
	public static function current_user_can( $cap ) {
		return current_user_can( $cap ) || current_user_can( 'manage_options' );
	}
}
