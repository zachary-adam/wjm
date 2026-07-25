<?php
/**
 * Feature allow / disallow switches — public submission & frontend gates.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Access {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 55 );
		add_action( 'admin_post_wjm_save_access', array( __CLASS__, 'handle_save' ) );
	}

	/**
	 * @return array
	 */
	public static function defaults() {
		return array(
			'public_submissions'         => 1,
			'require_login'              => 1,
			'allow_guest_submit'         => 0,
			'who_can_submit'             => 'logged_in', // logged_in|researcher|anyone
			'require_manuscript'         => 1,
			'require_anonymized_file'    => 0,
			'blind_file_instructions'    => __( "For double-blind review, upload a manuscript with no author names, affiliations, acknowledgements, or identifying metadata (Oxford-style). Also upload a separate title page with full author details for editors only.", 'wisdom-journal-manager' ),
			'require_abstract'           => 1,
			'require_authors'            => 1,
			'require_keywords'           => 0,
			'require_funding'            => 0,
			'require_conflicts'          => 0,
			'require_ethics'             => 0,
			'require_data_availability'  => 0,
			'require_cover_letter'       => 0,
			'allow_open_access_request'  => 1,
			'allow_supplementary'        => 1,
			'allow_cover_letter'         => 1,
			'allow_suggested_reviewers'  => 1,
			'show_apc_hint_on_submit'    => 1,
			'show_my_papers_shortcode'   => 1,
			'public_paper_metrics'       => 1,
			'public_galleys'             => 1,
			'public_subscriptions'       => 1,
			'public_search'              => 1,
			'max_file_mb'                => 25,
			'allowed_extensions'         => 'pdf,doc,docx',
			'submission_notice'          => __( 'By submitting you confirm the work is original and not under review elsewhere.', 'wisdom-journal-manager' ),
		);
	}

	/**
	 * @return array
	 */
	public static function settings() {
		$stored = get_option( 'wjm_access_settings', array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$s = self::settings();
		return isset( $s[ $key ] ) ? $s[ $key ] : null;
	}

	/**
	 * @param string $key Setting key.
	 * @return bool
	 */
	public static function allowed( $key ) {
		return ! empty( self::get( $key ) );
	}

	/**
	 * Can current visitor submit?
	 *
	 * @return true|WP_Error
	 */
	public static function can_submit() {
		if ( ! self::allowed( 'public_submissions' ) ) {
			return new WP_Error( 'wjm_closed', __( 'Public submissions are currently closed.', 'wisdom-journal-manager' ) );
		}

		$who = self::get( 'who_can_submit' );
		if ( 'anyone' === $who || self::allowed( 'allow_guest_submit' ) ) {
			return true;
		}

		if ( ! is_user_logged_in() ) {
			return new WP_Error( 'wjm_login', __( 'Please log in to submit a manuscript.', 'wisdom-journal-manager' ) );
		}

		if ( 'researcher' === $who ) {
			$user = wp_get_current_user();
			$ok   = current_user_can( 'manage_options' )
				|| current_user_can( 'edit_sjm_papers' )
				|| in_array( 'sjm_researcher', (array) $user->roles, true )
				|| in_array( 'sjm_editor', (array) $user->roles, true )
				|| in_array( 'sjm_student', (array) $user->roles, true );
			if ( ! $ok ) {
				return new WP_Error( 'wjm_role', __( 'Your account is not allowed to submit. Contact the editorial office.', 'wisdom-journal-manager' ) );
			}
		}

		return true;
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Access', 'wisdom-journal-manager' ),
			__( 'Access', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-access',
			array( __CLASS__, 'render_page' )
		);
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$s = self::settings();
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Access rules saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'Access', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Start with Simple only: who can submit. Open More only if you need extra form fields or double-blind files.', 'wisdom-journal-manager' ); ?></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_access" />
				<?php wp_nonce_field( 'wjm_save_access' ); ?>

				<h2><?php esc_html_e( 'Simple', 'wisdom-journal-manager' ); ?></h2>
				<table class="form-table">
					<?php self::toggle_row( 'public_submissions', __( 'Accept public submissions', 'wisdom-journal-manager' ), $s ); ?>
					<tr>
						<th><?php esc_html_e( 'Who can submit', 'wisdom-journal-manager' ); ?></th>
						<td>
							<select name="who_can_submit">
								<option value="logged_in" <?php selected( $s['who_can_submit'], 'logged_in' ); ?>><?php esc_html_e( 'Any logged-in user', 'wisdom-journal-manager' ); ?></option>
								<option value="researcher" <?php selected( $s['who_can_submit'], 'researcher' ); ?>><?php esc_html_e( 'Researchers / editors / students only', 'wisdom-journal-manager' ); ?></option>
								<option value="anyone" <?php selected( $s['who_can_submit'], 'anyone' ); ?>><?php esc_html_e( 'Anyone (including guests)', 'wisdom-journal-manager' ); ?></option>
							</select>
						</td>
					</tr>
					<?php self::toggle_row( 'allow_guest_submit', __( 'Allow guest submit (no login)', 'wisdom-journal-manager' ), $s ); ?>
					<tr>
						<th><?php esc_html_e( 'Max file size (MB)', 'wisdom-journal-manager' ); ?></th>
						<td><input type="number" min="1" max="200" name="max_file_mb" value="<?php echo esc_attr( $s['max_file_mb'] ); ?>" /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Allowed extensions', 'wisdom-journal-manager' ); ?></th>
						<td><input type="text" class="regular-text" name="allowed_extensions" value="<?php echo esc_attr( $s['allowed_extensions'] ); ?>" placeholder="pdf,doc,docx" /></td>
					</tr>
				</table>

				<details class="wjm-details-calm" style="margin:1rem 0 1.5rem;">
					<summary><?php esc_html_e( 'Double-blind files (Oxford-style)', 'wisdom-journal-manager' ); ?></summary>
					<table class="form-table">
						<?php self::toggle_row( 'require_anonymized_file', __( 'Require anonymized manuscript + title page', 'wisdom-journal-manager' ), $s ); ?>
						<tr>
							<th><?php esc_html_e( 'Author instructions', 'wisdom-journal-manager' ); ?></th>
							<td>
								<textarea class="large-text" rows="4" name="blind_file_instructions"><?php echo esc_textarea( $s['blind_file_instructions'] ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Shown on the submit form. Authors anonymize the file themselves — same approach many presses use.', 'wisdom-journal-manager' ); ?></p>
							</td>
						</tr>
					</table>
				</details>

				<details class="wjm-details-calm" style="margin:1rem 0 1.5rem;">
					<summary><?php esc_html_e( 'More form rules', 'wisdom-journal-manager' ); ?></summary>
					<table class="form-table">
						<?php self::toggle_row( 'require_manuscript', __( 'Require manuscript file', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_abstract', __( 'Require abstract', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_authors', __( 'Require author list', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_keywords', __( 'Require keywords', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_funding', __( 'Require funding statement', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_conflicts', __( 'Require conflicts statement', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_ethics', __( 'Require ethics statement', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_data_availability', __( 'Require data availability', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'require_cover_letter', __( 'Require cover letter', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'allow_cover_letter', __( 'Show cover letter field', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'allow_supplementary', __( 'Allow supplementary files', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'allow_open_access_request', __( 'Allow open-access request', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'allow_suggested_reviewers', __( 'Allow suggested reviewers', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'show_apc_hint_on_submit', __( 'Show fee hint on submit form', 'wisdom-journal-manager' ), $s ); ?>
						<tr>
							<th><?php esc_html_e( 'Author declaration text', 'wisdom-journal-manager' ); ?></th>
							<td><textarea class="large-text" rows="3" name="submission_notice"><?php echo esc_textarea( $s['submission_notice'] ); ?></textarea></td>
						</tr>
					</table>
				</details>

				<details class="wjm-details-calm" style="margin:0 0 1.5rem;">
					<summary><?php esc_html_e( 'Public frontend', 'wisdom-journal-manager' ); ?></summary>
					<table class="form-table">
						<?php self::toggle_row( 'public_paper_metrics', __( 'Show citation metrics on papers', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'public_galleys', __( 'Show galleys / downloads', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'public_subscriptions', __( 'Show journal subscribe box', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'public_search', __( 'Show search on journal pages', 'wisdom-journal-manager' ), $s ); ?>
						<?php self::toggle_row( 'show_my_papers_shortcode', __( 'Enable My papers shortcode', 'wisdom-journal-manager' ), $s ); ?>
					</table>
				</details>

				<?php submit_button( __( 'Save access rules', 'wisdom-journal-manager' ) ); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * @param string $key Key.
	 * @param string $label Label.
	 * @param array  $s Settings.
	 */
	private static function toggle_row( $key, $label, $s ) {
		?>
		<tr>
			<th><?php echo esc_html( $label ); ?></th>
			<td>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( $key ); ?>" value="1" <?php checked( ! empty( $s[ $key ] ) ); ?> />
					<?php esc_html_e( 'Allow', 'wisdom-journal-manager' ); ?>
				</label>
			</td>
		</tr>
		<?php
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_access' );

		$keys = array_keys( self::defaults() );
		$out  = self::defaults();
		foreach ( $keys as $key ) {
			if ( in_array( $key, array( 'who_can_submit', 'allowed_extensions', 'submission_notice', 'blind_file_instructions', 'max_file_mb' ), true ) ) {
				continue;
			}
			$out[ $key ] = ! empty( $_POST[ $key ] ) ? 1 : 0;
		}
		$out['who_can_submit']     = isset( $_POST['who_can_submit'] ) ? sanitize_key( wp_unslash( $_POST['who_can_submit'] ) ) : 'logged_in';
		$out['allowed_extensions'] = isset( $_POST['allowed_extensions'] ) ? sanitize_text_field( wp_unslash( $_POST['allowed_extensions'] ) ) : 'pdf,doc,docx';
		$out['submission_notice']  = isset( $_POST['submission_notice'] ) ? sanitize_textarea_field( wp_unslash( $_POST['submission_notice'] ) ) : '';
		$out['blind_file_instructions'] = isset( $_POST['blind_file_instructions'] ) ? sanitize_textarea_field( wp_unslash( $_POST['blind_file_instructions'] ) ) : '';
		$out['max_file_mb']        = isset( $_POST['max_file_mb'] ) ? absint( $_POST['max_file_mb'] ) : 25;
		if ( ! in_array( $out['who_can_submit'], array( 'logged_in', 'researcher', 'anyone' ), true ) ) {
			$out['who_can_submit'] = 'logged_in';
		}

		update_option( 'wjm_access_settings', $out );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-access&saved=1' ) );
		exit;
	}
}
