<?php
/**
 * Admin menus: Automation, Authors, Security, Settings.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Admin {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menus' ) );
		add_action( 'admin_init', array( __CLASS__, 'handle_settings_save' ) );
	}

	public static function menus() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Authors', 'wisdom-journal-manager' ),
			__( 'Authors', 'wisdom-journal-manager' ),
			'manage_sjm_authors',
			'wjm-authors',
			array( __CLASS__, 'render_authors' )
		);

		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Automation', 'wisdom-journal-manager' ),
			__( 'Automation', 'wisdom-journal-manager' ),
			'manage_sjm_settings',
			'wjm-automation',
			array( __CLASS__, 'render_automation' )
		);

		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Plugin Verification', 'wisdom-journal-manager' ),
			__( 'Plugin Verification', 'wisdom-journal-manager' ),
			'manage_sjm_settings',
			'wjm-diagnostics',
			array( 'WJM_Diagnostics', 'render_page' )
		);

		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Security Logs', 'wisdom-journal-manager' ),
			__( 'Security Logs', 'wisdom-journal-manager' ),
			'view_sjm_security_logs',
			'wjm-security',
			array( __CLASS__, 'render_security' )
		);

		// Allow admins who only have manage_options.
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'WJM Settings', 'wisdom-journal-manager' ),
			__( 'Settings', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-settings',
			array( __CLASS__, 'render_settings' )
		);
	}

	public static function handle_settings_save() {
		if ( ! isset( $_POST['wjm_save_settings'] ) && ! isset( $_POST['wjm_save_automation'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'manage_sjm_settings' ) ) {
			return;
		}

		if ( isset( $_POST['wjm_save_settings'] ) ) {
			check_admin_referer( 'wjm_settings' );
			$keys = array(
				'wjm_api_crossref'         => 'wjm_api_crossref',
				'wjm_api_semantic_scholar' => 'wjm_api_semantic_scholar',
				'wjm_api_scopus'           => 'wjm_api_scopus',
				'wjm_api_wos'              => 'wjm_api_wos',
				'wjm_crossref_user'        => 'wjm_crossref_user',
				'wjm_crossref_pass'        => 'wjm_crossref_pass',
			);
			foreach ( $keys as $field => $option ) {
				if ( isset( $_POST[ $field ] ) && '' !== $_POST[ $field ] ) {
					WJM_Encryption::set_secret( $option, sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) );
				}
			}
			if ( isset( $_POST['wjm_doi_prefix'] ) || isset( $_POST['wjm_doi_pattern'] ) ) {
				WJM_DOI::save_settings( wp_unslash( $_POST ) );
			}
			if ( ! empty( $_POST['wjm_datacite_user'] ) ) {
				WJM_Encryption::set_secret( 'wjm_datacite_user', sanitize_text_field( wp_unslash( $_POST['wjm_datacite_user'] ) ) );
			}
			if ( ! empty( $_POST['wjm_datacite_pass'] ) ) {
				WJM_Encryption::set_secret( 'wjm_datacite_pass', sanitize_text_field( wp_unslash( $_POST['wjm_datacite_pass'] ) ) );
			}
			WJM_Audit::log( 'info', 'settings_updated', 'API credentials updated.' );
			add_settings_error( 'wjm', 'wjm_saved', __( 'Settings saved.', 'wisdom-journal-manager' ), 'updated' );
		}

		if ( isset( $_POST['wjm_save_automation'] ) ) {
			check_admin_referer( 'wjm_automation' );
			$schedule = isset( $_POST['wjm_citation_schedule'] ) ? sanitize_key( wp_unslash( $_POST['wjm_citation_schedule'] ) ) : 'weekly';
			if ( ! in_array( $schedule, array( 'daily', 'weekly', 'monthly', 'disabled' ), true ) ) {
				$schedule = 'weekly';
			}
			update_option( 'wjm_citation_schedule', $schedule );
			if ( 'disabled' === $schedule ) {
				WJM_Automation_System::clear_events();
			} else {
				WJM_Automation_System::schedule_events();
			}
			if ( ! empty( $_POST['wjm_create_catalog'] ) ) {
				WJM_Automated_Pages::ensure_catalog_page();
			}
			if ( ! empty( $_POST['wjm_create_submit'] ) ) {
				WJM_Automated_Pages::ensure_submit_page();
			}
			add_settings_error( 'wjm', 'wjm_auto', __( 'Automation settings saved.', 'wisdom-journal-manager' ), 'updated' );
		}
	}

	public static function render_authors() {
		if ( ! current_user_can( 'manage_sjm_authors' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$authors    = WJM_Author_Profiles::get_all_authors();
		$edit       = isset( $_GET['edit'] ) ? WJM_Author_Profiles::get_author( absint( $_GET['edit'] ) ) : null;
		$duplicates = WJM_Author_Unification::find_duplicates();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Authors', 'wisdom-journal-manager' ); ?></h1>
			<div class="wjm-admin-grid">
				<div>
					<h2><?php echo $edit ? esc_html__( 'Edit Author', 'wisdom-journal-manager' ) : esc_html__( 'Add Author', 'wisdom-journal-manager' ); ?></h2>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="wjm_save_author" />
						<input type="hidden" name="author_id" value="<?php echo $edit ? esc_attr( $edit->id ) : '0'; ?>" />
						<?php wp_nonce_field( 'wjm_save_author' ); ?>
						<table class="form-table">
							<tr><th><?php esc_html_e( 'First name', 'wisdom-journal-manager' ); ?></th><td><input name="first_name" class="regular-text" value="<?php echo $edit ? esc_attr( $edit->first_name ) : ''; ?>" required /></td></tr>
							<tr><th><?php esc_html_e( 'Last name', 'wisdom-journal-manager' ); ?></th><td><input name="last_name" class="regular-text" value="<?php echo $edit ? esc_attr( $edit->last_name ) : ''; ?>" required /></td></tr>
							<tr><th>ORCID</th><td><input name="orcid" class="regular-text" value="<?php echo $edit ? esc_attr( $edit->orcid ) : ''; ?>" placeholder="0000-0000-0000-0000" /></td></tr>
							<tr><th><?php esc_html_e( 'Email', 'wisdom-journal-manager' ); ?></th><td><input type="email" name="email" class="regular-text" value="<?php echo $edit ? esc_attr( $edit->email ) : ''; ?>" /></td></tr>
							<tr><th><?php esc_html_e( 'Affiliation', 'wisdom-journal-manager' ); ?></th><td><textarea name="affiliation" class="large-text" rows="2"><?php echo $edit ? esc_textarea( $edit->affiliation ) : ''; ?></textarea></td></tr>
							<tr><th><?php esc_html_e( 'Bio', 'wisdom-journal-manager' ); ?></th><td><textarea name="bio" class="large-text" rows="4"><?php echo $edit ? esc_textarea( $edit->bio ) : ''; ?></textarea></td></tr>
							<tr><th><?php esc_html_e( 'H-index', 'wisdom-journal-manager' ); ?></th><td><input type="number" name="h_index" value="<?php echo $edit && null !== $edit->h_index ? esc_attr( $edit->h_index ) : ''; ?>" /></td></tr>
						</table>
						<?php submit_button( $edit ? __( 'Update Author', 'wisdom-journal-manager' ) : __( 'Add Author', 'wisdom-journal-manager' ) ); ?>
					</form>
				</div>
				<div>
					<h2><?php esc_html_e( 'All Authors', 'wisdom-journal-manager' ); ?></h2>
					<table class="widefat striped">
						<thead><tr><th><?php esc_html_e( 'Name', 'wisdom-journal-manager' ); ?></th><th>ORCID</th><th></th></tr></thead>
						<tbody>
						<?php foreach ( $authors as $author ) : ?>
							<tr>
								<td><?php echo esc_html( $author->last_name . ', ' . $author->first_name ); ?></td>
								<td><?php echo esc_html( $author->orcid ); ?></td>
								<td>
									<a href="<?php echo esc_url( admin_url( 'admin.php?page=wjm-authors&edit=' . $author->id ) ); ?>"><?php esc_html_e( 'Edit', 'wisdom-journal-manager' ); ?></a>
									|
									<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_delete_author&author_id=' . $author->id ), 'wjm_delete_author' ) ); ?>" onclick="return confirm('Delete author?');"><?php esc_html_e( 'Delete', 'wisdom-journal-manager' ); ?></a>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>

					<?php if ( $duplicates ) : ?>
						<h2><?php esc_html_e( 'Possible Duplicates', 'wisdom-journal-manager' ); ?></h2>
						<?php foreach ( $duplicates as $group ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wjm-merge-form">
								<input type="hidden" name="action" value="wjm_merge_authors" />
								<?php wp_nonce_field( 'wjm_merge_authors' ); ?>
								<p>
									<?php foreach ( $group as $author ) : ?>
										<label><input type="radio" name="target_id" value="<?php echo esc_attr( $author->id ); ?>" required /> Keep <?php echo esc_html( $author->last_name . ', ' . $author->first_name ); ?> (#<?php echo esc_html( $author->id ); ?>)</label><br />
									<?php endforeach; ?>
									<select name="source_id" required>
										<option value=""><?php esc_html_e( 'Merge from…', 'wisdom-journal-manager' ); ?></option>
										<?php foreach ( $group as $author ) : ?>
											<option value="<?php echo esc_attr( $author->id ); ?>">#<?php echo esc_html( $author->id . ' ' . $author->last_name ); ?></option>
										<?php endforeach; ?>
									</select>
									<?php submit_button( __( 'Merge', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
								</p>
							</form>
						<?php endforeach; ?>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	public static function render_automation() {
		settings_errors( 'wjm' );
		$schedule = get_option( 'wjm_citation_schedule', 'weekly' );
		$next     = wp_next_scheduled( WJM_Citation_Tracking::CRON_HOOK );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Automation', 'wisdom-journal-manager' ); ?></h1>
			<form method="post">
				<?php wp_nonce_field( 'wjm_automation' ); ?>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Citation update frequency', 'wisdom-journal-manager' ); ?></th>
						<td>
							<select name="wjm_citation_schedule">
								<?php foreach ( array( 'daily', 'weekly', 'monthly', 'disabled' ) as $opt ) : ?>
									<option value="<?php echo esc_attr( $opt ); ?>" <?php selected( $schedule, $opt ); ?>><?php echo esc_html( ucfirst( $opt ) ); ?></option>
								<?php endforeach; ?>
							</select>
							<?php if ( $next ) : ?>
								<p class="description"><?php echo esc_html( sprintf( __( 'Next run: %s', 'wisdom-journal-manager' ), gmdate( 'Y-m-d H:i:s', $next ) . ' UTC' ) ); ?></p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Catalog page', 'wisdom-journal-manager' ); ?></th>
						<td><label><input type="checkbox" name="wjm_create_catalog" value="1" /> <?php esc_html_e( 'Create / ensure Journals catalog page with shortcodes', 'wisdom-journal-manager' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Submit page', 'wisdom-journal-manager' ); ?></th>
						<td><label><input type="checkbox" name="wjm_create_submit" value="1" /> <?php esc_html_e( 'Create / ensure manuscript submission page', 'wisdom-journal-manager' ); ?></label></td>
					</tr>
				</table>
				<?php submit_button( __( 'Save Automation', 'wisdom-journal-manager' ), 'primary', 'wjm_save_automation' ); ?>
			</form>
		</div>
		<?php
	}

	public static function render_settings() {
		settings_errors( 'wjm' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'WJM Settings', 'wisdom-journal-manager' ); ?></h1>
			<p><?php esc_html_e( 'API keys are stored encrypted. For DOI generation / CrossRef membership, use DOI Manager.', 'wisdom-journal-manager' ); ?></p>
			<p><a class="button button-primary" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' ) ); ?>"><?php esc_html_e( 'Open DOI Manager', 'wisdom-journal-manager' ); ?></a></p>
			<form method="post">
				<?php wp_nonce_field( 'wjm_settings' ); ?>
				<table class="form-table">
					<tr><th>Semantic Scholar API key</th><td><input type="password" class="regular-text" name="wjm_api_semantic_scholar" autocomplete="new-password" /></td></tr>
					<tr><th>Scopus API key</th><td><input type="password" class="regular-text" name="wjm_api_scopus" autocomplete="new-password" /></td></tr>
					<tr><th>Web of Science API key</th><td><input type="password" class="regular-text" name="wjm_api_wos" autocomplete="new-password" /></td></tr>
					<tr><th>CrossRef (optional mailto token)</th><td><input type="password" class="regular-text" name="wjm_api_crossref" autocomplete="new-password" /></td></tr>
				</table>
				<p class="description"><?php esc_html_e( 'REST API base:', 'wisdom-journal-manager' ); ?> <code><?php echo esc_html( rest_url( 'wjm/v1/' ) ); ?></code></p>
				<?php submit_button( __( 'Save Settings', 'wisdom-journal-manager' ), 'primary', 'wjm_save_settings' ); ?>
			</form>
		</div>
		<?php
	}

	public static function render_security() {
		if ( ! current_user_can( 'view_sjm_security_logs' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$logs = WJM_Audit::recent( 100 );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Security Audit Log', 'wisdom-journal-manager' ); ?></h1>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Severity', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Event', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Message', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'User', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'IP', 'wisdom-journal-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $logs as $log ) : ?>
					<tr>
						<td><?php echo esc_html( $log->created_at ); ?></td>
						<td><?php echo esc_html( $log->severity ); ?></td>
						<td><?php echo esc_html( $log->event_type ); ?></td>
						<td><?php echo esc_html( $log->message ); ?></td>
						<td><?php echo esc_html( $log->user_id ); ?></td>
						<td><?php echo esc_html( $log->ip_address ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}
}
