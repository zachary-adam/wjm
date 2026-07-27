<?php
/**
 * Getting started / setup checklist.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Getting_Started {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 5 );
		add_action( 'admin_init', array( __CLASS__, 'maybe_redirect' ) );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Getting Started', 'wisdom-journal-manager' ),
			__( 'Getting Started', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-getting-started',
			array( __CLASS__, 'render' )
		);
	}

	public static function maybe_redirect() {
		if ( ! get_transient( 'wjm_activation_redirect' ) ) {
			return;
		}
		delete_transient( 'wjm_activation_redirect' );
		if ( is_network_admin() || isset( $_GET['activate-multi'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-getting-started' ) );
		exit;
	}

	public static function render() {
		$checks = self::checklist();
		$catalog = (int) get_option( 'wjm_catalog_page_id' );
		$submit  = (int) get_option( 'wjm_submit_page_id' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Wisdom Journal Manager — Getting Started', 'wisdom-journal-manager' ); ?></h1>
			<p><?php esc_html_e( 'Complete this checklist to go live with your journal.', 'wisdom-journal-manager' ); ?></p>

			<table class="widefat striped">
				<thead><tr><th><?php esc_html_e( 'Step', 'wisdom-journal-manager' ); ?></th><th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th><th></th></tr></thead>
				<tbody>
				<?php foreach ( $checks as $row ) : ?>
					<tr>
						<td><?php echo esc_html( $row['label'] ); ?></td>
						<td><span class="wjm-status-<?php echo $row['ok'] ? 'ok' : 'fail'; ?>"><?php echo $row['ok'] ? '✓' : '○'; ?></span></td>
						<td><?php echo wp_kses_post( $row['action'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Quick links', 'wisdom-journal-manager' ); ?></h2>
			<ul>
				<li><a href="<?php echo esc_url( admin_url( 'post-new.php?post_type=sjm_journal' ) ); ?>"><?php esc_html_e( 'Create a journal', 'wisdom-journal-manager' ); ?></a></li>
				<li><a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ); ?>"><?php esc_html_e( 'Editor inbox', 'wisdom-journal-manager' ); ?></a></li>
				<li><a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-settings' ) ); ?>"><?php esc_html_e( 'API / DOI settings', 'wisdom-journal-manager' ); ?></a></li>
				<li><a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-diagnostics' ) ); ?>"><?php esc_html_e( 'Plugin verification', 'wisdom-journal-manager' ); ?></a></li>
				<?php if ( $catalog ) : ?>
					<li><a href="<?php echo esc_url( get_permalink( $catalog ) ); ?>"><?php esc_html_e( 'Public journals page', 'wisdom-journal-manager' ); ?></a></li>
				<?php endif; ?>
				<?php if ( $submit ) : ?>
					<li><a href="<?php echo esc_url( get_permalink( $submit ) ); ?>"><?php esc_html_e( 'Submit manuscript page', 'wisdom-journal-manager' ); ?></a></li>
				<?php endif; ?>
				<li><code><?php echo esc_html( rest_url( 'wjm/v1/journals' ) ); ?></code></li>
			</ul>

			<h2><?php esc_html_e( 'Recommended first workflow', 'wisdom-journal-manager' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Create a Journal, then an Issue under it.', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Open the Submit page as an author (or Researcher role) and submit a PDF.', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'In Editor Inbox, open the paper → assign a reviewer (double-blind).', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Reviewer accepts invitation under Journals → My Reviews and submits recommendation.', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'Editor moves status to Accepted → Production → Published, then Register DOI / Export JATS.', 'wisdom-journal-manager' ); ?></li>
			</ol>
		</div>
		<?php
	}

	/**
	 * @return array[]
	 */
	private static function checklist() {
		$journals = (int) wp_count_posts( 'sjm_journal' )->publish;
		$prefix   = (string) get_option( 'wjm_doi_prefix', '' );
		$tables   = true;
		global $wpdb;
		foreach ( array( 'authors', 'workflow', 'assignments', 'reviews' ) as $key ) {
			$table = WJM_Database_Schema::table( $key );
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
				$tables = false;
				break;
			}
		}

		return array(
			array(
				'label'  => __( 'Database tables created', 'wisdom-journal-manager' ),
				'ok'     => $tables,
				'action' => $tables ? '—' : '<a href="' . esc_url( admin_url( 'plugins.php' ) ) . '">Re-activate plugin</a>',
			),
			array(
				'label'  => __( 'At least one journal published', 'wisdom-journal-manager' ),
				'ok'     => $journals > 0,
				'action' => '<a href="' . esc_url( admin_url( 'post-new.php?post_type=sjm_journal' ) ) . '">Add journal</a>',
			),
			array(
				'label'  => __( 'Submit page exists', 'wisdom-journal-manager' ),
				'ok'     => (bool) get_option( 'wjm_submit_page_id' ),
				'action' => '<a href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-automation' ) ) . '">Automation</a>',
			),
			array(
				'label'  => __( 'DOI prefix configured', 'wisdom-journal-manager' ),
				'ok'     => '' !== $prefix || ! empty( WJM_DOI::settings()['prefix'] ),
				'action' => '<a href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' ) ) . '">DOI Manager</a>',
			),
			array(
				'label'  => __( 'DOI agency credentials saved (CrossRef or DataCite)', 'wisdom-journal-manager' ),
				'ok'     => WJM_DOI::credential_status()['crossref'] || WJM_DOI::credential_status()['datacite'] || 'local' === WJM_DOI::settings()['agency'],
				'action' => '<a href="' . esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-doi' ) ) . '">Add credentials</a>',
			),
			array(
				'label'  => __( 'Roles registered (Editor + Reviewer)', 'wisdom-journal-manager' ),
				'ok'     => (bool) get_role( 'sjm_editor' ) && (bool) get_role( 'sjm_reviewer' ),
				'action' => '—',
			),
		);
	}
}
