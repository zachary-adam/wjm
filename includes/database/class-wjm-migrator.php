<?php
/**
 * One-shot / repair migration: CPT + postmeta → relational tables.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Migrator {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_wjm_run_db_migrate', array( __CLASS__, 'handle_migrate' ) );
		add_action( 'admin_init', array( __CLASS__, 'maybe_auto_migrate' ) );
	}

	/**
	 * After relational schema exists, migrate once automatically.
	 */
	public static function maybe_auto_migrate() {
		if ( get_option( 'wjm_relational_migrated' ) ) {
			return;
		}
		if ( ! get_option( 'wjm_relational_db_version' ) ) {
			return;
		}
		// Defer heavy work to admin only.
		if ( ! is_admin() || wp_doing_ajax() ) {
			return;
		}
		self::run();
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Database', 'wisdom-journal-manager' ),
			__( 'Database', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-database',
			array( __CLASS__, 'render_page' )
		);
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$health = self::health();
		if ( ! empty( $_GET['migrated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Migration complete.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'WJM Database', 'wisdom-journal-manager' ); ?></h1>
			<p><?php esc_html_e( 'Relational source of truth: journals → issues → papers (with foreign keys). CPTs stay for URLs and the WP admin editor.', 'wisdom-journal-manager' ); ?></p>

			<table class="widefat striped" style="max-width:720px;">
				<tbody>
					<tr><th><?php esc_html_e( 'Schema version', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( (string) get_option( 'wjm_relational_db_version', '—' ) ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Migration flag', 'wisdom-journal-manager' ); ?></th><td><?php echo get_option( 'wjm_relational_migrated' ) ? '✓ done' : '○ pending'; ?></td></tr>
					<tr><th><?php esc_html_e( 'Journals (table / CPT)', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $health['journals_table'] . ' / ' . $health['journals_cpt'] ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Issues (table / CPT)', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $health['issues_table'] . ' / ' . $health['issues_cpt'] ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Papers (table / CPT)', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $health['papers_table'] . ' / ' . $health['papers_cpt'] ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Orphan papers (no journal link)', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( (string) $health['orphan_papers'] ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Foreign keys', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( implode( ', ', $health['fks'] ) ?: 'none detected' ); ?></td></tr>
				</tbody>
			</table>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1.25rem;">
				<input type="hidden" name="action" value="wjm_run_db_migrate" />
				<?php wp_nonce_field( 'wjm_run_db_migrate' ); ?>
				<?php submit_button( __( 'Rebuild / re-sync relational tables from CPTs', 'wisdom-journal-manager' ), 'primary' ); ?>
			</form>

			<p class="description">
				<?php esc_html_e( 'Safe to re-run. Upserts by post_id; does not delete published content.', 'wisdom-journal-manager' ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * @return array
	 */
	public static function health() {
		global $wpdb;
		$j = WJM_Relational_Schema::table( 'journals' );
		$i = WJM_Relational_Schema::table( 'issues' );
		$p = WJM_Relational_Schema::table( 'papers' );

		$fks = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME IN (%s,%s) AND CONSTRAINT_TYPE = 'FOREIGN KEY'",
				$i,
				$p
			)
		);

		return array(
			'journals_table' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$j}" ),
			'issues_table'   => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$i}" ),
			'papers_table'   => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$p}" ),
			'journals_cpt'   => self::count_cpt( 'sjm_journal' ),
			'issues_cpt'     => self::count_cpt( 'sjm_issue' ),
			'papers_cpt'     => self::count_cpt( 'sjm_paper' ),
			'orphan_papers'  => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$p} WHERE journal_id IS NULL AND journal_post_id IS NULL" ),
			'fks'            => $fks ? $fks : array(),
		);
	}

	/**
	 * @param string $post_type Post type.
	 * @return int
	 */
	private static function count_cpt( $post_type ) {
		$counts = wp_count_posts( $post_type );
		if ( ! $counts ) {
			return 0;
		}
		$total = 0;
		foreach ( (array) $counts as $status => $n ) {
			if ( 'auto-draft' === $status || 'trash' === $status ) {
				continue;
			}
			$total += (int) $n;
		}
		return $total;
	}

	/**
	 * Full sync: journals → issues → papers (order matters for FKs).
	 *
	 * @return array Counts.
	 */
	public static function run() {
		WJM_Relational_Schema::create_tables();

		$counts = array(
			'journals' => 0,
			'issues'   => 0,
			'papers'   => 0,
		);

		$journals = get_posts(
			array(
				'post_type'      => 'sjm_journal',
				'post_status'    => 'any',
				'posts_per_page' => -1,
				'fields'         => 'ids',
			)
		);
		foreach ( $journals as $id ) {
			WJM_Sync::sync_journal( $id );
			$counts['journals']++;
		}

		$issues = get_posts(
			array(
				'post_type'      => 'sjm_issue',
				'post_status'    => 'any',
				'posts_per_page' => -1,
				'fields'         => 'ids',
			)
		);
		foreach ( $issues as $id ) {
			WJM_Sync::sync_issue( $id );
			$counts['issues']++;
		}

		$papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'any',
				'posts_per_page' => -1,
				'fields'         => 'ids',
			)
		);
		foreach ( $papers as $id ) {
			WJM_Sync::sync_paper( $id );
			$counts['papers']++;
		}

		update_option( 'wjm_relational_migrated', 1 );
		update_option( 'wjm_relational_migrated_at', current_time( 'mysql', true ) );
		WJM_Audit::log( 'info', 'db_migrated', 'Relational migration completed.', $counts );

		return $counts;
	}

	public static function handle_migrate() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_run_db_migrate' );
		self::run();
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-database&migrated=1' ) );
		exit;
	}
}
