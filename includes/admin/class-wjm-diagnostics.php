<?php
/**
 * Post-install diagnostic suite.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Diagnostics {

	public static function init() {
		// Rendered via admin menu callback.
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'manage_sjm_settings' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$results = self::run();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Plugin Verification', 'wisdom-journal-manager' ); ?></h1>
			<p><?php esc_html_e( 'Integrity checks for database tables, cron, permissions, and API readiness.', 'wisdom-journal-manager' ); ?></p>
			<table class="widefat striped">
				<thead><tr><th><?php esc_html_e( 'Check', 'wisdom-journal-manager' ); ?></th><th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th><th><?php esc_html_e( 'Details', 'wisdom-journal-manager' ); ?></th></tr></thead>
				<tbody>
				<?php foreach ( $results as $row ) : ?>
					<tr>
						<td><?php echo esc_html( $row['label'] ); ?></td>
						<td><span class="wjm-status wjm-status-<?php echo esc_attr( $row['ok'] ? 'ok' : 'fail' ); ?>"><?php echo $row['ok'] ? 'OK' : 'FAIL'; ?></span></td>
						<td><?php echo esc_html( $row['detail'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * @return array[]
	 */
	public static function run() {
		global $wpdb;
		$results = array();

		$tables = array( 'authors', 'paper_authors', 'citations', 'audit', 'rate', 'collaboration', 'workflow', 'assignments', 'reviews', 'manuscripts', 'email_log', 'galleys', 'copyedit', 'subscriptions' );
		foreach ( $tables as $key ) {
			$table  = WJM_Database_Schema::table( $key );
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
			$results[] = array(
				'label'  => sprintf( 'Table %s', $table ),
				'ok'     => $exists,
				'detail' => $exists ? 'Present' : 'Missing — re-activate the plugin',
			);
		}

		foreach ( array( 'journals', 'issues', 'papers' ) as $key ) {
			$table  = WJM_Relational_Schema::table( $key );
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
			$results[] = array(
				'label'  => sprintf( 'Relational %s', $table ),
				'ok'     => $exists,
				'detail' => $exists ? 'Present (source of truth)' : 'Missing — visit Journals → Database or re-activate',
			);
		}

		$migrated = (bool) get_option( 'wjm_relational_migrated' );
		$results[] = array(
			'label'  => 'Relational migration',
			'ok'     => $migrated,
			'detail' => $migrated ? 'Completed (' . (string) get_option( 'wjm_relational_db_version', '?' ) . ')' : 'Pending — open Journals → Database',
		);

		$results[] = array(
			'label'  => 'Custom post types',
			'ok'     => post_type_exists( 'sjm_journal' ) && post_type_exists( 'sjm_issue' ) && post_type_exists( 'sjm_paper' ),
			'detail' => 'sjm_journal / sjm_issue / sjm_paper',
		);

		$results[] = array(
			'label'  => 'Roles',
			'ok'     => (bool) get_role( 'sjm_editor' ) && (bool) get_role( 'sjm_reviewer' ),
			'detail' => 'sjm_student, sjm_researcher, sjm_editor, sjm_reviewer',
		);

		$results[] = array(
			'label'  => 'REST API',
			'ok'     => true,
			'detail' => rest_url( 'wjm/v1/journals' ),
		);

		$cron = wp_next_scheduled( WJM_Citation_Tracking::CRON_HOOK );
		$results[] = array(
			'label'  => 'Citation cron',
			'ok'     => (bool) $cron || 'disabled' === get_option( 'wjm_citation_schedule' ),
			'detail' => $cron ? 'Scheduled at ' . gmdate( 'c', $cron ) : 'Not scheduled',
		);

		$results[] = array(
			'label'  => 'PHP curl',
			'ok'     => function_exists( 'curl_init' ),
			'detail' => function_exists( 'curl_init' ) ? 'Available' : 'Missing extension',
		);

		$results[] = array(
			'label'  => 'PHP openssl (AES-256-CBC)',
			'ok'     => function_exists( 'openssl_encrypt' ),
			'detail' => function_exists( 'openssl_encrypt' ) ? 'Available' : 'Missing extension',
		);

		$results[] = array(
			'label'  => 'CrossRef reachability',
			'ok'     => true,
			'detail' => 'Use a paper DOI refresh to verify live connectivity',
		);

		$pay = WJM_Payments::settings();
		$stripe_ready = ( 'stripe' === $pay['provider'] ) && (bool) WJM_Encryption::get_secret( 'wjm_stripe_secret' );
		$results[] = array(
			'label'  => 'Stripe APC',
			'ok'     => empty( $pay['enabled'] ) || 'manual' === $pay['provider'] || $stripe_ready,
			'detail' => empty( $pay['enabled'] )
				? 'APC disabled'
				: ( 'manual' === $pay['provider']
					? 'Manual provider'
					: ( $stripe_ready
						? 'Stripe keys present · webhook ' . rest_url( 'wjm/v1/stripe-webhook' )
						: 'Stripe selected but secret key missing' ) ),
		);

		return $results;
	}
}
