<?php
/**
 * Administrative analytics dashboard.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Analytics_Dashboard {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Analytics', 'wisdom-journal-manager' ),
			__( 'Analytics', 'wisdom-journal-manager' ),
			'view_sjm_analytics',
			'wjm-analytics',
			array( __CLASS__, 'render' )
		);
	}

	public static function render() {
		if ( ! current_user_can( 'view_sjm_analytics' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$stats = self::collect();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'WJM Analytics', 'wisdom-journal-manager' ); ?></h1>
			<div class="wjm-stats">
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['journals'] ); ?></strong><span><?php esc_html_e( 'Journals', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['issues'] ); ?></strong><span><?php esc_html_e( 'Issues', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['papers'] ); ?></strong><span><?php esc_html_e( 'Papers', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['authors'] ); ?></strong><span><?php esc_html_e( 'Authors', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['citations'] ); ?></strong><span><?php esc_html_e( 'Citation total (max/source)', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['open_access'] ); ?></strong><span><?php esc_html_e( 'Open access papers', 'wisdom-journal-manager' ); ?></span></div>
			</div>

			<h2><?php esc_html_e( 'Top cited papers', 'wisdom-journal-manager' ); ?></h2>
			<table class="widefat striped">
				<thead><tr><th><?php esc_html_e( 'Paper', 'wisdom-journal-manager' ); ?></th><th><?php esc_html_e( 'Citations', 'wisdom-journal-manager' ); ?></th></tr></thead>
				<tbody>
				<?php foreach ( $stats['top_papers'] as $row ) : ?>
					<tr>
						<td><a href="<?php echo esc_url( get_edit_post_link( $row['id'] ) ); ?>"><?php echo esc_html( $row['title'] ); ?></a></td>
						<td><?php echo esc_html( $row['citations'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * @return array
	 */
	public static function collect() {
		global $wpdb;

		$journals = (int) wp_count_posts( 'sjm_journal' )->publish;
		$issues   = (int) wp_count_posts( 'sjm_issue' )->publish;
		$papers   = (int) wp_count_posts( 'sjm_paper' )->publish;
		$authors  = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . WJM_Database_Schema::table( 'authors' ) );
		$citations = (int) $wpdb->get_var( 'SELECT COALESCE(SUM(citation_count),0) FROM (SELECT MAX(citation_count) AS citation_count FROM ' . WJM_Database_Schema::table( 'citations' ) . ' GROUP BY paper_id) t' );

		$oa = new WP_Query(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'publish',
				'posts_per_page' => 1,
				'fields'         => 'ids',
				'meta_key'       => '_sjm_open_access',
				'meta_value'     => '1',
			)
		);

		$top_ids = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => 10,
				'meta_key'       => '_sjm_citation_total',
				'orderby'        => 'meta_value_num',
				'order'          => 'DESC',
				'fields'         => 'ids',
			)
		);

		$top_papers = array();
		foreach ( $top_ids as $id ) {
			$top_papers[] = array(
				'id'        => $id,
				'title'     => get_the_title( $id ),
				'citations' => (int) get_post_meta( $id, '_sjm_citation_total', true ),
			);
		}

		return array(
			'journals'    => $journals,
			'issues'      => $issues,
			'papers'      => $papers,
			'authors'     => $authors,
			'citations'   => $citations,
			'open_access' => (int) $oa->found_posts,
			'top_papers'  => $top_papers,
		);
	}
}
