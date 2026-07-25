<?php
/**
 * Administrative analytics + publisher multi-journal KPIs.
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

		$stats    = self::collect();
		$journals = self::journal_kpis();
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'Publisher KPIs', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Cross-journal snapshot for the publishing program on this site.', 'wisdom-journal-manager' ); ?></p>
			<div class="wjm-stats">
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['journals'] ); ?></strong><span><?php esc_html_e( 'Journals', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['issues'] ); ?></strong><span><?php esc_html_e( 'Issues', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['papers'] ); ?></strong><span><?php esc_html_e( 'Papers', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['in_review'] ); ?></strong><span><?php esc_html_e( 'In review', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['accepted'] ); ?></strong><span><?php esc_html_e( 'Accepted', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['apc_paid'] ); ?></strong><span><?php esc_html_e( 'APC paid', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['authors'] ); ?></strong><span><?php esc_html_e( 'Authors', 'wisdom-journal-manager' ); ?></span></div>
				<div class="wjm-stat"><strong><?php echo esc_html( $stats['citations'] ); ?></strong><span><?php esc_html_e( 'Citations', 'wisdom-journal-manager' ); ?></span></div>
			</div>

			<h2><?php esc_html_e( 'Per journal', 'wisdom-journal-manager' ); ?></h2>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Journal', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Papers', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Submitted', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'In review', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Revision', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Accepted', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Published', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Rejected', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'OA', 'wisdom-journal-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( ! $journals ) : ?>
					<tr><td colspan="9"><?php esc_html_e( 'No journals yet.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $journals as $row ) : ?>
						<tr>
							<td><a href="<?php echo esc_url( get_edit_post_link( $row['id'] ) ); ?>"><?php echo esc_html( $row['title'] ); ?></a></td>
							<td><?php echo esc_html( (string) $row['total'] ); ?></td>
							<td><?php echo esc_html( (string) $row['submitted'] ); ?></td>
							<td><?php echo esc_html( (string) $row['under_review'] ); ?></td>
							<td><?php echo esc_html( (string) $row['revision'] ); ?></td>
							<td><?php echo esc_html( (string) $row['accepted'] ); ?></td>
							<td><?php echo esc_html( (string) $row['published'] ); ?></td>
							<td><?php echo esc_html( (string) $row['rejected'] ); ?></td>
							<td><?php echo esc_html( (string) $row['oa'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>

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
				<?php if ( ! $stats['top_papers'] ) : ?>
					<tr><td colspan="2"><?php esc_html_e( 'No citation data yet.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php endif; ?>
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

		$stats   = class_exists( 'WJM_Repository' ) ? WJM_Repository::stats() : array();
		$authors = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . WJM_Database_Schema::table( 'authors' ) );

		$top_papers = array();
		if ( class_exists( 'WJM_Repository' ) && class_exists( 'WJM_Relational_Schema' ) ) {
			$table = WJM_Relational_Schema::table( 'papers' );
			$rows  = $wpdb->get_results( "SELECT post_id, title, citation_total FROM {$table} WHERE status = 'publish' ORDER BY citation_total DESC LIMIT 10" );
			foreach ( (array) $rows as $row ) {
				$top_papers[] = array(
					'id'        => (int) $row->post_id,
					'title'     => $row->title,
					'citations' => (int) $row->citation_total,
				);
			}
		}

		$in_review = self::count_status( array( 'under_review', 'revision' ) );
		$accepted  = self::count_status( array( 'accepted', 'copyediting', 'production' ) );
		$apc_paid  = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->postmeta} WHERE meta_key = %s AND meta_value = %s",
				'_sjm_apc_status',
				'paid'
			)
		);

		return array(
			'journals'    => isset( $stats['journals'] ) ? $stats['journals'] : (int) wp_count_posts( 'sjm_journal' )->publish,
			'issues'      => isset( $stats['issues'] ) ? $stats['issues'] : (int) wp_count_posts( 'sjm_issue' )->publish,
			'papers'      => isset( $stats['papers'] ) ? $stats['papers'] : (int) wp_count_posts( 'sjm_paper' )->publish,
			'authors'     => $authors,
			'citations'   => isset( $stats['citations'] ) ? $stats['citations'] : 0,
			'open_access' => isset( $stats['open_access'] ) ? $stats['open_access'] : 0,
			'top_papers'  => $top_papers,
			'in_review'   => $in_review,
			'accepted'    => $accepted,
			'apc_paid'    => $apc_paid,
		);
	}

	/**
	 * @param string[] $statuses Workflow statuses.
	 * @return int
	 */
	private static function count_status( $statuses ) {
		$q = new WP_Query(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => array( 'publish', 'private', 'draft', 'pending' ),
				'posts_per_page' => 1,
				'fields'         => 'ids',
				'meta_query'     => array(
					array(
						'key'     => '_sjm_workflow_status',
						'value'   => $statuses,
						'compare' => 'IN',
					),
				),
			)
		);
		return (int) $q->found_posts;
	}

	/**
	 * @return array[]
	 */
	public static function journal_kpis() {
		$journals = get_posts(
			array(
				'post_type'      => 'sjm_journal',
				'post_status'    => array( 'publish', 'private', 'draft' ),
				'posts_per_page' => 100,
				'orderby'        => 'title',
				'order'          => 'ASC',
			)
		);
		$out = array();
		foreach ( $journals as $j ) {
			$papers = get_posts(
				array(
					'post_type'      => 'sjm_paper',
					'post_status'    => array( 'publish', 'private', 'draft', 'pending' ),
					'posts_per_page' => -1,
					'fields'         => 'ids',
					'meta_key'       => '_sjm_journal_id',
					'meta_value'     => $j->ID,
				)
			);
			$counts = array(
				'submitted'    => 0,
				'under_review' => 0,
				'revision'     => 0,
				'accepted'     => 0,
				'published'    => 0,
				'rejected'     => 0,
				'oa'           => 0,
			);
			foreach ( $papers as $pid ) {
				$st = class_exists( 'WJM_Workflow' ) ? WJM_Workflow::get_status( $pid ) : '';
				if ( isset( $counts[ $st ] ) ) {
					$counts[ $st ]++;
				} elseif ( 'publish' === get_post_status( $pid ) ) {
					$counts['published']++;
				} elseif ( in_array( $st, array( 'copyediting', 'production' ), true ) ) {
					$counts['accepted']++;
				}
				if ( get_post_meta( $pid, '_sjm_open_access', true ) ) {
					$counts['oa']++;
				}
			}
			$out[] = array_merge(
				array(
					'id'    => $j->ID,
					'title' => $j->post_title,
					'total' => count( $papers ),
				),
				$counts
			);
		}
		return $out;
	}
}
