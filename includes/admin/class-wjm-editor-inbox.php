<?php
/**
 * Editor inbox — submissions awaiting action.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Editor_Inbox {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_notices', array( __CLASS__, 'badge_notice' ) );
	}

	public static function menu() {
		$pending = self::count_pending();
		$label   = __( 'Editor Inbox', 'wisdom-journal-manager' );
		if ( $pending ) {
			$label .= ' <span class="awaiting-mod">' . (int) $pending . '</span>';
		}

		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Editor Inbox', 'wisdom-journal-manager' ),
			$label,
			'edit_others_sjm_papers',
			'wjm-inbox',
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * @return int
	 */
	public static function count_pending() {
		$q = new WP_Query(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => array( 'private', 'draft', 'pending', 'publish' ),
				'posts_per_page' => 1,
				'fields'         => 'ids',
				'meta_query'     => array(
					array(
						'key'     => WJM_Workflow::META_STATUS,
						'value'   => array( 'submitted', 'screening', 'under_review', 'resubmitted', 'accepted', 'copyediting', 'production' ),
						'compare' => 'IN',
					),
				),
			)
		);
		return (int) $q->found_posts;
	}

	public static function badge_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'sjm_journal_page_wjm-inbox' === $screen->id ) {
			return;
		}
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$count = self::count_pending();
		if ( $count < 1 ) {
			return;
		}
		printf(
			'<div class="notice notice-info"><p>%s <a href="%s">%s</a></p></div>',
			esc_html( sprintf( _n( '%d manuscript needs attention.', '%d manuscripts need attention.', $count, 'wisdom-journal-manager' ), $count ) ),
			esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ),
			esc_html__( 'Open Editor Inbox', 'wisdom-journal-manager' )
		);
	}

	public static function render() {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$statuses = array( 'submitted', 'screening', 'under_review', 'revision', 'resubmitted', 'accepted', 'copyediting', 'production' );
		$filter   = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$meta_in  = $filter && in_array( $filter, $statuses, true ) ? array( $filter ) : $statuses;

		$q = new WP_Query(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => array( 'private', 'draft', 'pending', 'publish' ),
				'posts_per_page' => 100,
				'orderby'        => 'modified',
				'order'          => 'DESC',
				'meta_query'     => array(
					array(
						'key'     => WJM_Workflow::META_STATUS,
						'value'   => $meta_in,
						'compare' => 'IN',
					),
				),
			)
		);

		$labels = WJM_Workflow::statuses();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Editor Inbox', 'wisdom-journal-manager' ); ?></h1>
			<ul class="subsubsub">
				<li><a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ); ?>" <?php echo ! $filter ? 'class="current"' : ''; ?>><?php esc_html_e( 'All active', 'wisdom-journal-manager' ); ?></a> |</li>
				<?php foreach ( $statuses as $st ) : ?>
					<li>
						<a href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox&status=' . $st ) ); ?>" <?php echo $filter === $st ? 'class="current"' : ''; ?>>
							<?php echo esc_html( $labels[ $st ] ); ?>
						</a>
						<?php echo $st !== end( $statuses ) ? ' |' : ''; ?>
					</li>
				<?php endforeach; ?>
			</ul>
			<table class="widefat striped" style="margin-top:1rem;">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Title', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Author', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Reviews', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Updated', 'wisdom-journal-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( ! $q->have_posts() ) : ?>
					<tr><td colspan="5"><?php esc_html_e( 'Inbox zero — nothing waiting.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php endif; ?>
				<?php while ( $q->have_posts() ) : ?>
					<?php
					$q->the_post();
					$status = WJM_Workflow::get_status( get_the_ID() );
					$assigns = WJM_Peer_Review::get_assignments( get_the_ID() );
					$done    = 0;
					foreach ( $assigns as $a ) {
						if ( 'completed' === $a->status ) {
							$done++;
						}
					}
					?>
					<tr>
						<td><a href="<?php echo esc_url( get_edit_post_link() ); ?>"><strong><?php the_title(); ?></strong></a></td>
						<td><span class="wjm-status-badge wjm-status-<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $labels[ $status ] ?? $status ); ?></span></td>
						<td><?php the_author(); ?></td>
						<td><?php echo esc_html( $done . '/' . count( $assigns ) ); ?></td>
						<td><?php echo esc_html( get_the_modified_date( 'Y-m-d H:i' ) ); ?></td>
					</tr>
				<?php endwhile; ?>
				<?php wp_reset_postdata(); ?>
				</tbody>
			</table>
		</div>
		<?php
	}
}
