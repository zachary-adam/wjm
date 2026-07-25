<?php
/**
 * Issue assembler — order papers in an issue TOC.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Issue_Assembler {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_action( 'admin_post_wjm_save_issue_toc', array( __CLASS__, 'handle_save' ) );
		add_filter( 'template_include', array( __CLASS__, 'template_include' ), 20 );
	}

	public static function template_include( $template ) {
		if ( is_singular( 'sjm_issue' ) ) {
			$custom = WJM_PLUGIN_DIR . 'templates/single-sjm_issue.php';
			if ( file_exists( $custom ) ) {
				return $custom;
			}
		}
		return $template;
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_issue_toc',
			__( 'Issue assembler (TOC)', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render' ),
			'sjm_issue',
			'normal',
			'high'
		);
	}

	/**
	 * @param int $issue_id Issue ID.
	 * @return int[] Ordered paper IDs.
	 */
	public static function get_toc( $issue_id ) {
		$toc = get_post_meta( $issue_id, '_sjm_toc_order', true );
		if ( is_array( $toc ) && $toc ) {
			return array_map( 'absint', $toc );
		}
		$papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => 200,
				'post_status'    => array( 'publish', 'private' ),
				'meta_key'       => '_sjm_issue_id',
				'meta_value'     => absint( $issue_id ),
				'orderby'        => 'title',
				'order'          => 'ASC',
				'fields'         => 'ids',
			)
		);
		return $papers;
	}

	public static function render( $post ) {
		$toc = self::get_toc( $post->ID );
		$all = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'posts_per_page' => 200,
				'post_status'    => array( 'publish', 'private', 'draft' ),
				'meta_key'       => '_sjm_issue_id',
				'meta_value'     => $post->ID,
				'orderby'        => 'title',
				'order'          => 'ASC',
			)
		);
		// Also allow journal papers not yet assigned.
		$journal_id = (int) get_post_meta( $post->ID, '_sjm_journal_id', true );
		if ( $journal_id ) {
			$extra = get_posts(
				array(
					'post_type'      => 'sjm_paper',
					'posts_per_page' => 100,
					'post_status'    => array( 'publish', 'private' ),
					'meta_key'       => '_sjm_journal_id',
					'meta_value'     => $journal_id,
					'orderby'        => 'title',
					'order'          => 'ASC',
				)
			);
			$seen = wp_list_pluck( $all, 'ID' );
			foreach ( $extra as $p ) {
				if ( ! in_array( $p->ID, $seen, true ) ) {
					$all[] = $p;
				}
			}
		}
		?>
		<p class="description"><?php esc_html_e( 'Order papers for this issue. Checked papers are linked to the issue and listed in TOC order on the public issue page.', 'wisdom-journal-manager' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="wjm_save_issue_toc" />
			<input type="hidden" name="issue_id" value="<?php echo esc_attr( $post->ID ); ?>" />
			<?php wp_nonce_field( 'wjm_save_issue_toc_' . $post->ID ); ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Include', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Order', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Paper', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Pages', 'wisdom-journal-manager' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php
				$order_map = array_flip( $toc );
				$i         = 0;
				foreach ( $all as $paper ) :
					$i++;
					$in    = in_array( $paper->ID, $toc, true ) || (int) get_post_meta( $paper->ID, '_sjm_issue_id', true ) === (int) $post->ID;
					$ord   = isset( $order_map[ $paper->ID ] ) ? ( $order_map[ $paper->ID ] + 1 ) : ( 100 + $i );
					$pages = get_post_meta( $paper->ID, '_sjm_page_range', true );
					?>
					<tr>
						<td><input type="checkbox" name="include[]" value="<?php echo esc_attr( $paper->ID ); ?>" <?php checked( $in ); ?> /></td>
						<td><input type="number" name="order[<?php echo esc_attr( $paper->ID ); ?>]" value="<?php echo esc_attr( $ord ); ?>" style="width:4.5rem;" min="1" /></td>
						<td><a href="<?php echo esc_url( get_edit_post_link( $paper->ID ) ); ?>"><?php echo esc_html( $paper->post_title ); ?></a></td>
						<td><input type="text" name="pages[<?php echo esc_attr( $paper->ID ); ?>]" value="<?php echo esc_attr( $pages ); ?>" placeholder="1–12" style="width:6rem;" /></td>
					</tr>
				<?php endforeach; ?>
				<?php if ( ! $all ) : ?>
					<tr><td colspan="4"><?php esc_html_e( 'No papers linked to this journal/issue yet.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php endif; ?>
				</tbody>
			</table>
			<?php submit_button( __( 'Save TOC', 'wisdom-journal-manager' ) ); ?>
		</form>
		<?php
	}

	public static function handle_save() {
		$issue_id = isset( $_POST['issue_id'] ) ? absint( $_POST['issue_id'] ) : 0;
		check_admin_referer( 'wjm_save_issue_toc_' . $issue_id );
		if ( ! current_user_can( 'edit_post', $issue_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$include = isset( $_POST['include'] ) ? array_map( 'absint', (array) $_POST['include'] ) : array();
		$orders  = isset( $_POST['order'] ) ? (array) wp_unslash( $_POST['order'] ) : array();
		$pages   = isset( $_POST['pages'] ) ? (array) wp_unslash( $_POST['pages'] ) : array();

		$sortable = array();
		foreach ( $include as $pid ) {
			$sortable[ $pid ] = isset( $orders[ $pid ] ) ? (int) $orders[ $pid ] : 999;
		}
		asort( $sortable );
		$toc = array_keys( $sortable );
		update_post_meta( $issue_id, '_sjm_toc_order', $toc );

		foreach ( $toc as $pid ) {
			update_post_meta( $pid, '_sjm_issue_id', $issue_id );
			if ( isset( $pages[ $pid ] ) ) {
				update_post_meta( $pid, '_sjm_page_range', sanitize_text_field( $pages[ $pid ] ) );
			}
		}

		WJM_Audit::log( 'info', 'issue_toc_saved', sprintf( 'TOC saved for issue %d (%d papers)', $issue_id, count( $toc ) ), array( 'issue_id' => $issue_id ) );
		wp_safe_redirect( get_edit_post_link( $issue_id, 'raw' ) );
		exit;
	}
}
