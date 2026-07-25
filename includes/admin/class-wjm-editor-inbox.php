<?php
/**
 * Editor inbox — triage board (kanban), SLA clocks, editor claims.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Editor_Inbox {

	const META_CLAIM = '_sjm_editor_claim';
	const META_CLAIM_AT = '_sjm_editor_claim_at';

	/** Target days in status before SLA warns. */
	const SLA_DAYS = array(
		'submitted'    => 3,
		'screening'    => 5,
		'under_review' => 21,
		'revision'     => 30,
		'resubmitted'  => 5,
		'accepted'     => 14,
		'copyediting'  => 14,
		'production'   => 14,
	);

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_notices', array( __CLASS__, 'badge_notice' ) );
		add_action( 'admin_post_wjm_claim_paper', array( __CLASS__, 'handle_claim' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
	}

	public static function assets( $hook ) {
		if ( false === strpos( (string) $hook, 'wjm-inbox' ) ) {
			return;
		}
		WJM::enqueue_fonts();
		wp_enqueue_style( 'wjm-admin', WJM_PLUGIN_URL . 'assets/css/admin.css', array( 'wjm-fonts' ), WJM_VERSION . '.' . (string) filemtime( WJM_PLUGIN_DIR . 'assets/css/admin.css' ) );
		wp_add_inline_style(
			'wjm-admin',
			'.wjm-triage{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1rem;margin-top:1.25rem;align-items:start;width:100%;max-width:none;}
			.wjm-triage-col{background:#fff;border:1px solid #c8cfc4;border-radius:2px;min-height:8rem;}
			.wjm-triage-col h3{margin:0;padding:0.65rem 0.75rem;font-size:12px;text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid #dfe5d8;background:#F6F7ED;color:#001F3F;}
			.wjm-triage-card{display:block;padding:0.75rem;border-bottom:1px solid #eee;text-decoration:none;color:inherit;}
			.wjm-triage-card:hover{background:#edf7f1;}
			.wjm-triage-card strong{display:block;margin-bottom:0.25rem;color:#001F3F;}
			.wjm-sla{font-size:11px;font-weight:600;}
			.wjm-sla-ok{color:#00603A;}
			.wjm-sla-warn{color:#9a6700;}
			.wjm-sla-late{color:#b32d2e;}
			.wjm-claim{font-size:11px;color:#5a6558;margin-top:0.35rem;}'
		);
	}

	public static function menu() {
		$pending = self::count_pending();
		$label   = __( 'Inbox', 'wisdom-journal-manager' );
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
						'value'   => array( 'submitted', 'screening', 'under_review', 'resubmitted', 'revision', 'accepted', 'copyediting', 'production' ),
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
			'<div class="notice notice-info is-dismissible"><p>%s <a href="%s">%s</a></p></div>',
			esc_html( sprintf( _n( '%d manuscript needs attention.', '%d manuscripts need attention.', $count, 'wisdom-journal-manager' ), $count ) ),
			esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) ),
			esc_html__( 'Open triage board', 'wisdom-journal-manager' )
		);
	}

	/**
	 * Days since last workflow change (fallback: modified).
	 *
	 * @param int    $paper_id Paper ID.
	 * @param string $status   Status.
	 * @return array{days:int,label:string,class:string}
	 */
	public static function sla_for( $paper_id, $status ) {
		$history = WJM_Workflow::history( $paper_id );
		$since   = get_the_modified_date( 'U', $paper_id );
		foreach ( $history as $row ) {
			if ( isset( $row->to_status ) && $row->to_status === $status && ! empty( $row->created_at ) ) {
				$since = strtotime( $row->created_at . ' UTC' );
				break;
			}
		}
		$days = max( 0, (int) floor( ( time() - (int) $since ) / DAY_IN_SECONDS ) );
		$limit = isset( self::SLA_DAYS[ $status ] ) ? self::SLA_DAYS[ $status ] : 14;
		if ( $days > $limit ) {
			$class = 'wjm-sla-late';
			$label = sprintf( /* translators: 1: days 2: limit */ __( '%1$dd · overdue (>%2$dd)', 'wisdom-journal-manager' ), $days, $limit );
		} elseif ( $days >= max( 1, (int) floor( $limit * 0.7 ) ) ) {
			$class = 'wjm-sla-warn';
			$label = sprintf( /* translators: 1: days 2: limit */ __( '%1$dd · due soon (%2$dd)', 'wisdom-journal-manager' ), $days, $limit );
		} else {
			$class = 'wjm-sla-ok';
			$label = sprintf( /* translators: %d days */ __( '%dd waiting', 'wisdom-journal-manager' ), $days );
		}
		return array(
			'days'  => $days,
			'label' => $label,
			'class' => $class,
		);
	}

	public static function handle_claim() {
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		check_admin_referer( 'wjm_claim_paper_' . $paper_id );
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$clear = ! empty( $_POST['clear'] );
		if ( $clear ) {
			delete_post_meta( $paper_id, self::META_CLAIM );
			delete_post_meta( $paper_id, self::META_CLAIM_AT );
		} else {
			update_post_meta( $paper_id, self::META_CLAIM, get_current_user_id() );
			update_post_meta( $paper_id, self::META_CLAIM_AT, current_time( 'mysql', true ) );
			WJM_Audit::log(
				'info',
				'editor_claimed',
				sprintf( 'Editor claimed paper %d', $paper_id ),
				array( 'paper_id' => $paper_id )
			);
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox' ) );
		exit;
	}

	public static function render() {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$columns = array( 'submitted', 'screening', 'under_review', 'revision', 'resubmitted', 'accepted', 'copyediting', 'production' );
		$view    = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : 'board'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$labels  = WJM_Workflow::statuses();

		$q = new WP_Query(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => array( 'private', 'draft', 'pending', 'publish' ),
				'posts_per_page' => 200,
				'orderby'        => 'modified',
				'order'          => 'DESC',
				'meta_query'     => array(
					array(
						'key'     => WJM_Workflow::META_STATUS,
						'value'   => $columns,
						'compare' => 'IN',
					),
				),
			)
		);

		$by_status = array_fill_keys( $columns, array() );
		while ( $q->have_posts() ) {
			$q->the_post();
			$st = WJM_Workflow::get_status( get_the_ID() );
			if ( isset( $by_status[ $st ] ) ) {
				$by_status[ $st ][] = get_post();
			}
		}
		wp_reset_postdata();

		$any = false;
		foreach ( $by_status as $list ) {
			if ( $list ) {
				$any = true;
				break;
			}
		}

		$submit = (int) get_option( 'wjm_submit_page_id' );
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'Inbox', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Your daily page: claim a paper, review, decide, publish.', 'wisdom-journal-manager' ); ?></p>

			<?php if ( ! $any ) : ?>
				<div class="wjm-empty-coach">
					<h2><?php esc_html_e( 'Empty — practice in 1 click', 'wisdom-journal-manager' ); ?></h2>
					<p><?php esc_html_e( 'Import the demo journal, open a sample paper from here, then Accept or ask for revision.', 'wisdom-journal-manager' ); ?></p>
					<div class="wjm-home-actions" style="margin-top:1rem;">
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
							<input type="hidden" name="action" value="wjm_import_demo" />
							<?php wp_nonce_field( 'wjm_import_demo' ); ?>
							<button type="submit" class="button button-primary"><?php esc_html_e( 'Import demo', 'wisdom-journal-manager' ); ?></button>
						</form>
						<?php if ( $submit ) : ?>
							<a class="button" href="<?php echo esc_url( get_permalink( $submit ) ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Author submit page', 'wisdom-journal-manager' ); ?></a>
						<?php else : ?>
							<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_quick_setup' ), 'wjm_quick_setup' ) ); ?>"><?php esc_html_e( 'Create submit page', 'wisdom-journal-manager' ); ?></a>
						<?php endif; ?>
						<a class="button" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-help' ) ); ?>"><?php esc_html_e( '3-minute Help', 'wisdom-journal-manager' ); ?></a>
					</div>
				</div>
			<?php else : ?>
			<p>
				<a class="<?php echo 'board' === $view ? 'button button-primary' : 'button'; ?>" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox&view=board' ) ); ?>"><?php esc_html_e( 'Board', 'wisdom-journal-manager' ); ?></a>
				<a class="<?php echo 'list' === $view ? 'button button-primary' : 'button'; ?>" href="<?php echo esc_url( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-inbox&view=list' ) ); ?>"><?php esc_html_e( 'List', 'wisdom-journal-manager' ); ?></a>
			</p>

			<?php if ( 'list' === $view ) : ?>
				<table class="widefat striped" style="margin-top:1rem;">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Title', 'wisdom-journal-manager' ); ?></th>
							<th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th>
							<th><?php esc_html_e( 'Waiting', 'wisdom-journal-manager' ); ?></th>
							<th><?php esc_html_e( 'Claim', 'wisdom-journal-manager' ); ?></th>
							<th><?php esc_html_e( 'Reviews', 'wisdom-journal-manager' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php
					foreach ( $columns as $st ) :
						foreach ( $by_status[ $st ] as $post ) :
							self::render_list_row( $post, $st, $labels );
						endforeach;
					endforeach;
					?>
					</tbody>
				</table>
			<?php else : ?>
				<div class="wjm-triage">
					<?php foreach ( $columns as $st ) : ?>
						<div class="wjm-triage-col">
							<h3><?php echo esc_html( $labels[ $st ] ?? $st ); ?> <span style="opacity:0.6;">(<?php echo count( $by_status[ $st ] ); ?>)</span></h3>
							<?php if ( ! $by_status[ $st ] ) : ?>
								<p class="description" style="padding:0.75rem;"><?php esc_html_e( '—', 'wisdom-journal-manager' ); ?></p>
							<?php endif; ?>
							<?php foreach ( $by_status[ $st ] as $post ) : ?>
								<?php self::render_card( $post, $st ); ?>
							<?php endforeach; ?>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * @param WP_Post $post Post.
	 * @param string  $status Status.
	 */
	private static function render_card( $post, $status ) {
		$sla   = self::sla_for( $post->ID, $status );
		$claim = (int) get_post_meta( $post->ID, self::META_CLAIM, true );
		$cu    = $claim ? get_userdata( $claim ) : null;
		$assigns = class_exists( 'WJM_Peer_Review' ) ? WJM_Peer_Review::get_assignments( $post->ID ) : array();
		$done  = 0;
		foreach ( $assigns as $a ) {
			if ( 'completed' === $a->status ) {
				$done++;
			}
		}
		?>
		<div class="wjm-triage-card">
			<a href="<?php echo esc_url( get_edit_post_link( $post->ID ) ); ?>"><strong><?php echo esc_html( get_the_title( $post ) ); ?></strong></a>
			<span class="wjm-sla <?php echo esc_attr( $sla['class'] ); ?>"><?php echo esc_html( $sla['label'] ); ?></span>
			<?php if ( $assigns ) : ?>
				<div class="description"><?php echo esc_html( sprintf( __( 'Reviews %1$d/%2$d', 'wisdom-journal-manager' ), $done, count( $assigns ) ) ); ?></div>
			<?php endif; ?>
			<div class="wjm-claim">
				<?php if ( $cu ) : ?>
					<?php echo esc_html( sprintf( __( 'Claimed: %s', 'wisdom-journal-manager' ), $cu->display_name ) ); ?>
					<?php if ( (int) $claim === get_current_user_id() || current_user_can( 'manage_options' ) ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
							<input type="hidden" name="action" value="wjm_claim_paper" />
							<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
							<input type="hidden" name="clear" value="1" />
							<?php wp_nonce_field( 'wjm_claim_paper_' . $post->ID ); ?>
							<button type="submit" class="button-link"><?php esc_html_e( 'Release', 'wisdom-journal-manager' ); ?></button>
						</form>
					<?php endif; ?>
				<?php else : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
						<input type="hidden" name="action" value="wjm_claim_paper" />
						<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
						<?php wp_nonce_field( 'wjm_claim_paper_' . $post->ID ); ?>
						<button type="submit" class="button-link"><?php esc_html_e( 'Claim', 'wisdom-journal-manager' ); ?></button>
					</form>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * @param WP_Post $post Post.
	 * @param string  $status Status.
	 * @param array   $labels Labels.
	 */
	private static function render_list_row( $post, $status, $labels ) {
		$sla   = self::sla_for( $post->ID, $status );
		$claim = (int) get_post_meta( $post->ID, self::META_CLAIM, true );
		$cu    = $claim ? get_userdata( $claim ) : null;
		$assigns = class_exists( 'WJM_Peer_Review' ) ? WJM_Peer_Review::get_assignments( $post->ID ) : array();
		$done  = 0;
		foreach ( $assigns as $a ) {
			if ( 'completed' === $a->status ) {
				$done++;
			}
		}
		?>
		<tr>
			<td><a href="<?php echo esc_url( get_edit_post_link( $post->ID ) ); ?>"><strong><?php echo esc_html( get_the_title( $post ) ); ?></strong></a></td>
			<td><span class="wjm-status-badge wjm-status-<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $labels[ $status ] ?? $status ); ?></span></td>
			<td><span class="wjm-sla <?php echo esc_attr( $sla['class'] ); ?>"><?php echo esc_html( $sla['label'] ); ?></span></td>
			<td><?php echo $cu ? esc_html( $cu->display_name ) : '—'; ?></td>
			<td><?php echo esc_html( $done . '/' . count( $assigns ) ); ?></td>
		</tr>
		<?php
	}
}
