<?php
/**
 * OJS-style production: galleys (PDF/HTML/XML) + copyediting checklist.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Production {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_boxes' ) );
		add_action( 'admin_post_wjm_upload_galley', array( __CLASS__, 'handle_upload_galley' ) );
		add_action( 'admin_post_wjm_delete_galley', array( __CLASS__, 'handle_delete_galley' ) );
		add_action( 'admin_post_wjm_toggle_copyedit', array( __CLASS__, 'handle_toggle_copyedit' ) );
		add_action( 'sjm_workflow_transition', array( __CLASS__, 'on_enter_copyediting' ), 15, 4 );
		add_shortcode( 'wjm_galleys', array( __CLASS__, 'shortcode_galleys' ) );
	}

	/**
	 * Default copyedit checklist (seeded per paper).
	 *
	 * @return array
	 */
	public static function default_tasks() {
		return array(
			'lang_edit'   => __( 'Language / style edit complete', 'wisdom-journal-manager' ),
			'refs_check'  => __( 'References formatted & verified', 'wisdom-journal-manager' ),
			'figs_check'  => __( 'Figures/tables checked', 'wisdom-journal-manager' ),
			'metadata'    => __( 'Title/abstract/keywords finalized', 'wisdom-journal-manager' ),
			'author_ok'   => __( 'Author approved copyedits', 'wisdom-journal-manager' ),
			'ready_galley'=> __( 'Ready for galley production', 'wisdom-journal-manager' ),
		);
	}

	public static function meta_boxes() {
		add_meta_box(
			'wjm_copyedit',
			__( 'Copyediting', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_copyedit' ),
			'sjm_paper',
			'normal',
			'default'
		);
		add_meta_box(
			'wjm_galleys',
			__( 'Galleys (Production)', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_galleys' ),
			'sjm_paper',
			'normal',
			'default'
		);
	}

	/**
	 * @param int $paper_id Paper ID.
	 */
	public static function seed_copyedit_tasks( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'copyedit' );
		foreach ( self::default_tasks() as $key => $label ) {
			$exists = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT id FROM {$table} WHERE paper_id = %d AND task_key = %s",
					$paper_id,
					$key
				)
			);
			if ( ! $exists ) {
				$wpdb->insert(
					$table,
					array(
						'paper_id' => absint( $paper_id ),
						'task_key' => $key,
						'label'    => $label,
						'is_done'  => 0,
					),
					array( '%d', '%s', '%s', '%d' )
				);
			}
		}
	}

	public static function on_enter_copyediting( $paper_id, $from, $to, $note = '' ) {
		unset( $from, $note );
		if ( in_array( $to, array( 'copyediting', 'production', 'accepted' ), true ) ) {
			self::seed_copyedit_tasks( $paper_id );
		}
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function get_tasks( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'copyedit' );
		self::seed_copyedit_tasks( $paper_id );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY id ASC",
				absint( $paper_id )
			)
		);
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @param bool $public_only Public galleys only.
	 * @return object[]
	 */
	public static function get_galleys( $paper_id, $public_only = false ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'galleys' );
		$sql   = "SELECT * FROM {$table} WHERE paper_id = %d";
		if ( $public_only ) {
			$sql .= ' AND is_public = 1';
		}
		$sql .= ' ORDER BY sort_order ASC, id ASC';
		return $wpdb->get_results( $wpdb->prepare( $sql, absint( $paper_id ) ) );
	}

	public static function render_copyedit( $post ) {
		if ( ! current_user_can( 'edit_post', $post->ID ) ) {
			return;
		}
		$tasks = self::get_tasks( $post->ID );
		$done  = 0;
		foreach ( $tasks as $t ) {
			if ( (int) $t->is_done ) {
				$done++;
			}
		}
		$total = count( $tasks );
		?>
		<p><?php echo esc_html( sprintf( __( 'Progress: %1$d / %2$d tasks', 'wisdom-journal-manager' ), $done, $total ) ); ?></p>
		<ul class="wjm-copyedit-list">
			<?php foreach ( $tasks as $task ) : ?>
				<li>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
						<input type="hidden" name="action" value="wjm_toggle_copyedit" />
						<input type="hidden" name="task_id" value="<?php echo esc_attr( $task->id ); ?>" />
						<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
						<?php wp_nonce_field( 'wjm_toggle_copyedit' ); ?>
						<label>
							<input type="checkbox" name="is_done" value="1" <?php checked( (int) $task->is_done, 1 ); ?> onchange="this.form.submit()" />
							<?php echo esc_html( $task->label ); ?>
						</label>
					</form>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	public static function render_galleys( $post ) {
		if ( ! current_user_can( 'edit_post', $post->ID ) ) {
			return;
		}
		$galleys = self::get_galleys( $post->ID, false );
		?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Label', 'wisdom-journal-manager' ); ?></th>
					<th><?php esc_html_e( 'Type', 'wisdom-journal-manager' ); ?></th>
					<th><?php esc_html_e( 'Public', 'wisdom-journal-manager' ); ?></th>
					<th></th>
				</tr>
			</thead>
			<tbody>
			<?php if ( ! $galleys ) : ?>
				<tr><td colspan="4"><?php esc_html_e( 'No galleys yet. Upload PDF/HTML/XML for readers.', 'wisdom-journal-manager' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $galleys as $g ) : ?>
				<?php $url = wp_get_attachment_url( $g->attachment_id ); ?>
				<tr>
					<td><a href="<?php echo esc_url( $url ); ?>" target="_blank" rel="noopener"><?php echo esc_html( $g->label ); ?></a></td>
					<td><?php echo esc_html( strtoupper( $g->galley_type ) ); ?></td>
					<td><?php echo (int) $g->is_public ? '✓' : '—'; ?></td>
					<td>
						<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_delete_galley&galley_id=' . $g->id . '&paper_id=' . $post->ID ), 'wjm_delete_galley_' . $g->id ) ); ?>" onclick="return confirm('Delete galley?');"><?php esc_html_e( 'Delete', 'wisdom-journal-manager' ); ?></a>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data" style="margin-top:1rem;">
			<input type="hidden" name="action" value="wjm_upload_galley" />
			<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
			<?php wp_nonce_field( 'wjm_upload_galley' ); ?>
			<p>
				<input type="text" name="label" placeholder="<?php esc_attr_e( 'Label (e.g. PDF)', 'wisdom-journal-manager' ); ?>" value="PDF" required />
				<select name="galley_type">
					<option value="pdf">PDF</option>
					<option value="html">HTML</option>
					<option value="xml">XML / JATS</option>
					<option value="epub">EPUB</option>
					<option value="other"><?php esc_html_e( 'Other', 'wisdom-journal-manager' ); ?></option>
				</select>
				<label><input type="checkbox" name="is_public" value="1" checked /> <?php esc_html_e( 'Public download', 'wisdom-journal-manager' ); ?></label>
			</p>
			<p><input type="file" name="galley_file" required accept=".pdf,.html,.htm,.xml,.epub,.doc,.docx" /></p>
			<?php submit_button( __( 'Upload galley', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php
	}

	public static function handle_upload_galley() {
		check_admin_referer( 'wjm_upload_galley' );
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		if ( ! $paper_id || ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';

		$attachment_id = media_handle_upload( 'galley_file', $paper_id );
		if ( is_wp_error( $attachment_id ) ) {
			wp_safe_redirect( add_query_arg( 'wjm_err', rawurlencode( $attachment_id->get_error_message() ), get_edit_post_link( $paper_id, 'raw' ) ) );
			exit;
		}

		global $wpdb;
		$wpdb->insert(
			WJM_Database_Schema::table( 'galleys' ),
			array(
				'paper_id'      => $paper_id,
				'attachment_id' => $attachment_id,
				'label'         => isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : 'PDF',
				'galley_type'   => isset( $_POST['galley_type'] ) ? sanitize_key( wp_unslash( $_POST['galley_type'] ) ) : 'pdf',
				'locale'        => 'en_US',
				'is_public'     => ! empty( $_POST['is_public'] ) ? 1 : 0,
				'sort_order'    => 0,
				'uploaded_by'   => get_current_user_id(),
				'created_at'    => current_time( 'mysql', true ),
			),
			array( '%d', '%d', '%s', '%s', '%s', '%d', '%d', '%d', '%s' )
		);

		$status = WJM_Workflow::get_status( $paper_id );
		if ( in_array( $status, array( 'accepted', 'copyediting' ), true ) ) {
			WJM_Workflow::transition( $paper_id, 'production', __( 'Galley uploaded', 'wisdom-journal-manager' ) );
		}

		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}

	public static function handle_delete_galley() {
		$galley_id = isset( $_GET['galley_id'] ) ? absint( $_GET['galley_id'] ) : 0;
		$paper_id  = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_delete_galley_' . $galley_id );
		if ( ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		global $wpdb;
		$wpdb->delete( WJM_Database_Schema::table( 'galleys' ), array( 'id' => $galley_id ), array( '%d' ) );
		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}

	public static function handle_toggle_copyedit() {
		check_admin_referer( 'wjm_toggle_copyedit' );
		$task_id  = isset( $_POST['task_id'] ) ? absint( $_POST['task_id'] ) : 0;
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		if ( ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$done = ! empty( $_POST['is_done'] ) ? 1 : 0;
		global $wpdb;
		$wpdb->update(
			WJM_Database_Schema::table( 'copyedit' ),
			array(
				'is_done' => $done,
				'done_by' => $done ? get_current_user_id() : null,
				'done_at' => $done ? current_time( 'mysql', true ) : null,
			),
			array( 'id' => $task_id ),
			array( '%d', '%d', '%s' ),
			array( '%d' )
		);
		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}

	public static function shortcode_galleys( $atts ) {
		$atts = shortcode_atts( array( 'id' => 0 ), $atts, 'wjm_galleys' );
		$paper_id = absint( $atts['id'] );
		if ( ! $paper_id ) {
			$paper_id = get_the_ID();
		}
		return self::render_public_galleys( $paper_id );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return string
	 */
	public static function render_public_galleys( $paper_id ) {
		$galleys = self::get_galleys( $paper_id, true );
		if ( ! $galleys ) {
			return '';
		}
		ob_start();
		echo '<div class="wjm-galleys">';
		echo '<p class="wjm-eyebrow">' . esc_html__( 'Full text', 'wisdom-journal-manager' ) . '</p>';
		echo '<div class="wjm-galley-actions">';
		foreach ( $galleys as $g ) {
			$url = wp_get_attachment_url( $g->attachment_id );
			if ( ! $url ) {
				continue;
			}
			printf(
				'<a class="wjm-btn wjm-btn-galley" href="%s" target="_blank" rel="noopener">%s</a>',
				esc_url( $url ),
				esc_html( $g->label ? $g->label : strtoupper( $g->galley_type ) )
			);
		}
		echo '</div></div>';
		return ob_get_clean();
	}
}
