<?php
/**
 * Shared editorial notes / collaboration workspace.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Collaboration_Tools {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_action( 'wp_ajax_wjm_add_collab_note', array( __CLASS__, 'ajax_add_note' ) );
	}

	public static function meta_box() {
		foreach ( array( 'sjm_journal', 'sjm_issue', 'sjm_paper' ) as $type ) {
			add_meta_box(
				'wjm_collaboration',
				__( 'Editorial Notes', 'wisdom-journal-manager' ),
				array( __CLASS__, 'render_box' ),
				$type,
				'side',
				'default'
			);
		}
	}

	public static function render_box( $post ) {
		if ( ! current_user_can( 'edit_post', $post->ID ) ) {
			return;
		}
		$notes = self::get_notes( $post->post_type, $post->ID );
		?>
		<div class="wjm-collab" data-object-type="<?php echo esc_attr( $post->post_type ); ?>" data-object-id="<?php echo esc_attr( $post->ID ); ?>">
			<ul class="wjm-collab-notes">
				<?php foreach ( $notes as $note ) : ?>
					<li>
						<strong><?php echo esc_html( get_the_author_meta( 'display_name', $note->user_id ) ); ?></strong>
						<em><?php echo esc_html( $note->created_at ); ?></em>
						<p><?php echo esc_html( $note->note ); ?></p>
					</li>
				<?php endforeach; ?>
			</ul>
			<textarea class="widefat wjm-collab-input" rows="3" placeholder="<?php esc_attr_e( 'Add a note…', 'wisdom-journal-manager' ); ?>"></textarea>
			<p><button type="button" class="button wjm-collab-submit"><?php esc_html_e( 'Add Note', 'wisdom-journal-manager' ); ?></button></p>
		</div>
		<?php
	}

	/**
	 * @param string $object_type CPT.
	 * @param int    $object_id   Post ID.
	 * @return object[]
	 */
	public static function get_notes( $object_type, $object_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'collaboration' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE object_type = %s AND object_id = %d ORDER BY created_at DESC LIMIT 50",
				sanitize_key( $object_type ),
				absint( $object_id )
			)
		);
	}

	public static function ajax_add_note() {
		check_ajax_referer( 'wjm_admin', 'nonce' );

		$object_type = isset( $_POST['object_type'] ) ? sanitize_key( wp_unslash( $_POST['object_type'] ) ) : '';
		$object_id   = isset( $_POST['object_id'] ) ? absint( $_POST['object_id'] ) : 0;
		$note        = isset( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : '';

		if ( ! $object_id || ! $note || ! current_user_can( 'edit_post', $object_id ) ) {
			wp_send_json_error( array( 'message' => 'Invalid request' ), 400 );
		}

		global $wpdb;
		$wpdb->insert(
			WJM_Database_Schema::table( 'collaboration' ),
			array(
				'object_type' => $object_type,
				'object_id'   => $object_id,
				'user_id'     => get_current_user_id(),
				'note'        => $note,
				'created_at'  => current_time( 'mysql', true ),
			),
			array( '%s', '%d', '%d', '%s', '%s' )
		);

		wp_send_json_success(
			array(
				'author' => wp_get_current_user()->display_name,
				'note'   => $note,
				'time'   => current_time( 'mysql', true ),
			)
		);
	}
}
