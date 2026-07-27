<?php
/**
 * Author submission portal + manuscript file management.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Submissions {

	public static function init() {
		add_shortcode( 'wjm_submit', array( __CLASS__, 'render_form' ) );
		add_shortcode( 'wjm_my_submissions', array( __CLASS__, 'render_my_submissions' ) );
		add_action( 'admin_post_wjm_submit_paper', array( __CLASS__, 'handle_submit' ) );
		add_action( 'admin_post_nopriv_wjm_submit_paper', array( __CLASS__, 'handle_submit' ) );
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_action( 'admin_post_wjm_upload_manuscript', array( __CLASS__, 'handle_upload' ) );
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_manuscripts',
			__( 'Manuscript Files', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_files_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return object[]
	 */
	public static function get_files( $paper_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'manuscripts' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE paper_id = %d ORDER BY created_at DESC",
				absint( $paper_id )
			)
		);
	}

	/**
	 * Attach an uploaded media file to a paper.
	 *
	 * @param int    $paper_id      Paper ID.
	 * @param int    $attachment_id Attachment ID.
	 * @param string $role          manuscript|supplement|revision|camera_ready.
	 * @param string $version       Version label.
	 * @return int
	 */
	public static function attach_file( $paper_id, $attachment_id, $role = 'manuscript', $version = '' ) {
		global $wpdb;
		$wpdb->insert(
			WJM_Database_Schema::table( 'manuscripts' ),
			array(
				'paper_id'      => absint( $paper_id ),
				'attachment_id' => absint( $attachment_id ),
				'file_role'     => sanitize_key( $role ),
				'version_label' => sanitize_text_field( $version ),
				'uploaded_by'   => get_current_user_id(),
				'created_at'    => current_time( 'mysql', true ),
			),
			array( '%d', '%d', '%s', '%s', '%d', '%s' )
		);
		return (int) $wpdb->insert_id;
	}

	public static function render_form( $atts ) {
		if ( ! is_user_logged_in() ) {
			return '<p>' . esc_html__( 'Please log in to submit a manuscript.', 'wisdom-journal-manager' ) . ' <a href="' . esc_url( wp_login_url( get_permalink() ) ) . '">' . esc_html__( 'Log in', 'wisdom-journal-manager' ) . '</a></p>';
		}

		$atts = shortcode_atts(
			array(
				'journal_id' => 0,
			),
			$atts,
			'wjm_submit'
		);

		$journals = get_posts(
			array(
				'post_type'      => 'sjm_journal',
				'posts_per_page' => -1,
				'post_status'    => 'publish',
				'orderby'        => 'title',
				'order'          => 'ASC',
			)
		);

		$types = array(
			'original_research' => __( 'Original Research', 'wisdom-journal-manager' ),
			'review'            => __( 'Review', 'wisdom-journal-manager' ),
			'case_study'        => __( 'Case Study', 'wisdom-journal-manager' ),
			'editorial'         => __( 'Editorial', 'wisdom-journal-manager' ),
			'letter'            => __( 'Letter', 'wisdom-journal-manager' ),
			'meta_analysis'     => __( 'Meta-analysis', 'wisdom-journal-manager' ),
			'systematic_review' => __( 'Systematic Review', 'wisdom-journal-manager' ),
		);

		ob_start();
		if ( isset( $_GET['wjm_submitted'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="wjm-notice wjm-notice-success"><p>' . esc_html__( 'Manuscript submitted successfully. Editors have been notified.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		if ( isset( $_GET['wjm_err'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="wjm-notice wjm-notice-error"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['wjm_err'] ) ) ) . '</p></div>';
		}
		?>
		<form class="wjm-submit-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
			<input type="hidden" name="action" value="wjm_submit_paper" />
			<?php wp_nonce_field( 'wjm_submit_paper' ); ?>

			<p>
				<label for="wjm_journal_id"><strong><?php esc_html_e( 'Journal', 'wisdom-journal-manager' ); ?></strong></label>
				<select name="journal_id" id="wjm_journal_id" required>
					<option value=""><?php esc_html_e( '— Select journal —', 'wisdom-journal-manager' ); ?></option>
					<?php foreach ( $journals as $journal ) : ?>
						<option value="<?php echo esc_attr( $journal->ID ); ?>" <?php selected( (int) $atts['journal_id'], $journal->ID ); ?>>
							<?php echo esc_html( $journal->post_title ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</p>
			<p>
				<label for="wjm_title"><strong><?php esc_html_e( 'Title', 'wisdom-journal-manager' ); ?></strong></label>
				<input type="text" name="title" id="wjm_title" required />
			</p>
			<p>
				<label for="wjm_abstract"><strong><?php esc_html_e( 'Abstract', 'wisdom-journal-manager' ); ?></strong></label>
				<textarea name="abstract" id="wjm_abstract" rows="8" required></textarea>
			</p>
			<p>
				<label for="wjm_keywords"><strong><?php esc_html_e( 'Keywords (comma-separated)', 'wisdom-journal-manager' ); ?></strong></label>
				<input type="text" name="keywords" id="wjm_keywords" />
			</p>
			<p>
				<label for="wjm_paper_type"><strong><?php esc_html_e( 'Paper type', 'wisdom-journal-manager' ); ?></strong></label>
				<select name="paper_type" id="wjm_paper_type">
					<?php foreach ( $types as $key => $label ) : ?>
						<option value="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
			</p>
			<p>
				<label for="wjm_authors_text"><strong><?php esc_html_e( 'Authors (one per line: First Last; Affiliation; ORCID)', 'wisdom-journal-manager' ); ?></strong></label>
				<textarea name="authors_text" id="wjm_authors_text" rows="4" placeholder="Ada Lovelace; Analytical Engine Lab; 0000-0000-0000-0000"></textarea>
			</p>
			<p>
				<label for="wjm_funding"><strong><?php esc_html_e( 'Funding statement', 'wisdom-journal-manager' ); ?></strong></label>
				<textarea name="funding" id="wjm_funding" rows="2"></textarea>
			</p>
			<p>
				<label for="wjm_conflicts"><strong><?php esc_html_e( 'Conflicts of interest', 'wisdom-journal-manager' ); ?></strong></label>
				<textarea name="conflicts" id="wjm_conflicts" rows="2"></textarea>
			</p>
			<p>
				<label>
					<input type="checkbox" name="open_access" value="1" />
					<?php esc_html_e( 'Request open access', 'wisdom-journal-manager' ); ?>
				</label>
			</p>
			<p>
				<label for="wjm_manuscript"><strong><?php esc_html_e( 'Manuscript file (PDF/DOCX)', 'wisdom-journal-manager' ); ?></strong></label>
				<input type="file" name="manuscript" id="wjm_manuscript" accept=".pdf,.doc,.docx" required />
			</p>
			<p>
				<button type="submit" class="wjm-btn"><?php esc_html_e( 'Submit manuscript', 'wisdom-journal-manager' ); ?></button>
			</p>
		</form>
		<?php
		return ob_get_clean();
	}

	public static function handle_submit() {
		if ( ! is_user_logged_in() ) {
			auth_redirect();
		}
		check_admin_referer( 'wjm_submit_paper' );

		$title      = isset( $_POST['title'] ) ? sanitize_text_field( wp_unslash( $_POST['title'] ) ) : '';
		$abstract   = isset( $_POST['abstract'] ) ? sanitize_textarea_field( wp_unslash( $_POST['abstract'] ) ) : '';
		$journal_id = isset( $_POST['journal_id'] ) ? absint( $_POST['journal_id'] ) : 0;

		if ( ! $title || ! $abstract || ! $journal_id ) {
			self::redirect_err( __( 'Title, abstract, and journal are required.', 'wisdom-journal-manager' ) );
		}

		if ( empty( $_FILES['manuscript']['name'] ) ) {
			self::redirect_err( __( 'Manuscript file is required.', 'wisdom-journal-manager' ) );
		}

		$paper_id = wp_insert_post(
			array(
				'post_type'    => 'sjm_paper',
				'post_title'   => $title,
				'post_content' => $abstract,
				'post_status'  => 'private',
				'post_author'  => get_current_user_id(),
			),
			true
		);

		if ( is_wp_error( $paper_id ) ) {
			self::redirect_err( $paper_id->get_error_message() );
		}

		// Link to latest issue of journal if present, else store journal hint.
		$issues = get_posts(
			array(
				'post_type'      => 'sjm_issue',
				'posts_per_page' => 1,
				'meta_key'       => '_sjm_journal_id',
				'meta_value'     => $journal_id,
				'orderby'        => 'date',
				'order'          => 'DESC',
				'fields'         => 'ids',
			)
		);
		if ( $issues ) {
			update_post_meta( $paper_id, '_sjm_issue_id', $issues[0] );
		}
		update_post_meta( $paper_id, '_sjm_journal_id', $journal_id );
		update_post_meta( $paper_id, '_sjm_abstract', $abstract );
		update_post_meta( $paper_id, '_sjm_paper_type', isset( $_POST['paper_type'] ) ? sanitize_key( wp_unslash( $_POST['paper_type'] ) ) : 'original_research' );
		update_post_meta( $paper_id, '_sjm_open_access', ! empty( $_POST['open_access'] ) ? '1' : '0' );
		update_post_meta( $paper_id, '_sjm_funding', isset( $_POST['funding'] ) ? sanitize_textarea_field( wp_unslash( $_POST['funding'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_conflicts', isset( $_POST['conflicts'] ) ? sanitize_textarea_field( wp_unslash( $_POST['conflicts'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_submission_date', gmdate( 'Y-m-d' ) );

		if ( ! empty( $_POST['keywords'] ) ) {
			$keywords = array_filter( array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_POST['keywords'] ) ) ) ) );
			wp_set_object_terms( $paper_id, $keywords, 'sjm_keyword', false );
		}

		self::parse_and_link_authors( $paper_id, isset( $_POST['authors_text'] ) ? wp_unslash( $_POST['authors_text'] ) : '' );

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';

		$attachment_id = media_handle_upload( 'manuscript', $paper_id );
		if ( is_wp_error( $attachment_id ) ) {
			self::redirect_err( $attachment_id->get_error_message() );
		}
		self::attach_file( $paper_id, $attachment_id, 'manuscript', 'v1' );

		WJM_Workflow::transition( $paper_id, 'submitted', __( 'Author submission portal', 'wisdom-journal-manager' ) );

		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::notify_editors( $paper_id, 'new_submission' );
			WJM_Email::send_template( get_current_user_id(), 'submission_received', $paper_id );
		}

		do_action( 'sjm_after_save_paper', $paper_id );

		$redirect = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_submitted', '1', $redirect ) );
		exit;
	}

	/**
	 * Parse author lines and create/link author records.
	 *
	 * @param int    $paper_id Paper ID.
	 * @param string $text     Multiline author text.
	 */
	private static function parse_and_link_authors( $paper_id, $text ) {
		$lines = array_filter( array_map( 'trim', explode( "\n", (string) $text ) ) );
		$ids   = array();
		foreach ( $lines as $line ) {
			$parts = array_map( 'trim', explode( ';', $line ) );
			$name  = $parts[0] ?? '';
			if ( ! $name ) {
				continue;
			}
			$name_parts = preg_split( '/\s+/', $name );
			$last       = array_pop( $name_parts );
			$first      = implode( ' ', $name_parts );
			$author_id  = WJM_Author_Profiles::save_author(
				array(
					'first_name'  => $first ? $first : $name,
					'last_name'   => $last ? $last : '',
					'affiliation' => $parts[1] ?? '',
					'orcid'       => $parts[2] ?? '',
					'email'       => '',
				)
			);
			if ( $author_id ) {
				$ids[] = $author_id;
			}
		}
		if ( $ids ) {
			WJM_Author_Profiles::sync_paper_authors( $paper_id, $ids );
		}
	}

	private static function redirect_err( $message ) {
		$redirect = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_err', rawurlencode( $message ), $redirect ) );
		exit;
	}

	public static function render_my_submissions() {
		if ( ! is_user_logged_in() ) {
			return '<p>' . esc_html__( 'Please log in.', 'wisdom-journal-manager' ) . '</p>';
		}

		$papers = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'author'         => get_current_user_id(),
				'post_status'    => array( 'publish', 'private', 'draft', 'pending' ),
				'posts_per_page' => 50,
			)
		);

		ob_start();
		echo '<ul class="wjm-my-submissions">';
		if ( ! $papers ) {
			echo '<li>' . esc_html__( 'No submissions yet.', 'wisdom-journal-manager' ) . '</li>';
		}
		foreach ( $papers as $paper ) {
			$status = WJM_Workflow::get_status( $paper->ID );
			$label  = WJM_Workflow::statuses()[ $status ] ?? $status;
			echo '<li><strong>' . esc_html( $paper->post_title ) . '</strong> — <span class="wjm-status-badge wjm-status-' . esc_attr( $status ) . '">' . esc_html( $label ) . '</span></li>';
		}
		echo '</ul>';
		return ob_get_clean();
	}

	public static function render_files_box( $post ) {
		$files = self::get_files( $post->ID );
		echo '<ul class="wjm-file-list">';
		foreach ( $files as $file ) {
			$url = wp_get_attachment_url( $file->attachment_id );
			echo '<li><a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html( $file->file_role . ( $file->version_label ? ' (' . $file->version_label . ')' : '' ) ) . '</a></li>';
		}
		if ( ! $files ) {
			echo '<li>' . esc_html__( 'No files yet.', 'wisdom-journal-manager' ) . '</li>';
		}
		echo '</ul>';
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
			<input type="hidden" name="action" value="wjm_upload_manuscript" />
			<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
			<?php wp_nonce_field( 'wjm_upload_manuscript' ); ?>
			<p>
				<select name="file_role">
					<option value="manuscript"><?php esc_html_e( 'Manuscript', 'wisdom-journal-manager' ); ?></option>
					<option value="revision"><?php esc_html_e( 'Revision', 'wisdom-journal-manager' ); ?></option>
					<option value="supplement"><?php esc_html_e( 'Supplement', 'wisdom-journal-manager' ); ?></option>
					<option value="camera_ready"><?php esc_html_e( 'Camera ready', 'wisdom-journal-manager' ); ?></option>
				</select>
			</p>
			<p><input type="file" name="manuscript" required /></p>
			<?php submit_button( __( 'Upload', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php
	}

	public static function handle_upload() {
		check_admin_referer( 'wjm_upload_manuscript' );
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		if ( ! $paper_id || ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';

		$attachment_id = media_handle_upload( 'manuscript', $paper_id );
		if ( ! is_wp_error( $attachment_id ) ) {
			$role = isset( $_POST['file_role'] ) ? sanitize_key( wp_unslash( $_POST['file_role'] ) ) : 'manuscript';
			self::attach_file( $paper_id, $attachment_id, $role );
		}

		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}
}
