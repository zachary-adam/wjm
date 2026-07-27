<?php
/**
 * Meta boxes and post meta for journals, issues, and papers.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Meta {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'register_meta_boxes' ) );
		add_action( 'save_post_sjm_journal', array( __CLASS__, 'save_journal' ), 10, 2 );
		add_action( 'save_post_sjm_issue', array( __CLASS__, 'save_issue' ), 10, 2 );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'save_paper' ), 10, 2 );
	}

	public static function register_meta_boxes() {
		add_meta_box( 'wjm_journal_details', __( 'Journal Details', 'wisdom-journal-manager' ), array( __CLASS__, 'render_journal' ), 'sjm_journal', 'normal', 'high' );
		add_meta_box( 'wjm_issue_details', __( 'Issue Details', 'wisdom-journal-manager' ), array( __CLASS__, 'render_issue' ), 'sjm_issue', 'normal', 'high' );
		add_meta_box( 'wjm_paper_details', __( 'Paper Details', 'wisdom-journal-manager' ), array( __CLASS__, 'render_paper' ), 'sjm_paper', 'normal', 'high' );
		add_meta_box( 'wjm_paper_compliance', __( 'Compliance Metadata', 'wisdom-journal-manager' ), array( __CLASS__, 'render_compliance' ), 'sjm_paper', 'normal', 'default' );
		add_meta_box( 'wjm_paper_authors', __( 'Authors', 'wisdom-journal-manager' ), array( __CLASS__, 'render_paper_authors' ), 'sjm_paper', 'side', 'default' );
	}

	public static function render_journal( $post ) {
		wp_nonce_field( 'wjm_save_journal', 'wjm_journal_nonce' );
		$issn      = get_post_meta( $post->ID, '_sjm_issn', true );
		$publisher = get_post_meta( $post->ID, '_sjm_publisher', true );
		$board     = get_post_meta( $post->ID, '_sjm_editorial_board', true );
		?>
		<p>
			<label for="sjm_issn"><strong><?php esc_html_e( 'ISSN', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" class="widefat" id="sjm_issn" name="sjm_issn" value="<?php echo esc_attr( $issn ); ?>" />
		</p>
		<p>
			<label for="sjm_publisher"><strong><?php esc_html_e( 'Publisher', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" class="widefat" id="sjm_publisher" name="sjm_publisher" value="<?php echo esc_attr( $publisher ); ?>" />
		</p>
		<p>
			<label for="sjm_editorial_board"><strong><?php esc_html_e( 'Editorial Board', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="5" id="sjm_editorial_board" name="sjm_editorial_board"><?php echo esc_textarea( $board ); ?></textarea>
		</p>
		<?php
	}

	public static function render_issue( $post ) {
		wp_nonce_field( 'wjm_save_issue', 'wjm_issue_nonce' );
		$journal_id    = (int) get_post_meta( $post->ID, '_sjm_journal_id', true );
		$volume        = get_post_meta( $post->ID, '_sjm_volume', true );
		$number        = get_post_meta( $post->ID, '_sjm_number', true );
		$special       = get_post_meta( $post->ID, '_sjm_special_issue', true );
		$guest_editors = get_post_meta( $post->ID, '_sjm_guest_editors', true );

		$journals = get_posts(
			array(
				'post_type'      => 'sjm_journal',
				'posts_per_page' => -1,
				'post_status'    => 'publish',
				'orderby'        => 'title',
				'order'          => 'ASC',
			)
		);
		?>
		<p>
			<label for="sjm_journal_id"><strong><?php esc_html_e( 'Parent Journal', 'wisdom-journal-manager' ); ?></strong></label><br />
			<select class="widefat" id="sjm_journal_id" name="sjm_journal_id">
				<option value=""><?php esc_html_e( '— Select —', 'wisdom-journal-manager' ); ?></option>
				<?php foreach ( $journals as $journal ) : ?>
					<option value="<?php echo esc_attr( $journal->ID ); ?>" <?php selected( $journal_id, $journal->ID ); ?>>
						<?php echo esc_html( $journal->post_title ); ?>
					</option>
				<?php endforeach; ?>
			</select>
		</p>
		<p>
			<label for="sjm_volume"><strong><?php esc_html_e( 'Volume', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" id="sjm_volume" name="sjm_volume" value="<?php echo esc_attr( $volume ); ?>" />
		</p>
		<p>
			<label for="sjm_number"><strong><?php esc_html_e( 'Issue Number', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" id="sjm_number" name="sjm_number" value="<?php echo esc_attr( $number ); ?>" />
		</p>
		<p>
			<label>
				<input type="checkbox" name="sjm_special_issue" value="1" <?php checked( $special, '1' ); ?> />
				<?php esc_html_e( 'Special Issue', 'wisdom-journal-manager' ); ?>
			</label>
		</p>
		<p>
			<label for="sjm_guest_editors"><strong><?php esc_html_e( 'Guest Editors', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="3" id="sjm_guest_editors" name="sjm_guest_editors"><?php echo esc_textarea( $guest_editors ); ?></textarea>
		</p>
		<?php
	}

	public static function render_paper( $post ) {
		wp_nonce_field( 'wjm_save_paper', 'wjm_paper_nonce' );
		$fields = array(
			'_sjm_issue_id'       => get_post_meta( $post->ID, '_sjm_issue_id', true ),
			'_sjm_doi'            => get_post_meta( $post->ID, '_sjm_doi', true ),
			'_sjm_abstract'       => get_post_meta( $post->ID, '_sjm_abstract', true ),
			'_sjm_paper_type'     => get_post_meta( $post->ID, '_sjm_paper_type', true ),
			'_sjm_open_access'    => get_post_meta( $post->ID, '_sjm_open_access', true ),
			'_sjm_submission_date'=> get_post_meta( $post->ID, '_sjm_submission_date', true ),
			'_sjm_acceptance_date'=> get_post_meta( $post->ID, '_sjm_acceptance_date', true ),
			'_sjm_page_range'     => get_post_meta( $post->ID, '_sjm_page_range', true ),
		);

		$issues = get_posts(
			array(
				'post_type'      => 'sjm_issue',
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
		?>
		<p>
			<label for="sjm_issue_id"><strong><?php esc_html_e( 'Parent Issue', 'wisdom-journal-manager' ); ?></strong></label><br />
			<select class="widefat" id="sjm_issue_id" name="sjm_issue_id">
				<option value=""><?php esc_html_e( '— Select —', 'wisdom-journal-manager' ); ?></option>
				<?php foreach ( $issues as $issue ) : ?>
					<option value="<?php echo esc_attr( $issue->ID ); ?>" <?php selected( (int) $fields['_sjm_issue_id'], $issue->ID ); ?>>
						<?php echo esc_html( $issue->post_title ); ?>
					</option>
				<?php endforeach; ?>
			</select>
		</p>
		<p>
			<label for="sjm_doi"><strong><?php esc_html_e( 'DOI', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" class="widefat" id="sjm_doi" name="sjm_doi" value="<?php echo esc_attr( $fields['_sjm_doi'] ); ?>" placeholder="10.xxxx/xxxxx" />
		</p>
		<p>
			<label for="sjm_abstract"><strong><?php esc_html_e( 'Abstract', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="6" id="sjm_abstract" name="sjm_abstract"><?php echo esc_textarea( $fields['_sjm_abstract'] ); ?></textarea>
		</p>
		<p>
			<label for="sjm_paper_type"><strong><?php esc_html_e( 'Paper Type', 'wisdom-journal-manager' ); ?></strong></label><br />
			<select id="sjm_paper_type" name="sjm_paper_type">
				<?php foreach ( $types as $key => $label ) : ?>
					<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $fields['_sjm_paper_type'], $key ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
		</p>
		<p>
			<label>
				<input type="checkbox" name="sjm_open_access" value="1" <?php checked( $fields['_sjm_open_access'], '1' ); ?> />
				<?php esc_html_e( 'Open Access', 'wisdom-journal-manager' ); ?>
			</label>
		</p>
		<p>
			<label for="sjm_submission_date"><strong><?php esc_html_e( 'Submission Date', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="date" id="sjm_submission_date" name="sjm_submission_date" value="<?php echo esc_attr( $fields['_sjm_submission_date'] ); ?>" />
		</p>
		<p>
			<label for="sjm_acceptance_date"><strong><?php esc_html_e( 'Acceptance Date', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="date" id="sjm_acceptance_date" name="sjm_acceptance_date" value="<?php echo esc_attr( $fields['_sjm_acceptance_date'] ); ?>" />
		</p>
		<p>
			<label for="sjm_page_range"><strong><?php esc_html_e( 'Page Range', 'wisdom-journal-manager' ); ?></strong></label><br />
			<input type="text" id="sjm_page_range" name="sjm_page_range" value="<?php echo esc_attr( $fields['_sjm_page_range'] ); ?>" placeholder="12-28" />
		</p>
		<?php
	}

	public static function render_compliance( $post ) {
		$funding  = get_post_meta( $post->ID, '_sjm_funding', true );
		$coi      = get_post_meta( $post->ID, '_sjm_conflicts', true );
		$ethics   = get_post_meta( $post->ID, '_sjm_ethics', true );
		$data_av  = get_post_meta( $post->ID, '_sjm_data_availability', true );
		?>
		<p>
			<label for="sjm_funding"><strong><?php esc_html_e( 'Funding Statement', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="3" id="sjm_funding" name="sjm_funding"><?php echo esc_textarea( $funding ); ?></textarea>
		</p>
		<p>
			<label for="sjm_conflicts"><strong><?php esc_html_e( 'Conflicts of Interest', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="3" id="sjm_conflicts" name="sjm_conflicts"><?php echo esc_textarea( $coi ); ?></textarea>
		</p>
		<p>
			<label for="sjm_ethics"><strong><?php esc_html_e( 'Ethics Committee Approval', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="3" id="sjm_ethics" name="sjm_ethics"><?php echo esc_textarea( $ethics ); ?></textarea>
		</p>
		<p>
			<label for="sjm_data_availability"><strong><?php esc_html_e( 'Data Availability Statement', 'wisdom-journal-manager' ); ?></strong></label><br />
			<textarea class="widefat" rows="3" id="sjm_data_availability" name="sjm_data_availability"><?php echo esc_textarea( $data_av ); ?></textarea>
		</p>
		<?php
	}

	public static function render_paper_authors( $post ) {
		$linked = WJM_Author_Profiles::get_authors_for_paper( $post->ID );
		$all    = WJM_Author_Profiles::get_all_authors();
		$ids    = wp_list_pluck( $linked, 'id' );
		?>
		<p><?php esc_html_e( 'Select authors for this paper.', 'wisdom-journal-manager' ); ?></p>
		<select name="sjm_author_ids[]" multiple="multiple" class="widefat" style="min-height:140px;">
			<?php foreach ( $all as $author ) : ?>
				<option value="<?php echo esc_attr( $author->id ); ?>" <?php selected( in_array( (int) $author->id, array_map( 'intval', $ids ), true ) ); ?>>
					<?php echo esc_html( $author->last_name . ', ' . $author->first_name ); ?>
					<?php if ( $author->orcid ) : ?>
						(<?php echo esc_html( $author->orcid ); ?>)
					<?php endif; ?>
				</option>
			<?php endforeach; ?>
		</select>
		<p class="description">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wjm-authors' ) ); ?>">
				<?php esc_html_e( 'Manage authors', 'wisdom-journal-manager' ); ?>
			</a>
		</p>
		<?php
	}

	public static function save_journal( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_journal_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_journal_nonce'] ) ), 'wjm_save_journal' ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}

		self::update_text( $post_id, '_sjm_issn', 'sjm_issn' );
		self::update_text( $post_id, '_sjm_publisher', 'sjm_publisher' );
		self::update_textarea( $post_id, '_sjm_editorial_board', 'sjm_editorial_board' );

		/**
		 * Fires after journal metadata is saved.
		 *
		 * @param int $post_id Journal post ID.
		 */
		do_action( 'sjm_after_save_journal', $post_id );
	}

	public static function save_issue( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_issue_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_issue_nonce'] ) ), 'wjm_save_issue' ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}

		update_post_meta( $post_id, '_sjm_journal_id', isset( $_POST['sjm_journal_id'] ) ? absint( $_POST['sjm_journal_id'] ) : 0 );
		self::update_text( $post_id, '_sjm_volume', 'sjm_volume' );
		self::update_text( $post_id, '_sjm_number', 'sjm_number' );
		update_post_meta( $post_id, '_sjm_special_issue', ! empty( $_POST['sjm_special_issue'] ) ? '1' : '0' );
		self::update_textarea( $post_id, '_sjm_guest_editors', 'sjm_guest_editors' );
	}

	public static function save_paper( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_paper_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_paper_nonce'] ) ), 'wjm_save_paper' ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}

		update_post_meta( $post_id, '_sjm_issue_id', isset( $_POST['sjm_issue_id'] ) ? absint( $_POST['sjm_issue_id'] ) : 0 );
		self::update_text( $post_id, '_sjm_doi', 'sjm_doi' );
		self::update_textarea( $post_id, '_sjm_abstract', 'sjm_abstract' );
		self::update_text( $post_id, '_sjm_paper_type', 'sjm_paper_type' );
		update_post_meta( $post_id, '_sjm_open_access', ! empty( $_POST['sjm_open_access'] ) ? '1' : '0' );
		self::update_text( $post_id, '_sjm_submission_date', 'sjm_submission_date' );
		self::update_text( $post_id, '_sjm_acceptance_date', 'sjm_acceptance_date' );
		self::update_text( $post_id, '_sjm_page_range', 'sjm_page_range' );
		self::update_textarea( $post_id, '_sjm_funding', 'sjm_funding' );
		self::update_textarea( $post_id, '_sjm_conflicts', 'sjm_conflicts' );
		self::update_textarea( $post_id, '_sjm_ethics', 'sjm_ethics' );
		self::update_textarea( $post_id, '_sjm_data_availability', 'sjm_data_availability' );

		$author_ids = isset( $_POST['sjm_author_ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['sjm_author_ids'] ) ) : array();
		WJM_Author_Profiles::sync_paper_authors( $post_id, $author_ids );

		/**
		 * Fires after paper metadata is saved.
		 *
		 * @param int $post_id Paper post ID.
		 */
		do_action( 'sjm_after_save_paper', $post_id );
	}

	private static function update_text( $post_id, $meta_key, $field ) {
		if ( isset( $_POST[ $field ] ) ) {
			update_post_meta( $post_id, $meta_key, sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) );
		}
	}

	private static function update_textarea( $post_id, $meta_key, $field ) {
		if ( isset( $_POST[ $field ] ) ) {
			update_post_meta( $post_id, $meta_key, sanitize_textarea_field( wp_unslash( $_POST[ $field ] ) ) );
		}
	}
}
