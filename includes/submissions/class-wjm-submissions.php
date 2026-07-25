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
	 * @param int    $paper_id Paper ID.
	 * @param int    $attachment_id Attachment ID.
	 * @param string $role Role.
	 * @param string $version Version.
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

	/**
	 * @return array
	 */
	public static function paper_types() {
		return array(
			'original_research' => __( 'Original Research', 'wisdom-journal-manager' ),
			'review'            => __( 'Review', 'wisdom-journal-manager' ),
			'case_study'        => __( 'Case Study', 'wisdom-journal-manager' ),
			'editorial'         => __( 'Editorial', 'wisdom-journal-manager' ),
			'letter'            => __( 'Letter', 'wisdom-journal-manager' ),
			'meta_analysis'     => __( 'Meta-analysis', 'wisdom-journal-manager' ),
			'systematic_review' => __( 'Systematic Review', 'wisdom-journal-manager' ),
			'methods'           => __( 'Methods / Protocol', 'wisdom-journal-manager' ),
			'data_paper'        => __( 'Data Paper', 'wisdom-journal-manager' ),
			'corrigendum'       => __( 'Corrigendum', 'wisdom-journal-manager' ),
			'erratum'           => __( 'Erratum', 'wisdom-journal-manager' ),
			'retraction'        => __( 'Retraction', 'wisdom-journal-manager' ),
		);
	}

	public static function render_form( $atts ) {
		$atts = shortcode_atts( array( 'journal_id' => 0 ), $atts, 'wjm_submit' );
		if ( ! $atts['journal_id'] && isset( $_GET['journal_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$atts['journal_id'] = absint( $_GET['journal_id'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		$can = class_exists( 'WJM_Access' ) ? WJM_Access::can_submit() : true;
		if ( is_wp_error( $can ) ) {
			$code = $can->get_error_code();
			$html = '<div class="wjm-submit-portal"><div class="wjm-stage"><div class="wjm-stage__copy">';
			$html .= '<p class="wjm-eyebrow">' . esc_html__( 'Submissions', 'wisdom-journal-manager' ) . '</p>';
			$html .= '<h2 class="wjm-stage__title">' . esc_html__( 'Not available right now', 'wisdom-journal-manager' ) . '</h2>';
			$html .= '<p class="wjm-stage__lead">' . esc_html( $can->get_error_message() ) . '</p>';
			if ( 'wjm_login' === $code ) {
				$html .= '<p><a class="wjm-btn" href="' . esc_url( wp_login_url( get_permalink() ) ) . '">' . esc_html__( 'Log in to submit', 'wisdom-journal-manager' ) . '</a></p>';
			}
			$html .= '</div></div></div>';
			return $html;
		}

		$need_login = class_exists( 'WJM_Access' )
			&& ! WJM_Access::allowed( 'allow_guest_submit' )
			&& 'anyone' !== WJM_Access::get( 'who_can_submit' )
			&& ! is_user_logged_in();
		if ( $need_login ) {
			return '<div class="wjm-submit-portal"><div class="wjm-submit-gate"><p>' . esc_html__( 'Log in to submit your manuscript.', 'wisdom-journal-manager' ) . '</p><p><a class="wjm-btn" href="' . esc_url( wp_login_url( get_permalink() ) ) . '">' . esc_html__( 'Log in to submit', 'wisdom-journal-manager' ) . '</a></p></div></div>';
		}

		$access = class_exists( 'WJM_Access' ) ? WJM_Access::settings() : array();
		$draft  = class_exists( 'WJM_Drafts' ) ? WJM_Drafts::get_draft() : array();
		$journals = get_posts(
			array(
				'post_type'      => 'sjm_journal',
				'posts_per_page' => -1,
				'post_status'    => 'publish',
				'orderby'        => 'title',
				'order'          => 'ASC',
			)
		);

		$ext = ! empty( $access['allowed_extensions'] ) ? $access['allowed_extensions'] : 'pdf,doc,docx';
		$accept = '.' . implode( ',.', array_map( 'trim', explode( ',', $ext ) ) );
		$max_mb = ! empty( $access['max_file_mb'] ) ? (int) $access['max_file_mb'] : 25;
		$pay    = class_exists( 'WJM_Payments' ) ? WJM_Payments::settings() : array();

		ob_start();
		if ( isset( $_GET['wjm_draft_saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="wjm-notice wjm-notice-success"><p>' . esc_html__( 'Draft saved — come back anytime to finish.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		if ( ! empty( $draft ) && ! empty( $draft['saved_at'] ) && empty( $_GET['wjm_draft_saved'] ) && empty( $_GET['wjm_submitted'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="wjm-notice"><p>' . esc_html__( 'Resuming your saved draft.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		if ( isset( $_GET['wjm_submitted'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="wjm-notice wjm-notice-success"><p>' . esc_html__( 'Manuscript received. Editors have been notified — track it under My papers.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		if ( isset( $_GET['wjm_err'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="wjm-notice wjm-notice-error"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['wjm_err'] ) ) ) . '</p></div>';
		}
		?>
		<div class="wjm-submit-portal wjm-shama">
			<header class="wjm-stage">
				<div class="wjm-stage__copy">
					<p class="wjm-eyebrow"><?php esc_html_e( 'Submit', 'wisdom-journal-manager' ); ?></p>
					<h2 class="wjm-stage__title"><?php esc_html_e( 'Manuscript submission', 'wisdom-journal-manager' ); ?></h2>
					<p class="wjm-stage__lead"><?php esc_html_e( 'Complete each section. Required fields are marked. Save a draft anytime — upload the manuscript on final submit.', 'wisdom-journal-manager' ); ?></p>
				</div>
			</header>

			<?php if ( isset( $_GET['wjm_orcid'] ) && 'connected' === $_GET['wjm_orcid'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="wjm-notice wjm-notice-success"><p><?php esc_html_e( 'ORCID connected. You can fill your author line below.', 'wisdom-journal-manager' ); ?></p></div>
			<?php endif; ?>

			<?php if ( ! empty( $access['show_apc_hint_on_submit'] ) && ! empty( $pay['enabled'] ) ) : ?>
				<p class="wjm-notice"><?php echo esc_html( sprintf( __( 'This journal may charge an APC (%1$s %2$s). Payment is requested after acceptance unless waived.', 'wisdom-journal-manager' ), $pay['currency'], number_format( (float) $pay['default_apc'], 2 ) ) ); ?></p>
			<?php endif; ?>

			<?php
			if ( class_exists( 'WJM_ORCID' ) ) {
				echo WJM_ORCID::render_submit_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in method
			}
			?>

			<form class="wjm-submit-form wjm-submit-form--thorough" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
				<input type="hidden" name="action" value="wjm_submit_paper" />
				<?php wp_nonce_field( 'wjm_submit_paper' ); ?>

				<?php if ( ! is_user_logged_in() ) : ?>
					<section class="wjm-submit-section">
						<p class="wjm-eyebrow"><span class="wjm-step-num">0</span><?php esc_html_e( 'Contact', 'wisdom-journal-manager' ); ?></p>
						<h3 class="wjm-sec-title"><?php esc_html_e( 'Your email', 'wisdom-journal-manager' ); ?></h3>
						<p>
							<label for="wjm_guest_email"><?php esc_html_e( 'Email', 'wisdom-journal-manager' ); ?> *</label>
							<input type="email" name="guest_email" id="wjm_guest_email" value="<?php echo esc_attr( WJM_Drafts::val( 'guest_email' ) ); ?>" required />
						</p>
						<p>
							<label for="wjm_guest_name"><?php esc_html_e( 'Your name', 'wisdom-journal-manager' ); ?> *</label>
							<input type="text" name="guest_name" id="wjm_guest_name" value="<?php echo esc_attr( WJM_Drafts::val( 'guest_name' ) ); ?>" required />
						</p>
					</section>
				<?php endif; ?>

				<section class="wjm-submit-section">
					<p class="wjm-eyebrow"><span class="wjm-step-num">1</span><?php esc_html_e( 'Venue', 'wisdom-journal-manager' ); ?></p>
					<h3 class="wjm-sec-title"><?php esc_html_e( 'Journal & article type', 'wisdom-journal-manager' ); ?></h3>
					<p>
						<label for="wjm_journal_id"><?php esc_html_e( 'Journal', 'wisdom-journal-manager' ); ?> *</label>
						<select name="journal_id" id="wjm_journal_id" required>
							<option value=""><?php esc_html_e( '— Select journal —', 'wisdom-journal-manager' ); ?></option>
							<?php
							$sel_j = (int) $atts['journal_id'] ? (int) $atts['journal_id'] : (int) WJM_Drafts::val( 'journal_id' );
							foreach ( $journals as $journal ) :
								?>
								<option value="<?php echo esc_attr( $journal->ID ); ?>" <?php selected( $sel_j, $journal->ID ); ?>>
									<?php echo esc_html( $journal->post_title ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</p>
					<p>
						<label for="wjm_paper_type"><?php esc_html_e( 'Paper type', 'wisdom-journal-manager' ); ?></label>
						<select name="paper_type" id="wjm_paper_type">
							<?php foreach ( self::paper_types() as $key => $label ) : ?>
								<option value="<?php echo esc_attr( $key ); ?>" <?php selected( WJM_Drafts::val( 'paper_type', 'original_research' ), $key ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
					</p>
					<p>
						<label for="wjm_preprint"><?php esc_html_e( 'Preprint URL or DOI (optional)', 'wisdom-journal-manager' ); ?></label>
						<input type="text" name="preprint_url" id="wjm_preprint" value="<?php echo esc_attr( WJM_Drafts::val( 'preprint_url' ) ); ?>" placeholder="https://biorxiv.org/... or 10.1101/…" />
						<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-preprint-fetch><?php esc_html_e( 'Import from preprint', 'wisdom-journal-manager' ); ?></button>
						<span class="description" data-wjm-preprint-msg hidden></span>
					</p>
				</section>

				<section class="wjm-submit-section">
					<p class="wjm-eyebrow"><span class="wjm-step-num">2</span><?php esc_html_e( 'Manuscript', 'wisdom-journal-manager' ); ?></p>
					<h3 class="wjm-sec-title"><?php esc_html_e( 'Title, abstract, keywords', 'wisdom-journal-manager' ); ?></h3>
					<p>
						<label for="wjm_title"><?php esc_html_e( 'Title', 'wisdom-journal-manager' ); ?> *</label>
						<input type="text" name="title" id="wjm_title" required maxlength="300" value="<?php echo esc_attr( WJM_Drafts::val( 'title' ) ); ?>" />
					</p>
					<p>
						<label for="wjm_abstract"><?php esc_html_e( 'Abstract', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_abstract'] ) ? ' *' : ''; ?></label>
						<textarea name="abstract" id="wjm_abstract" rows="8" <?php echo ! empty( $access['require_abstract'] ) ? 'required' : ''; ?>><?php echo esc_textarea( WJM_Drafts::val( 'abstract' ) ); ?></textarea>
					</p>
					<p>
						<label for="wjm_keywords"><?php esc_html_e( 'Keywords (comma-separated)', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_keywords'] ) ? ' *' : ''; ?></label>
						<input type="text" name="keywords" id="wjm_keywords" <?php echo ! empty( $access['require_keywords'] ) ? 'required' : ''; ?> value="<?php echo esc_attr( WJM_Drafts::val( 'keywords' ) ); ?>" placeholder="<?php esc_attr_e( 'open science, peer review, knowledge systems', 'wisdom-journal-manager' ); ?>" />
					</p>
				</section>

				<section class="wjm-submit-section">
					<p class="wjm-eyebrow"><span class="wjm-step-num">3</span><?php esc_html_e( 'People', 'wisdom-journal-manager' ); ?></p>
					<h3 class="wjm-sec-title"><?php esc_html_e( 'Authors', 'wisdom-journal-manager' ); ?></h3>
					<p>
						<label for="wjm_authors_text"><?php esc_html_e( 'One author per line', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_authors'] ) ? ' *' : ''; ?></label>
						<textarea name="authors_text" id="wjm_authors_text" rows="5" <?php echo ! empty( $access['require_authors'] ) ? 'required' : ''; ?> placeholder="Ada Lovelace; Analytical Engine Lab; 0000-0000-0000-0000; writing_original; ada@example.com"><?php echo esc_textarea( WJM_Drafts::val( 'authors_text' ) ); ?></textarea>
						<span class="description"><?php esc_html_e( 'Format: First Last; Affiliation; ORCID; CRediT role; email (email triggers co-author confirm)', 'wisdom-journal-manager' ); ?></span>
					</p>
					<?php if ( class_exists( 'WJM_Author_Profiles' ) ) : ?>
						<p>
							<label for="wjm_credit_pick"><?php esc_html_e( 'Insert CRediT role slug', 'wisdom-journal-manager' ); ?></label>
							<select id="wjm_credit_pick">
								<option value=""><?php esc_html_e( '— Choose role —', 'wisdom-journal-manager' ); ?></option>
								<?php foreach ( WJM_Author_Profiles::credit_roles() as $ck => $cl ) : ?>
									<option value="<?php echo esc_attr( $ck ); ?>"><?php echo esc_html( $cl . ' (' . $ck . ')' ); ?></option>
								<?php endforeach; ?>
							</select>
							<button type="button" class="button" id="wjm_credit_insert"><?php esc_html_e( 'Copy slug', 'wisdom-journal-manager' ); ?></button>
						</p>
						<script>
						(function(){
							var btn=document.getElementById('wjm_credit_insert');
							var sel=document.getElementById('wjm_credit_pick');
							if(!btn||!sel) return;
							btn.addEventListener('click',function(){
								if(!sel.value) return;
								if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(sel.value);}
								else { window.prompt('CRediT slug', sel.value); }
							});
						})();
						</script>
					<?php endif; ?>
					<p>
						<label for="wjm_corresponding"><?php esc_html_e( 'Corresponding author email', 'wisdom-journal-manager' ); ?></label>
						<input type="email" name="corresponding_email" id="wjm_corresponding" value="<?php echo esc_attr( WJM_Drafts::val( 'corresponding_email', wp_get_current_user()->user_email ) ); ?>" />
					</p>
					<?php if ( ! empty( $access['allow_suggested_reviewers'] ) ) : ?>
						<p>
							<label for="wjm_suggested"><?php esc_html_e( 'Suggested reviewers (optional)', 'wisdom-journal-manager' ); ?></label>
							<textarea name="suggested_reviewers" id="wjm_suggested" rows="3" placeholder="<?php esc_attr_e( 'Name — email — expertise (one per line)', 'wisdom-journal-manager' ); ?>"><?php echo esc_textarea( WJM_Drafts::val( 'suggested_reviewers' ) ); ?></textarea>
						</p>
					<?php endif; ?>
				</section>

				<section class="wjm-submit-section">
					<p class="wjm-eyebrow"><span class="wjm-step-num">4</span><?php esc_html_e( 'Statements', 'wisdom-journal-manager' ); ?></p>
					<h3 class="wjm-sec-title"><?php esc_html_e( 'Ethics & compliance', 'wisdom-journal-manager' ); ?></h3>
					<?php if ( ! empty( $access['allow_cover_letter'] ) ) : ?>
						<p>
							<label for="wjm_cover"><?php esc_html_e( 'Cover letter', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_cover_letter'] ) ? ' *' : ''; ?></label>
							<textarea name="cover_letter" id="wjm_cover" rows="4" <?php echo ! empty( $access['require_cover_letter'] ) ? 'required' : ''; ?>><?php echo esc_textarea( WJM_Drafts::val( 'cover_letter' ) ); ?></textarea>
						</p>
					<?php endif; ?>
					<p>
						<label for="wjm_funding"><?php esc_html_e( 'Funding', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_funding'] ) ? ' *' : ''; ?></label>
						<textarea name="funding" id="wjm_funding" rows="2" <?php echo ! empty( $access['require_funding'] ) ? 'required' : ''; ?>><?php echo esc_textarea( WJM_Drafts::val( 'funding' ) ); ?></textarea>
					</p>
					<p>
						<label for="wjm_conflicts"><?php esc_html_e( 'Conflicts of interest', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_conflicts'] ) ? ' *' : ''; ?></label>
						<textarea name="conflicts" id="wjm_conflicts" rows="2" <?php echo ! empty( $access['require_conflicts'] ) ? 'required' : ''; ?>><?php echo esc_textarea( WJM_Drafts::val( 'conflicts' ) ); ?></textarea>
					</p>
					<p>
						<label for="wjm_ethics"><?php esc_html_e( 'Ethics / IRB', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_ethics'] ) ? ' *' : ''; ?></label>
						<textarea name="ethics" id="wjm_ethics" rows="2" <?php echo ! empty( $access['require_ethics'] ) ? 'required' : ''; ?>><?php echo esc_textarea( WJM_Drafts::val( 'ethics' ) ); ?></textarea>
					</p>
					<p>
						<label for="wjm_data"><?php esc_html_e( 'Data availability', 'wisdom-journal-manager' ); ?><?php echo ! empty( $access['require_data_availability'] ) ? ' *' : ''; ?></label>
						<textarea name="data_availability" id="wjm_data" rows="2" <?php echo ! empty( $access['require_data_availability'] ) ? 'required' : ''; ?>><?php echo esc_textarea( WJM_Drafts::val( 'data_availability' ) ); ?></textarea>
					</p>
					<?php if ( ! empty( $access['allow_open_access_request'] ) ) : ?>
						<p class="wjm-check">
							<label><input type="checkbox" name="open_access" value="1" /> <?php esc_html_e( 'Request open access', 'wisdom-journal-manager' ); ?></label>
						</p>
					<?php endif; ?>
				</section>

				<section class="wjm-submit-section">
					<p class="wjm-eyebrow"><span class="wjm-step-num">5</span><?php esc_html_e( 'Files', 'wisdom-journal-manager' ); ?></p>
					<h3 class="wjm-sec-title"><?php esc_html_e( 'Upload', 'wisdom-journal-manager' ); ?></h3>
					<?php if ( ! empty( $access['require_anonymized_file'] ) || ! empty( $access['blind_file_instructions'] ) ) : ?>
						<div class="wjm-blind-file-box" style="margin:0 0 1rem;padding:0.85rem 1rem;border:1px solid #c3c4c7;background:#f6f7f7;">
							<strong><?php esc_html_e( 'Double-blind file rules', 'wisdom-journal-manager' ); ?></strong>
							<p style="margin:0.4rem 0 0;"><?php echo esc_html( $access['blind_file_instructions'] ); ?></p>
							<ul style="margin:0.5rem 0 0;padding-left:1.2rem;">
								<li><?php esc_html_e( 'Anonymized manuscript: no names, emails, affiliations, or acknowledgements.', 'wisdom-journal-manager' ); ?></li>
								<li><?php esc_html_e( 'Separate title page: full author list for editors only (not sent to reviewers).', 'wisdom-journal-manager' ); ?></li>
							</ul>
						</div>
					<?php endif; ?>
					<p>
						<label for="wjm_manuscript"><?php echo ! empty( $access['require_anonymized_file'] ) ? esc_html__( 'Anonymized manuscript (for reviewers)', 'wisdom-journal-manager' ) : esc_html__( 'Manuscript', 'wisdom-journal-manager' ); ?><?php echo ( ! empty( $access['require_manuscript'] ) || ! empty( $access['require_anonymized_file'] ) ) ? ' *' : ''; ?></label>
						<input type="file" name="manuscript" id="wjm_manuscript" accept="<?php echo esc_attr( $accept ); ?>" <?php echo ( ! empty( $access['require_manuscript'] ) || ! empty( $access['require_anonymized_file'] ) ) ? 'required' : ''; ?> />
						<span class="description"><?php echo esc_html( sprintf( __( 'Allowed: %1$s · max %2$d MB', 'wisdom-journal-manager' ), $ext, $max_mb ) ); ?></span>
					</p>
					<?php if ( ! empty( $access['require_anonymized_file'] ) ) : ?>
						<p>
							<label for="wjm_title_page"><?php esc_html_e( 'Title page with author details (editors only)', 'wisdom-journal-manager' ); ?> *</label>
							<input type="file" name="title_page" id="wjm_title_page" accept="<?php echo esc_attr( $accept ); ?>" required />
						</p>
						<p class="wjm-check">
							<label>
								<input type="checkbox" name="declare_anonymized" value="1" required />
								<?php esc_html_e( 'I confirm the manuscript file is anonymized (no author-identifying information).', 'wisdom-journal-manager' ); ?>
							</label>
						</p>
					<?php endif; ?>
					<?php if ( ! empty( $access['allow_supplementary'] ) ) : ?>
						<p>
							<label for="wjm_supplement"><?php esc_html_e( 'Supplementary file (optional)', 'wisdom-journal-manager' ); ?></label>
							<input type="file" name="supplement" id="wjm_supplement" accept="<?php echo esc_attr( $accept ); ?>" />
						</p>
					<?php endif; ?>
				</section>

				<section class="wjm-submit-section wjm-submit-section--declare">
					<p class="wjm-check">
						<label>
							<input type="checkbox" name="declare_original" value="1" required />
							<?php echo esc_html( ! empty( $access['submission_notice'] ) ? $access['submission_notice'] : __( 'I confirm this work is original and not under review elsewhere.', 'wisdom-journal-manager' ) ); ?>
						</label>
					</p>
					<p>
						<button type="submit" class="wjm-btn"><?php esc_html_e( 'Submit manuscript', 'wisdom-journal-manager' ); ?></button>
						<button type="submit" class="wjm-btn wjm-btn-secondary" name="action" value="wjm_save_draft" formnovalidate><?php esc_html_e( 'Save draft', 'wisdom-journal-manager' ); ?></button>
					</p>
				</section>
			</form>
		</div>
		<?php
		return ob_get_clean();
	}

	public static function handle_submit() {
		$can = class_exists( 'WJM_Access' ) ? WJM_Access::can_submit() : true;
		if ( is_wp_error( $can ) ) {
			self::redirect_err( $can->get_error_message() );
		}

		$access = class_exists( 'WJM_Access' ) ? WJM_Access::settings() : array();
		$guest  = false;

		if ( ! is_user_logged_in() ) {
			if ( empty( $access['allow_guest_submit'] ) && 'anyone' !== ( $access['who_can_submit'] ?? '' ) ) {
				auth_redirect();
			}
			$guest = true;
		}

		check_admin_referer( 'wjm_submit_paper' );

		$title      = isset( $_POST['title'] ) ? sanitize_text_field( wp_unslash( $_POST['title'] ) ) : '';
		$abstract   = isset( $_POST['abstract'] ) ? sanitize_textarea_field( wp_unslash( $_POST['abstract'] ) ) : '';
		$journal_id = isset( $_POST['journal_id'] ) ? absint( $_POST['journal_id'] ) : 0;

		if ( ! $title || ! $journal_id ) {
			self::redirect_err( __( 'Title and journal are required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_abstract'] ) && ! $abstract ) {
			self::redirect_err( __( 'Abstract is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_authors'] ) && empty( $_POST['authors_text'] ) ) {
			self::redirect_err( __( 'Author list is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_keywords'] ) && empty( $_POST['keywords'] ) ) {
			self::redirect_err( __( 'Keywords are required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_funding'] ) && empty( $_POST['funding'] ) ) {
			self::redirect_err( __( 'Funding statement is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_conflicts'] ) && empty( $_POST['conflicts'] ) ) {
			self::redirect_err( __( 'Conflicts statement is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_ethics'] ) && empty( $_POST['ethics'] ) ) {
			self::redirect_err( __( 'Ethics statement is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_data_availability'] ) && empty( $_POST['data_availability'] ) ) {
			self::redirect_err( __( 'Data availability is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_cover_letter'] ) && empty( $_POST['cover_letter'] ) ) {
			self::redirect_err( __( 'Cover letter is required.', 'wisdom-journal-manager' ) );
		}
		if ( empty( $_POST['declare_original'] ) ) {
			self::redirect_err( __( 'Please confirm the originality declaration.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_manuscript'] ) && empty( $_FILES['manuscript']['name'] ) ) {
			self::redirect_err( __( 'Manuscript file is required.', 'wisdom-journal-manager' ) );
		}
		if ( ! empty( $access['require_anonymized_file'] ) ) {
			if ( empty( $_FILES['manuscript']['name'] ) ) {
				self::redirect_err( __( 'Anonymized manuscript is required for double-blind review.', 'wisdom-journal-manager' ) );
			}
			if ( empty( $_FILES['title_page']['name'] ) ) {
				self::redirect_err( __( 'Title page with author details is required (editors only).', 'wisdom-journal-manager' ) );
			}
			if ( empty( $_POST['declare_anonymized'] ) ) {
				self::redirect_err( __( 'Please confirm the manuscript is anonymized.', 'wisdom-journal-manager' ) );
			}
		}

		$author_id = get_current_user_id();
		if ( $guest ) {
			$email = isset( $_POST['guest_email'] ) ? sanitize_email( wp_unslash( $_POST['guest_email'] ) ) : '';
			$name  = isset( $_POST['guest_name'] ) ? sanitize_text_field( wp_unslash( $_POST['guest_name'] ) ) : '';
			if ( ! $email || ! is_email( $email ) || ! $name ) {
				self::redirect_err( __( 'Guest name and valid email are required.', 'wisdom-journal-manager' ) );
			}
			$user = get_user_by( 'email', $email );
			if ( $user ) {
				$author_id = $user->ID;
			} else {
				$login = sanitize_user( current( explode( '@', $email ) ) . '_' . wp_generate_password( 4, false ), true );
				$pass  = wp_generate_password( 16, true );
				$uid   = wp_create_user( $login, $pass, $email );
				if ( is_wp_error( $uid ) ) {
					self::redirect_err( $uid->get_error_message() );
				}
				wp_update_user(
					array(
						'ID'           => $uid,
						'display_name' => $name,
						'first_name'   => $name,
						'role'         => 'sjm_researcher',
					)
				);
				$author_id = $uid;
			}
		}

		$paper_id = wp_insert_post(
			array(
				'post_type'    => 'sjm_paper',
				'post_title'   => $title,
				'post_content' => isset( $_POST['cover_letter'] ) ? sanitize_textarea_field( wp_unslash( $_POST['cover_letter'] ) ) : $abstract,
				'post_status'  => 'private',
				'post_author'  => $author_id ? $author_id : 1,
			),
			true
		);

		if ( is_wp_error( $paper_id ) ) {
			self::redirect_err( $paper_id->get_error_message() );
		}

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
		update_post_meta( $paper_id, '_sjm_ethics', isset( $_POST['ethics'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ethics'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_data_availability', isset( $_POST['data_availability'] ) ? sanitize_textarea_field( wp_unslash( $_POST['data_availability'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_cover_letter', isset( $_POST['cover_letter'] ) ? sanitize_textarea_field( wp_unslash( $_POST['cover_letter'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_corresponding_email', isset( $_POST['corresponding_email'] ) ? sanitize_email( wp_unslash( $_POST['corresponding_email'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_suggested_reviewers', isset( $_POST['suggested_reviewers'] ) ? sanitize_textarea_field( wp_unslash( $_POST['suggested_reviewers'] ) ) : '' );
		update_post_meta( $paper_id, '_sjm_submission_date', gmdate( 'Y-m-d' ) );
		if ( ! empty( $_POST['preprint_url'] ) ) {
			$pre = sanitize_text_field( wp_unslash( $_POST['preprint_url'] ) );
			if ( class_exists( 'WJM_Preprint' ) ) {
				$doi = WJM_Preprint::extract_doi( $pre );
				if ( $doi && 0 !== stripos( $pre, 'http' ) ) {
					$pre = 'https://doi.org/' . $doi;
				}
			}
			update_post_meta( $paper_id, '_sjm_preprint_url', esc_url_raw( $pre ) );
		}
		if ( ! empty( $_POST['authors_text'] ) ) {
			update_post_meta( $paper_id, '_sjm_authors_confirm_queue', sanitize_textarea_field( wp_unslash( $_POST['authors_text'] ) ) );
		}

		if ( ! empty( $_POST['keywords'] ) ) {
			$keywords = array_filter( array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_POST['keywords'] ) ) ) ) );
			wp_set_object_terms( $paper_id, $keywords, 'sjm_keyword', false );
		}

		self::parse_and_link_authors( $paper_id, isset( $_POST['authors_text'] ) ? wp_unslash( $_POST['authors_text'] ) : '' );

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';

		if ( ! empty( $_FILES['manuscript']['name'] ) ) {
			self::validate_upload( $_FILES['manuscript'], $access ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$attachment_id = media_handle_upload( 'manuscript', $paper_id );
			if ( is_wp_error( $attachment_id ) ) {
				self::redirect_err( $attachment_id->get_error_message() );
			}
			$role = ! empty( $access['require_anonymized_file'] ) ? 'anonymized_manuscript' : 'manuscript';
			self::attach_file( $paper_id, $attachment_id, $role, 'v1' );
		}

		if ( ! empty( $access['require_anonymized_file'] ) && ! empty( $_FILES['title_page']['name'] ) ) {
			self::validate_upload( $_FILES['title_page'], $access ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$tp = media_handle_upload( 'title_page', $paper_id );
			if ( is_wp_error( $tp ) ) {
				self::redirect_err( $tp->get_error_message() );
			}
			self::attach_file( $paper_id, $tp, 'title_page', 'v1' );
		}

		if ( ! empty( $access['allow_supplementary'] ) && ! empty( $_FILES['supplement']['name'] ) ) {
			self::validate_upload( $_FILES['supplement'], $access ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$sup = media_handle_upload( 'supplement', $paper_id );
			if ( ! is_wp_error( $sup ) ) {
				self::attach_file( $paper_id, $sup, 'supplement', 'v1' );
			}
		}

		WJM_Workflow::transition( $paper_id, 'submitted', __( 'Author submission portal', 'wisdom-journal-manager' ) );

		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::notify_editors( $paper_id, 'new_submission' );
			if ( $author_id ) {
				WJM_Email::send_template( $author_id, 'submission_received', $paper_id );
			}
		}

		do_action( 'sjm_after_save_paper', $paper_id );

		if ( class_exists( 'WJM_Drafts' ) ) {
			WJM_Drafts::clear_draft();
		}

		$redirect = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_submitted', '1', $redirect ) );
		exit;
	}

	/**
	 * @param array $file $_FILES row.
	 * @param array $access Access settings.
	 */
	private static function validate_upload( $file, $access ) {
		$max = ( ! empty( $access['max_file_mb'] ) ? (int) $access['max_file_mb'] : 25 ) * 1024 * 1024;
		if ( ! empty( $file['size'] ) && $file['size'] > $max ) {
			self::redirect_err( __( 'File exceeds the maximum allowed size.', 'wisdom-journal-manager' ) );
		}
		$exts = array_map( 'trim', explode( ',', ! empty( $access['allowed_extensions'] ) ? $access['allowed_extensions'] : 'pdf,doc,docx' ) );
		$name = isset( $file['name'] ) ? $file['name'] : '';
		$ext  = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		if ( $ext && ! in_array( $ext, $exts, true ) ) {
			self::redirect_err( __( 'File type not allowed.', 'wisdom-journal-manager' ) );
		}
	}

	/**
	 * @param int    $paper_id Paper ID.
	 * @param string $text Author lines.
	 */
	private static function parse_and_link_authors( $paper_id, $text ) {
		$lines = array_filter( array_map( 'trim', explode( "\n", (string) $text ) ) );
		$ids   = array();
		$roles = array();
		foreach ( $lines as $line ) {
			$parts = array_map( 'trim', explode( ';', $line ) );
			$name  = $parts[0] ?? '';
			if ( ! $name ) {
				continue;
			}
			$name_parts = preg_split( '/\s+/', $name );
			$last       = array_pop( $name_parts );
			$first      = implode( ' ', $name_parts );
			$role       = isset( $parts[3] ) ? sanitize_key( $parts[3] ) : '';
			$email      = isset( $parts[4] ) ? sanitize_email( $parts[4] ) : '';
			if ( $role && is_email( $parts[3] ) ) {
				$email = sanitize_email( $parts[3] );
				$role  = '';
			}
			$author_id = WJM_Author_Profiles::save_author(
				array(
					'first_name'  => $first ? $first : $name,
					'last_name'   => $last ? $last : '',
					'affiliation' => $parts[1] ?? '',
					'orcid'       => $parts[2] ?? '',
					'email'       => $email,
				)
			);
			if ( $author_id ) {
				$ids[] = $author_id;
				if ( $role ) {
					$roles[ $author_id ] = $role;
				}
			}
		}
		if ( $ids ) {
			WJM_Author_Profiles::sync_paper_authors( $paper_id, $ids, $roles );
		}
	}

	private static function redirect_err( $message ) {
		$redirect = wp_get_referer() ? wp_get_referer() : home_url( '/' );
		wp_safe_redirect( add_query_arg( 'wjm_err', rawurlencode( $message ), $redirect ) );
		exit;
	}

	public static function render_my_submissions() {
		if ( class_exists( 'WJM_Access' ) && ! WJM_Access::allowed( 'show_my_papers_shortcode' ) ) {
			return '';
		}
		if ( ! is_user_logged_in() ) {
			return '<p>' . esc_html__( 'Please log in to see your papers.', 'wisdom-journal-manager' ) . ' <a href="' . esc_url( wp_login_url( get_permalink() ) ) . '">' . esc_html__( 'Log in', 'wisdom-journal-manager' ) . '</a></p>';
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
		echo '<div class="wjm-my-papers wjm-shama">';
		echo '<p class="wjm-eyebrow">' . esc_html__( 'Account', 'wisdom-journal-manager' ) . '</p>';
		echo '<h3 class="wjm-sec-title">' . esc_html__( 'My papers', 'wisdom-journal-manager' ) . '</h3>';
		if ( ! $papers ) {
			echo '<p class="description">' . esc_html__( 'No submissions yet.', 'wisdom-journal-manager' ) . '</p>';
			echo '</div>';
			return ob_get_clean();
		}
		echo '<ul class="wjm-my-submissions">';
		foreach ( $papers as $paper ) {
			$status = WJM_Workflow::get_status( $paper->ID );
			$label  = WJM_Workflow::statuses()[ $status ] ?? $status;
			$apc    = get_post_meta( $paper->ID, '_sjm_apc_status', true );
			echo '<li>';
			echo '<a href="' . esc_url( get_permalink( $paper->ID ) ) . '"><strong>' . esc_html( $paper->post_title ) . '</strong></a> ';
			echo '<span class="wjm-status-badge wjm-status-' . esc_attr( $status ) . '">' . esc_html( $label ) . '</span>';
			if ( $apc && 'unpaid' === $apc ) {
				echo ' <a class="wjm-btn" style="padding:0.25rem 0.6rem;font-size:0.85rem;" href="' . esc_url( get_permalink( $paper->ID ) . '#wjm-apc' ) . '">' . esc_html__( 'Pay APC', 'wisdom-journal-manager' ) . '</a>';
			} elseif ( $apc && 'paid' === $apc ) {
				echo ' <span class="description">' . esc_html__( 'APC paid', 'wisdom-journal-manager' ) . '</span>';
			}
			echo '</li>';
		}
		echo '</ul></div>';
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
			<?php wp_nonce_field( 'wjm_upload_manuscript_' . $post->ID ); ?>
			<p>
				<select name="file_role">
					<option value="manuscript"><?php esc_html_e( 'Manuscript', 'wisdom-journal-manager' ); ?></option>
					<option value="anonymized_manuscript"><?php esc_html_e( 'Anonymized manuscript', 'wisdom-journal-manager' ); ?></option>
					<option value="title_page"><?php esc_html_e( 'Title page (editors)', 'wisdom-journal-manager' ); ?></option>
					<option value="supplement"><?php esc_html_e( 'Supplement', 'wisdom-journal-manager' ); ?></option>
					<option value="revision"><?php esc_html_e( 'Revision', 'wisdom-journal-manager' ); ?></option>
					<option value="camera_ready"><?php esc_html_e( 'Camera ready', 'wisdom-journal-manager' ); ?></option>
				</select>
			</p>
			<p><input type="file" name="manuscript_file" required /></p>
			<p><input type="text" name="version_label" placeholder="v2" class="widefat" /></p>
			<?php submit_button( __( 'Upload', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php
	}

	public static function handle_upload() {
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		check_admin_referer( 'wjm_upload_manuscript_' . $paper_id );
		if ( ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';
		$attachment_id = media_handle_upload( 'manuscript_file', $paper_id );
		if ( is_wp_error( $attachment_id ) ) {
			wp_die( esc_html( $attachment_id->get_error_message() ) );
		}
		$role    = isset( $_POST['file_role'] ) ? sanitize_key( wp_unslash( $_POST['file_role'] ) ) : 'manuscript';
		$version = isset( $_POST['version_label'] ) ? sanitize_text_field( wp_unslash( $_POST['version_label'] ) ) : '';
		self::attach_file( $paper_id, $attachment_id, $role, $version );
		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}
}
