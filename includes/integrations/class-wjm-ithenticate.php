<?php
/**
 * iThenticate / Turnitin Core API (TCA) — submit manuscript, pull similarity %.
 * Never auto-rejects; stores score for editors.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Ithenticate {

	const OPT       = 'wjm_ithenticate_settings';
	const META_ID   = '_sjm_ithenticate_submission_id';
	const META_URL  = '_sjm_ithenticate_report_url';
	const META_STAT = '_sjm_ithenticate_status';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 57 );
		add_action( 'admin_post_wjm_save_ithenticate', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_wjm_ithenticate_submit', array( __CLASS__, 'handle_submit' ) );
		add_action( 'admin_post_wjm_ithenticate_refresh', array( __CLASS__, 'handle_refresh' ) );
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ), 20 );
	}

	/**
	 * @return array
	 */
	public static function defaults() {
		return array(
			'enabled'           => 0,
			'api_base'          => '',
			'warn_threshold'    => 25,
			'integration_name'  => 'WisdomJournalManager',
			'auto_on_submit'    => 0,
		);
	}

	/**
	 * @return array
	 */
	public static function settings() {
		$stored = get_option( self::OPT, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * @return string
	 */
	public static function api_key() {
		return class_exists( 'WJM_Encryption' ) ? WJM_Encryption::get_secret( 'wjm_ithenticate_api_key' ) : (string) get_option( 'wjm_ithenticate_api_key', '' );
	}

	/**
	 * @return bool
	 */
	public static function ready() {
		$s = self::settings();
		return ! empty( $s['enabled'] ) && ! empty( $s['api_base'] ) && (bool) self::api_key();
	}

	/**
	 * Normalize base to …/api/v1
	 *
	 * @param string $base Base URL.
	 * @return string
	 */
	public static function normalize_base( $base ) {
		$base = untrailingslashit( trim( $base ) );
		if ( ! $base ) {
			return '';
		}
		if ( false === stripos( $base, '/api/v1' ) ) {
			$base .= '/api/v1';
		}
		return untrailingslashit( $base );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'iThenticate', 'wisdom-journal-manager' ),
			__( 'iThenticate', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-ithenticate',
			array( __CLASS__, 'render_settings' )
		);
	}

	public static function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$s = self::settings();
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$n = get_transient( 'wjm_ithenticate_notice' );
			delete_transient( 'wjm_ithenticate_notice' );
			if ( 'need_keys' === $n ) {
				echo '<div class="notice notice-warning"><p>' . esc_html__( 'Enable stayed OFF — API base URL + API key are required first.', 'wisdom-journal-manager' ) . '</p></div>';
			} else {
				echo '<div class="notice notice-success"><p>' . esc_html__( 'iThenticate settings saved.', 'wisdom-journal-manager' ) . '</p></div>';
			}
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'iThenticate / Similarity Check', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Turnitin Core API (iThenticate 2 / Similarity Check). Scores are stored for editors — never auto-reject.', 'wisdom-journal-manager' ); ?></p>
			<div class="notice notice-info inline">
				<p><strong><?php esc_html_e( 'Requirement to turn this on:', 'wisdom-journal-manager' ); ?></strong>
				<?php esc_html_e( 'A Turnitin / iThenticate 2 (or Crossref Similarity Check) tenant with an API key and base URL. Without those, leave Enable off — manual similarity % on the paper still works.', 'wisdom-journal-manager' ); ?></p>
			</div>
			<ol>
				<li><?php esc_html_e( 'Create an API key in your iThenticate 2 / Crossref Similarity Check admin.', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'API base example: https://crossref-XXXX.turnitin.com/api/v1 (or your tenant URL + /api/v1).', 'wisdom-journal-manager' ); ?></li>
				<li><?php esc_html_e( 'On a paper, use “Submit to iThenticate” after a manuscript file is attached.', 'wisdom-journal-manager' ); ?></li>
			</ol>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_ithenticate" />
				<?php wp_nonce_field( 'wjm_save_ithenticate' ); ?>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Enable', 'wisdom-journal-manager' ); ?></th>
						<td><label><input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $s['enabled'] ) ); ?> /> <?php esc_html_e( 'Show submit/refresh on papers', 'wisdom-journal-manager' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'API base URL', 'wisdom-journal-manager' ); ?></th>
						<td><input type="url" class="large-text" name="api_base" value="<?php echo esc_attr( $s['api_base'] ); ?>" placeholder="https://….turnitin.com/api/v1" /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'API key', 'wisdom-journal-manager' ); ?></th>
						<td><input type="password" class="large-text" name="api_key" value="" autocomplete="new-password" placeholder="<?php echo self::api_key() ? esc_attr__( '•••• saved — leave blank to keep', 'wisdom-journal-manager' ) : ''; ?>" /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Warn threshold %', 'wisdom-journal-manager' ); ?></th>
						<td>
							<input type="number" min="0" max="100" name="warn_threshold" value="<?php echo esc_attr( $s['warn_threshold'] ); ?>" style="width:5rem;" />
							<p class="description"><?php esc_html_e( 'At or above this score, soft “similarity needs review” integrity flag is set. Still never auto-rejects.', 'wisdom-journal-manager' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save iThenticate settings', 'wisdom-journal-manager' ) ); ?>
			</form>
			<p class="description"><?php echo self::ready() ? esc_html__( 'API is configured.', 'wisdom-journal-manager' ) : esc_html__( 'Enable + base URL + API key required.', 'wisdom-journal-manager' ); ?></p>
		</div>
		<?php
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_ithenticate' );
		$base = isset( $_POST['api_base'] ) ? self::normalize_base( esc_url_raw( wp_unslash( $_POST['api_base'] ) ) ) : '';
		$key  = ! empty( $_POST['api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) : self::api_key();
		$want = ! empty( $_POST['enabled'] ) ? 1 : 0;
		if ( $want && ( ! $base || ! $key ) ) {
			$want = 0;
			set_transient( 'wjm_ithenticate_notice', 'need_keys', 60 );
		}
		update_option(
			self::OPT,
			array(
				'enabled'          => $want,
				'api_base'         => $base,
				'warn_threshold'   => isset( $_POST['warn_threshold'] ) ? max( 0, min( 100, (float) wp_unslash( $_POST['warn_threshold'] ) ) ) : 25,
				'integration_name' => 'WisdomJournalManager',
				'auto_on_submit'   => 0,
			)
		);
		if ( ! empty( $_POST['api_key'] ) ) {
			$key = sanitize_text_field( wp_unslash( $_POST['api_key'] ) );
			if ( class_exists( 'WJM_Encryption' ) ) {
				WJM_Encryption::set_secret( 'wjm_ithenticate_api_key', $key );
			} else {
				update_option( 'wjm_ithenticate_api_key', $key );
			}
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-ithenticate&saved=1' ) );
		exit;
	}

	public static function meta_box() {
		if ( ! self::ready() ) {
			return;
		}
		add_meta_box(
			'wjm_ithenticate',
			__( 'iThenticate', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_paper_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	public static function render_paper_box( $post ) {
		$pct    = get_post_meta( $post->ID, '_sjm_similarity_pct', true );
		$status = get_post_meta( $post->ID, self::META_STAT, true );
		$sid    = get_post_meta( $post->ID, self::META_ID, true );
		$url    = get_post_meta( $post->ID, self::META_URL, true );
		$err    = get_post_meta( $post->ID, '_sjm_ithenticate_error', true );
		if ( ! empty( $_GET['ithenticate'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$flag = sanitize_key( wp_unslash( $_GET['ithenticate'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( 'ok' === $flag ) {
				echo '<p class="description" style="color:green;">' . esc_html__( 'iThenticate updated.', 'wisdom-journal-manager' ) . '</p>';
			} elseif ( 'err' === $flag ) {
				echo '<p class="description" style="color:#b32d2e;">' . esc_html( $err ? $err : __( 'Request failed.', 'wisdom-journal-manager' ) ) . '</p>';
			}
		}
		if ( '' !== $pct && null !== $pct ) {
			echo '<p><strong>' . esc_html__( 'Similarity', 'wisdom-journal-manager' ) . ':</strong> ' . esc_html( $pct ) . '%</p>';
		}
		if ( $status ) {
			echo '<p class="description">' . esc_html( sprintf( __( 'Status: %s', 'wisdom-journal-manager' ), $status ) ) . '</p>';
		}
		if ( $url ) {
			echo '<p><a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html__( 'Open report', 'wisdom-journal-manager' ) . '</a></p>';
		}
		if ( $sid ) {
			echo '<p class="description"><code>' . esc_html( $sid ) . '</code></p>';
		}
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0.5rem 0;">
			<input type="hidden" name="action" value="wjm_ithenticate_submit" />
			<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
			<?php wp_nonce_field( 'wjm_ithenticate_submit_' . $post->ID ); ?>
			<?php submit_button( __( 'Submit to iThenticate', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php if ( $sid ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_ithenticate_refresh" />
				<input type="hidden" name="paper_id" value="<?php echo esc_attr( $post->ID ); ?>" />
				<?php wp_nonce_field( 'wjm_ithenticate_refresh_' . $post->ID ); ?>
				<?php submit_button( __( 'Refresh score', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
			</form>
		<?php endif; ?>
		<p class="description"><?php esc_html_e( 'Requires a manuscript file on this paper.', 'wisdom-journal-manager' ); ?></p>
		<?php
	}

	public static function handle_submit() {
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		check_admin_referer( 'wjm_ithenticate_submit_' . $paper_id );
		if ( ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$result = self::submit_paper( $paper_id );
		$redir  = get_edit_post_link( $paper_id, 'raw' );
		if ( is_wp_error( $result ) ) {
			update_post_meta( $paper_id, '_sjm_ithenticate_error', $result->get_error_message() );
			wp_safe_redirect( add_query_arg( 'ithenticate', 'err', $redir ) );
			exit;
		}
		delete_post_meta( $paper_id, '_sjm_ithenticate_error' );
		wp_safe_redirect( add_query_arg( 'ithenticate', 'ok', $redir ) );
		exit;
	}

	public static function handle_refresh() {
		$paper_id = isset( $_POST['paper_id'] ) ? absint( $_POST['paper_id'] ) : 0;
		check_admin_referer( 'wjm_ithenticate_refresh_' . $paper_id );
		if ( ! current_user_can( 'edit_post', $paper_id ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$result = self::refresh_score( $paper_id );
		$redir  = get_edit_post_link( $paper_id, 'raw' );
		if ( is_wp_error( $result ) ) {
			update_post_meta( $paper_id, '_sjm_ithenticate_error', $result->get_error_message() );
			wp_safe_redirect( add_query_arg( 'ithenticate', 'err', $redir ) );
			exit;
		}
		delete_post_meta( $paper_id, '_sjm_ithenticate_error' );
		wp_safe_redirect( add_query_arg( 'ithenticate', 'ok', $redir ) );
		exit;
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return true|WP_Error
	 */
	public static function submit_paper( $paper_id ) {
		if ( ! self::ready() ) {
			return new WP_Error( 'wjm_ith', __( 'iThenticate is not configured.', 'wisdom-journal-manager' ) );
		}
		$file_path = self::manuscript_path( $paper_id );
		if ( is_wp_error( $file_path ) ) {
			return $file_path;
		}

		$owner = wp_get_current_user();
		$body  = array(
			'owner'       => $owner && $owner->user_email ? $owner->user_email : get_option( 'admin_email' ),
			'title'       => get_the_title( $paper_id ),
			'submitter'   => $owner && $owner->user_email ? $owner->user_email : get_option( 'admin_email' ),
			'metadata'    => array(
				'custom' => array(
					array(
						'key'   => 'wjm_paper_id',
						'value' => (string) $paper_id,
					),
				),
			),
		);

		$created = self::request( 'POST', '/submissions', $body );
		if ( is_wp_error( $created ) ) {
			return $created;
		}
		$sid = $created['id'] ?? ( $created['submission_id'] ?? '' );
		if ( ! $sid ) {
			return new WP_Error( 'wjm_ith', __( 'No submission id returned from iThenticate.', 'wisdom-journal-manager' ) );
		}
		update_post_meta( $paper_id, self::META_ID, sanitize_text_field( $sid ) );
		update_post_meta( $paper_id, self::META_STAT, 'CREATED' );

		$upload = self::upload_file( $sid, $file_path );
		if ( is_wp_error( $upload ) ) {
			update_post_meta( $paper_id, self::META_STAT, 'UPLOAD_ERROR' );
			return $upload;
		}
		update_post_meta( $paper_id, self::META_STAT, 'PROCESSING' );

		$gen = self::request( 'PUT', '/submissions/' . rawurlencode( $sid ) . '/similarity', array( 'generation_settings' => array( 'search_repositories' => array( 'INTERNET', 'SUBMITTED_WORK', 'PUBLICATION', 'CROSSREF', 'CROSSREF_POSTED_CONTENT' ) ) ) );
		if ( is_wp_error( $gen ) ) {
			// Some tenants use POST.
			$gen = self::request( 'POST', '/submissions/' . rawurlencode( $sid ) . '/similarity', array() );
		}
		if ( is_wp_error( $gen ) ) {
			update_post_meta( $paper_id, self::META_STAT, 'SIMILARITY_QUEUED' );
			// Still try refresh later.
		} else {
			update_post_meta( $paper_id, self::META_STAT, 'SIMILARITY_PROCESSING' );
		}

		// Best-effort immediate poll.
		self::refresh_score( $paper_id );

		if ( class_exists( 'WJM_Audit' ) ) {
			WJM_Audit::log( 'info', 'ithenticate_submit', sprintf( 'Paper %d → iThenticate %s', $paper_id, $sid ), array( 'paper_id' => $paper_id ) );
		}
		return true;
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return true|WP_Error
	 */
	public static function refresh_score( $paper_id ) {
		$sid = get_post_meta( $paper_id, self::META_ID, true );
		if ( ! $sid ) {
			return new WP_Error( 'wjm_ith', __( 'No iThenticate submission on this paper.', 'wisdom-journal-manager' ) );
		}
		$report = self::request( 'GET', '/submissions/' . rawurlencode( $sid ) . '/similarity' );
		if ( is_wp_error( $report ) ) {
			return $report;
		}

		$pct = null;
		if ( isset( $report['overall_match_percentage'] ) ) {
			$pct = (float) $report['overall_match_percentage'];
		} elseif ( isset( $report['similarity']['overall_match_percentage'] ) ) {
			$pct = (float) $report['similarity']['overall_match_percentage'];
		} elseif ( isset( $report['status'] ) && 'COMPLETE' !== strtoupper( (string) $report['status'] ) ) {
			update_post_meta( $paper_id, self::META_STAT, sanitize_text_field( $report['status'] ) );
			return true;
		}

		if ( null !== $pct ) {
			update_post_meta( $paper_id, '_sjm_similarity_pct', (string) round( $pct, 1 ) );
			update_post_meta( $paper_id, '_sjm_similarity_source', 'iThenticate' );
			update_post_meta( $paper_id, self::META_STAT, 'COMPLETE' );
			self::maybe_flag( $paper_id, $pct );
		}

		$viewer = self::request(
			'POST',
			'/submissions/' . rawurlencode( $sid ) . '/viewer-url',
			array(
				'viewer_default_permission_set' => 'INSTRUCTOR',
				'locale'                        => 'en-US',
			)
		);
		if ( ! is_wp_error( $viewer ) && ! empty( $viewer['viewer_url'] ) ) {
			update_post_meta( $paper_id, self::META_URL, esc_url_raw( $viewer['viewer_url'] ) );
		} elseif ( ! empty( $report['viewer_url'] ) ) {
			update_post_meta( $paper_id, self::META_URL, esc_url_raw( $report['viewer_url'] ) );
		}

		return true;
	}

	/**
	 * Soft integrity flag only.
	 *
	 * @param int   $paper_id Paper ID.
	 * @param float $pct Percent.
	 */
	private static function maybe_flag( $paper_id, $pct ) {
		$s = self::settings();
		if ( $pct < (float) $s['warn_threshold'] ) {
			return;
		}
		if ( ! class_exists( 'WJM_Integrity' ) ) {
			return;
		}
		$flags = WJM_Integrity::get_flags( $paper_id );
		$flags['plagiarism_review'] = 1;
		update_post_meta( $paper_id, WJM_Integrity::META, $flags );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return string|WP_Error Absolute path.
	 */
	private static function manuscript_path( $paper_id ) {
		$attachment_id = 0;
		if ( class_exists( 'WJM_Submissions' ) ) {
			$files = WJM_Submissions::get_files( $paper_id );
			foreach ( (array) $files as $f ) {
				if ( 'manuscript' === ( $f->file_role ?? '' ) || ! $attachment_id ) {
					$attachment_id = (int) $f->attachment_id;
					if ( 'manuscript' === ( $f->file_role ?? '' ) ) {
						break;
					}
				}
			}
		}
		if ( ! $attachment_id ) {
			return new WP_Error( 'wjm_ith', __( 'No manuscript file attached.', 'wisdom-journal-manager' ) );
		}
		$path = get_attached_file( $attachment_id );
		if ( ! $path || ! file_exists( $path ) ) {
			return new WP_Error( 'wjm_ith', __( 'Manuscript file missing on disk.', 'wisdom-journal-manager' ) );
		}
		return $path;
	}

	/**
	 * @param string $sid Submission id.
	 * @param string $path File path.
	 * @return true|WP_Error
	 */
	private static function upload_file( $sid, $path ) {
		$s    = self::settings();
		$base = self::normalize_base( $s['api_base'] );
		$url  = $base . '/submissions/' . rawurlencode( $sid ) . '/original';
		$bin  = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $bin ) {
			return new WP_Error( 'wjm_ith', __( 'Could not read manuscript file.', 'wisdom-journal-manager' ) );
		}
		$res = wp_remote_request(
			$url,
			array(
				'method'  => 'PUT',
				'timeout' => 120,
				'headers' => self::headers(
					array(
						'Content-Type'        => 'binary/octet-stream',
						'Content-Disposition' => 'inline; filename="' . basename( $path ) . '"',
					)
				),
				'body'    => $bin,
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$code = wp_remote_retrieve_response_code( $res );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'wjm_ith', sprintf( /* translators: %d HTTP status */ __( 'Upload failed (HTTP %d).', 'wisdom-journal-manager' ), $code ) . ' ' . wp_remote_retrieve_body( $res ) );
		}
		return true;
	}

	/**
	 * @param string     $method HTTP method.
	 * @param string     $path Path under /api/v1.
	 * @param array|null $json JSON body.
	 * @return array|WP_Error
	 */
	private static function request( $method, $path, $json = null ) {
		$s    = self::settings();
		$base = self::normalize_base( $s['api_base'] );
		$url  = $base . $path;
		$args = array(
			'method'  => $method,
			'timeout' => 60,
			'headers' => self::headers( array( 'Content-Type' => 'application/json' ) ),
		);
		if ( null !== $json ) {
			$args['body'] = wp_json_encode( $json );
		}
		$res = wp_remote_request( $url, $args );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$code = wp_remote_retrieve_response_code( $res );
		$raw  = wp_remote_retrieve_body( $res );
		$data = json_decode( $raw, true );
		if ( $code < 200 || $code >= 300 ) {
			$msg = is_array( $data ) ? wp_json_encode( $data ) : $raw;
			return new WP_Error( 'wjm_ith', sprintf( 'HTTP %d: %s', $code, $msg ) );
		}
		return is_array( $data ) ? $data : array();
	}

	/**
	 * @param array $extra Extra headers.
	 * @return array
	 */
	private static function headers( $extra = array() ) {
		$s = self::settings();
		return array_merge(
			array(
				'Authorization'                 => 'Bearer ' . self::api_key(),
				'X-Turnitin-Integration-Name'   => $s['integration_name'] ? $s['integration_name'] : 'WisdomJournalManager',
				'X-Turnitin-Integration-Version'=> WJM_VERSION,
			),
			$extra
		);
	}
}
