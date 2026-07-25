<?php
/**
 * Reviewer recognition — certificates + CSV export (Publons-friendly).
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Reviewer_Recognition {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 56 );
		add_action( 'admin_post_wjm_export_reviews_csv', array( __CLASS__, 'handle_export' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_certificate' ) );
		add_action( 'admin_post_wjm_send_reviewer_credit', array( __CLASS__, 'handle_credit_email' ) );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Reviewer recognition', 'wisdom-journal-manager' ),
			__( 'Recognition', 'wisdom-journal-manager' ),
			'edit_others_sjm_papers',
			'wjm-recognition',
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * Completed reviews grouped by reviewer.
	 *
	 * @param int $year Optional year filter (0 = all).
	 * @return array[]
	 */
	public static function completed_by_reviewer( $year = 0 ) {
		global $wpdb;
		$reviews = WJM_Database_Schema::table( 'reviews' );
		$sql     = "SELECT reviewer_user_id, COUNT(*) AS cnt, MIN(submitted_at) AS first_at, MAX(submitted_at) AS last_at
			FROM {$reviews}
			WHERE submitted_at IS NOT NULL";
		$args    = array();
		if ( $year ) {
			$sql   .= ' AND YEAR(submitted_at) = %d';
			$args[] = absint( $year );
		}
		$sql .= ' GROUP BY reviewer_user_id ORDER BY cnt DESC';
		$rows = $args ? $wpdb->get_results( $wpdb->prepare( $sql, $args ) ) : $wpdb->get_results( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$user = get_userdata( $row->reviewer_user_id );
			if ( ! $user ) {
				continue;
			}
			$out[] = array(
				'user_id'  => (int) $row->reviewer_user_id,
				'name'     => $user->display_name,
				'email'    => $user->user_email,
				'orcid'    => class_exists( 'WJM_ORCID' ) ? WJM_ORCID::user_orcid( $user->ID ) : (string) get_user_meta( $user->ID, '_wjm_orcid', true ),
				'count'    => (int) $row->cnt,
				'first_at' => $row->first_at,
				'last_at'  => $row->last_at,
			);
		}
		return $out;
	}

	/**
	 * @param int $user_id Reviewer.
	 * @param int $year Year filter.
	 * @return object[]
	 */
	public static function reviews_for_user( $user_id, $year = 0 ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'reviews' );
		$sql   = "SELECT * FROM {$table} WHERE reviewer_user_id = %d AND submitted_at IS NOT NULL";
		$args  = array( absint( $user_id ) );
		if ( $year ) {
			$sql   .= ' AND YEAR(submitted_at) = %d';
			$args[] = absint( $year );
		}
		$sql .= ' ORDER BY submitted_at DESC';
		return $wpdb->get_results( $wpdb->prepare( $sql, $args ) );
	}

	public static function render() {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$year = isset( $_GET['year'] ) ? absint( $_GET['year'] ) : (int) gmdate( 'Y' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$rows = self::completed_by_reviewer( $year );
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'Reviewer recognition', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Certificates and CSV export for completed reviews. Soft recognition only — never invents reviews.', 'wisdom-journal-manager' ); ?></p>
			<form method="get" style="margin:1rem 0;">
				<input type="hidden" name="post_type" value="sjm_journal" />
				<input type="hidden" name="page" value="wjm-recognition" />
				<label><?php esc_html_e( 'Year', 'wisdom-journal-manager' ); ?>
					<input type="number" name="year" value="<?php echo esc_attr( (string) $year ); ?>" min="2000" max="2100" style="width:6rem;" />
				</label>
				<?php submit_button( __( 'Filter', 'wisdom-journal-manager' ), 'secondary', '', false ); ?>
				<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_export_reviews_csv&year=' . $year ), 'wjm_export_reviews_csv' ) ); ?>">
					<?php esc_html_e( 'Export CSV', 'wisdom-journal-manager' ); ?>
				</a>
			</form>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Reviewer', 'wisdom-journal-manager' ); ?></th>
						<th>ORCID</th>
						<th><?php esc_html_e( 'Reviews', 'wisdom-journal-manager' ); ?></th>
						<th><?php esc_html_e( 'Last', 'wisdom-journal-manager' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( ! $rows ) : ?>
					<tr><td colspan="5"><?php esc_html_e( 'No completed reviews in this year.', 'wisdom-journal-manager' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td>
								<strong><?php echo esc_html( $row['name'] ); ?></strong><br />
								<span class="description"><?php echo esc_html( $row['email'] ); ?></span>
							</td>
							<td><?php echo $row['orcid'] ? esc_html( $row['orcid'] ) : '—'; ?></td>
							<td><?php echo esc_html( (string) $row['count'] ); ?></td>
							<td><?php echo esc_html( $row['last_at'] ); ?></td>
							<td>
								<a class="button button-small" target="_blank" href="<?php echo esc_url( add_query_arg( array( 'wjm_certificate' => $row['user_id'], 'year' => $year ), home_url( '/' ) ) ); ?>">
									<?php esc_html_e( 'Certificate', 'wisdom-journal-manager' ); ?>
								</a>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
									<input type="hidden" name="action" value="wjm_send_reviewer_credit" />
									<input type="hidden" name="user_id" value="<?php echo esc_attr( $row['user_id'] ); ?>" />
									<input type="hidden" name="year" value="<?php echo esc_attr( (string) $year ); ?>" />
									<?php wp_nonce_field( 'wjm_send_reviewer_credit_' . $row['user_id'] ); ?>
									<button type="submit" class="button button-small"><?php esc_html_e( 'Email thanks', 'wisdom-journal-manager' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
			<p class="description"><?php esc_html_e( 'CSV columns suit Web of Science Reviewer Recognition / Publons-style imports. ORCID credit email is a thank-you with certificate link — reviewers claim credit in their ORCID account.', 'wisdom-journal-manager' ); ?></p>
		</div>
		<?php
	}

	public static function handle_export() {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_export_reviews_csv' );
		$year = isset( $_GET['year'] ) ? absint( $_GET['year'] ) : 0;
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=wjm-reviewer-recognition-' . ( $year ? $year : 'all' ) . '.csv' );
		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'reviewer_name', 'reviewer_email', 'orcid', 'paper_title', 'paper_doi', 'reviewed_at', 'recommendation', 'journal' ) );
		global $wpdb;
		$table = WJM_Database_Schema::table( 'reviews' );
		$sql   = "SELECT * FROM {$table} WHERE submitted_at IS NOT NULL";
		$args  = array();
		if ( $year ) {
			$sql   .= ' AND YEAR(submitted_at) = %d';
			$args[] = $year;
		}
		$sql  .= ' ORDER BY submitted_at DESC';
		$rows  = $args ? $wpdb->get_results( $wpdb->prepare( $sql, $args ) ) : $wpdb->get_results( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		foreach ( (array) $rows as $r ) {
			$user = get_userdata( $r->reviewer_user_id );
			$jid  = (int) get_post_meta( $r->paper_id, '_sjm_journal_id', true );
			fputcsv(
				$out,
				array(
					$user ? $user->display_name : '',
					$user ? $user->user_email : '',
					$user && class_exists( 'WJM_ORCID' ) ? WJM_ORCID::user_orcid( $user->ID ) : '',
					get_the_title( $r->paper_id ),
					get_post_meta( $r->paper_id, '_sjm_doi', true ),
					$r->submitted_at,
					$r->recommendation,
					$jid ? get_the_title( $jid ) : '',
				)
			);
		}
		fclose( $out );
		exit;
	}

	public static function handle_credit_email() {
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		$year    = isset( $_POST['year'] ) ? absint( $_POST['year'] ) : (int) gmdate( 'Y' );
		check_admin_referer( 'wjm_send_reviewer_credit_' . $user_id );
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			wp_die( esc_html__( 'User not found.', 'wisdom-journal-manager' ) );
		}
		$count = count( self::reviews_for_user( $user_id, $year ) );
		$cert  = add_query_arg( array( 'wjm_certificate' => $user_id, 'year' => $year ), home_url( '/' ) );
		$orcid = class_exists( 'WJM_ORCID' ) ? WJM_ORCID::user_orcid( $user_id ) : '';
		$body  = sprintf(
			"Dear %s,\n\nThank you for completing %d peer review(s) in %d for %s.\n\nYour recognition certificate:\n%s\n\n",
			$user->display_name,
			$count,
			$year,
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			$cert
		);
		if ( $orcid ) {
			$body .= sprintf( "Your ORCID (%s) is on file. You can add peer review credit in your ORCID record.\n", $orcid );
		}
		wp_mail(
			$user->user_email,
			sprintf( '[%s] Peer review recognition %d', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), $year ),
			$body
		);
		if ( class_exists( 'WJM_Audit' ) ) {
			WJM_Audit::log( 'info', 'reviewer_credit_email', sprintf( 'Recognition email to user %d (%d)', $user_id, $year ), array( 'user_id' => $user_id ) );
		}
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-recognition&year=' . $year . '&sent=1' ) );
		exit;
	}

	public static function maybe_certificate() {
		if ( empty( $_GET['wjm_certificate'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$user_id = absint( $_GET['wjm_certificate'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$year    = isset( $_GET['year'] ) ? absint( $_GET['year'] ) : (int) gmdate( 'Y' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$user    = get_userdata( $user_id );
		$reviews = self::reviews_for_user( $user_id, $year );
		if ( ! $user || ! $reviews ) {
			status_header( 404 );
			wp_die( esc_html__( 'Certificate not available.', 'wisdom-journal-manager' ) );
		}
		$can_view = is_user_logged_in() && ( get_current_user_id() === $user_id || current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' ) );
		if ( ! $can_view ) {
			auth_redirect();
		}
		$orcid = class_exists( 'WJM_ORCID' ) ? WJM_ORCID::user_orcid( $user_id ) : '';
		status_header( 200 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>" />
	<title><?php echo esc_html( sprintf( __( 'Peer review certificate — %s', 'wisdom-journal-manager' ), $user->display_name ) ); ?></title>
	<style>
		body{font-family:Georgia,serif;max-width:40rem;margin:2rem auto;padding:0 1.25rem;color:#1a1a1a;line-height:1.5}
		h1{font-size:1.75rem;margin-bottom:0.25rem}
		.meta{color:#555;margin-bottom:1.5rem}
		ul{padding-left:1.2rem}
		@media print{.no-print{display:none}}
	</style>
</head>
<body>
	<p class="no-print"><button onclick="window.print()"><?php esc_html_e( 'Print', 'wisdom-journal-manager' ); ?></button></p>
	<h1><?php esc_html_e( 'Certificate of peer review', 'wisdom-journal-manager' ); ?></h1>
	<p class="meta"><?php echo esc_html( get_bloginfo( 'name' ) ); ?> · <?php echo esc_html( (string) $year ); ?></p>
	<p><?php echo esc_html( sprintf( __( 'This certifies that %s completed %d peer review(s).', 'wisdom-journal-manager' ), $user->display_name, count( $reviews ) ) ); ?></p>
	<?php if ( $orcid ) : ?>
		<p>ORCID: <a href="https://orcid.org/<?php echo esc_attr( $orcid ); ?>"><?php echo esc_html( $orcid ); ?></a></p>
	<?php endif; ?>
	<ul>
		<?php foreach ( $reviews as $r ) : ?>
			<li>
				<?php echo esc_html( get_the_title( $r->paper_id ) ); ?>
				— <?php echo esc_html( $r->submitted_at ); ?>
			</li>
		<?php endforeach; ?>
	</ul>
	<p class="meta"><?php echo esc_html( sprintf( __( 'Issued %s', 'wisdom-journal-manager' ), gmdate( 'Y-m-d' ) ) ); ?></p>
</body>
</html>
		<?php
		exit;
	}
}
