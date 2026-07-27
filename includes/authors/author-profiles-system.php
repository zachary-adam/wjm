<?php
/**
 * Author record management and profile rendering.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Author_Profiles {

	public static function init() {
		add_action( 'admin_post_wjm_save_author', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_wjm_delete_author', array( __CLASS__, 'handle_delete' ) );
	}

	/**
	 * @return object[]
	 */
	public static function get_all_authors() {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'authors' );
		return $wpdb->get_results( "SELECT * FROM {$table} ORDER BY last_name ASC, first_name ASC" );
	}

	/**
	 * @param int $author_id Author ID.
	 * @return object|null
	 */
	public static function get_author( $author_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'authors' );
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", absint( $author_id ) )
		);
	}

	/**
	 * @param int $paper_id Paper post ID.
	 * @return object[]
	 */
	public static function get_authors_for_paper( $paper_id ) {
		global $wpdb;
		$authors = WJM_Database_Schema::table( 'authors' );
		$link    = WJM_Database_Schema::table( 'paper_authors' );
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT a.*, pa.author_order, pa.is_corresponding
				FROM {$authors} a
				INNER JOIN {$link} pa ON pa.author_id = a.id
				WHERE pa.paper_id = %d
				ORDER BY pa.author_order ASC",
				absint( $paper_id )
			)
		);
	}

	/**
	 * @param array $data Author fields.
	 * @param int   $author_id Optional update ID.
	 * @return int|false
	 */
	public static function save_author( $data, $author_id = 0 ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'authors' );

		$row = array(
			'user_id'     => ! empty( $data['user_id'] ) ? absint( $data['user_id'] ) : null,
			'orcid'       => ! empty( $data['orcid'] ) ? sanitize_text_field( $data['orcid'] ) : null,
			'first_name'  => sanitize_text_field( $data['first_name'] ?? '' ),
			'last_name'   => sanitize_text_field( $data['last_name'] ?? '' ),
			'email'       => sanitize_email( $data['email'] ?? '' ),
			'affiliation' => sanitize_textarea_field( $data['affiliation'] ?? '' ),
			'bio'         => wp_kses_post( $data['bio'] ?? '' ),
			'h_index'     => isset( $data['h_index'] ) && '' !== $data['h_index'] ? absint( $data['h_index'] ) : null,
		);

		if ( $author_id ) {
			$wpdb->update( $table, $row, array( 'id' => absint( $author_id ) ) );
			return absint( $author_id );
		}

		$wpdb->insert( $table, $row );
		return (int) $wpdb->insert_id;
	}

	/**
	 * Sync many-to-many paper ↔ author links.
	 *
	 * @param int   $paper_id   Paper ID.
	 * @param int[] $author_ids Author IDs in order.
	 */
	public static function sync_paper_authors( $paper_id, $author_ids ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'paper_authors' );
		$paper_id = absint( $paper_id );

		$wpdb->delete( $table, array( 'paper_id' => $paper_id ), array( '%d' ) );

		$order = 1;
		foreach ( array_unique( array_filter( array_map( 'absint', $author_ids ) ) ) as $author_id ) {
			$wpdb->insert(
				$table,
				array(
					'paper_id'         => $paper_id,
					'author_id'        => $author_id,
					'author_order'     => $order,
					'is_corresponding' => 1 === $order ? 1 : 0,
				),
				array( '%d', '%d', '%d', '%d' )
			);
			$order++;
		}
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_sjm_authors' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_author' );

		$author_id = isset( $_POST['author_id'] ) ? absint( $_POST['author_id'] ) : 0;
		self::save_author( wp_unslash( $_POST ), $author_id );

		wp_safe_redirect( admin_url( 'admin.php?page=wjm-authors&saved=1' ) );
		exit;
	}

	public static function handle_delete() {
		if ( ! current_user_can( 'manage_sjm_authors' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_delete_author' );

		global $wpdb;
		$author_id = isset( $_GET['author_id'] ) ? absint( $_GET['author_id'] ) : 0;
		if ( $author_id ) {
			$wpdb->delete( WJM_Database_Schema::table( 'paper_authors' ), array( 'author_id' => $author_id ), array( '%d' ) );
			$wpdb->delete( WJM_Database_Schema::table( 'authors' ), array( 'id' => $author_id ), array( '%d' ) );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=wjm-authors&deleted=1' ) );
		exit;
	}

	/**
	 * Render public author profile HTML.
	 *
	 * @param int $author_id Author ID.
	 * @return string
	 */
	public static function render_profile( $author_id ) {
		$author = self::get_author( $author_id );
		if ( ! $author ) {
			return '<p>' . esc_html__( 'Author not found.', 'wisdom-journal-manager' ) . '</p>';
		}

		global $wpdb;
		$link  = WJM_Database_Schema::table( 'paper_authors' );
		$ids   = $wpdb->get_col(
			$wpdb->prepare( "SELECT paper_id FROM {$link} WHERE author_id = %d ORDER BY paper_id DESC", $author_id )
		);

		ob_start();
		?>
		<div class="wjm-author-profile">
			<h2><?php echo esc_html( trim( $author->first_name . ' ' . $author->last_name ) ); ?></h2>
			<?php if ( $author->orcid ) : ?>
				<p class="wjm-orcid">ORCID: <a href="https://orcid.org/<?php echo esc_attr( $author->orcid ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $author->orcid ); ?></a></p>
			<?php endif; ?>
			<?php if ( $author->affiliation ) : ?>
				<p class="wjm-affiliation"><?php echo esc_html( $author->affiliation ); ?></p>
			<?php endif; ?>
			<?php if ( null !== $author->h_index ) : ?>
				<p class="wjm-hindex"><?php echo esc_html( sprintf( __( 'H-index: %d', 'wisdom-journal-manager' ), (int) $author->h_index ) ); ?></p>
			<?php endif; ?>
			<?php if ( $author->bio ) : ?>
				<div class="wjm-bio"><?php echo wp_kses_post( wpautop( $author->bio ) ); ?></div>
			<?php endif; ?>
			<?php if ( $ids ) : ?>
				<h3><?php esc_html_e( 'Publications', 'wisdom-journal-manager' ); ?></h3>
				<ul class="wjm-author-papers">
					<?php foreach ( $ids as $paper_id ) : ?>
						<li><a href="<?php echo esc_url( get_permalink( $paper_id ) ); ?>"><?php echo esc_html( get_the_title( $paper_id ) ); ?></a></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>
		<?php
		return ob_get_clean();
	}
}
