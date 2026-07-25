<?php
/**
 * VAT + Read & Publish / institutional APC deals.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Deals {

	const OPT_DEALS = 'wjm_rp_deals';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 58 );
		add_action( 'admin_post_wjm_save_deals', array( __CLASS__, 'handle_save' ) );
		add_filter( 'wjm_apc_amount', array( __CLASS__, 'apply_rp_deal' ), 15, 2 );
		add_filter( 'wjm_apc_amount', array( __CLASS__, 'apply_vat' ), 25, 2 );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'save_paper' ), 28, 2 );
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'VAT & R&P deals', 'wisdom-journal-manager' ),
			__( 'VAT & R&P', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-deals',
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * @return array domain => percent
	 */
	public static function deals() {
		$raw = get_option( self::OPT_DEALS, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * @return float VAT percent from payment settings.
	 */
	public static function vat_rate() {
		$s = class_exists( 'WJM_Payments' ) ? WJM_Payments::settings() : array();
		return isset( $s['vat_percent'] ) ? max( 0, (float) $s['vat_percent'] ) : 0;
	}

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$deals = self::deals();
		$text  = '';
		foreach ( $deals as $domain => $pct ) {
			$text .= $domain . '=' . $pct . "\n";
		}
		$vat = self::vat_rate();
		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Deals saved.', 'wisdom-journal-manager' ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple">
			<h1><?php esc_html_e( 'VAT & Read & Publish deals', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Institutional email domains get an APC discount or full cover. VAT is added on the payable amount (Money settings).', 'wisdom-journal-manager' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_deals" />
				<?php wp_nonce_field( 'wjm_save_deals' ); ?>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'VAT %', 'wisdom-journal-manager' ); ?></th>
						<td>
							<input type="number" step="0.01" min="0" max="100" name="vat_percent" value="<?php echo esc_attr( (string) $vat ); ?>" style="width:6rem;" />
							<p class="description"><?php esc_html_e( 'Stored with Money settings. 0 = no VAT line.', 'wisdom-journal-manager' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'R&P / institutional deals', 'wisdom-journal-manager' ); ?></th>
						<td>
							<textarea name="deals" class="large-text" rows="10" placeholder="ox.ac.uk=100&#10;harvard.edu=100&#10;example.org=50"><?php echo esc_textarea( $text ); ?></textarea>
							<p class="description"><?php esc_html_e( 'One per line: emaildomain=percent (100 = fully covered). Matched against corresponding / author email or submitting user.', 'wisdom-journal-manager' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save deals', 'wisdom-journal-manager' ) ); ?>
			</form>
		</div>
		<?php
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_deals' );
		$s = class_exists( 'WJM_Payments' ) ? WJM_Payments::settings() : array();
		$s['vat_percent'] = isset( $_POST['vat_percent'] ) ? (float) wp_unslash( $_POST['vat_percent'] ) : 0;
		update_option( 'wjm_payment_settings', $s );

		$raw = isset( $_POST['deals'] ) ? sanitize_textarea_field( wp_unslash( $_POST['deals'] ) ) : '';
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $line ) {
			$line = trim( $line );
			if ( ! $line || false === strpos( $line, '=' ) ) {
				continue;
			}
			list( $domain, $pct ) = array_map( 'trim', explode( '=', $line, 2 ) );
			$domain = strtolower( sanitize_text_field( $domain ) );
			$domain = ltrim( $domain, '@' );
			$pct    = max( 0, min( 100, (float) $pct ) );
			if ( $domain ) {
				$out[ $domain ] = $pct;
			}
		}
		update_option( self::OPT_DEALS, $out );
		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-deals&saved=1' ) );
		exit;
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_institution',
			__( 'Institution / R&P', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_paper_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	public static function render_paper_box( $post ) {
		$inst = get_post_meta( $post->ID, '_sjm_institution_domain', true );
		?>
		<p>
			<label><?php esc_html_e( 'Institution email domain', 'wisdom-journal-manager' ); ?></label>
			<input type="text" class="widefat" name="sjm_institution_domain" value="<?php echo esc_attr( $inst ); ?>" placeholder="ox.ac.uk" />
		</p>
		<p class="description"><?php esc_html_e( 'Overrides auto-detect from corresponding email for R&P matching.', 'wisdom-journal-manager' ); ?></p>
		<?php
	}

	public static function save_paper( $post_id, $post ) {
		if ( wp_is_post_revision( $post_id ) || ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		if ( isset( $_POST['sjm_institution_domain'] ) ) {
			$d = strtolower( sanitize_text_field( wp_unslash( $_POST['sjm_institution_domain'] ) ) );
			$d = ltrim( $d, '@' );
			update_post_meta( $post_id, '_sjm_institution_domain', $d );
		}
		unset( $post );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return string Domain or empty.
	 */
	public static function domain_for_paper( $paper_id ) {
		$forced = get_post_meta( $paper_id, '_sjm_institution_domain', true );
		if ( $forced ) {
			return strtolower( ltrim( (string) $forced, '@' ) );
		}
		$email = get_post_meta( $paper_id, '_sjm_corresponding_email', true );
		if ( ! $email ) {
			$post = get_post( $paper_id );
			if ( $post ) {
				$user = get_userdata( $post->post_author );
				$email = $user ? $user->user_email : '';
			}
		}
		if ( ! $email || false === strpos( $email, '@' ) ) {
			return '';
		}
		return strtolower( substr( $email, strrpos( $email, '@' ) + 1 ) );
	}

	/**
	 * @param float $amount Amount.
	 * @param int   $paper_id Paper ID.
	 * @return float
	 */
	public static function apply_rp_deal( $amount, $paper_id ) {
		$deals  = self::deals();
		$domain = self::domain_for_paper( $paper_id );
		if ( ! $domain || ! $deals ) {
			return $amount;
		}
		$pct = null;
		foreach ( $deals as $d => $p ) {
			if ( $domain === $d || ( strlen( $domain ) > strlen( $d ) && substr( $domain, -strlen( $d ) - 1 ) === '.' . $d ) ) {
				$pct = (float) $p;
				break;
			}
		}
		if ( null === $pct ) {
			return $amount;
		}
		update_post_meta( $paper_id, '_sjm_rp_deal', $domain . '=' . $pct );
		$new = round( $amount * ( 1 - ( $pct / 100 ) ), 2 );
		if ( $pct >= 100 && class_exists( 'WJM_Payments' ) ) {
			update_post_meta( $paper_id, WJM_Payments::META_STATUS, 'waived' );
		}
		return max( 0, $new );
	}

	/**
	 * @param float $amount Amount after discounts.
	 * @param int   $paper_id Paper ID.
	 * @return float
	 */
	public static function apply_vat( $amount, $paper_id ) {
		$vat = self::vat_rate();
		if ( $vat <= 0 || $amount <= 0 ) {
			delete_post_meta( $paper_id, '_sjm_vat_amount' );
			return $amount;
		}
		$vat_amt = round( $amount * ( $vat / 100 ), 2 );
		update_post_meta( $paper_id, '_sjm_vat_amount', $vat_amt );
		update_post_meta( $paper_id, '_sjm_vat_rate', $vat );
		return round( $amount + $vat_amt, 2 );
	}

	/**
	 * Breakdown for UI (call after amount_for_paper so VAT meta is fresh).
	 *
	 * @param int $paper_id Paper ID.
	 * @return array{net:float,vat:float,total:float,rate:float,deal:string}
	 */
	public static function breakdown( $paper_id ) {
		$total = class_exists( 'WJM_Payments' ) ? WJM_Payments::amount_for_paper( $paper_id ) : 0;
		$vat   = (float) get_post_meta( $paper_id, '_sjm_vat_amount', true );
		$rate  = (float) get_post_meta( $paper_id, '_sjm_vat_rate', true );
		if ( $vat <= 0 && self::vat_rate() > 0 && $total > 0 ) {
			$rate = self::vat_rate();
			$net  = round( $total / ( 1 + ( $rate / 100 ) ), 2 );
			$vat  = round( $total - $net, 2 );
		} else {
			$net = round( max( 0, $total - $vat ), 2 );
		}
		return array(
			'net'   => $net,
			'vat'   => $vat,
			'total' => $total,
			'rate'  => $rate ? $rate : self::vat_rate(),
			'deal'  => (string) get_post_meta( $paper_id, '_sjm_rp_deal', true ),
		);
	}
}
