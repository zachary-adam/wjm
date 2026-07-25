<?php
/**
 * APC payments — manual bank transfer or live Stripe Checkout + webhooks.
 *
 * Publishers store their own Stripe keys (encrypted). No Stripe PHP SDK required.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Payments {

	const META_AMOUNT      = '_sjm_apc_amount';
	const META_STATUS      = '_sjm_apc_status';
	const META_PAID_AT     = '_sjm_apc_paid_at';
	const META_PROVIDER    = '_sjm_apc_provider';
	const META_SESSION     = '_sjm_stripe_session_id';
	const META_INTENT      = '_sjm_stripe_payment_intent';
	const META_CUSTOMER    = '_sjm_stripe_customer_email';
	const META_LAST_ERROR  = '_sjm_stripe_last_error';
	const META_INVOICE     = '_sjm_stripe_invoice_id';
	const META_INVOICE_URL = '_sjm_stripe_invoice_url';
	const META_RECEIPT_URL = '_sjm_stripe_receipt_url';
	const META_REFUND_ID   = '_sjm_stripe_refund_id';
	const META_REFUNDED_AT = '_sjm_apc_refunded_at';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_wjm_save_payment_settings', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_wjm_test_stripe', array( __CLASS__, 'handle_test_stripe' ) );
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'save_paper_payment_meta' ), 30, 2 );
		add_shortcode( 'wjm_pay_apc', array( __CLASS__, 'shortcode_pay' ) );
		add_shortcode( 'wjm_apc_receipt', array( __CLASS__, 'shortcode_receipt' ) );
		add_action( 'admin_post_wjm_mark_apc_paid', array( __CLASS__, 'handle_mark_paid' ) );
		add_action( 'admin_post_wjm_stripe_checkout', array( __CLASS__, 'handle_checkout' ) );
		add_action( 'admin_post_nopriv_wjm_stripe_checkout', array( __CLASS__, 'handle_checkout' ) );
		add_action( 'admin_post_wjm_stripe_refund', array( __CLASS__, 'handle_refund' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_verify_return' ) );
		add_action( 'sjm_apc_paid', array( __CLASS__, 'on_apc_paid' ), 10, 2 );
		add_action( 'sjm_apc_refunded', array( __CLASS__, 'on_apc_refunded' ), 10, 2 );
	}

	/**
	 * Notify editors when APC clears.
	 *
	 * @param int   $paper_id Paper ID.
	 * @param array $session Stripe session or empty.
	 */
	public static function on_apc_paid( $paper_id, $session = array() ) {
		unset( $session );
		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::notify_editors( $paper_id, 'apc_paid' );
		}
	}

	/**
	 * @param int   $paper_id Paper ID.
	 * @param array $refund Refund object.
	 */
	public static function on_apc_refunded( $paper_id, $refund = array() ) {
		unset( $refund );
		if ( class_exists( 'WJM_Email' ) ) {
			WJM_Email::notify_editors( $paper_id, 'apc_refunded' );
		}
	}

	/**
	 * @return array
	 */
	public static function settings() {
		$defaults = array(
			'enabled'                 => 0,
			'provider'                => 'manual',
			'currency'                => 'USD',
			'default_apc'             => '0',
			'stripe_mode'             => 'test',
			'success_url'             => '',
			'cancel_url'              => '',
			'instructions'            => __( 'Pay the article processing charge to proceed with publication.', 'wisdom-journal-manager' ),
			'subscriptions_enabled'   => 0,
			'subscription_amount'     => '0',
			'subscription_interval'   => 'year',
			'vat_percent'             => '0',
		);
		$stored = get_option( 'wjm_payment_settings', array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( $defaults, $stored );
	}

	public static function register_rest() {
		register_rest_route(
			'wjm/v1',
			'/stripe-webhook',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle_webhook' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	public static function menu() {
		add_submenu_page(
			'edit.php?post_type=sjm_journal',
			__( 'Payments / APC', 'wisdom-journal-manager' ),
			__( 'Payments / APC', 'wisdom-journal-manager' ),
			'manage_options',
			'wjm-payments',
			array( __CLASS__, 'render_page' )
		);
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'manage_sjm_settings' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		$s           = self::settings();
		$has_stripe  = (bool) WJM_Encryption::get_secret( 'wjm_stripe_secret' );
		$has_webhook = (bool) WJM_Encryption::get_secret( 'wjm_stripe_webhook_secret' );
		$webhook_url = rest_url( 'wjm/v1/stripe-webhook' );
		$last_test   = get_option( 'wjm_stripe_last_connection_test', array() );

		if ( ! empty( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$notice = get_transient( 'wjm_payments_notice' );
			delete_transient( 'wjm_payments_notice' );
			if ( 'stripe_keys' === $notice ) {
				echo '<div class="notice notice-warning"><p>' . esc_html__( 'Stripe APC stayed OFF — add a Secret key first, then turn Charge authors on.', 'wisdom-journal-manager' ) . '</p></div>';
			} else {
				echo '<div class="notice notice-success"><p>' . esc_html__( 'Saved.', 'wisdom-journal-manager' ) . '</p></div>';
			}
		}
		if ( ! empty( $_GET['stripe_test'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$ok  = '1' === $_GET['stripe_test']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = is_array( $last_test ) && ! empty( $last_test['message'] ) ? $last_test['message'] : '';
			echo '<div class="notice notice-' . ( $ok ? 'success' : 'error' ) . '"><p>' . esc_html( $msg ) . '</p></div>';
		}
		?>
		<div class="wrap wjm-simple wjm-money-simple">
			<h1><?php esc_html_e( 'Money', 'wisdom-journal-manager' ); ?></h1>
			<p class="wjm-lead"><?php esc_html_e( 'Leave this off for free / diamond OA. Turn it on only if authors pay an APC.', 'wisdom-journal-manager' ); ?></p>
			<div class="notice notice-info inline" style="margin:0 0 1rem;">
				<p><strong><?php esc_html_e( 'Requirement to turn Stripe on:', 'wisdom-journal-manager' ); ?></strong>
				<?php esc_html_e( 'Stripe account → Developers → API keys (Secret + Publishable) + Webhook signing secret pointing to the URL below. Manual bank payments need no Stripe.', 'wisdom-journal-manager' ); ?>
				· <a href="https://dashboard.stripe.com/apikeys" target="_blank" rel="noopener"><?php esc_html_e( 'Stripe API keys', 'wisdom-journal-manager' ); ?></a></p>
			</div>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_save_payment_settings" />
				<?php wp_nonce_field( 'wjm_save_payment_settings' ); ?>

				<table class="form-table">
					<tr>
						<th><span class="wjm-step-num">1</span><?php esc_html_e( 'Charge authors?', 'wisdom-journal-manager' ); ?></th>
						<td>
							<label><input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $s['enabled'] ) ); ?> /> <?php esc_html_e( 'Yes — collect APC', 'wisdom-journal-manager' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><span class="wjm-step-num">2</span><?php esc_html_e( 'How much?', 'wisdom-journal-manager' ); ?></th>
						<td>
							<input type="number" step="0.01" min="0" name="default_apc" value="<?php echo esc_attr( $s['default_apc'] ); ?>" />
							<input type="text" name="currency" value="<?php echo esc_attr( $s['currency'] ); ?>" class="small-text" maxlength="3" style="margin-left:6px;" />
						</td>
					</tr>
					<tr>
						<th><span class="wjm-step-num">3</span><?php esc_html_e( 'How to pay?', 'wisdom-journal-manager' ); ?></th>
						<td>
							<select name="provider">
								<option value="manual" <?php selected( $s['provider'], 'manual' ); ?>><?php esc_html_e( 'Manual (bank / outside WP)', 'wisdom-journal-manager' ); ?></option>
								<option value="stripe" <?php selected( $s['provider'], 'stripe' ); ?>><?php esc_html_e( 'Stripe (card checkout)', 'wisdom-journal-manager' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><span class="wjm-step-num">4</span><?php esc_html_e( 'Stripe keys', 'wisdom-journal-manager' ); ?></th>
						<td>
							<p class="description" style="margin-top:0;"><?php esc_html_e( 'From Stripe Dashboard → Developers → API keys. Skip if using Manual.', 'wisdom-journal-manager' ); ?></p>
							<p>
								<input type="password" class="regular-text" name="stripe_secret" autocomplete="new-password" placeholder="<?php echo $has_stripe ? esc_attr__( 'Secret key saved — leave blank to keep', 'wisdom-journal-manager' ) : 'sk_test_…'; ?>" /><br />
								<input type="text" class="regular-text" name="stripe_publishable" value="<?php echo esc_attr( (string) get_option( 'wjm_stripe_publishable', '' ) ); ?>" placeholder="pk_test_…" style="margin-top:6px;" />
							</p>
							<p>
								<label><?php esc_html_e( 'Webhook secret', 'wisdom-journal-manager' ); ?></label><br />
								<input type="password" class="regular-text" name="stripe_webhook_secret" autocomplete="new-password" placeholder="<?php echo $has_webhook ? esc_attr__( 'Saved — leave blank to keep', 'wisdom-journal-manager' ) : 'whsec_…'; ?>" />
							</p>
							<p class="description">
								<?php esc_html_e( 'Copy this URL into Stripe → Webhooks → Add endpoint:', 'wisdom-journal-manager' ); ?><br />
								<code id="wjm-webhook-url"><?php echo esc_html( $webhook_url ); ?></code>
								<button type="button" class="button button-small" onclick="navigator.clipboard.writeText(document.getElementById('wjm-webhook-url').textContent)"><?php esc_html_e( 'Copy', 'wisdom-journal-manager' ); ?></button>
							</p>
							<p class="description"><?php esc_html_e( 'Events: checkout.session.completed, checkout.session.async_payment_succeeded, customer.subscription.updated, customer.subscription.deleted, invoice.paid', 'wisdom-journal-manager' ); ?></p>
							<select name="stripe_mode">
								<option value="test" <?php selected( $s['stripe_mode'], 'test' ); ?>><?php esc_html_e( 'Test mode', 'wisdom-journal-manager' ); ?></option>
								<option value="live" <?php selected( $s['stripe_mode'], 'live' ); ?>><?php esc_html_e( 'Live mode', 'wisdom-journal-manager' ); ?></option>
							</select>
						</td>
					</tr>
				</table>

				<details style="margin:1rem 0;">
					<summary><?php esc_html_e( 'More options', 'wisdom-journal-manager' ); ?></summary>
					<table class="form-table">
						<tr>
							<th><?php esc_html_e( 'Author instructions', 'wisdom-journal-manager' ); ?></th>
							<td><textarea class="large-text" rows="3" name="instructions"><?php echo esc_textarea( $s['instructions'] ); ?></textarea></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Success / cancel URLs', 'wisdom-journal-manager' ); ?></th>
							<td>
								<input type="url" class="regular-text" name="success_url" value="<?php echo esc_attr( $s['success_url'] ); ?>" placeholder="<?php esc_attr_e( 'Optional success URL', 'wisdom-journal-manager' ); ?>" /><br />
								<input type="url" class="regular-text" name="cancel_url" value="<?php echo esc_attr( $s['cancel_url'] ); ?>" placeholder="<?php esc_attr_e( 'Optional cancel URL', 'wisdom-journal-manager' ); ?>" style="margin-top:6px;" />
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Journal subscriptions', 'wisdom-journal-manager' ); ?></th>
							<td>
								<label><input type="checkbox" name="subscriptions_enabled" value="1" <?php checked( ! empty( $s['subscriptions_enabled'] ) ); ?> /> <?php esc_html_e( 'Offer recurring journal subscriptions', 'wisdom-journal-manager' ); ?></label>
								<p>
									<input type="number" step="0.01" min="0" name="subscription_amount" value="<?php echo esc_attr( $s['subscription_amount'] ); ?>" />
									<select name="subscription_interval">
										<option value="year" <?php selected( $s['subscription_interval'], 'year' ); ?>><?php esc_html_e( 'Yearly', 'wisdom-journal-manager' ); ?></option>
										<option value="month" <?php selected( $s['subscription_interval'], 'month' ); ?>><?php esc_html_e( 'Monthly', 'wisdom-journal-manager' ); ?></option>
									</select>
								</p>
							</td>
						</tr>
					</table>
				</details>

				<?php submit_button( __( 'Save', 'wisdom-journal-manager' ) ); ?>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wjm_test_stripe" />
				<?php wp_nonce_field( 'wjm_test_stripe' ); ?>
				<?php submit_button( __( 'Test Stripe connection', 'wisdom-journal-manager' ), 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'manage_sjm_settings' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_save_payment_settings' );

		$settings = array(
			'enabled'               => ! empty( $_POST['enabled'] ) ? 1 : 0,
			'provider'              => isset( $_POST['provider'] ) ? sanitize_key( wp_unslash( $_POST['provider'] ) ) : 'manual',
			'currency'              => isset( $_POST['currency'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['currency'] ) ) ) : 'USD',
			'default_apc'           => isset( $_POST['default_apc'] ) ? sanitize_text_field( wp_unslash( $_POST['default_apc'] ) ) : '0',
			'stripe_mode'           => isset( $_POST['stripe_mode'] ) ? sanitize_key( wp_unslash( $_POST['stripe_mode'] ) ) : 'test',
			'success_url'           => isset( $_POST['success_url'] ) ? esc_url_raw( wp_unslash( $_POST['success_url'] ) ) : '',
			'cancel_url'            => isset( $_POST['cancel_url'] ) ? esc_url_raw( wp_unslash( $_POST['cancel_url'] ) ) : '',
			'instructions'          => isset( $_POST['instructions'] ) ? sanitize_textarea_field( wp_unslash( $_POST['instructions'] ) ) : '',
			'subscriptions_enabled' => ! empty( $_POST['subscriptions_enabled'] ) ? 1 : 0,
			'subscription_amount'   => isset( $_POST['subscription_amount'] ) ? sanitize_text_field( wp_unslash( $_POST['subscription_amount'] ) ) : '0',
			'subscription_interval' => isset( $_POST['subscription_interval'] ) ? sanitize_key( wp_unslash( $_POST['subscription_interval'] ) ) : 'year',
		);
		if ( ! in_array( $settings['provider'], array( 'manual', 'stripe' ), true ) ) {
			$settings['provider'] = 'manual';
		}
		if ( ! in_array( $settings['subscription_interval'], array( 'month', 'year' ), true ) ) {
			$settings['subscription_interval'] = 'year';
		}

		// Stripe APC requires keys before “on”.
		$secret_now = class_exists( 'WJM_Encryption' ) ? WJM_Encryption::get_secret( 'wjm_stripe_secret' ) : '';
		if ( ! empty( $_POST['stripe_secret'] ) ) {
			$secret_now = sanitize_text_field( wp_unslash( $_POST['stripe_secret'] ) );
		}
		if ( ! empty( $settings['enabled'] ) && 'stripe' === $settings['provider'] && ! $secret_now ) {
			$settings['enabled'] = 0;
			$settings['subscriptions_enabled'] = 0;
			set_transient( 'wjm_payments_notice', 'stripe_keys', 60 );
		}

		update_option( 'wjm_payment_settings', $settings );

		if ( ! empty( $_POST['stripe_secret'] ) ) {
			WJM_Encryption::set_secret( 'wjm_stripe_secret', sanitize_text_field( wp_unslash( $_POST['stripe_secret'] ) ) );
		}
		if ( ! empty( $_POST['stripe_webhook_secret'] ) ) {
			WJM_Encryption::set_secret( 'wjm_stripe_webhook_secret', sanitize_text_field( wp_unslash( $_POST['stripe_webhook_secret'] ) ) );
		}
		if ( isset( $_POST['stripe_publishable'] ) ) {
			update_option( 'wjm_stripe_publishable', sanitize_text_field( wp_unslash( $_POST['stripe_publishable'] ) ), false );
		}

		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-payments&saved=1' ) );
		exit;
	}

	public static function handle_test_stripe() {
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'manage_sjm_settings' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_test_stripe' );

		$result = self::stripe_request( 'GET', 'balance' );
		$ok     = ! is_wp_error( $result );
		$msg    = $ok
			? __( 'Stripe connection OK — balance endpoint reachable with your secret key.', 'wisdom-journal-manager' )
			: sprintf(
				/* translators: %s: error message */
				__( 'Stripe connection failed: %s', 'wisdom-journal-manager' ),
				$result->get_error_message()
			);

		update_option(
			'wjm_stripe_last_connection_test',
			array(
				'ok'      => $ok ? 1 : 0,
				'message' => $msg,
				'at'      => current_time( 'mysql', true ),
			),
			false
		);

		wp_safe_redirect( admin_url( 'edit.php?post_type=sjm_journal&page=wjm-payments&stripe_test=' . ( $ok ? '1' : '0' ) ) );
		exit;
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_apc',
			__( 'APC / Payment', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_paper_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	public static function render_paper_box( $post ) {
		$s      = self::settings();
		$amount = get_post_meta( $post->ID, self::META_AMOUNT, true );
		if ( '' === $amount ) {
			$amount = $s['default_apc'];
		}
		$status = get_post_meta( $post->ID, self::META_STATUS, true );
		if ( ! $status ) {
			$status = 'unpaid';
		}
		$session = get_post_meta( $post->ID, self::META_SESSION, true );
		$paid_at = get_post_meta( $post->ID, self::META_PAID_AT, true );
		$err     = get_post_meta( $post->ID, self::META_LAST_ERROR, true );

		wp_nonce_field( 'wjm_paper_apc', 'wjm_paper_apc_nonce' );
		?>
		<p>
			<label><?php esc_html_e( 'APC amount', 'wisdom-journal-manager' ); ?></label><br />
			<input type="number" step="0.01" min="0" name="sjm_apc_amount" value="<?php echo esc_attr( $amount ); ?>" class="widefat" <?php disabled( empty( $s['enabled'] ) ); ?> />
			<span class="description"><?php echo esc_html( $s['currency'] ); ?></span>
		</p>
		<p>
			<label><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></label><br />
			<select name="sjm_apc_status" class="widefat" <?php disabled( empty( $s['enabled'] ) ); ?>>
				<option value="unpaid" <?php selected( $status, 'unpaid' ); ?>><?php esc_html_e( 'Unpaid', 'wisdom-journal-manager' ); ?></option>
				<option value="waived" <?php selected( $status, 'waived' ); ?>><?php esc_html_e( 'Waived', 'wisdom-journal-manager' ); ?></option>
				<option value="pending" <?php selected( $status, 'pending' ); ?>><?php esc_html_e( 'Pending', 'wisdom-journal-manager' ); ?></option>
				<option value="paid" <?php selected( $status, 'paid' ); ?>><?php esc_html_e( 'Paid', 'wisdom-journal-manager' ); ?></option>
				<option value="refunded" <?php selected( $status, 'refunded' ); ?>><?php esc_html_e( 'Refunded', 'wisdom-journal-manager' ); ?></option>
			</select>
		</p>
		<?php if ( 'paid' === $status && get_post_meta( $post->ID, self::META_INTENT, true ) && ( current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' ) ) ) : ?>
			<p>
				<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wjm_stripe_refund&paper_id=' . $post->ID ), 'wjm_stripe_refund_' . $post->ID ) ); ?>">
					<?php esc_html_e( 'Refund via Stripe', 'wisdom-journal-manager' ); ?>
				</a>
			</p>
		<?php endif; ?>
		<?php if ( get_post_meta( $post->ID, self::META_INVOICE_URL, true ) || get_post_meta( $post->ID, self::META_RECEIPT_URL, true ) ) : ?>
			<p class="description">
				<?php if ( get_post_meta( $post->ID, self::META_INVOICE_URL, true ) ) : ?>
					<a href="<?php echo esc_url( get_post_meta( $post->ID, self::META_INVOICE_URL, true ) ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Stripe invoice', 'wisdom-journal-manager' ); ?></a>
				<?php endif; ?>
				<?php if ( get_post_meta( $post->ID, self::META_RECEIPT_URL, true ) ) : ?>
					 · <a href="<?php echo esc_url( get_post_meta( $post->ID, self::META_RECEIPT_URL, true ) ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Receipt', 'wisdom-journal-manager' ); ?></a>
				<?php endif; ?>
			</p>
		<?php endif; ?>
		<?php if ( $session ) : ?>
			<p class="description"><?php echo esc_html( 'Stripe session: ' . $session ); ?></p>
		<?php endif; ?>
		<?php if ( $paid_at ) : ?>
			<p class="description"><?php echo esc_html( sprintf( __( 'Paid at: %s', 'wisdom-journal-manager' ), $paid_at ) ); ?></p>
		<?php endif; ?>
		<?php if ( $err ) : ?>
			<p class="description" style="color:#b32d2e;"><?php echo esc_html( $err ); ?></p>
		<?php endif; ?>
		<?php if ( empty( $s['enabled'] ) ) : ?>
			<p class="description"><?php esc_html_e( 'Enable APC under Journals → Payments / APC.', 'wisdom-journal-manager' ); ?></p>
		<?php endif; ?>
		<?php
	}

	public static function save_paper_payment_meta( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_paper_apc_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_paper_apc_nonce'] ) ), 'wjm_paper_apc' ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		if ( isset( $_POST['sjm_apc_amount'] ) ) {
			update_post_meta( $post_id, self::META_AMOUNT, sanitize_text_field( wp_unslash( $_POST['sjm_apc_amount'] ) ) );
		}
		if ( isset( $_POST['sjm_apc_status'] ) ) {
			$status = sanitize_key( wp_unslash( $_POST['sjm_apc_status'] ) );
			if ( in_array( $status, array( 'unpaid', 'waived', 'pending', 'paid', 'refunded' ), true ) ) {
				update_post_meta( $post_id, self::META_STATUS, $status );
				if ( 'paid' === $status && ! get_post_meta( $post_id, self::META_PAID_AT, true ) ) {
					update_post_meta( $post_id, self::META_PAID_AT, current_time( 'mysql', true ) );
					update_post_meta( $post_id, self::META_PROVIDER, 'manual' );
				}
			}
		}
		unset( $post );
	}

	/**
	 * @param int $paper_id Paper post ID.
	 * @return float
	 */
	public static function amount_for_paper( $paper_id ) {
		$s      = self::settings();
		$amount = get_post_meta( $paper_id, self::META_AMOUNT, true );
		if ( '' === $amount || null === $amount ) {
			$amount = $s['default_apc'];
		}
		$amount = max( 0, (float) $amount );
		/**
		 * Filter APC amount (e.g. waiver codes).
		 *
		 * @param float $amount   Amount.
		 * @param int   $paper_id Paper ID.
		 */
		return (float) apply_filters( 'wjm_apc_amount', $amount, (int) $paper_id );
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return bool
	 */
	public static function user_can_pay( $paper_id ) {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		if ( current_user_can( 'edit_post', $paper_id ) || current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' ) ) {
			return true;
		}
		$post = get_post( $paper_id );
		return $post && (int) $post->post_author === get_current_user_id();
	}

	public static function shortcode_pay( $atts ) {
		$atts     = shortcode_atts( array( 'paper_id' => 0 ), $atts, 'wjm_pay_apc' );
		$paper_id = absint( $atts['paper_id'] );
		if ( ! $paper_id ) {
			$paper_id = get_the_ID();
		}
		$s = self::settings();
		if ( empty( $s['enabled'] ) || ! $paper_id || 'sjm_paper' !== get_post_type( $paper_id ) ) {
			return '';
		}

		$amount = self::amount_for_paper( $paper_id );
		$status = get_post_meta( $paper_id, self::META_STATUS, true );
		if ( ! $status ) {
			$status = 'unpaid';
		}

		$notice = '';
		if ( isset( $_GET['wjm_apc'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$flag = sanitize_key( wp_unslash( $_GET['wjm_apc'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( 'success' === $flag ) {
				$notice = '<p class="wjm-notice wjm-notice-success">' . esc_html__( 'Payment received — thank you. Status will update momentarily.', 'wisdom-journal-manager' ) . '</p>';
			} elseif ( 'cancel' === $flag ) {
				$notice = '<p class="wjm-notice">' . esc_html__( 'Checkout canceled. You can try again when ready.', 'wisdom-journal-manager' ) . '</p>';
			} elseif ( 'error' === $flag ) {
				$notice = '<p class="wjm-notice wjm-notice-error">' . esc_html__( 'Could not start Stripe Checkout. Contact the editorial office.', 'wisdom-journal-manager' ) . '</p>';
			}
		}

		ob_start();
		echo '<div class="wjm-apc-box" id="wjm-apc">';
		echo '<h3>' . esc_html__( 'Article processing charge', 'wisdom-journal-manager' ) . '</h3>';
		echo '<p class="wjm-apc-amount"><strong>' . esc_html( $s['currency'] . ' ' . number_format( $amount, 2 ) ) . '</strong></p>';
		if ( class_exists( 'WJM_Deals' ) ) {
			$bd = WJM_Deals::breakdown( $paper_id );
			if ( $bd['vat'] > 0 || $bd['deal'] ) {
				echo '<p class="description wjm-apc-breakdown">';
				if ( $bd['deal'] ) {
					echo esc_html( sprintf( __( 'R&P deal: %s', 'wisdom-journal-manager' ), $bd['deal'] ) ) . '<br />';
				}
				if ( $bd['vat'] > 0 ) {
					echo esc_html(
						sprintf(
							/* translators: 1: net 2: vat rate 3: vat amount 4: currency */
							__( 'Net %4$s %1$s + VAT (%2$s%%) %4$s %3$s', 'wisdom-journal-manager' ),
							number_format( $bd['net'], 2 ),
							number_format( $bd['rate'], 2 ),
							number_format( $bd['vat'], 2 ),
							$s['currency']
						)
					);
				}
				echo '</p>';
			}
		}
		echo '<p class="wjm-apc-status">' . esc_html( sprintf( __( 'Status: %s', 'wisdom-journal-manager' ), ucfirst( $status ) ) ) . '</p>';
		echo '<p>' . esc_html( $s['instructions'] ) . '</p>';
		echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built above with esc_html

		$waiver = isset( $_GET['wjm_waiver'] ) ? sanitize_text_field( wp_unslash( $_GET['wjm_waiver'] ) ) : (string) get_post_meta( $paper_id, '_sjm_waiver_code', true ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( 'paid' === $status || 'waived' === $status ) {
			echo '<p class="wjm-notice wjm-notice-success">' . esc_html__( 'No payment due.', 'wisdom-journal-manager' ) . '</p>';
			echo do_shortcode( '[wjm_apc_receipt paper_id="' . absint( $paper_id ) . '"]' );
		} elseif ( 'refunded' === $status ) {
			echo '<p class="wjm-notice">' . esc_html__( 'This APC was refunded.', 'wisdom-journal-manager' ) . '</p>';
			echo do_shortcode( '[wjm_apc_receipt paper_id="' . absint( $paper_id ) . '"]' );
		} else {
			echo '<form method="get" class="wjm-waiver-form" action="' . esc_url( get_permalink( $paper_id ) ) . '#wjm-apc" style="margin:0.75rem 0;">';
			echo '<label for="wjm_waiver">' . esc_html__( 'Waiver code', 'wisdom-journal-manager' ) . '</label> ';
			echo '<input type="text" name="wjm_waiver" id="wjm_waiver" value="' . esc_attr( $waiver ) . '" /> ';
			echo '<button type="submit" class="wjm-btn wjm-btn-secondary">' . esc_html__( 'Apply', 'wisdom-journal-manager' ) . '</button>';
			echo '</form>';

			if ( 'stripe' === $s['provider'] && WJM_Encryption::get_secret( 'wjm_stripe_secret' ) && $amount > 0 ) {
				if ( ! is_user_logged_in() ) {
					echo '<p><a class="wjm-btn" href="' . esc_url( wp_login_url( get_permalink( $paper_id ) . '#wjm-apc' ) ) . '">' . esc_html__( 'Log in to pay with Stripe', 'wisdom-journal-manager' ) . '</a></p>';
				} elseif ( self::user_can_pay( $paper_id ) ) {
					$checkout = admin_url( 'admin-post.php?action=wjm_stripe_checkout&paper_id=' . $paper_id );
					if ( $waiver ) {
						$checkout = add_query_arg( 'wjm_waiver', $waiver, $checkout );
					}
					$url = wp_nonce_url( $checkout, 'wjm_stripe_checkout_' . $paper_id );
					echo '<p><a class="wjm-btn wjm-btn-pay" href="' . esc_url( $url ) . '">' . esc_html__( 'Pay with Stripe', 'wisdom-journal-manager' ) . '</a></p>';
				} else {
					echo '<p class="description">' . esc_html__( 'Only the submitting author or an editor can pay this APC.', 'wisdom-journal-manager' ) . '</p>';
				}
			} elseif ( 'manual' === $s['provider'] ) {
				echo '<p class="description">' . esc_html__( 'Pay using the instructions above. An editor will mark this as paid.', 'wisdom-journal-manager' ) . '</p>';
			} elseif ( $amount <= 0 ) {
				echo '<p class="description">' . esc_html__( 'APC amount is zero — nothing to charge.', 'wisdom-journal-manager' ) . '</p>';
			} else {
				echo '<p class="description">' . esc_html__( 'Stripe is selected but no secret key is configured yet.', 'wisdom-journal-manager' ) . '</p>';
			}
		}

		if ( current_user_can( 'edit_others_sjm_papers' ) || current_user_can( 'manage_options' ) ) {
			$url = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_mark_apc_paid&paper_id=' . $paper_id ), 'wjm_mark_apc_' . $paper_id );
			echo '<p><a class="wjm-btn wjm-btn-secondary" href="' . esc_url( $url ) . '">' . esc_html__( 'Mark APC paid', 'wisdom-journal-manager' ) . '</a></p>';
			if ( 'paid' === $status && get_post_meta( $paper_id, self::META_INTENT, true ) ) {
				$refund = wp_nonce_url( admin_url( 'admin-post.php?action=wjm_stripe_refund&paper_id=' . $paper_id ), 'wjm_stripe_refund_' . $paper_id );
				echo '<p><a class="wjm-btn wjm-btn-secondary" href="' . esc_url( $refund ) . '">' . esc_html__( 'Refund via Stripe', 'wisdom-journal-manager' ) . '</a></p>';
			}
		}
		echo '</div>';
		return ob_get_clean();
	}

	/**
	 * Printable APC receipt / invoice summary.
	 *
	 * @param array $atts Shortcode atts.
	 * @return string
	 */
	public static function shortcode_receipt( $atts ) {
		$atts     = shortcode_atts( array( 'paper_id' => 0 ), $atts, 'wjm_apc_receipt' );
		$paper_id = absint( $atts['paper_id'] );
		if ( ! $paper_id ) {
			$paper_id = get_the_ID();
		}
		if ( ! $paper_id || 'sjm_paper' !== get_post_type( $paper_id ) ) {
			return '';
		}

		$status = get_post_meta( $paper_id, self::META_STATUS, true );
		if ( ! in_array( $status, array( 'paid', 'refunded', 'waived' ), true ) ) {
			return '';
		}
		if ( ! is_user_logged_in() ) {
			return '';
		}
		if ( ! self::user_can_pay( $paper_id ) && ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			return '';
		}

		$s        = self::settings();
		$amount   = self::amount_for_paper( $paper_id );
		$paid_at  = get_post_meta( $paper_id, self::META_PAID_AT, true );
		$provider = get_post_meta( $paper_id, self::META_PROVIDER, true );
		$session  = get_post_meta( $paper_id, self::META_SESSION, true );
		$intent   = get_post_meta( $paper_id, self::META_INTENT, true );
		$invoice  = get_post_meta( $paper_id, self::META_INVOICE, true );
		$inv_url  = get_post_meta( $paper_id, self::META_INVOICE_URL, true );
		$rcp_url  = get_post_meta( $paper_id, self::META_RECEIPT_URL, true );
		$refund   = get_post_meta( $paper_id, self::META_REFUND_ID, true );
		$email    = get_post_meta( $paper_id, self::META_CUSTOMER, true );
		$number   = 'WJM-' . $paper_id . ( $paid_at ? '-' . gmdate( 'Ymd', strtotime( $paid_at ) ) : '' );

		ob_start();
		?>
		<div class="wjm-receipt" id="wjm-receipt">
			<div class="wjm-receipt-actions">
				<button type="button" class="wjm-btn wjm-btn-secondary" onclick="window.print()"><?php esc_html_e( 'Print receipt', 'wisdom-journal-manager' ); ?></button>
				<?php if ( $inv_url ) : ?>
					<a class="wjm-btn wjm-btn-secondary" href="<?php echo esc_url( $inv_url ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Open Stripe invoice', 'wisdom-journal-manager' ); ?></a>
				<?php endif; ?>
				<?php if ( $rcp_url ) : ?>
					<a class="wjm-btn wjm-btn-secondary" href="<?php echo esc_url( $rcp_url ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Stripe receipt', 'wisdom-journal-manager' ); ?></a>
				<?php endif; ?>
			</div>
			<div class="wjm-receipt-card">
				<p class="wjm-eyebrow"><?php esc_html_e( 'Payment receipt', 'wisdom-journal-manager' ); ?></p>
				<h3><?php echo esc_html( get_the_title( $paper_id ) ); ?></h3>
				<table class="wjm-receipt-table">
					<tr><th><?php esc_html_e( 'Receipt #', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $number ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Status', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( ucfirst( $status ) ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Amount', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $s['currency'] . ' ' . number_format( $amount, 2 ) ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Provider', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $provider ? $provider : '—' ); ?></td></tr>
					<?php if ( $paid_at ) : ?><tr><th><?php esc_html_e( 'Paid at', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $paid_at ); ?></td></tr><?php endif; ?>
					<?php if ( $email ) : ?><tr><th><?php esc_html_e( 'Payer', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $email ); ?></td></tr><?php endif; ?>
					<?php if ( $invoice ) : ?><tr><th><?php esc_html_e( 'Invoice ID', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $invoice ); ?></td></tr><?php endif; ?>
					<?php if ( $session ) : ?><tr><th><?php esc_html_e( 'Checkout session', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $session ); ?></td></tr><?php endif; ?>
					<?php if ( $intent ) : ?><tr><th><?php esc_html_e( 'Payment intent', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $intent ); ?></td></tr><?php endif; ?>
					<?php if ( $refund ) : ?><tr><th><?php esc_html_e( 'Refund ID', 'wisdom-journal-manager' ); ?></th><td><?php echo esc_html( $refund ); ?></td></tr><?php endif; ?>
				</table>
			</div>
		</div>
		<?php
		return ob_get_clean();
	}

	public static function handle_checkout() {
		$paper_id = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_stripe_checkout_' . $paper_id );

		$s = self::settings();
		if ( empty( $s['enabled'] ) || 'stripe' !== $s['provider'] ) {
			wp_die( esc_html__( 'Stripe payments are not enabled.', 'wisdom-journal-manager' ) );
		}
		if ( ! self::user_can_pay( $paper_id ) || 'sjm_paper' !== get_post_type( $paper_id ) ) {
			wp_die( esc_html__( 'You cannot pay for this paper.', 'wisdom-journal-manager' ) );
		}

		$status = get_post_meta( $paper_id, self::META_STATUS, true );
		if ( in_array( $status, array( 'paid', 'waived' ), true ) ) {
			wp_safe_redirect( get_permalink( $paper_id ) );
			exit;
		}

		$amount = self::amount_for_paper( $paper_id );
		if ( $amount <= 0 ) {
			wp_die( esc_html__( 'APC amount must be greater than zero.', 'wisdom-journal-manager' ) );
		}

		$user = wp_get_current_user();
		$session = self::create_checkout_session( $paper_id, $amount, $user );
		if ( is_wp_error( $session ) ) {
			update_post_meta( $paper_id, self::META_LAST_ERROR, $session->get_error_message() );
			WJM_Audit::log( 'warning', 'stripe_checkout_failed', $session->get_error_message(), array( 'paper_id' => $paper_id ) );
			wp_safe_redirect( add_query_arg( 'wjm_apc', 'error', get_permalink( $paper_id ) ) );
			exit;
		}

		update_post_meta( $paper_id, self::META_SESSION, sanitize_text_field( $session['id'] ) );
		update_post_meta( $paper_id, self::META_STATUS, 'pending' );
		update_post_meta( $paper_id, self::META_PROVIDER, 'stripe' );
		delete_post_meta( $paper_id, self::META_LAST_ERROR );
		if ( class_exists( 'WJM_Sync' ) ) {
			WJM_Sync::sync_paper( $paper_id );
		}

		wp_safe_redirect( esc_url_raw( $session['url'] ) );
		exit;
	}

	/**
	 * @param int      $paper_id Paper ID.
	 * @param float    $amount Amount in major units.
	 * @param WP_User  $user Paying user.
	 * @return array|WP_Error Session data.
	 */
	public static function create_checkout_session( $paper_id, $amount, $user ) {
		$s        = self::settings();
		$currency = strtolower( $s['currency'] ? $s['currency'] : 'usd' );
		$unit     = self::to_stripe_unit_amount( $amount, $currency );
		if ( is_wp_error( $unit ) ) {
			return $unit;
		}

		$paper_url = get_permalink( $paper_id );
		if ( $s['success_url'] ) {
			$success = str_replace(
				array( '{paper_id}', '{session_id}' ),
				array( (string) $paper_id, '{CHECKOUT_SESSION_ID}' ),
				$s['success_url']
			);
		} else {
			$success = add_query_arg( 'wjm_apc', 'success', $paper_url );
			$success .= ( false !== strpos( $success, '?' ) ? '&' : '?' ) . 'session_id={CHECKOUT_SESSION_ID}';
		}
		if ( false === strpos( $success, '{CHECKOUT_SESSION_ID}' ) ) {
			$success .= ( false !== strpos( $success, '?' ) ? '&' : '?' ) . 'session_id={CHECKOUT_SESSION_ID}';
		}

		$cancel = $s['cancel_url']
			? str_replace( '{paper_id}', (string) $paper_id, $s['cancel_url'] )
			: add_query_arg( 'wjm_apc', 'cancel', $paper_url );

		$title = get_the_title( $paper_id );
		$body  = array(
			'mode'                                   => 'payment',
			'success_url'                            => $success,
			'cancel_url'                             => $cancel,
			'client_reference_id'                    => (string) $paper_id,
			'customer_email'                         => $user && $user->user_email ? $user->user_email : '',
			'metadata[paper_id]'                     => (string) $paper_id,
			'metadata[wjm]'                          => 'apc',
			'metadata[site]'                         => home_url( '/' ),
			'invoice_creation[enabled]'              => 'true',
			'payment_intent_data[metadata][paper_id]'=> (string) $paper_id,
			'line_items[0][quantity]'                => 1,
			'line_items[0][price_data][currency]'     => $currency,
			'line_items[0][price_data][unit_amount]'  => $unit,
			'line_items[0][price_data][product_data][name]' => sprintf(
				/* translators: %s: paper title */
				__( 'APC — %s', 'wisdom-journal-manager' ),
				wp_strip_all_tags( $title )
			),
			'line_items[0][price_data][product_data][metadata][paper_id]' => (string) $paper_id,
		);

		if ( empty( $body['customer_email'] ) ) {
			unset( $body['customer_email'] );
		}

		return self::stripe_request( 'POST', 'checkout/sessions', $body );
	}

	/**
	 * After redirect from Stripe, confirm session if webhook is slow/missing.
	 */
	public static function maybe_verify_return() {
		if ( empty( $_GET['wjm_apc'] ) || 'success' !== sanitize_key( wp_unslash( $_GET['wjm_apc'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( empty( $_GET['session_id'] ) || ! is_singular( 'sjm_paper' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$session_id = sanitize_text_field( wp_unslash( $_GET['session_id'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$paper_id   = get_the_ID();
		if ( ! $session_id || ! $paper_id ) {
			return;
		}

		$status = get_post_meta( $paper_id, self::META_STATUS, true );
		if ( 'paid' === $status ) {
			return;
		}

		$session = self::stripe_request( 'GET', 'checkout/sessions/' . rawurlencode( $session_id ) );
		if ( is_wp_error( $session ) ) {
			return;
		}

		$meta_paper = isset( $session['metadata']['paper_id'] ) ? absint( $session['metadata']['paper_id'] ) : 0;
		$ref_paper  = isset( $session['client_reference_id'] ) ? absint( $session['client_reference_id'] ) : 0;
		if ( $meta_paper && $meta_paper !== $paper_id ) {
			return;
		}
		if ( $ref_paper && $ref_paper !== $paper_id ) {
			return;
		}

		$payment_status = isset( $session['payment_status'] ) ? $session['payment_status'] : '';
		if ( in_array( $payment_status, array( 'paid', 'no_payment_required' ), true ) ) {
			self::mark_paid_from_stripe( $paper_id, $session );
		}
	}

	/**
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function handle_webhook( $request ) {
		$payload = $request->get_body();
		$sig     = $request->get_header( 'stripe-signature' );
		$secret  = WJM_Encryption::get_secret( 'wjm_stripe_webhook_secret' );

		if ( ! $secret ) {
			WJM_Audit::log( 'warning', 'stripe_webhook', 'Webhook received but signing secret not configured.' );
			return new WP_Error( 'wjm_stripe_no_secret', 'Webhook secret not configured', array( 'status' => 400 ) );
		}

		$event = self::verify_webhook( $payload, $sig, $secret );
		if ( is_wp_error( $event ) ) {
			WJM_Audit::log( 'warning', 'stripe_webhook_invalid', $event->get_error_message() );
			return $event;
		}

		$type = isset( $event['type'] ) ? $event['type'] : '';
		$object = isset( $event['data']['object'] ) ? $event['data']['object'] : array();

		if ( in_array( $type, array( 'customer.subscription.updated', 'customer.subscription.deleted', 'customer.subscription.created' ), true ) ) {
			if ( class_exists( 'WJM_Subscriptions' ) ) {
				WJM_Subscriptions::upsert_from_stripe_subscription( $object );
			}
			return rest_ensure_response( array( 'received' => true, 'type' => $type ) );
		}

		if ( 'invoice.paid' === $type ) {
			self::maybe_attach_invoice_from_event( $object );
			return rest_ensure_response( array( 'received' => true, 'type' => $type ) );
		}

		if ( ! in_array( $type, array( 'checkout.session.completed', 'checkout.session.async_payment_succeeded' ), true ) ) {
			return rest_ensure_response( array( 'received' => true, 'ignored' => $type ) );
		}

		$session = $object;
		$wjm     = isset( $session['metadata']['wjm'] ) ? $session['metadata']['wjm'] : '';

		if ( 'subscription' === $wjm || ( isset( $session['mode'] ) && 'subscription' === $session['mode'] ) ) {
			if ( class_exists( 'WJM_Subscriptions' ) ) {
				WJM_Subscriptions::upsert_from_session( $session );
			}
			return rest_ensure_response( array( 'received' => true, 'type' => $type, 'kind' => 'subscription' ) );
		}

		$paper_id = 0;
		if ( ! empty( $session['metadata']['paper_id'] ) ) {
			$paper_id = absint( $session['metadata']['paper_id'] );
		} elseif ( ! empty( $session['client_reference_id'] ) && is_numeric( $session['client_reference_id'] ) ) {
			$paper_id = absint( $session['client_reference_id'] );
		}

		if ( ! $paper_id || 'sjm_paper' !== get_post_type( $paper_id ) ) {
			return new WP_Error( 'wjm_stripe_paper', 'Unknown paper for session', array( 'status' => 400 ) );
		}

		$payment_status = isset( $session['payment_status'] ) ? $session['payment_status'] : '';
		if ( in_array( $payment_status, array( 'paid', 'no_payment_required' ), true ) || 'checkout.session.completed' === $type ) {
			if ( 'unpaid' === $payment_status && 'checkout.session.async_payment_succeeded' !== $type ) {
				update_post_meta( $paper_id, self::META_STATUS, 'pending' );
				update_post_meta( $paper_id, self::META_SESSION, sanitize_text_field( $session['id'] ) );
			} else {
				self::mark_paid_from_stripe( $paper_id, $session );
			}
		}

		return rest_ensure_response( array( 'received' => true, 'paper_id' => $paper_id ) );
	}

	/**
	 * Verify Stripe-Signature header (no SDK).
	 *
	 * @param string $payload Raw body.
	 * @param string $header  Stripe-Signature.
	 * @param string $secret  whsec_…
	 * @return array|WP_Error Decoded event.
	 */
	public static function verify_webhook( $payload, $header, $secret ) {
		if ( ! $payload || ! $header ) {
			return new WP_Error( 'wjm_stripe_sig', 'Missing payload or signature', array( 'status' => 400 ) );
		}

		$parts = array();
		foreach ( explode( ',', $header ) as $item ) {
			$kv = explode( '=', trim( $item ), 2 );
			if ( 2 === count( $kv ) ) {
				$parts[ $kv[0] ][] = $kv[1];
			}
		}
		if ( empty( $parts['t'][0] ) || empty( $parts['v1'] ) ) {
			return new WP_Error( 'wjm_stripe_sig', 'Invalid signature header', array( 'status' => 400 ) );
		}

		$timestamp = (int) $parts['t'][0];
		if ( abs( time() - $timestamp ) > 300 ) {
			return new WP_Error( 'wjm_stripe_sig', 'Timestamp outside tolerance', array( 'status' => 400 ) );
		}

		$signed   = $timestamp . '.' . $payload;
		$expected = hash_hmac( 'sha256', $signed, $secret );
		$valid    = false;
		foreach ( $parts['v1'] as $sig ) {
			if ( hash_equals( $expected, $sig ) ) {
				$valid = true;
				break;
			}
		}
		if ( ! $valid ) {
			return new WP_Error( 'wjm_stripe_sig', 'Signature mismatch', array( 'status' => 400 ) );
		}

		$event = json_decode( $payload, true );
		if ( ! is_array( $event ) ) {
			return new WP_Error( 'wjm_stripe_json', 'Invalid JSON', array( 'status' => 400 ) );
		}
		return $event;
	}

	/**
	 * @param int   $paper_id Paper ID.
	 * @param array $session Stripe session object.
	 */
	public static function mark_paid_from_stripe( $paper_id, $session ) {
		$current = get_post_meta( $paper_id, self::META_STATUS, true );
		if ( 'paid' === $current ) {
			self::attach_invoice_meta( $paper_id, $session );
			return;
		}

		update_post_meta( $paper_id, self::META_STATUS, 'paid' );
		update_post_meta( $paper_id, self::META_PAID_AT, current_time( 'mysql', true ) );
		update_post_meta( $paper_id, self::META_PROVIDER, 'stripe' );
		if ( ! empty( $session['id'] ) ) {
			update_post_meta( $paper_id, self::META_SESSION, sanitize_text_field( $session['id'] ) );
		}
		if ( ! empty( $session['payment_intent'] ) ) {
			$intent = is_array( $session['payment_intent'] ) ? $session['payment_intent']['id'] : $session['payment_intent'];
			update_post_meta( $paper_id, self::META_INTENT, sanitize_text_field( $intent ) );
		}
		if ( ! empty( $session['customer_details']['email'] ) ) {
			update_post_meta( $paper_id, self::META_CUSTOMER, sanitize_email( $session['customer_details']['email'] ) );
		} elseif ( ! empty( $session['customer_email'] ) ) {
			update_post_meta( $paper_id, self::META_CUSTOMER, sanitize_email( $session['customer_email'] ) );
		}
		self::attach_invoice_meta( $paper_id, $session );
		delete_post_meta( $paper_id, self::META_LAST_ERROR );

		if ( class_exists( 'WJM_Sync' ) ) {
			WJM_Sync::sync_paper( $paper_id );
		}

		WJM_Audit::log(
			'info',
			'apc_paid_stripe',
			"APC paid via Stripe for paper {$paper_id}",
			array(
				'session' => isset( $session['id'] ) ? $session['id'] : '',
			)
		);

		/**
		 * Fires after APC is marked paid via Stripe.
		 *
		 * @param int   $paper_id Paper post ID.
		 * @param array $session  Stripe Checkout session.
		 */
		do_action( 'sjm_apc_paid', $paper_id, $session );
	}

	/**
	 * Persist Stripe invoice / receipt URLs from a Checkout session.
	 *
	 * @param int   $paper_id Paper ID.
	 * @param array $session Session.
	 */
	public static function attach_invoice_meta( $paper_id, $session ) {
		$invoice_id = '';
		if ( ! empty( $session['invoice'] ) ) {
			$invoice_id = is_array( $session['invoice'] ) ? $session['invoice']['id'] : $session['invoice'];
		}
		if ( $invoice_id ) {
			update_post_meta( $paper_id, self::META_INVOICE, sanitize_text_field( $invoice_id ) );
			$invoice = self::stripe_request( 'GET', 'invoices/' . rawurlencode( $invoice_id ) );
			if ( ! is_wp_error( $invoice ) ) {
				if ( ! empty( $invoice['hosted_invoice_url'] ) ) {
					update_post_meta( $paper_id, self::META_INVOICE_URL, esc_url_raw( $invoice['hosted_invoice_url'] ) );
				}
				if ( ! empty( $invoice['invoice_pdf'] ) ) {
					update_post_meta( $paper_id, self::META_RECEIPT_URL, esc_url_raw( $invoice['invoice_pdf'] ) );
				}
			}
		}

		// Charge receipt URL via payment intent → latest charge.
		$intent_id = get_post_meta( $paper_id, self::META_INTENT, true );
		if ( ! $intent_id && ! empty( $session['payment_intent'] ) ) {
			$intent_id = is_array( $session['payment_intent'] ) ? $session['payment_intent']['id'] : $session['payment_intent'];
		}
		if ( $intent_id && ! get_post_meta( $paper_id, self::META_RECEIPT_URL, true ) ) {
			$pi = self::stripe_request( 'GET', 'payment_intents/' . rawurlencode( $intent_id ) . '?expand[]=latest_charge' );
			if ( ! is_wp_error( $pi ) && ! empty( $pi['latest_charge']['receipt_url'] ) ) {
				update_post_meta( $paper_id, self::META_RECEIPT_URL, esc_url_raw( $pi['latest_charge']['receipt_url'] ) );
			}
		}
	}

	/**
	 * Link invoice.paid webhook to a paper when metadata is present.
	 *
	 * @param array $invoice Stripe invoice.
	 */
	public static function maybe_attach_invoice_from_event( $invoice ) {
		$paper_id = 0;
		if ( ! empty( $invoice['metadata']['paper_id'] ) ) {
			$paper_id = absint( $invoice['metadata']['paper_id'] );
		}
		if ( ! $paper_id && ! empty( $invoice['payment_intent'] ) ) {
			$intent_id = is_array( $invoice['payment_intent'] ) ? $invoice['payment_intent']['id'] : $invoice['payment_intent'];
			$posts     = get_posts(
				array(
					'post_type'      => 'sjm_paper',
					'posts_per_page' => 1,
					'fields'         => 'ids',
					'meta_key'       => self::META_INTENT,
					'meta_value'     => $intent_id,
				)
			);
			$paper_id = $posts ? (int) $posts[0] : 0;
		}
		if ( ! $paper_id ) {
			return;
		}
		if ( ! empty( $invoice['id'] ) ) {
			update_post_meta( $paper_id, self::META_INVOICE, sanitize_text_field( $invoice['id'] ) );
		}
		if ( ! empty( $invoice['hosted_invoice_url'] ) ) {
			update_post_meta( $paper_id, self::META_INVOICE_URL, esc_url_raw( $invoice['hosted_invoice_url'] ) );
		}
		if ( ! empty( $invoice['invoice_pdf'] ) ) {
			update_post_meta( $paper_id, self::META_RECEIPT_URL, esc_url_raw( $invoice['invoice_pdf'] ) );
		}
	}

	public static function handle_refund() {
		$paper_id = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_stripe_refund_' . $paper_id );
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$intent = get_post_meta( $paper_id, self::META_INTENT, true );
		if ( ! $intent ) {
			wp_die( esc_html__( 'No Stripe payment intent on this paper.', 'wisdom-journal-manager' ) );
		}

		$refund = self::stripe_request(
			'POST',
			'refunds',
			array(
				'payment_intent' => $intent,
				'metadata[paper_id]' => (string) $paper_id,
				'metadata[wjm]' => 'apc_refund',
			)
		);

		if ( is_wp_error( $refund ) ) {
			update_post_meta( $paper_id, self::META_LAST_ERROR, $refund->get_error_message() );
			WJM_Audit::log( 'warning', 'stripe_refund_failed', $refund->get_error_message(), array( 'paper_id' => $paper_id ) );
			wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
			exit;
		}

		update_post_meta( $paper_id, self::META_STATUS, 'refunded' );
		update_post_meta( $paper_id, self::META_REFUND_ID, sanitize_text_field( $refund['id'] ) );
		update_post_meta( $paper_id, self::META_REFUNDED_AT, current_time( 'mysql', true ) );
		delete_post_meta( $paper_id, self::META_LAST_ERROR );
		if ( class_exists( 'WJM_Sync' ) ) {
			WJM_Sync::sync_paper( $paper_id );
		}
		WJM_Audit::log( 'info', 'apc_refunded', "APC refunded for paper {$paper_id}", array( 'refund' => $refund['id'] ) );
		do_action( 'sjm_apc_refunded', $paper_id, $refund );

		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}

	public static function handle_mark_paid() {
		$paper_id = isset( $_GET['paper_id'] ) ? absint( $_GET['paper_id'] ) : 0;
		check_admin_referer( 'wjm_mark_apc_' . $paper_id );
		if ( ! current_user_can( 'edit_others_sjm_papers' ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		update_post_meta( $paper_id, self::META_STATUS, 'paid' );
		update_post_meta( $paper_id, self::META_PAID_AT, current_time( 'mysql', true ) );
		update_post_meta( $paper_id, self::META_PROVIDER, 'manual' );
		if ( class_exists( 'WJM_Sync' ) ) {
			WJM_Sync::sync_paper( $paper_id );
		}
		WJM_Audit::log( 'info', 'apc_paid', "APC marked paid for paper {$paper_id}" );
		do_action( 'sjm_apc_paid', $paper_id, array() );
		wp_safe_redirect( get_edit_post_link( $paper_id, 'raw' ) );
		exit;
	}

	/**
	 * Convert major currency units to Stripe's smallest unit.
	 *
	 * @param float  $amount Amount.
	 * @param string $currency Lowercase ISO code.
	 * @return int|WP_Error
	 */
	public static function to_stripe_unit_amount( $amount, $currency ) {
		$currency = strtolower( $currency );
		$zero     = array( 'bif', 'clp', 'djf', 'gnf', 'jpy', 'kmf', 'krw', 'mga', 'pyg', 'rwf', 'ugx', 'vnd', 'vuv', 'xaf', 'xof', 'xpf' );
		$three    = array( 'bhd', 'jod', 'kwd', 'omr', 'tnd' );

		if ( in_array( $currency, $zero, true ) ) {
			$unit = (int) round( $amount );
		} elseif ( in_array( $currency, $three, true ) ) {
			$unit = (int) round( $amount * 1000 );
		} else {
			$unit = (int) round( $amount * 100 );
		}

		if ( $unit < 1 ) {
			return new WP_Error( 'wjm_stripe_amount', __( 'Amount too small for Stripe.', 'wisdom-journal-manager' ) );
		}
		return $unit;
	}

	/**
	 * Call Stripe REST API.
	 *
	 * @param string $method GET|POST.
	 * @param string $path   Path without leading slash.
	 * @param array  $body   Form body for POST.
	 * @return array|WP_Error
	 */
	public static function stripe_request( $method, $path, $body = array() ) {
		$secret = WJM_Encryption::get_secret( 'wjm_stripe_secret' );
		if ( ! $secret ) {
			return new WP_Error( 'wjm_stripe_key', __( 'Stripe secret key not configured.', 'wisdom-journal-manager' ) );
		}

		$args = array(
			'method'  => strtoupper( $method ),
			'timeout' => 30,
			'headers' => array(
				'Authorization' => 'Bearer ' . $secret,
				'Stripe-Version'=> '2024-06-20',
			),
		);

		if ( 'POST' === $args['method'] ) {
			$args['headers']['Content-Type'] = 'application/x-www-form-urlencoded';
			$args['body']                    = $body;
		}

		$url      = 'https://api.stripe.com/v1/' . ltrim( $path, '/' );
		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code < 200 || $code >= 300 || ! is_array( $data ) ) {
			$message = is_array( $data ) && ! empty( $data['error']['message'] )
				? $data['error']['message']
				: sprintf( 'HTTP %d from Stripe', $code );
			return new WP_Error( 'wjm_stripe_http', $message, array( 'status' => $code, 'body' => $data ) );
		}

		return $data;
	}
}
