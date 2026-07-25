<?php
/**
 * Journal subscriptions via Stripe Checkout (recurring).
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Subscriptions {

	const META_ENABLED = '_sjm_subscription_enabled';
	const META_AMOUNT  = '_sjm_subscription_amount';

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_action( 'save_post_sjm_journal', array( __CLASS__, 'save_journal_meta' ), 40, 2 );
		add_shortcode( 'wjm_subscribe', array( __CLASS__, 'shortcode' ) );
		add_action( 'admin_post_wjm_stripe_subscribe', array( __CLASS__, 'handle_checkout' ) );
		add_action( 'admin_post_nopriv_wjm_stripe_subscribe', array( __CLASS__, 'handle_checkout' ) );
		add_action( 'admin_post_wjm_cancel_subscription', array( __CLASS__, 'handle_cancel' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_verify_return' ) );
	}

	/**
	 * Whether site-level subscriptions are on.
	 *
	 * @return bool
	 */
	public static function enabled() {
		$s = WJM_Payments::settings();
		return ! empty( $s['enabled'] ) && ! empty( $s['subscriptions_enabled'] ) && 'stripe' === $s['provider'];
	}

	public static function meta_box() {
		add_meta_box(
			'wjm_subscription',
			__( 'Subscription', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_journal_box' ),
			'sjm_journal',
			'side',
			'default'
		);
	}

	public static function render_journal_box( $post ) {
		$s       = WJM_Payments::settings();
		$enabled = get_post_meta( $post->ID, self::META_ENABLED, true );
		$amount  = get_post_meta( $post->ID, self::META_AMOUNT, true );
		if ( '' === $amount ) {
			$amount = isset( $s['subscription_amount'] ) ? $s['subscription_amount'] : '0';
		}
		wp_nonce_field( 'wjm_journal_sub', 'wjm_journal_sub_nonce' );
		?>
		<p>
			<label>
				<input type="checkbox" name="sjm_subscription_enabled" value="1" <?php checked( '1', $enabled ); ?> <?php disabled( ! self::enabled() ); ?> />
				<?php esc_html_e( 'Offer Stripe subscription', 'wisdom-journal-manager' ); ?>
			</label>
		</p>
		<p>
			<label><?php esc_html_e( 'Price', 'wisdom-journal-manager' ); ?></label><br />
			<input type="number" step="0.01" min="0" name="sjm_subscription_amount" value="<?php echo esc_attr( $amount ); ?>" class="widefat" <?php disabled( ! self::enabled() ); ?> />
			<span class="description">
				<?php
				echo esc_html(
					( $s['currency'] ?? 'USD' ) . ' / ' . ( isset( $s['subscription_interval'] ) ? $s['subscription_interval'] : 'year' )
				);
				?>
			</span>
		</p>
		<?php if ( ! self::enabled() ) : ?>
			<p class="description"><?php esc_html_e( 'Enable subscriptions under Journals → Payments / APC.', 'wisdom-journal-manager' ); ?></p>
		<?php endif; ?>
		<?php
	}

	public static function save_journal_meta( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_journal_sub_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_journal_sub_nonce'] ) ), 'wjm_journal_sub' ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		update_post_meta( $post_id, self::META_ENABLED, ! empty( $_POST['sjm_subscription_enabled'] ) ? '1' : '0' );
		if ( isset( $_POST['sjm_subscription_amount'] ) ) {
			update_post_meta( $post_id, self::META_AMOUNT, sanitize_text_field( wp_unslash( $_POST['sjm_subscription_amount'] ) ) );
		}
		unset( $post );
	}

	/**
	 * @param int $journal_id Journal post ID.
	 * @return float
	 */
	public static function amount_for_journal( $journal_id ) {
		$s      = WJM_Payments::settings();
		$amount = get_post_meta( $journal_id, self::META_AMOUNT, true );
		if ( '' === $amount || null === $amount ) {
			$amount = isset( $s['subscription_amount'] ) ? $s['subscription_amount'] : '0';
		}
		return max( 0, (float) $amount );
	}

	/**
	 * @param int $user_id User ID.
	 * @param int $journal_id Journal post ID.
	 * @return object|null
	 */
	public static function get_active( $user_id, $journal_id ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'subscriptions' );
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_id = %d AND journal_post_id = %d AND status IN ('active','trialing') ORDER BY id DESC LIMIT 1",
				absint( $user_id ),
				absint( $journal_id )
			)
		);
	}

	/**
	 * @param int $user_id User ID.
	 * @param int $journal_id Journal post ID.
	 * @return bool
	 */
	public static function user_has_access( $user_id, $journal_id ) {
		if ( ! $user_id || ! $journal_id ) {
			return false;
		}
		if ( user_can( $user_id, 'edit_others_sjm_papers' ) || user_can( $user_id, 'manage_options' ) ) {
			return true;
		}
		$row = self::get_active( $user_id, $journal_id );
		if ( ! $row ) {
			return false;
		}
		if ( ! empty( $row->current_period_end ) && strtotime( $row->current_period_end ) < time() ) {
			return false;
		}
		return true;
	}

	public static function shortcode( $atts ) {
		$atts       = shortcode_atts( array( 'journal_id' => 0 ), $atts, 'wjm_subscribe' );
		$journal_id = absint( $atts['journal_id'] );
		if ( ! $journal_id ) {
			$journal_id = get_the_ID();
		}
		if ( ! self::enabled() || ! $journal_id || 'sjm_journal' !== get_post_type( $journal_id ) ) {
			return '';
		}
		if ( '1' !== get_post_meta( $journal_id, self::META_ENABLED, true ) ) {
			return '';
		}

		$s      = WJM_Payments::settings();
		$amount = self::amount_for_journal( $journal_id );
		$interval = isset( $s['subscription_interval'] ) ? $s['subscription_interval'] : 'year';

		$notice = '';
		if ( isset( $_GET['wjm_sub'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$flag = sanitize_key( wp_unslash( $_GET['wjm_sub'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( 'success' === $flag ) {
				$notice = '<p class="wjm-notice wjm-notice-success">' . esc_html__( 'Subscription activated. Thank you.', 'wisdom-journal-manager' ) . '</p>';
			} elseif ( 'cancel' === $flag ) {
				$notice = '<p class="wjm-notice">' . esc_html__( 'Checkout canceled.', 'wisdom-journal-manager' ) . '</p>';
			} elseif ( 'error' === $flag ) {
				$notice = '<p class="wjm-notice wjm-notice-error">' . esc_html__( 'Could not start subscription checkout.', 'wisdom-journal-manager' ) . '</p>';
			}
		}

		ob_start();
		echo '<div class="wjm-apc-box wjm-subscribe-box" id="wjm-subscribe">';
		echo '<h3>' . esc_html__( 'Journal subscription', 'wisdom-journal-manager' ) . '</h3>';
		echo '<p class="wjm-apc-amount"><strong>' . esc_html( $s['currency'] . ' ' . number_format( $amount, 2 ) . ' / ' . $interval ) . '</strong></p>';
		echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		if ( ! is_user_logged_in() ) {
			echo '<p><a class="wjm-btn" href="' . esc_url( wp_login_url( get_permalink( $journal_id ) . '#wjm-subscribe' ) ) . '">' . esc_html__( 'Log in to subscribe', 'wisdom-journal-manager' ) . '</a></p>';
		} else {
			$active = self::get_active( get_current_user_id(), $journal_id );
			if ( $active ) {
				echo '<p class="wjm-notice wjm-notice-success">' . esc_html__( 'You have an active subscription.', 'wisdom-journal-manager' ) . '</p>';
				if ( ! empty( $active->current_period_end ) ) {
					echo '<p class="description">' . esc_html( sprintf( __( 'Renews / ends: %s', 'wisdom-journal-manager' ), $active->current_period_end ) ) . '</p>';
				}
				$cancel = wp_nonce_url(
					admin_url( 'admin-post.php?action=wjm_cancel_subscription&journal_id=' . $journal_id ),
					'wjm_cancel_sub_' . $journal_id
				);
				echo '<p><a class="wjm-btn wjm-btn-secondary" href="' . esc_url( $cancel ) . '">' . esc_html__( 'Cancel at period end', 'wisdom-journal-manager' ) . '</a></p>';
			} elseif ( $amount > 0 && WJM_Encryption::get_secret( 'wjm_stripe_secret' ) ) {
				$url = wp_nonce_url(
					admin_url( 'admin-post.php?action=wjm_stripe_subscribe&journal_id=' . $journal_id ),
					'wjm_stripe_subscribe_' . $journal_id
				);
				echo '<p><a class="wjm-btn wjm-btn-pay" href="' . esc_url( $url ) . '">' . esc_html__( 'Subscribe with Stripe', 'wisdom-journal-manager' ) . '</a></p>';
			} else {
				echo '<p class="description">' . esc_html__( 'Subscription price is not configured.', 'wisdom-journal-manager' ) . '</p>';
			}
		}
		echo '</div>';
		return ob_get_clean();
	}

	public static function handle_checkout() {
		$journal_id = isset( $_GET['journal_id'] ) ? absint( $_GET['journal_id'] ) : 0;
		check_admin_referer( 'wjm_stripe_subscribe_' . $journal_id );

		if ( ! self::enabled() || ! is_user_logged_in() || 'sjm_journal' !== get_post_type( $journal_id ) ) {
			wp_die( esc_html__( 'Subscriptions are not available.', 'wisdom-journal-manager' ) );
		}
		if ( '1' !== get_post_meta( $journal_id, self::META_ENABLED, true ) ) {
			wp_die( esc_html__( 'This journal does not offer subscriptions.', 'wisdom-journal-manager' ) );
		}
		if ( self::get_active( get_current_user_id(), $journal_id ) ) {
			wp_safe_redirect( get_permalink( $journal_id ) );
			exit;
		}

		$amount = self::amount_for_journal( $journal_id );
		if ( $amount <= 0 ) {
			wp_die( esc_html__( 'Subscription amount must be greater than zero.', 'wisdom-journal-manager' ) );
		}

		$user    = wp_get_current_user();
		$session = self::create_checkout_session( $journal_id, $amount, $user );
		if ( is_wp_error( $session ) ) {
			WJM_Audit::log( 'warning', 'stripe_subscribe_failed', $session->get_error_message(), array( 'journal_id' => $journal_id ) );
			wp_safe_redirect( add_query_arg( 'wjm_sub', 'error', get_permalink( $journal_id ) ) );
			exit;
		}

		wp_safe_redirect( esc_url_raw( $session['url'] ) );
		exit;
	}

	/**
	 * @param int     $journal_id Journal ID.
	 * @param float   $amount Amount.
	 * @param WP_User $user User.
	 * @return array|WP_Error
	 */
	public static function create_checkout_session( $journal_id, $amount, $user ) {
		$s        = WJM_Payments::settings();
		$currency = strtolower( $s['currency'] ? $s['currency'] : 'usd' );
		$interval = in_array( $s['subscription_interval'] ?? '', array( 'month', 'year' ), true ) ? $s['subscription_interval'] : 'year';
		$unit     = WJM_Payments::to_stripe_unit_amount( $amount, $currency );
		if ( is_wp_error( $unit ) ) {
			return $unit;
		}

		$journal_url = get_permalink( $journal_id );
		$success     = add_query_arg( 'wjm_sub', 'success', $journal_url );
		$success    .= ( false !== strpos( $success, '?' ) ? '&' : '?' ) . 'session_id={CHECKOUT_SESSION_ID}';
		$cancel      = add_query_arg( 'wjm_sub', 'cancel', $journal_url );

		$body = array(
			'mode'                => 'subscription',
			'success_url'         => $success,
			'cancel_url'          => $cancel,
			'client_reference_id' => 'journal_' . $journal_id . '_user_' . $user->ID,
			'customer_email'      => $user->user_email,
			'metadata[wjm]'       => 'subscription',
			'metadata[journal_id]'=> (string) $journal_id,
			'metadata[user_id]'   => (string) $user->ID,
			'subscription_data[metadata][journal_id]' => (string) $journal_id,
			'subscription_data[metadata][user_id]'    => (string) $user->ID,
			'line_items[0][quantity]' => 1,
			'line_items[0][price_data][currency]' => $currency,
			'line_items[0][price_data][unit_amount]' => $unit,
			'line_items[0][price_data][recurring][interval]' => $interval,
			'line_items[0][price_data][product_data][name]' => sprintf(
				/* translators: %s: journal title */
				__( 'Subscription — %s', 'wisdom-journal-manager' ),
				wp_strip_all_tags( get_the_title( $journal_id ) )
			),
			'line_items[0][price_data][product_data][metadata][journal_id]' => (string) $journal_id,
		);

		return WJM_Payments::stripe_request( 'POST', 'checkout/sessions', $body );
	}

	public static function maybe_verify_return() {
		if ( empty( $_GET['wjm_sub'] ) || 'success' !== sanitize_key( wp_unslash( $_GET['wjm_sub'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( empty( $_GET['session_id'] ) || ! is_singular( 'sjm_journal' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$session_id = sanitize_text_field( wp_unslash( $_GET['session_id'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$session    = WJM_Payments::stripe_request( 'GET', 'checkout/sessions/' . rawurlencode( $session_id ) . '?expand[]=subscription' );
		if ( is_wp_error( $session ) ) {
			return;
		}
		self::upsert_from_session( $session );
	}

	/**
	 * @param array $session Checkout session.
	 */
	public static function upsert_from_session( $session ) {
		$journal_id = isset( $session['metadata']['journal_id'] ) ? absint( $session['metadata']['journal_id'] ) : 0;
		$user_id    = isset( $session['metadata']['user_id'] ) ? absint( $session['metadata']['user_id'] ) : 0;
		if ( ! $journal_id || ! $user_id ) {
			return;
		}

		$sub = isset( $session['subscription'] ) ? $session['subscription'] : null;
		if ( is_string( $sub ) && $sub ) {
			$fetched = WJM_Payments::stripe_request( 'GET', 'subscriptions/' . rawurlencode( $sub ) );
			$sub     = is_wp_error( $fetched ) ? null : $fetched;
		}
		if ( ! is_array( $sub ) ) {
			return;
		}

		self::upsert_subscription_row( $user_id, $journal_id, $sub, $session );
	}

	/**
	 * Handle Stripe subscription object from webhook.
	 *
	 * @param array $sub Stripe subscription.
	 */
	public static function upsert_from_stripe_subscription( $sub ) {
		$journal_id = isset( $sub['metadata']['journal_id'] ) ? absint( $sub['metadata']['journal_id'] ) : 0;
		$user_id    = isset( $sub['metadata']['user_id'] ) ? absint( $sub['metadata']['user_id'] ) : 0;
		if ( ! $journal_id || ! $user_id ) {
			return;
		}
		self::upsert_subscription_row( $user_id, $journal_id, $sub, array() );
	}

	/**
	 * @param int   $user_id User.
	 * @param int   $journal_id Journal.
	 * @param array $sub Stripe subscription.
	 * @param array $session Optional session.
	 */
	private static function upsert_subscription_row( $user_id, $journal_id, $sub, $session ) {
		global $wpdb;
		$table = WJM_Database_Schema::table( 'subscriptions' );
		$status = isset( $sub['status'] ) ? sanitize_key( $sub['status'] ) : 'active';
		$period_end = ! empty( $sub['current_period_end'] ) ? gmdate( 'Y-m-d H:i:s', (int) $sub['current_period_end'] ) : null;
		$customer = '';
		if ( ! empty( $sub['customer'] ) ) {
			$customer = is_array( $sub['customer'] ) ? $sub['customer']['id'] : $sub['customer'];
		}

		$row = array(
			'user_id'                 => absint( $user_id ),
			'journal_post_id'         => absint( $journal_id ),
			'stripe_subscription_id'  => sanitize_text_field( $sub['id'] ),
			'stripe_customer_id'      => sanitize_text_field( $customer ),
			'stripe_session_id'       => ! empty( $session['id'] ) ? sanitize_text_field( $session['id'] ) : null,
			'status'                  => $status,
			'current_period_end'      => $period_end,
			'cancel_at_period_end'    => ! empty( $sub['cancel_at_period_end'] ) ? 1 : 0,
			'updated_at'              => current_time( 'mysql', true ),
		);

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE stripe_subscription_id = %s",
				$row['stripe_subscription_id']
			)
		);

		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'id' => $existing ) );
		} else {
			$row['created_at'] = current_time( 'mysql', true );
			$wpdb->insert( $table, $row );
		}

		WJM_Audit::log(
			'info',
			'subscription_upsert',
			"Subscription {$status} for user {$user_id} / journal {$journal_id}",
			array( 'subscription' => $row['stripe_subscription_id'] )
		);
	}

	public static function handle_cancel() {
		$journal_id = isset( $_GET['journal_id'] ) ? absint( $_GET['journal_id'] ) : 0;
		check_admin_referer( 'wjm_cancel_sub_' . $journal_id );
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}

		$active = self::get_active( get_current_user_id(), $journal_id );
		if ( ! $active || empty( $active->stripe_subscription_id ) ) {
			wp_safe_redirect( get_permalink( $journal_id ) );
			exit;
		}

		$result = WJM_Payments::stripe_request(
			'POST',
			'subscriptions/' . rawurlencode( $active->stripe_subscription_id ),
			array( 'cancel_at_period_end' => 'true' )
		);

		if ( ! is_wp_error( $result ) ) {
			self::upsert_from_stripe_subscription( $result );
		}

		wp_safe_redirect( add_query_arg( 'wjm_sub', 'success', get_permalink( $journal_id ) ) );
		exit;
	}
}
