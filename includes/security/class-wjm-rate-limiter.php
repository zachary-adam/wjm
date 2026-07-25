<?php
/**
 * Hourly API / data-fetch rate limiting by user role.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Rate_Limiter {

	public static function init() {
		// Available for modules to call check().
	}

	/**
	 * Attempt to consume one unit from a bucket.
	 *
	 * @param string $bucket api|fetch
	 * @param int    $user_id Optional user ID.
	 * @return true|WP_Error
	 */
	public static function check( $bucket = 'api', $user_id = 0 ) {
		$user_id = $user_id ? absint( $user_id ) : get_current_user_id();
		if ( ! $user_id ) {
			return new WP_Error( 'wjm_rate_auth', __( 'Authentication required.', 'wisdom-journal-manager' ), array( 'status' => 401 ) );
		}

		$limits = WJM_Roles::rate_limits_for_user( $user_id );
		$limit  = ( 'fetch' === $bucket ) ? $limits['fetch'] : $limits['api'];

		global $wpdb;
		$table = WJM_Database_Schema::table( 'rate' );
		$now   = current_time( 'mysql', true );
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_id = %d AND bucket = %s",
				$user_id,
				$bucket
			)
		);

		$window_start = gmdate( 'Y-m-d H:00:00' );

		if ( ! $row ) {
			$wpdb->insert(
				$table,
				array(
					'user_id'      => $user_id,
					'bucket'       => $bucket,
					'hit_count'    => 1,
					'window_start' => $window_start,
				),
				array( '%d', '%s', '%d', '%s' )
			);
			return true;
		}

		if ( $row->window_start < $window_start ) {
			$wpdb->update(
				$table,
				array(
					'hit_count'    => 1,
					'window_start' => $window_start,
				),
				array(
					'user_id' => $user_id,
					'bucket'  => $bucket,
				),
				array( '%d', '%s' ),
				array( '%d', '%s' )
			);
			return true;
		}

		if ( (int) $row->hit_count >= $limit ) {
			WJM_Audit::log(
				'warning',
				'rate_limit_exceeded',
				sprintf( 'User %d exceeded %s rate limit.', $user_id, $bucket ),
				array( 'bucket' => $bucket, 'limit' => $limit )
			);
			return new WP_Error(
				'wjm_rate_limited',
				__( 'Rate limit exceeded. Try again later.', 'wisdom-journal-manager' ),
				array( 'status' => 429 )
			);
		}

		$wpdb->update(
			$table,
			array( 'hit_count' => (int) $row->hit_count + 1 ),
			array(
				'user_id' => $user_id,
				'bucket'  => $bucket,
			),
			array( '%d' ),
			array( '%d', '%s' )
		);

		unset( $now );
		return true;
	}
}
