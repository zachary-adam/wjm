<?php
/**
 * Scheduled tasks and automation settings.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Automation_System {

	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'maybe_reschedule' ) );
	}

	/**
	 * Schedule citation cron based on settings.
	 */
	public static function schedule_events() {
		self::clear_events();

		$freq = get_option( 'wjm_citation_schedule', 'weekly' );
		$recurrence = 'daily';
		if ( 'weekly' === $freq ) {
			$recurrence = 'weekly';
		} elseif ( 'monthly' === $freq ) {
			$recurrence = 'wjm_monthly';
		}

		if ( ! wp_next_scheduled( WJM_Citation_Tracking::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, $recurrence, WJM_Citation_Tracking::CRON_HOOK );
		}
	}

	public static function clear_events() {
		$timestamp = wp_next_scheduled( WJM_Citation_Tracking::CRON_HOOK );
		while ( $timestamp ) {
			wp_unschedule_event( $timestamp, WJM_Citation_Tracking::CRON_HOOK );
			$timestamp = wp_next_scheduled( WJM_Citation_Tracking::CRON_HOOK );
		}
	}

	public static function maybe_reschedule() {
		if ( isset( $_POST['wjm_save_automation'] ) ) {
			return;
		}
		if ( ! wp_next_scheduled( WJM_Citation_Tracking::CRON_HOOK ) && 'disabled' !== get_option( 'wjm_citation_schedule', 'weekly' ) ) {
			self::schedule_events();
		}
	}
}
