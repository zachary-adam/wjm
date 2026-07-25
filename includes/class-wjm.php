<?php
/**
 * Main plugin orchestrator.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM {

	/** @var WJM|null */
	private static $instance = null;

	/**
	 * Singleton accessor.
	 *
	 * @return WJM
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		WJM_Database_Schema::maybe_upgrade();
		$this->init_hooks();
		$this->load_modules();
	}

	private function init_hooks() {
		add_action( 'init', array( 'WJM_Post_Types', 'register' ) );
		add_action( 'init', array( 'WJM_Roles', 'ensure_roles' ) );
		add_action( 'init', array( 'WJM_Shortcodes', 'register' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_public_assets' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
	}

	private function load_modules() {
		WJM_Sync::init();
		WJM_Migrator::init();
		WJM_Meta::init();
		WJM_Author_Profiles::init();
		WJM_Author_Unification::init();
		WJM_Workflow::init();
		WJM_Peer_Review::init();
		WJM_Reviewer_Access::init();
		WJM_Reviewer_Recognition::init();
		WJM_Editorial_Trust::init();
		WJM_Submissions::init();
		WJM_Drafts::init();
		WJM_Extensions::init();
		WJM_Issue_Assembler::init();
		WJM_ORCID::init();
		WJM_Preprint::init();
		WJM_OAI::init();
		WJM_Ithenticate::init();
		WJM_Integrity::init();
		WJM_Email::init();
		WJM_JATS::init();
		WJM_DOI::init();
		WJM_REST_API::init();
		WJM_Templates::init();
		WJM_SEO::init();
		WJM_Payments::init();
		WJM_Deals::init();
		WJM_Subscriptions::init();
		WJM_Production::init();
		WJM_Citation_Tracking::init();
		WJM_Advanced_Metrics::init();
		WJM_Advanced_Search::init();
		WJM_Collaboration_Tools::init();
		WJM_Automation_System::init();
		WJM_Automated_Pages::init();
		WJM_Admin::init();
		WJM_Simple_UI::init();
		WJM_Analytics_Dashboard::init();
		WJM_Diagnostics::init();
		WJM_Editor_Inbox::init();
		WJM_Getting_Started::init();
		WJM_Help::init();
		WJM_Product_Guard::init();
		WJM_Access::init();
		WJM_Demo::init();
		WJM_Upgrade::init();
		WJM_Audit::init();
		WJM_Rate_Limiter::init();
	}

	public function enqueue_public_assets() {
		self::enqueue_fonts();
		$ver = WJM_VERSION . '.' . (string) filemtime( WJM_PLUGIN_DIR . 'assets/css/public.css' );
		wp_enqueue_style(
			'wjm-public',
			WJM_PLUGIN_URL . 'assets/css/public.css',
			array( 'wjm-fonts' ),
			$ver
		);
	}

	public function enqueue_admin_assets( $hook ) {
		$screen  = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$is_wjm  = $screen && in_array( $screen->post_type, array( 'sjm_journal', 'sjm_issue', 'sjm_paper' ), true );
		$is_page = ( false !== strpos( $hook, 'wjm-' ) || false !== strpos( $hook, 'sjm_journal' ) );
		if ( ! $is_wjm && ! $is_page ) {
			return;
		}

		self::enqueue_fonts();
		$ver = WJM_VERSION . '.' . (string) filemtime( WJM_PLUGIN_DIR . 'assets/css/admin.css' );
		wp_enqueue_style(
			'wjm-admin',
			WJM_PLUGIN_URL . 'assets/css/admin.css',
			array( 'wjm-fonts' ),
			$ver
		);
		wp_enqueue_script(
			'wjm-admin',
			WJM_PLUGIN_URL . 'assets/js/admin.js',
			array( 'jquery' ),
			WJM_VERSION,
			true
		);
		wp_localize_script(
			'wjm-admin',
			'wjmAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'wjm_admin' ),
			)
		);
	}

	/**
	 * Kindled Book typography (Inter + Source Serif 4) via Google Fonts.
	 * Documented under readme.txt → External services.
	 */
	public static function enqueue_fonts() {
		wp_enqueue_style(
			'wjm-fonts',
			'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Serif+4:opsz,wght@8..60,500;8..60,600;8..60,700&display=swap',
			array(),
			null
		);
	}
}
