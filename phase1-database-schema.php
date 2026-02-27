<?php
/**
 * Phase 1 Database Schema
 * Creates tables for: Citations, Metrics, Search Index
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Create all Phase 1 database tables
 */
function wjm_phase1_create_tables() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();

    // ========================================
    // 1. CITATIONS TABLE
    // ========================================
    $citations_table = $wpdb->prefix . 'wjm_citations';
    $sql_citations = "CREATE TABLE IF NOT EXISTS $citations_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        cited_paper_id bigint(20) UNSIGNED DEFAULT NULL,
        cited_doi varchar(255) DEFAULT NULL,
        citation_text text,
        citation_order int(11) DEFAULT 0,
        extraction_method varchar(50) DEFAULT 'manual',
        verified tinyint(1) DEFAULT 0,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY paper_id (paper_id),
        KEY cited_paper_id (cited_paper_id),
        KEY cited_doi (cited_doi),
        KEY verified (verified)
    ) $charset_collate;";

    // ========================================
    // 2. CITATION INDEX TABLE (for fast lookups)
    // ========================================
    $citation_index_table = $wpdb->prefix . 'wjm_citation_index';
    $sql_citation_index = "CREATE TABLE IF NOT EXISTS $citation_index_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        cited_by_count int(11) DEFAULT 0,
        citing_count int(11) DEFAULT 0,
        last_cited datetime DEFAULT NULL,
        h_index int(11) DEFAULT 0,
        updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY paper_id (paper_id),
        KEY cited_by_count (cited_by_count),
        KEY h_index (h_index)
    ) $charset_collate;";

    // ========================================
    // 3. PAPER METRICS TABLE
    // ========================================
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';
    $sql_metrics = "CREATE TABLE IF NOT EXISTS $metrics_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        metric_type varchar(50) NOT NULL,
        metric_value bigint(20) DEFAULT 0,
        metric_date date NOT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY paper_metric_date (paper_id, metric_type, metric_date),
        KEY paper_id (paper_id),
        KEY metric_type (metric_type),
        KEY metric_date (metric_date)
    ) $charset_collate;";

    // ========================================
    // 4. VIEW/DOWNLOAD TRACKING TABLE
    // ========================================
    $tracking_table = $wpdb->prefix . 'wjm_tracking';
    $sql_tracking = "CREATE TABLE IF NOT EXISTS $tracking_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        event_type varchar(20) NOT NULL,
        user_ip varchar(45) DEFAULT NULL,
        user_agent text,
        country_code varchar(2) DEFAULT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY paper_id (paper_id),
        KEY event_type (event_type),
        KEY created_at (created_at)
    ) $charset_collate;";

    // ========================================
    // 5. SEARCH INDEX TABLE
    // ========================================
    $search_index_table = $wpdb->prefix . 'wjm_search_index';
    $sql_search_index = "CREATE TABLE IF NOT EXISTS $search_index_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        content_type varchar(20) NOT NULL,
        content_text longtext,
        updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY paper_content (paper_id, content_type),
        FULLTEXT KEY content_search (content_text)
    ) $charset_collate ENGINE=InnoDB;";

    // ========================================
    // 6. SAVED SEARCHES TABLE
    // ========================================
    $saved_searches_table = $wpdb->prefix . 'wjm_saved_searches';
    $sql_saved_searches = "CREATE TABLE IF NOT EXISTS $saved_searches_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id bigint(20) UNSIGNED NOT NULL,
        search_name varchar(255) NOT NULL,
        search_query text NOT NULL,
        search_filters text,
        alert_enabled tinyint(1) DEFAULT 0,
        last_checked datetime DEFAULT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY alert_enabled (alert_enabled)
    ) $charset_collate;";

    // ========================================
    // 7. AUTHOR METRICS TABLE
    // ========================================
    $author_metrics_table = $wpdb->prefix . 'wjm_author_metrics';
    $sql_author_metrics = "CREATE TABLE IF NOT EXISTS $author_metrics_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        author_id bigint(20) UNSIGNED NOT NULL,
        total_papers int(11) DEFAULT 0,
        total_citations int(11) DEFAULT 0,
        h_index int(11) DEFAULT 0,
        i10_index int(11) DEFAULT 0,
        first_publication_year int(4) DEFAULT NULL,
        last_publication_year int(4) DEFAULT NULL,
        updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY author_id (author_id),
        KEY h_index (h_index),
        KEY total_citations (total_citations)
    ) $charset_collate;";

    // Execute all table creations
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

    dbDelta($sql_citations);
    dbDelta($sql_citation_index);
    dbDelta($sql_metrics);
    dbDelta($sql_tracking);
    dbDelta($sql_search_index);
    dbDelta($sql_saved_searches);
    dbDelta($sql_author_metrics);

    // Update database version
    update_option('wjm_phase1_db_version', '2.0.0');
    update_option('wjm_phase1_installed_date', current_time('mysql'));

    return true;
}

/**
 * Check if Phase 1 tables need updating
 */
function wjm_phase1_check_tables() {
    $current_version = get_option('wjm_phase1_db_version', '0');

    if (version_compare($current_version, '2.0.0', '<')) {
        wjm_phase1_create_tables();
    }
}
add_action('admin_init', 'wjm_phase1_check_tables');

/**
 * Drop Phase 1 tables (for development/testing)
 */
function wjm_phase1_drop_tables() {
    global $wpdb;

    $tables = array(
        $wpdb->prefix . 'wjm_citations',
        $wpdb->prefix . 'wjm_citation_index',
        $wpdb->prefix . 'wjm_paper_metrics',
        $wpdb->prefix . 'wjm_tracking',
        $wpdb->prefix . 'wjm_search_index',
        $wpdb->prefix . 'wjm_saved_searches',
        $wpdb->prefix . 'wjm_author_metrics'
    );

    foreach ($tables as $table) {
        $wpdb->query("DROP TABLE IF EXISTS `$table`");
    }

    delete_option('wjm_phase1_db_version');
    delete_option('wjm_phase1_installed_date');
}

/**
 * Get table statistics
 */
function wjm_phase1_get_table_stats() {
    global $wpdb;

    $stats = array();

    // Citations
    $citations_table = $wpdb->prefix . 'wjm_citations';
    $stats['citations'] = array(
        'total' => $wpdb->get_var("SELECT COUNT(*) FROM `$citations_table`"),
        'verified' => $wpdb->get_var("SELECT COUNT(*) FROM `$citations_table` WHERE verified = 1"),
        'unverified' => $wpdb->get_var("SELECT COUNT(*) FROM `$citations_table` WHERE verified = 0")
    );

    // Metrics
    $metrics_table = $wpdb->prefix . 'wjm_paper_metrics';
    $stats['metrics'] = array(
        'total_views' => $wpdb->get_var("SELECT SUM(metric_value) FROM `$metrics_table` WHERE metric_type = 'views'"),
        'total_downloads' => $wpdb->get_var("SELECT SUM(metric_value) FROM `$metrics_table` WHERE metric_type = 'downloads'"),
        'tracked_papers' => $wpdb->get_var("SELECT COUNT(DISTINCT paper_id) FROM `$metrics_table`")
    );

    // Search Index
    $search_table = $wpdb->prefix . 'wjm_search_index';
    $stats['search'] = array(
        'indexed_papers' => $wpdb->get_var("SELECT COUNT(DISTINCT paper_id) FROM `$search_table`"),
        'total_entries' => $wpdb->get_var("SELECT COUNT(*) FROM `$search_table`")
    );

    // Author Metrics
    $author_metrics_table = $wpdb->prefix . 'wjm_author_metrics';
    $stats['authors'] = array(
        'total' => $wpdb->get_var("SELECT COUNT(*) FROM `$author_metrics_table`"),
        'with_h_index' => $wpdb->get_var("SELECT COUNT(*) FROM `$author_metrics_table` WHERE h_index > 0")
    );

    return $stats;
}
