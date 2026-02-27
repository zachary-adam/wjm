<?php
/**
 * Author System Unification
 * Migrates old sjm_authors table to new wjm_author custom post type
 *
 * @package Wisdom Journal Manager
 * @version 2.5.2
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// DISABLE OLD AUTHOR MANAGEMENT PAGE
// ========================================

/**
 * Remove old Author Management menu
 */
function wjm_remove_old_author_menu() {
    remove_submenu_page('edit.php?post_type=journal', 'sjm-authors');
}
add_action('admin_menu', 'wjm_remove_old_author_menu', 999);

// ========================================
// MIGRATION FUNCTIONS
// ========================================

/**
 * Migrate authors from old table to new custom post type
 */
function wjm_migrate_old_authors_to_new() {
    global $wpdb;
    $old_table = $wpdb->prefix . 'sjm_authors';

    // Check if old table exists
    if ($wpdb->get_var("SHOW TABLES LIKE '$old_table'") !== $old_table) {
        return array('status' => 'no_table', 'message' => 'Old authors table does not exist. Nothing to migrate.');
    }

    // Get all authors from old table
    $old_authors = $wpdb->get_results("SELECT * FROM `$old_table`", ARRAY_A);

    if (empty($old_authors)) {
        return array('status' => 'no_data', 'message' => 'No authors found in old table. Nothing to migrate.');
    }

    $migrated = 0;
    $skipped = 0;
    $errors = array();

    foreach ($old_authors as $old_author) {
        // Check if already migrated (by email or ORCID)
        $exists = false;

        // Check by ORCID if exists
        if (!empty($old_author['orcid'])) {
            $existing = get_posts(array(
                'post_type' => 'wjm_author',
                'meta_key' => 'orcid_id',
                'meta_value' => $old_author['orcid'],
                'posts_per_page' => 1,
                'fields' => 'ids'
            ));
            if (!empty($existing)) {
                $exists = true;
            }
        }

        // Check by email if ORCID check didn't find it
        if (!$exists && !empty($old_author['email'])) {
            $existing = get_posts(array(
                'post_type' => 'wjm_author',
                'meta_key' => 'email',
                'meta_value' => $old_author['email'],
                'posts_per_page' => 1,
                'fields' => 'ids'
            ));
            if (!empty($existing)) {
                $exists = true;
            }
        }

        if ($exists) {
            $skipped++;
            continue;
        }

        // Create new author post
        $full_name = trim($old_author['first_name'] . ' ' . $old_author['last_name']);
        $bio = !empty($old_author['bio']) ? $old_author['bio'] : '';

        $post_data = array(
            'post_type' => 'wjm_author',
            'post_title' => $full_name,
            'post_content' => $bio,
            'post_status' => 'publish'
        );

        $author_id = wp_insert_post($post_data);

        if (is_wp_error($author_id)) {
            $errors[] = 'Failed to create author: ' . $full_name;
            continue;
        }

        // Save metadata
        update_post_meta($author_id, 'given_names', $old_author['first_name']);
        update_post_meta($author_id, 'family_name', $old_author['last_name']);
        update_post_meta($author_id, 'email', $old_author['email']);
        update_post_meta($author_id, 'affiliation', $old_author['affiliation']);
        update_post_meta($author_id, 'website', $old_author['website']);

        if (!empty($old_author['orcid'])) {
            update_post_meta($author_id, 'orcid_id', $old_author['orcid']);
            update_post_meta($author_id, 'orcid_verified', 0); // Not verified yet
            update_post_meta($author_id, 'orcid_url', 'https://orcid.org/' . $old_author['orcid']);
        }

        // Mark as migrated
        update_post_meta($author_id, '_migrated_from_old_table', current_time('mysql'));
        update_post_meta($author_id, '_old_author_id', $old_author['id']);

        $migrated++;
    }

    return array(
        'status' => 'success',
        'migrated' => $migrated,
        'skipped' => $skipped,
        'errors' => $errors,
        'message' => sprintf('Migration complete! Migrated: %d, Skipped (already exists): %d', $migrated, $skipped)
    );
}

/**
 * Admin page for migration
 */
function wjm_author_migration_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Insufficient permissions');
    }

    global $wpdb;
    $old_table     = $wpdb->prefix . 'sjm_authors';
    $has_old_table = $wpdb->get_var("SHOW TABLES LIKE '$old_table'") === $old_table;
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Author System Migration</h1>
                <p class="wjm-page-description">Unify legacy and new author systems</p>
            </div>
            <?php if ($has_old_table): ?>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wjm-author-migration&run_migration=1')); ?>"
                   class="wjm-btn wjm-btn-primary">Migrate Authors Now</a>
            <?php endif; ?>
        </div>

        <?php if (!$has_old_table): ?>

            <div class="wjm-card">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-yes-alt" style="color:var(--wjm-mint-ink);"></span>
                        System Unified
                    </h2>
                </div>
                <div class="wjm-card-body">
                    <p style="color:var(--wjm-mint-ink);font-weight:600;margin-bottom:1rem;">
                        The old author table does not exist. You are using the new Authors system.
                    </p>
                    <p style="font-size:0.875rem;color:var(--wjm-text-secondary);margin-bottom:1rem;">
                        All authors are managed through the Authors menu.
                    </p>
                    <a href="<?php echo esc_url(admin_url('edit.php?post_type=wjm_author')); ?>" class="wjm-btn wjm-btn-primary">Go to Authors</a>
                </div>
            </div>

        <?php else:
            $old_count = $wpdb->get_var("SELECT COUNT(*) FROM `$old_table`");
            $new_count = wp_count_posts('wjm_author')->publish;
        ?>

            <!-- Status -->
            <div class="wjm-stats-grid" style="margin-bottom:1.25rem;">
                <div class="wjm-stat-card wjm-stat-card--peach">
                    <div class="wjm-stat-content">
                        <div class="wjm-stat-label">Old System</div>
                        <div class="wjm-stat-value"><?php echo esc_html($old_count); ?></div>
                    </div>
                    <div class="wjm-stat-bar"></div>
                </div>
                <div class="wjm-stat-card wjm-stat-card--mint">
                    <div class="wjm-stat-content">
                        <div class="wjm-stat-label">New System</div>
                        <div class="wjm-stat-value"><?php echo esc_html($new_count); ?></div>
                    </div>
                    <div class="wjm-stat-bar"></div>
                </div>
            </div>

            <?php if (isset($_GET['run_migration'])): ?>

                <?php $result = wjm_migrate_old_authors_to_new(); ?>

                <div class="wjm-card" style="margin-bottom:1.25rem;">
                    <div class="wjm-card-header">
                        <h2 class="wjm-card-title">Migration Results</h2>
                    </div>
                    <div class="wjm-card-body">
                        <?php if ($result['status'] === 'success'): ?>
                            <p style="color:var(--wjm-mint-ink);font-weight:600;margin-bottom:1rem;"><?php echo esc_html($result['message']); ?></p>
                            <?php if ($result['migrated'] > 0): ?>
                                <p style="font-size:0.875rem;font-weight:600;color:var(--wjm-text-primary);margin-bottom:0.5rem;">What was migrated:</p>
                                <ul class="wjm-guide-ul">
                                    <li>Name (first + last)</li>
                                    <li>Email, Affiliation, Bio, Website</li>
                                    <li>ORCID (if provided)</li>
                                </ul>
                            <?php endif; ?>
                            <?php if (!empty($result['errors'])): ?>
                                <div style="margin-top:1rem;padding:0.875rem;background:var(--wjm-peach-bg);border-radius:6px;">
                                    <p style="font-weight:600;color:var(--wjm-peach-ink);margin-bottom:0.5rem;">Errors encountered:</p>
                                    <ul class="wjm-guide-ul">
                                        <?php foreach ($result['errors'] as $error): ?>
                                            <li><?php echo esc_html($error); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                            <div style="margin-top:1rem;">
                                <a href="<?php echo esc_url(admin_url('edit.php?post_type=wjm_author')); ?>" class="wjm-btn wjm-btn-primary">View Migrated Authors</a>
                            </div>
                        <?php else: ?>
                            <p style="color:var(--wjm-text-secondary);"><?php echo esc_html($result['message']); ?></p>
                        <?php endif; ?>
                    </div>
                </div>

            <?php else: ?>

                <!-- Migration options -->
                <div class="wjm-grid-2" style="align-items:start;">

                    <div class="wjm-card">
                        <div class="wjm-card-header">
                            <h2 class="wjm-card-title">Migrate to New System</h2>
                        </div>
                        <div class="wjm-card-body">
                            <p style="font-size:0.875rem;color:var(--wjm-text-secondary);margin-bottom:1rem;">
                                Safe to run — only creates new records, nothing is deleted.
                            </p>
                            <ul class="wjm-guide-ul" style="margin-bottom:1.25rem;">
                                <li>Copies all authors from old table to new system</li>
                                <li>Preserves name, email, affiliation, bio, ORCID</li>
                                <li>Skips duplicates (checks by ORCID and email)</li>
                                <li>Keeps old table intact</li>
                                <li>Enables ORCID API integration</li>
                            </ul>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=wjm-author-migration&run_migration=1')); ?>"
                               class="wjm-btn wjm-btn-primary">Migrate Authors Now</a>
                        </div>
                    </div>

                    <div class="wjm-card">
                        <div class="wjm-card-header">
                            <h2 class="wjm-card-title">Clean Up Old Table</h2>
                        </div>
                        <div class="wjm-card-body">
                            <p style="font-size:0.875rem;color:var(--wjm-text-secondary);margin-bottom:1rem;">
                                Optional — only do this after confirming migration was successful. This action is permanent.
                            </p>
                            <?php if (isset($_GET['delete_old_table'])): ?>
                                <?php if (wp_verify_nonce($_GET['_wpnonce'], 'delete_old_table')): ?>
                                    <?php $wpdb->query("DROP TABLE IF EXISTS `$old_table`"); ?>
                                    <div class="notice notice-success"><p>Old table deleted. You are now using only the new Authors system.</p></div>
                                    <script>setTimeout(function(){ window.location.href = "<?php echo esc_url(admin_url('admin.php?page=wjm-author-migration')); ?>"; }, 2000);</script>
                                <?php endif; ?>
                            <?php else: ?>
                                <?php $delete_url = wp_nonce_url(admin_url('admin.php?page=wjm-author-migration&delete_old_table=1'), 'delete_old_table'); ?>
                                <button type="button" class="wjm-btn wjm-btn-secondary"
                                        onclick="if(confirm('Permanently delete the old authors table? Only do this after a successful migration.')) { window.location.href = '<?php echo esc_js($delete_url); ?>'; }">
                                    Delete Old Table
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>

                </div>

            <?php endif; ?>

        <?php endif; ?>

    </div><?php
}

/**
 * Add migration page to admin menu
 */
function wjm_add_author_migration_menu() {
    add_submenu_page(
        'tools.php',
        'Author Migration',
        'Author Migration',
        'manage_options',
        'wjm-author-migration',
        'wjm_author_migration_page'
    );
}
add_action('admin_menu', 'wjm_add_author_migration_menu');

// ========================================
// ADMIN NOTICE
// ========================================

/**
 * Show admin notice about dual author systems
 */
function wjm_dual_author_system_notice() {
    global $wpdb;
    $old_table = $wpdb->prefix . 'sjm_authors';

    // Check if old table exists and has data
    $has_old_table = $wpdb->get_var("SHOW TABLES LIKE '$old_table'") === $old_table;

    if (!$has_old_table) {
        return; // No old table, no problem
    }

    $old_count = $wpdb->get_var("SELECT COUNT(*) FROM `$old_table`");

    if ($old_count == 0) {
        return; // Old table empty, no need to show notice
    }

    // Check if user dismissed notice
    if (get_option('wjm_author_migration_notice_dismissed')) {
        return;
    }

    $screen = get_current_screen();

    // Only show on relevant pages
    if (!in_array($screen->base, array('dashboard', 'edit-wjm_author', 'wjm_author', 'edit-paper'))) {
        return;
    }

    ?>
    <div class="notice notice-warning is-dismissible" data-notice="wjm-author-migration">
        <h3>🔄 Author System Upgrade Available</h3>
        <p><strong>You have authors in the old system that need to be migrated!</strong></p>
        <p>Found <strong><?php echo $old_count; ?> authors</strong> in the old system. Migrate them to the new Authors system to get:</p>
        <ul style="list-style: disc; margin-left: 20px;">
            <li>✅ ORCID API integration (auto-import author data)</li>
            <li>✅ Automatic metrics calculation (H-Index, i10-Index)</li>
            <li>✅ Author profile pages</li>
            <li>✅ Better WordPress integration</li>
        </ul>
        <p>
            <a href="<?php echo admin_url('tools.php?page=wjm-author-migration'); ?>" class="button button-primary">Migrate Authors Now</a>
            <button type="button" class="button" onclick="wjmDismissAuthorNotice()">Dismiss</button>
        </p>
    </div>

    <script>
    function wjmDismissAuthorNotice() {
        jQuery.post(ajaxurl, {
            action: 'wjm_dismiss_author_notice'
        }, function() {
            jQuery('[data-notice="wjm-author-migration"]').fadeOut();
        });
    }
    </script>
    <?php
}
add_action('admin_notices', 'wjm_dual_author_system_notice');

/**
 * AJAX handler to dismiss notice
 */
function wjm_ajax_dismiss_author_notice() {
    update_option('wjm_author_migration_notice_dismissed', true);
    wp_send_json_success();
}
add_action('wp_ajax_wjm_dismiss_author_notice', 'wjm_ajax_dismiss_author_notice');
