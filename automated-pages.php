<?php
/**
 * Automated Page Creation System for Wisdom Journal Manager
 * 
 * This system automatically creates 6 separate pages with proper titles,
 * content, and distinct grid/list layouts for the academic publishing platform.
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Automated Page Creation System
function sjm_create_automated_pages() {
    // Check if pages already exist to avoid duplicates
    $existing_pages = get_option('sjm_automated_pages_created', false);
    if ($existing_pages) {
        return;
    }
    
    $pages_to_create = array(
        // Journals Grid Page
        array(
            'title' => 'Academic Journals - Visual Grid',
            'slug' => 'journals-grid',
            'content' => '[journals layout="grid" per_page="12"]',
            'template' => 'page-journals-grid.php'
        ),
        
        // Journals List Page
        array(
            'title' => 'Academic Journals - Detailed List',
            'slug' => 'journals-list',
            'content' => '[journals layout="list" per_page="20"]',
            'template' => 'page-journals-list.php'
        ),
        
        // Papers Grid Page
        array(
            'title' => 'Research Papers - Comprehensive Database',
            'slug' => 'research-papers-grid',
            'content' => '[papers layout="grid" per_page="12"]',
            'template' => 'page-papers-grid.php'
        ),
        
        // Papers List Page
        array(
            'title' => 'Research Papers - Visual Discovery',
            'slug' => 'research-papers-list',
            'content' => '[papers layout="list" per_page="20"]',
            'template' => 'page-papers-list.php'
        ),
        
        // Issues Grid Page
        array(
            'title' => 'Journal Issues - Complete Catalog',
            'slug' => 'journal-issues-grid',
            'content' => '[issues layout="grid" per_page="12"]',
            'template' => 'page-issues-grid.php'
        ),
        
        // Issues List Page
        array(
            'title' => 'Journal Issues - Visual Archive',
            'slug' => 'journal-issues-list',
            'content' => '[issues layout="list" per_page="20"]',
            'template' => 'page-issues-list.php'
        )
    );
    
    $created_pages = array();
    
    foreach ($pages_to_create as $page_data) {
        // Check if page already exists
        $existing_page = get_page_by_path($page_data['slug']);
        if ($existing_page) {
            continue;
        }
        
        // Create the page
        $page_args = array(
            'post_title' => $page_data['title'],
            'post_content' => $page_data['content'],
            'post_status' => 'publish',
            'post_type' => 'page',
            'post_name' => $page_data['slug'],
            'page_template' => $page_data['template']
        );
        
        $page_id = wp_insert_post($page_args);
        
        if ($page_id && !is_wp_error($page_id)) {
            $created_pages[] = array(
                'id' => $page_id,
                'title' => $page_data['title'],
                'slug' => $page_data['slug'],
                'url' => get_permalink($page_id)
            );
        }
    }
    
    // Create navigation menu
    sjm_create_automated_menu($created_pages);
    
    // Mark as completed
    update_option('sjm_automated_pages_created', true);
    update_option('sjm_created_pages_list', $created_pages);
    
    return $created_pages;
}

// Create automated navigation menu
function sjm_create_automated_menu($pages) {
    $menu_name = 'Academic Publications Menu';
    $menu_exists = wp_get_nav_menu_object($menu_name);
    
    if (!$menu_exists) {
        $menu_id = wp_create_nav_menu($menu_name);
        
        if ($menu_id && !is_wp_error($menu_id)) {
            // Add menu items for all 6 pages, organized by type
            foreach ($pages as $page) {
                $menu_item = array(
                    'menu-item-title' => $page['title'],
                    'menu-item-url' => $page['url'],
                    'menu-item-status' => 'publish',
                    'menu-item-type' => 'post_type',
                    'menu-item-object' => 'page',
                    'menu-item-object-id' => $page['id']
                );
                
                wp_update_nav_menu_item($menu_id, 0, $menu_item);
            }
            
            // Assign menu to primary location if available
            $locations = get_nav_menu_locations();
            if (!isset($locations['primary'])) {
                $locations['primary'] = $menu_id;
                set_theme_mod('nav_menu_locations', $locations);
            }
        }
    }
}

// Add admin page for managing automated pages
function sjm_add_automated_pages_page() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Automated Pages',
        'Automated Pages',
        'manage_options',
        'sjm-automated-pages',
        'sjm_automated_pages_page'
    );
}
add_action('admin_menu', 'sjm_add_automated_pages_page');

// Automated pages management page
function sjm_automated_pages_page() {
    // Enhanced CSRF protection with capability check
    if (isset($_POST['sjm_create_pages'])) {
        if (!wp_verify_nonce($_POST['sjm_nonce'], 'sjm_create_pages')) {
            wp_die('Security check failed. Please try again.');
        }
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions to create pages.');
        }
        $created_pages = sjm_create_automated_pages();
        echo '<div class="notice notice-success"><p>Successfully created ' . count($created_pages) . ' pages!</p></div>';
    }

    if (isset($_POST['sjm_reset_pages'])) {
        if (!wp_verify_nonce($_POST['sjm_nonce'], 'sjm_reset_pages')) {
            wp_die('Security check failed. Please try again.');
        }
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions to reset pages.');
        }
        delete_option('sjm_automated_pages_created');
        delete_option('sjm_created_pages_list');
        echo '<div class="notice notice-success"><p>Automated pages reset successfully!</p></div>';
    }
    
    $pages_created = get_option('sjm_automated_pages_created', false);
    $created_pages_list = get_option('sjm_created_pages_list', array());
    
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div>
                <h1 class="wjm-page-title">Automated Pages</h1>
                <p class="wjm-page-description">Create and manage front-end pages for journals, papers, and issues</p>
            </div>
            <?php if (!$pages_created): ?>
                <form method="post" style="margin:0;">
                    <?php wp_nonce_field('sjm_create_pages', 'sjm_nonce'); ?>
                    <button type="submit" name="sjm_create_pages" class="wjm-btn wjm-btn-primary">Create Automated Pages</button>
                </form>
            <?php else: ?>
                <form method="post" style="margin:0;" onsubmit="return confirm('Reset the automated pages? This allows recreation.');">
                    <?php wp_nonce_field('sjm_reset_pages', 'sjm_nonce'); ?>
                    <button type="submit" name="sjm_reset_pages" class="wjm-btn wjm-btn-secondary">Reset Automated Pages</button>
                </form>
            <?php endif; ?>
        </div>

        <!-- Status card -->
        <div class="wjm-card" style="margin-bottom:1.25rem;">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons <?php echo $pages_created ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
                    Status
                </h2>
            </div>
            <div class="wjm-card-body">
                <?php if ($pages_created): ?>
                    <p style="color:var(--wjm-mint-ink);font-weight:600;margin:0;">
                        Automated pages have been created successfully.
                    </p>
                <?php else: ?>
                    <p style="color:var(--wjm-peach-ink);font-weight:600;margin:0;">
                        Automated pages have not been created yet. Click "Create Automated Pages" above to get started.
                    </p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Created pages table -->
        <?php if ($pages_created && !empty($created_pages_list)): ?>
            <div class="wjm-card" style="margin-bottom:1.25rem;">
                <div class="wjm-card-header">
                    <h2 class="wjm-card-title">
                        <span class="dashicons dashicons-admin-page"></span>
                        Created Pages
                    </h2>
                </div>
                <div class="wjm-card-body" style="padding:0;">
                    <table class="wjm-table">
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>Slug</th>
                                <th>URL</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($created_pages_list as $page): ?>
                                <tr>
                                    <td><?php echo esc_html($page['title']); ?></td>
                                    <td><code class="wjm-code-block"><?php echo esc_html($page['slug']); ?></code></td>
                                    <td>
                                        <a href="<?php echo esc_url($page['url']); ?>" target="_blank" style="color:var(--wjm-primary);">View Page</a>
                                    </td>
                                    <td>
                                        <a href="<?php echo esc_url(admin_url('post.php?post=' . $page['id'] . '&action=edit')); ?>" class="wjm-btn wjm-btn-secondary wjm-btn-sm">Edit</a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <!-- What will be created -->
        <div class="wjm-card">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">
                    <span class="dashicons dashicons-info-outline"></span>
                    What Will Be Created (6 Separate Pages)
                </h2>
            </div>
            <div class="wjm-card-body">
                <div class="wjm-tip-grid">
                    <div>
                        <p class="wjm-tip-title">Academic Journals</p>
                        <ul class="wjm-tip-list">
                            <li><strong>Grid View</strong> — Visual card-based display</li>
                            <li><strong>List View</strong> — Detailed list format</li>
                        </ul>
                    </div>
                    <div>
                        <p class="wjm-tip-title">Research Papers</p>
                        <ul class="wjm-tip-list">
                            <li><strong>Grid View</strong> — Visual paper cards</li>
                            <li><strong>List View</strong> — Detailed paper list</li>
                        </ul>
                    </div>
                    <div>
                        <p class="wjm-tip-title">Journal Issues</p>
                        <ul class="wjm-tip-list">
                            <li><strong>Grid View</strong> — Visual issue covers</li>
                            <li><strong>List View</strong> — Detailed issue list</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

    </div>
    <?php
}

// Hook to create pages on plugin activation
register_activation_hook(WJM_PLUGIN_FILE, 'sjm_create_automated_pages');

// Add activation notice
function sjm_activation_notice() {
    if (get_option('sjm_show_activation_notice', false)) {
        ?>
        <div class="notice notice-success is-dismissible">
            <p><strong>Wisdom Journal Manager</strong> has been activated successfully! 
            <a href="<?php echo esc_url(admin_url('edit.php?post_type=journal&page=sjm-automated-pages')); ?>">Click here to create automated pages</a> or 
            <a href="<?php echo esc_url(admin_url('edit.php?post_type=journal')); ?>">start creating journals</a>.</p>
        </div>
        <?php
        delete_option('sjm_show_activation_notice');
    }
}
add_action('admin_notices', 'sjm_activation_notice');

// Set activation notice flag
function sjm_set_activation_notice() {
    update_option('sjm_show_activation_notice', true);
}
register_activation_hook(WJM_PLUGIN_FILE, 'sjm_set_activation_notice'); 