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
    if (isset($_POST['sjm_create_pages']) && wp_verify_nonce($_POST['sjm_nonce'], 'sjm_create_pages')) {
        $created_pages = sjm_create_automated_pages();
        echo '<div class="notice notice-success"><p>Successfully created ' . count($created_pages) . ' pages!</p></div>';
    }
    
    if (isset($_POST['sjm_reset_pages']) && wp_verify_nonce($_POST['sjm_nonce'], 'sjm_reset_pages')) {
        delete_option('sjm_automated_pages_created');
        delete_option('sjm_created_pages_list');
        echo '<div class="notice notice-success"><p>Automated pages reset successfully!</p></div>';
    }
    
    $pages_created = get_option('sjm_automated_pages_created', false);
    $created_pages_list = get_option('sjm_created_pages_list', array());
    
    ?>
    <div class="wrap">
        <h1>Automated Pages Management</h1>
        
        <div class="sjm-automated-pages-container">
            <div class="sjm-pages-status">
                <h2>Status</h2>
                <?php if ($pages_created): ?>
                    <div class="sjm-status-success">
                        <span class="dashicons dashicons-yes"></span>
                        <strong>Automated pages have been created</strong>
                    </div>
                <?php else: ?>
                    <div class="sjm-status-pending">
                        <span class="dashicons dashicons-warning"></span>
                        <strong>Automated pages not yet created</strong>
                    </div>
                <?php endif; ?>
            </div>
            
            <?php if ($pages_created && !empty($created_pages_list)): ?>
                <div class="sjm-created-pages">
                    <h2>Created Pages</h2>
                    <table class="wp-list-table widefat fixed striped">
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
                                    <td><code><?php echo esc_html($page['slug']); ?></code></td>
                                    <td><a href="<?php echo esc_url($page['url']); ?>" target="_blank">View Page</a></td>
                                    <td>
                                        <a href="<?php echo esc_url(admin_url('post.php?post=' . $page['id'] . '&action=edit')); ?>" class="button button-small">Edit</a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
            
            <div class="sjm-page-actions">
                <h2>Actions</h2>
                
                <?php if (!$pages_created): ?>
                    <form method="post" style="margin-bottom: 20px;">
                        <?php wp_nonce_field('sjm_create_pages', 'sjm_nonce'); ?>
                        <p>Click the button below to automatically create 6 separate pages - grid and list versions for each content type.</p>
                        <input type="submit" name="sjm_create_pages" class="button button-primary" value="Create Automated Pages">
                    </form>
                <?php else: ?>
                    <form method="post" style="margin-bottom: 20px;">
                        <?php wp_nonce_field('sjm_reset_pages', 'sjm_nonce'); ?>
                        <p>Reset the automated pages system to allow recreation of pages.</p>
                        <input type="submit" name="sjm_reset_pages" class="button button-secondary" value="Reset Automated Pages" onclick="return confirm('Are you sure you want to reset the automated pages? This will allow you to recreate them.')">
                    </form>
                <?php endif; ?>
            </div>
            
            <div class="sjm-pages-info">
                <h2>What Will Be Created (6 Separate Pages)</h2>
                <div class="sjm-pages-grid">
                    <div class="sjm-page-category">
                        <h3>📚 Academic Journals</h3>
                        <ul>
                            <li><strong>Grid View Page</strong> - Visual card-based display</li>
                            <li><strong>List View Page</strong> - Detailed list format</li>
                        </ul>
                    </div>
                    
                    <div class="sjm-page-category">
                        <h3>📄 Research Papers</h3>
                        <ul>
                            <li><strong>Grid View Page</strong> - Visual paper cards</li>
                            <li><strong>List View Page</strong> - Detailed paper list</li>
                        </ul>
                    </div>
                    
                    <div class="sjm-page-category">
                        <h3>📖 Journal Issues</h3>
                        <ul>
                            <li><strong>Grid View Page</strong> - Visual issue covers</li>
                            <li><strong>List View Page</strong> - Detailed issue list</li>
                        </ul>
                    </div>
                </div>
                
                <div class="sjm-pages-summary">
                    <h4>Summary:</h4>
                    <p>This will create <strong>6 separate pages</strong> total:</p>
                    <ul>
                        <li>Academic Journals - Grid View</li>
                        <li>Academic Journals - List View</li>
                        <li>Research Papers - Grid View</li>
                        <li>Research Papers - List View</li>
                        <li>Journal Issues - Grid View</li>
                        <li>Journal Issues - List View</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <style>
    .sjm-automated-pages-container {
        max-width: 1200px;
    }
    
    .sjm-pages-status {
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
        margin-bottom: 20px;
    }
    
    .sjm-status-success {
        color: #46b450;
        font-size: 16px;
    }
    
    .sjm-status-pending {
        color: #ffb900;
        font-size: 16px;
    }
    
    .sjm-created-pages {
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
        margin-bottom: 20px;
    }
    
    .sjm-page-actions {
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
        margin-bottom: 20px;
    }
    
    .sjm-pages-info {
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
    }
    
    .sjm-pages-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin-top: 15px;
    }
    
    .sjm-page-category {
        background: #f9f9f9;
        border: 1px solid #e5e5e5;
        border-radius: 4px;
        padding: 15px;
    }
    
    .sjm-page-category h3 {
        margin-top: 0;
        color: #23282d;
    }
    
    .sjm-page-category ul {
        margin: 0;
        padding-left: 20px;
    }
    
    .sjm-page-category li {
        margin-bottom: 5px;
        color: #666;
    }
    
    .sjm-pages-summary {
        background: #e7f3ff;
        border: 1px solid #b3d9ff;
        border-radius: 4px;
        padding: 15px;
        margin-top: 20px;
    }
    
    .sjm-pages-summary h4 {
        margin-top: 0;
        color: #0073aa;
    }
    
    .sjm-pages-summary ul {
        margin: 10px 0 0 20px;
        color: #666;
    }
    
    .sjm-pages-summary li {
        margin-bottom: 3px;
    }
    </style>
    <?php
}

// Hook to create pages on plugin activation
register_activation_hook(__FILE__, 'sjm_create_automated_pages');

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
register_activation_hook(__FILE__, 'sjm_set_activation_notice'); 