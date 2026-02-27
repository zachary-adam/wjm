<?php
/**
 * Collaboration Tools System
 * Co-author management, invitations, and collaborative workflows
 *
 * @package Wisdom Journal Manager
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// ========================================
// CO-AUTHOR MANAGEMENT
// ========================================

/**
 * Add co-author to a paper
 */
function wjm_add_coauthor($paper_id, $author_data) {
    // author_data can be: user_id, email, or author_post_id
    $coauthors = wjm_get_coauthors($paper_id);

    // Determine author identifier
    $author_entry = array();

    if (isset($author_data['user_id'])) {
        $author_entry['type'] = 'user';
        $author_entry['id'] = absint($author_data['user_id']);
        $user = get_user_by('id', $author_entry['id']);
        $author_entry['name'] = $user->display_name;
        $author_entry['email'] = $user->user_email;
    } elseif (isset($author_data['author_id'])) {
        $author_entry['type'] = 'author_profile';
        $author_entry['id'] = absint($author_data['author_id']);
        $author_post = get_post($author_entry['id']);
        $author_entry['name'] = $author_post->post_title;
        $author_entry['email'] = get_post_meta($author_entry['id'], 'email', true);
    } elseif (isset($author_data['email'])) {
        $author_entry['type'] = 'external';
        $author_entry['email'] = sanitize_email($author_data['email']);
        $author_entry['name'] = sanitize_text_field($author_data['name'] ?? $author_data['email']);
    }

    // Add additional data
    $author_entry['role'] = sanitize_text_field($author_data['role'] ?? 'Co-Author');
    $author_entry['order'] = isset($author_data['order']) ? absint($author_data['order']) : (count($coauthors) + 1);
    $author_entry['affiliation'] = sanitize_text_field($author_data['affiliation'] ?? '');
    $author_entry['added_date'] = current_time('mysql');
    $author_entry['status'] = $author_data['status'] ?? 'confirmed';
    $author_entry['contribution'] = sanitize_textarea_field($author_data['contribution'] ?? '');

    // Add to coauthors array
    $coauthors[] = $author_entry;

    // Sort by order
    usort($coauthors, function($a, $b) {
        return $a['order'] - $b['order'];
    });

    // Save
    update_post_meta($paper_id, '_coauthors', $coauthors);

    // Log audit event
    if (function_exists('wjm_log_audit_event')) {
        wjm_log_audit_event('coauthor_added', array(
            'paper_id' => $paper_id,
            'author_name' => $author_entry['name'],
            'author_email' => $author_entry['email']
        ));
    }

    return $author_entry;
}

/**
 * Get co-authors for a paper
 */
function wjm_get_coauthors($paper_id) {
    $coauthors = get_post_meta($paper_id, '_coauthors', true);

    if (!is_array($coauthors)) {
        return array();
    }

    return $coauthors;
}

/**
 * Remove co-author from a paper
 */
function wjm_remove_coauthor($paper_id, $author_index) {
    $coauthors = wjm_get_coauthors($paper_id);

    if (isset($coauthors[$author_index])) {
        $removed = $coauthors[$author_index];
        unset($coauthors[$author_index]);

        // Re-index array
        $coauthors = array_values($coauthors);

        // Save
        update_post_meta($paper_id, '_coauthors', $coauthors);

        // Log audit event
        if (function_exists('wjm_log_audit_event')) {
            wjm_log_audit_event('coauthor_removed', array(
                'paper_id' => $paper_id,
                'author_name' => $removed['name'] ?? 'Unknown'
            ));
        }

        return true;
    }

    return false;
}

/**
 * Update co-author order
 */
function wjm_update_coauthor_order($paper_id, $new_order) {
    // new_order is an array of author indices in desired order
    $coauthors = wjm_get_coauthors($paper_id);
    $reordered = array();

    foreach ($new_order as $order => $index) {
        if (isset($coauthors[$index])) {
            $coauthors[$index]['order'] = $order + 1;
            $reordered[] = $coauthors[$index];
        }
    }

    update_post_meta($paper_id, '_coauthors', $reordered);

    return true;
}

// ========================================
// COLLABORATION INVITATIONS
// ========================================

/**
 * Send collaboration invitation
 */
function wjm_send_collaboration_invite($paper_id, $email, $role = 'Co-Author') {
    $paper = get_post($paper_id);

    if (!$paper) {
        return new WP_Error('invalid_paper', 'Paper not found');
    }

    // Generate unique invite token
    $token = wp_generate_password(32, false);

    // Save invitation
    global $wpdb;
    $invites_table = $wpdb->prefix . 'wjm_collaboration_invites';

    // Create table if doesn't exist
    wjm_create_invites_table();

    $wpdb->insert($invites_table, array(
        'paper_id' => absint($paper_id),
        'email' => sanitize_email($email),
        'role' => sanitize_text_field($role),
        'token' => $token,
        'status' => 'pending',
        'invited_by' => get_current_user_id(),
        'created_at' => current_time('mysql'),
        'expires_at' => date('Y-m-d H:i:s', strtotime('+30 days'))
    ));

    $invite_id = $wpdb->insert_id;

    // Send email notification
    $subject = 'Invitation to Collaborate on: ' . $paper->post_title;
    $accept_url = add_query_arg(array(
        'wjm_action' => 'accept_invite',
        'token' => $token
    ), home_url('/'));

    $message = "You've been invited to collaborate on a research paper.\n\n";
    $message .= "Paper: " . $paper->post_title . "\n";
    $message .= "Role: " . $role . "\n\n";
    $message .= "Accept invitation: " . $accept_url . "\n\n";
    $message .= "This invitation expires in 30 days.\n";

    $sent = wp_mail($email, $subject, $message);

    if ($sent) {
        return array(
            'invite_id' => $invite_id,
            'token' => $token,
            'accept_url' => $accept_url
        );
    } else {
        return new WP_Error('email_failed', 'Failed to send invitation email');
    }
}

/**
 * Accept collaboration invitation
 */
function wjm_accept_collaboration_invite($token) {
    global $wpdb;
    $invites_table = $wpdb->prefix . 'wjm_collaboration_invites';

    // Get invitation
    $invite = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM `$invites_table` WHERE token = %s AND status = 'pending' AND expires_at > NOW()",
        $token
    ), ARRAY_A);

    if (!$invite) {
        return new WP_Error('invalid_token', 'Invalid or expired invitation');
    }

    // Add as co-author
    $result = wjm_add_coauthor($invite['paper_id'], array(
        'email' => $invite['email'],
        'role' => $invite['role'],
        'status' => 'confirmed'
    ));

    // Update invitation status
    $wpdb->update(
        $invites_table,
        array('status' => 'accepted', 'accepted_at' => current_time('mysql')),
        array('id' => absint($invite['id']))
    );

    // Check if user exists and grant paper edit permissions
    $user = get_user_by('email', $invite['email']);

    if ($user) {
        // Grant edit permissions to this paper
        wjm_grant_paper_access($invite['paper_id'], $user->ID, 'edit');
    }

    return array(
        'paper_id' => $invite['paper_id'],
        'email' => $invite['email'],
        'role' => $invite['role']
    );
}

/**
 * Create invitations table
 */
function wjm_create_invites_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wjm_collaboration_invites';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS `$table_name` (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        email varchar(255) NOT NULL,
        role varchar(100) DEFAULT 'Co-Author',
        token varchar(100) NOT NULL,
        status varchar(20) DEFAULT 'pending',
        invited_by bigint(20) UNSIGNED NOT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        accepted_at datetime DEFAULT NULL,
        expires_at datetime NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY token (token),
        KEY paper_id (paper_id),
        KEY email (email),
        KEY status (status)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

// Create table on plugin activation
register_activation_hook(WJM_PLUGIN_FILE, 'wjm_create_invites_table');

// ========================================
// PAPER ACCESS PERMISSIONS
// ========================================

/**
 * Grant user access to a paper
 */
function wjm_grant_paper_access($paper_id, $user_id, $permission = 'view') {
    // permission: view, edit, admin
    $access_list = get_post_meta($paper_id, '_collaborator_access', true);

    if (!is_array($access_list)) {
        $access_list = array();
    }

    $access_list[$user_id] = array(
        'permission' => $permission,
        'granted_at' => current_time('mysql'),
        'granted_by' => get_current_user_id()
    );

    update_post_meta($paper_id, '_collaborator_access', $access_list);

    return true;
}

/**
 * Revoke user access to a paper
 */
function wjm_revoke_paper_access($paper_id, $user_id) {
    $access_list = get_post_meta($paper_id, '_collaborator_access', true);

    if (is_array($access_list) && isset($access_list[$user_id])) {
        unset($access_list[$user_id]);
        update_post_meta($paper_id, '_collaborator_access', $access_list);
        return true;
    }

    return false;
}

/**
 * Check if user has access to a paper
 */
function wjm_user_can_access_paper($paper_id, $user_id, $required_permission = 'view') {
    // Author always has admin access
    $post = get_post($paper_id);

    if ($post && $post->post_author == $user_id) {
        return true;
    }

    // Check permission list
    $access_list = get_post_meta($paper_id, '_collaborator_access', true);

    if (!is_array($access_list) || !isset($access_list[$user_id])) {
        return false;
    }

    $user_permission = $access_list[$user_id]['permission'];

    // Permission hierarchy: admin > edit > view
    $permission_levels = array('view' => 1, 'edit' => 2, 'admin' => 3);

    return $permission_levels[$user_permission] >= $permission_levels[$required_permission];
}

// ========================================
// CONTRIBUTION TRACKING
// ========================================

/**
 * Record a contribution to a paper
 */
function wjm_record_contribution($paper_id, $user_id, $contribution_type, $description = '') {
    global $wpdb;
    $contributions_table = $wpdb->prefix . 'wjm_contributions';

    // Create table if doesn't exist
    wjm_create_contributions_table();

    $wpdb->insert($contributions_table, array(
        'paper_id' => absint($paper_id),
        'user_id' => absint($user_id),
        'contribution_type' => sanitize_text_field($contribution_type),
        'description' => sanitize_textarea_field($description),
        'created_at' => current_time('mysql')
    ));

    return $wpdb->insert_id;
}

/**
 * Get contributions for a paper
 */
function wjm_get_paper_contributions($paper_id, $limit = 50) {
    global $wpdb;
    $contributions_table = $wpdb->prefix . 'wjm_contributions';

    $results = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM `$contributions_table` WHERE paper_id = %d ORDER BY created_at DESC LIMIT %d",
        absint($paper_id),
        absint($limit)
    ), ARRAY_A);

    return $results;
}

/**
 * Get user contributions statistics
 */
function wjm_get_user_contribution_stats($user_id, $paper_id = null) {
    global $wpdb;
    $contributions_table = $wpdb->prefix . 'wjm_contributions';

    $where = $wpdb->prepare("WHERE user_id = %d", absint($user_id));

    if ($paper_id) {
        $where .= $wpdb->prepare(" AND paper_id = %d", absint($paper_id));
    }

    $results = $wpdb->get_results(
        "SELECT contribution_type, COUNT(*) as count FROM `$contributions_table` $where GROUP BY contribution_type",
        ARRAY_A
    );

    $stats = array();
    foreach ($results as $row) {
        $stats[$row['contribution_type']] = absint($row['count']);
    }

    return $stats;
}

/**
 * Create contributions table
 */
function wjm_create_contributions_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wjm_contributions';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS `$table_name` (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        paper_id bigint(20) UNSIGNED NOT NULL,
        user_id bigint(20) UNSIGNED NOT NULL,
        contribution_type varchar(50) NOT NULL,
        description text,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY paper_id (paper_id),
        KEY user_id (user_id),
        KEY contribution_type (contribution_type),
        KEY created_at (created_at)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

// Create table on plugin activation
register_activation_hook(WJM_PLUGIN_FILE, 'wjm_create_contributions_table');

/**
 * Check if collaboration tables exist on admin init
 */
function wjm_check_collaboration_tables() {
    global $wpdb;

    $invites_table = $wpdb->prefix . 'wjm_collaboration_invites';
    $contributions_table = $wpdb->prefix . 'wjm_contributions';

    // Check if tables exist
    $invites_exists = $wpdb->get_var("SHOW TABLES LIKE '$invites_table'") === $invites_table;
    $contributions_exists = $wpdb->get_var("SHOW TABLES LIKE '$contributions_table'") === $contributions_table;

    // Create if missing
    if (!$invites_exists) {
        wjm_create_invites_table();
    }

    if (!$contributions_exists) {
        wjm_create_contributions_table();
    }
}
add_action('admin_init', 'wjm_check_collaboration_tables');

// ========================================
// META BOXES
// ========================================

/**
 * Add Co-Authors meta box
 */
function wjm_add_coauthors_meta_box() {
    add_meta_box(
        'wjm_coauthors_meta_box',
        'Co-Authors',
        'wjm_coauthors_meta_box_callback',
        'paper',
        'normal',
        'high'
    );
}
add_action('add_meta_boxes', 'wjm_add_coauthors_meta_box');

/**
 * Co-Authors meta box callback
 */
function wjm_coauthors_meta_box_callback($post) {
    wp_nonce_field('wjm_save_coauthors', 'wjm_coauthors_nonce');

    $coauthors = wjm_get_coauthors($post->ID);
    ?>

    <div class="wjm-coauthors-wrapper">
        <h4>Current Co-Authors</h4>

        <?php if (empty($coauthors)): ?>
            <p style="color: #646970; font-style: italic;">No co-authors added yet.</p>
        <?php else: ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th width="5%">#</th>
                        <th width="25%">Name</th>
                        <th width="25%">Email</th>
                        <th width="20%">Role</th>
                        <th width="15%">Status</th>
                        <th width="10%">Actions</th>
                    </tr>
                </thead>
                <tbody id="wjm-coauthors-list">
                    <?php foreach ($coauthors as $index => $author): ?>
                        <tr data-author-index="<?php echo esc_attr($index); ?>">
                            <td><?php echo esc_html($author['order']); ?></td>
                            <td><?php echo esc_html($author['name']); ?></td>
                            <td><?php echo esc_html($author['email'] ?? 'N/A'); ?></td>
                            <td><?php echo esc_html($author['role']); ?></td>
                            <td>
                                <?php if ($author['status'] === 'confirmed'): ?>
                                    <span style="color: #00a32a;">✓ Confirmed</span>
                                <?php else: ?>
                                    <span style="color: #dba617;">⏳ Pending</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <button type="button" class="button button-small wjm-remove-coauthor" data-index="<?php echo esc_attr($index); ?>">Remove</button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <hr style="margin: 20px 0;">

        <h4>Add Co-Author</h4>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
            <div>
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Name</label>
                <input type="text" id="wjm-coauthor-name" class="widefat" placeholder="Full name" />
            </div>

            <div>
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Email</label>
                <input type="email" id="wjm-coauthor-email" class="widefat" placeholder="email@example.com" />
            </div>

            <div>
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Role</label>
                <select id="wjm-coauthor-role" class="widefat">
                    <option value="Co-Author">Co-Author</option>
                    <option value="First Author">First Author</option>
                    <option value="Corresponding Author">Corresponding Author</option>
                    <option value="Senior Author">Senior Author</option>
                    <option value="Contributor">Contributor</option>
                </select>
            </div>

            <div>
                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Affiliation</label>
                <input type="text" id="wjm-coauthor-affiliation" class="widefat" placeholder="Institution name" />
            </div>
        </div>

        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px; font-weight: 600;">Contribution (Optional)</label>
            <textarea id="wjm-coauthor-contribution" class="widefat" rows="3" placeholder="Describe this author's contribution to the paper..."></textarea>
        </div>

        <div style="display: flex; gap: 10px;">
            <button type="button" id="wjm-add-coauthor-btn" class="button button-primary" data-paper-id="<?php echo esc_attr($post->ID); ?>">
                Add Co-Author
            </button>

            <button type="button" id="wjm-send-invite-btn" class="button" data-paper-id="<?php echo esc_attr($post->ID); ?>">
                Add & Send Invitation
            </button>
        </div>

        <div id="wjm-coauthor-status" style="margin-top: 15px;"></div>
    </div>

    <script>
    jQuery(document).ready(function($) {
        // Add co-author
        $('#wjm-add-coauthor-btn, #wjm-send-invite-btn').on('click', function() {
            var $btn = $(this);
            var sendInvite = $btn.attr('id') === 'wjm-send-invite-btn';
            var paperId = $btn.data('paper-id');
            var $status = $('#wjm-coauthor-status');

            var name = $('#wjm-coauthor-name').val().trim();
            var email = $('#wjm-coauthor-email').val().trim();
            var role = $('#wjm-coauthor-role').val();
            var affiliation = $('#wjm-coauthor-affiliation').val().trim();
            var contribution = $('#wjm-coauthor-contribution').val().trim();

            if (!name || !email) {
                alert('Name and email are required');
                return;
            }

            $btn.prop('disabled', true);
            $status.html('<p style="color: #646970;">Adding co-author...</p>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_add_coauthor',
                    nonce: '<?php echo wp_create_nonce("wjm_save_coauthors"); ?>',
                    paper_id: paperId,
                    name: name,
                    email: email,
                    role: role,
                    affiliation: affiliation,
                    contribution: contribution,
                    send_invite: sendInvite
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<p style="color: #00a32a;">✓ Co-author added successfully!</p>');

                        // Clear form
                        $('#wjm-coauthor-name').val('');
                        $('#wjm-coauthor-email').val('');
                        $('#wjm-coauthor-affiliation').val('');
                        $('#wjm-coauthor-contribution').val('');

                        // Reload page
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        $status.html('<p style="color: #d63638;">Error: ' + response.data + '</p>');
                    }
                },
                error: function() {
                    $status.html('<p style="color: #d63638;">Connection error</p>');
                },
                complete: function() {
                    $btn.prop('disabled', false);
                }
            });
        });

        // Remove co-author
        $('.wjm-remove-coauthor').on('click', function() {
            if (!confirm('Remove this co-author?')) {
                return;
            }

            var $btn = $(this);
            var index = $btn.data('index');
            var $row = $btn.closest('tr');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'wjm_remove_coauthor',
                    nonce: '<?php echo wp_create_nonce("wjm_save_coauthors"); ?>',
                    paper_id: <?php echo esc_js($post->ID); ?>,
                    author_index: index
                },
                success: function(response) {
                    if (response.success) {
                        $row.fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        alert('Error removing co-author');
                    }
                }
            });
        });
    });
    </script>
    <?php
}

// ========================================
// AJAX HANDLERS
// ========================================

/**
 * AJAX: Add co-author
 */
function wjm_ajax_add_coauthor() {
    check_ajax_referer('wjm_save_coauthors', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $paper_id = absint($_POST['paper_id']);
    $send_invite = isset($_POST['send_invite']) && $_POST['send_invite'] === 'true';

    $author_data = array(
        'name' => sanitize_text_field($_POST['name']),
        'email' => sanitize_email($_POST['email']),
        'role' => sanitize_text_field($_POST['role']),
        'affiliation' => sanitize_text_field($_POST['affiliation']),
        'contribution' => sanitize_textarea_field($_POST['contribution']),
        'status' => $send_invite ? 'pending' : 'confirmed'
    );

    $result = wjm_add_coauthor($paper_id, $author_data);

    // Send invitation if requested
    if ($send_invite) {
        wjm_send_collaboration_invite($paper_id, $author_data['email'], $author_data['role']);
    }

    wp_send_json_success($result);
}
add_action('wp_ajax_wjm_add_coauthor', 'wjm_ajax_add_coauthor');

/**
 * AJAX: Remove co-author
 */
function wjm_ajax_remove_coauthor() {
    check_ajax_referer('wjm_save_coauthors', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Insufficient permissions');
    }

    $paper_id = absint($_POST['paper_id']);
    $author_index = absint($_POST['author_index']);

    $result = wjm_remove_coauthor($paper_id, $author_index);

    if ($result) {
        wp_send_json_success();
    } else {
        wp_send_json_error('Failed to remove co-author');
    }
}
add_action('wp_ajax_wjm_remove_coauthor', 'wjm_ajax_remove_coauthor');

// ========================================
// INVITATION HANDLER
// ========================================

/**
 * Handle invitation acceptance from URL
 */
function wjm_handle_invitation_acceptance() {
    if (isset($_GET['wjm_action']) && $_GET['wjm_action'] === 'accept_invite' && isset($_GET['token'])) {
        $token = sanitize_text_field($_GET['token']);

        $result = wjm_accept_collaboration_invite($token);

        if (is_wp_error($result)) {
            wp_die($result->get_error_message(), 'Invitation Error');
        }

        // Redirect to paper
        $paper_url = get_permalink($result['paper_id']);
        wp_redirect(add_query_arg('invitation', 'accepted', $paper_url));
        exit;
    }
}
add_action('template_redirect', 'wjm_handle_invitation_acceptance');

// ========================================
// SHORTCODES
// ========================================

/**
 * Display co-authors list
 */
function wjm_coauthors_list_shortcode($atts) {
    $atts = shortcode_atts(array(
        'paper_id' => get_the_ID()
    ), $atts);

    $coauthors = wjm_get_coauthors($atts['paper_id']);

    if (empty($coauthors)) {
        return '';
    }

    ob_start();
    ?>
    <div class="wjm-coauthors-list">
        <h4>Authors</h4>
        <ul style="list-style: none; padding: 0;">
            <?php foreach ($coauthors as $author): ?>
                <li style="padding: 8px 0; border-bottom: 1px solid #f0f0f1;">
                    <strong><?php echo esc_html($author['name']); ?></strong>
                    <?php if (!empty($author['affiliation'])): ?>
                        <br>
                        <small style="color: #646970;"><?php echo esc_html($author['affiliation']); ?></small>
                    <?php endif; ?>
                    <br>
                    <small style="color: #2271b1;"><?php echo esc_html($author['role']); ?></small>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('wjm_coauthors_list', 'wjm_coauthors_list_shortcode');
