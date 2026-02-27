<?php
get_header();

$user_id = get_query_var('user_profile_id');
$user = get_user_by('ID', $user_id);

if (!$user || !sjm_user_has_journal_roles($user)) {
    echo '<div class="sjm-single-container">';
    echo '<h1>User Profile Not Found</h1>';
    echo '<p>The requested user profile could not be found or user does not have journal roles.</p>';
    echo '</div>';
    get_footer();
    return;
}

// Get user's journal roles
$journal_roles = array(
    'journal_editor_in_chief' => 'Editor-in-Chief',
    'journal_managing_editor' => 'Managing Editor',
    'journal_guest_editor' => 'Guest Editor',
    'journal_reviewer' => 'Reviewer',
    'journal_author' => 'Author',
    'journal_copyeditor' => 'Copyeditor',
    'journal_proofreader' => 'Proofreader',
    'journal_layout_editor' => 'Layout Editor'
);

$user_journal_roles = array();
foreach ($user->roles as $role) {
    if (isset($journal_roles[$role])) {
        $user_journal_roles[] = $journal_roles[$role];
    }
}

// Get user's contributions based on roles
$user_papers = array();
$user_journals = array();
$user_issues = array();

// Get papers where user is involved
if (in_array('journal_author', $user->roles)) {
    $user_papers = get_posts(array(
        'post_type' => 'paper',
        'posts_per_page' => -1,
        'author' => $user_id
    ));
}

// Get journals where user has editorial roles
$all_journals = get_posts(array('post_type' => 'journal', 'posts_per_page' => -1));
foreach ($all_journals as $journal) {
    $journal_meta = get_post_meta($journal->ID);
    foreach ($journal_meta as $key => $value) {
        if (strpos($key, '_sjm_journal_') !== false && in_array($user_id, (array)$value)) {
            $user_journals[] = $journal;
            break;
        }
    }
}

// Get issues where user is involved
$all_issues = get_posts(array('post_type' => 'journal_issue', 'posts_per_page' => -1));
foreach ($all_issues as $issue) {
    $issue_meta = get_post_meta($issue->ID);
    foreach ($issue_meta as $key => $value) {
        if (strpos($key, '_sjm_issue_') !== false && in_array($user_id, (array)$value)) {
            $user_issues[] = $issue;
            break;
        }
    }
}

// Function to get role color and style for users
function sjm_get_user_role_style($role) {
    $role_styles = array(
        'Editor-in-Chief' => array('bg' => '#e8f5e8', 'color' => '#2e7d32', 'icon' => '👑'),
        'Managing Editor' => array('bg' => '#e3f2fd', 'color' => '#1565c0', 'icon' => '⚡'),
        'Guest Editor' => array('bg' => '#fce4ec', 'color' => '#c2185b', 'icon' => '👥'),
        'Reviewer' => array('bg' => '#f3e5f5', 'color' => '#7b1fa2', 'icon' => '🔍'),
        'Author' => array('bg' => '#e0f2f1', 'color' => '#00695c', 'icon' => '✍️'),
        'Copyeditor' => array('bg' => '#fff3e0', 'color' => '#ef6c00', 'icon' => '✏️'),
        'Proofreader' => array('bg' => '#f1f8e9', 'color' => '#558b2f', 'icon' => '🔎'),
        'Layout Editor' => array('bg' => '#fafafa', 'color' => '#424242', 'icon' => '🎨'),
        'default' => array('bg' => '#f5f5f5', 'color' => '#616161', 'icon' => '👤')
    );
    
    return isset($role_styles[$role]) ? $role_styles[$role] : $role_styles['default'];
}
?>

<style>
.sjm-user-profile {
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 20px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

.sjm-user-header {
    display: grid;
    grid-template-columns: 150px 1fr;
    gap: 30px;
    margin-bottom: 40px;
    padding: 30px;
    background: #f8f9fa;
    border-radius: 12px;
    border: 1px solid #e9ecef;
    color: #212529;
}

.sjm-user-avatar {
    width: 150px;
    height: 150px;
    border-radius: 50%;
    background: #e9ecef;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 36px;
    font-weight: bold;
    border: 3px solid #dee2e6;
    color: #6c757d;
}

.sjm-user-info h1 {
    font-size: 2.2rem;
    margin: 0 0 10px 0;
    font-weight: 700;
    color: #212529;
}

.sjm-user-title {
    font-size: 1.1rem;
    margin: 0 0 20px 0;
    color: #6c757d;
    font-weight: 500;
}

.sjm-role-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 15px;
}

.sjm-role-tag {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: 16px;
    font-size: 13px;
    font-weight: 500;
    margin: 2px 4px 2px 0;
}

.sjm-user-sections {
    display: grid;
    grid-template-columns: 1fr 350px;
    gap: 40px;
}

.sjm-user-main {
    display: flex;
    flex-direction: column;
    gap: 30px;
}

.sjm-user-sidebar {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.sjm-section {
    background: white;
    border-radius: 12px;
    padding: 30px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
}

.sjm-section h2 {
    font-size: 1.5rem;
    margin: 0 0 20px 0;
    color: #111827;
    font-weight: 600;
    border-bottom: 2px solid #e5e7eb;
    padding-bottom: 10px;
}

.sjm-contribution-item {
    margin-bottom: 20px;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
    border-left: 4px solid #dee2e6;
}

.sjm-contribution-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #212529;
    margin: 0 0 8px 0;
}

.sjm-contribution-meta {
    font-size: 14px;
    color: #6c757d;
    margin-bottom: 10px;
}

.sjm-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
    gap: 15px;
}

.sjm-stat-item {
    text-align: center;
    padding: 15px;
    background: #f8f9fa;
    border-radius: 8px;
    border: 1px solid #e9ecef;
}

.sjm-stat-number {
    font-size: 1.8rem;
    font-weight: 700;
    color: #1e40af;
    margin-bottom: 5px;
}

.sjm-stat-label {
    font-size: 12px;
    color: #6b7280;
    font-weight: 500;
}

.sjm-info-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid #f3f4f6;
}

.sjm-info-item:last-child {
    border-bottom: none;
}

.sjm-info-label {
    font-weight: 600;
    color: #374151;
    min-width: 80px;
    font-size: 14px;
}

.sjm-info-value {
    color: #6b7280;
    font-size: 14px;
    line-height: 1.5;
}

@media (max-width: 768px) {
    .sjm-user-header {
        grid-template-columns: 1fr;
        text-align: center;
    }
    
    .sjm-user-avatar {
        width: 120px;
        height: 120px;
        margin: 0 auto 20px;
    }
    
    .sjm-user-sections {
        grid-template-columns: 1fr;
    }
    
    .sjm-user-info h1 {
        font-size: 1.8rem;
    }
}
</style>

<div class="sjm-user-profile">
    <div class="sjm-user-header">
        <div class="sjm-user-avatar">
            <?php 
            $initials = '';
            $name_parts = explode(' ', $user->display_name);
            foreach ($name_parts as $part) {
                $initials .= strtoupper(substr($part, 0, 1));
            }
            echo esc_html(substr($initials, 0, 2));
            ?>
        </div>
        <div class="sjm-user-info">
            <h1><?php echo esc_html($user->display_name); ?></h1>
            <div class="sjm-user-title">
                <?php echo esc_html($user->user_email); ?>
            </div>
            
            <div class="sjm-role-tags">
                <?php foreach ($user_journal_roles as $role): 
                    $role_style = sjm_get_user_role_style($role);
                    ?>
                    <span class="sjm-role-tag" style="background-color: <?php echo $role_style['bg']; ?>; color: <?php echo $role_style['color']; ?>;">
                        <?php echo $role_style['icon']; ?> <?php echo esc_html($role); ?>
                    </span>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="sjm-user-sections">
        <div class="sjm-user-main">
            <?php if ($user_papers): ?>
                <div class="sjm-section">
                    <h2>Authored Papers (<?php echo count($user_papers); ?>)</h2>
                    <?php foreach ($user_papers as $paper): 
                        $paper_journal_id = get_post_meta($paper->ID, '_sjm_paper_journal', true);
                        $paper_journal = $paper_journal_id ? get_post($paper_journal_id) : null;
                        $paper_issue_id = get_post_meta($paper->ID, '_sjm_paper_issue', true);
                        $paper_issue = $paper_issue_id ? get_post($paper_issue_id) : null;
                        $acceptance_date = get_post_meta($paper->ID, '_sjm_acceptance_date', true);
                        $paper_type = get_post_meta($paper->ID, '_sjm_paper_type', true);
                        ?>
                        <div class="sjm-contribution-item">
                            <h3 class="sjm-contribution-title">
                                <a href="<?php echo get_permalink($paper->ID); ?>" style="color: #212529; text-decoration: none;">
                                    <?php echo esc_html($paper->post_title); ?>
                                </a>
                            </h3>
                            <div class="sjm-contribution-meta">
                                <?php if ($paper_journal): ?>
                                    <strong><?php echo esc_html($paper_journal->post_title); ?></strong>
                                <?php endif; ?>
                                <?php if ($paper_issue): ?>
                                    - <?php echo esc_html($paper_issue->post_title); ?>
                                <?php endif; ?>
                                <?php if ($acceptance_date): ?>
                                    (<?php echo date('Y', strtotime($acceptance_date)); ?>)
                                <?php endif; ?>
                                <?php if ($paper_type): ?>
                                    - <?php echo esc_html($paper_type); ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($user_journals): ?>
                <div class="sjm-section">
                    <h2>Journal Editorial Roles (<?php echo count($user_journals); ?>)</h2>
                    <?php foreach ($user_journals as $journal): ?>
                        <div class="sjm-contribution-item">
                            <h3 class="sjm-contribution-title">
                                <a href="<?php echo get_permalink($journal->ID); ?>" style="color: #212529; text-decoration: none;">
                                    <?php echo esc_html($journal->post_title); ?>
                                </a>
                            </h3>
                            <div class="sjm-contribution-meta">
                                Editorial role in journal management
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($user_issues): ?>
                <div class="sjm-section">
                    <h2>Issue Contributions (<?php echo count($user_issues); ?>)</h2>
                    <?php foreach ($user_issues as $issue): 
                        $issue_journal_id = get_post_meta($issue->ID, '_sjm_issue_journal', true);
                        $issue_journal = $issue_journal_id ? get_post($issue_journal_id) : null;
                        ?>
                        <div class="sjm-contribution-item">
                            <h3 class="sjm-contribution-title">
                                <a href="<?php echo get_permalink($issue->ID); ?>" style="color: #212529; text-decoration: none;">
                                    <?php echo esc_html($issue->post_title); ?>
                                </a>
                            </h3>
                            <div class="sjm-contribution-meta">
                                <?php if ($issue_journal): ?>
                                    <strong><?php echo esc_html($issue_journal->post_title); ?></strong>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
        
        <div class="sjm-user-sidebar">
            <div class="sjm-section">
                <h2>Statistics</h2>
                <div class="sjm-stats">
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($user_papers); ?></div>
                        <div class="sjm-stat-label">Papers</div>
                    </div>
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($user_journals); ?></div>
                        <div class="sjm-stat-label">Journals</div>
                    </div>
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($user_issues); ?></div>
                        <div class="sjm-stat-label">Issues</div>
                    </div>
                    <div class="sjm-stat-item">
                        <div class="sjm-stat-number"><?php echo count($user_journal_roles); ?></div>
                        <div class="sjm-stat-label">Roles</div>
                    </div>
                </div>
            </div>
            
            <div class="sjm-section">
                <h2>User Information</h2>
                <div>
                    <div class="sjm-info-item">
                        <div class="sjm-info-label">Username:</div>
                        <div class="sjm-info-value"><?php echo esc_html($user->user_login); ?></div>
                    </div>
                    
                    <div class="sjm-info-item">
                        <div class="sjm-info-label">Email:</div>
                        <div class="sjm-info-value">
                            <a href="mailto:<?php echo esc_attr($user->user_email); ?>" style="color: #2563eb;">
                                <?php echo esc_html($user->user_email); ?>
                            </a>
                        </div>
                    </div>
                    
                    <div class="sjm-info-item">
                        <div class="sjm-info-label">Member Since:</div>
                        <div class="sjm-info-value"><?php echo date('F j, Y', strtotime($user->user_registered)); ?></div>
                    </div>
                    
                    <?php if ($user->user_url): ?>
                        <div class="sjm-info-item">
                            <div class="sjm-info-label">Website:</div>
                            <div class="sjm-info-value">
                                <a href="<?php echo esc_url($user->user_url); ?>" target="_blank" style="color: #2563eb;">
                                    <?php echo esc_html($user->user_url); ?>
                                </a>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="sjm-section">
                <h2>Journal Roles</h2>
                <div>
                    <?php foreach ($user_journal_roles as $role): 
                        $role_style = sjm_get_user_role_style($role);
                        ?>
                        <div class="sjm-info-item">
                            <span class="sjm-role-tag" style="background-color: <?php echo $role_style['bg']; ?>; color: <?php echo $role_style['color']; ?>; margin: 0;">
                                <?php echo $role_style['icon']; ?> <?php echo esc_html($role); ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php get_footer(); ?> 