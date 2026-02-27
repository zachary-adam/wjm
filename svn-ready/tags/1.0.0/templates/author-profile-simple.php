<?php
get_header();

$author_id = get_query_var('author_profile_id');

echo '<div style="padding: 20px; max-width: 800px; margin: 0 auto;">';
echo '<h1>Author Profile Debug</h1>';
echo '<p><strong>Author ID:</strong> ' . esc_html($author_id) . '</p>';
echo '<p><strong>Request URI:</strong> ' . esc_html($_SERVER['REQUEST_URI']) . '</p>';

if ($author_id) {
    $author = sjm_get_author_by_id($author_id);
    if ($author) {
        echo '<h2>Author Found!</h2>';
        echo '<p><strong>Name:</strong> ' . esc_html($author->first_name . ' ' . $author->last_name) . '</p>';
        echo '<p><strong>Email:</strong> ' . esc_html($author->email) . '</p>';
        echo '<p><strong>Affiliation:</strong> ' . esc_html($author->affiliation) . '</p>';
        echo '<p><strong>ORCID:</strong> ' . esc_html($author->orcid) . '</p>';
        echo '<p><strong>Bio:</strong> ' . nl2br(esc_html($author->bio)) . '</p>';
    } else {
        echo '<h2>Author Not Found</h2>';
        echo '<p>No author found with ID: ' . esc_html($author_id) . '</p>';
        
        $all_authors = sjm_get_all_authors();
        echo '<h3>All Authors in Database:</h3>';
        echo '<ul>';
        foreach ($all_authors as $a) {
            echo '<li>ID: ' . esc_html($a->id) . ' - ' . esc_html($a->first_name . ' ' . $a->last_name) . '</li>';
        }
        echo '</ul>';
    }
} else {
    echo '<h2>No Author ID Found</h2>';
    echo '<p>The author_profile_id query variable is empty.</p>';
}

echo '</div>';

get_footer();
?> 