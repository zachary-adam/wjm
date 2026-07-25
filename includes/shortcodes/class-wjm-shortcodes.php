<?php
/**
 * Public shortcodes: [journals], [issues], [papers], [wjm_author_profile].
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Shortcodes {

	public static function register() {
		add_shortcode( 'journals', array( __CLASS__, 'journals' ) );
		add_shortcode( 'issues', array( __CLASS__, 'issues' ) );
		add_shortcode( 'papers', array( __CLASS__, 'papers' ) );
		add_shortcode( 'wjm_author_profile', array( __CLASS__, 'author_profile' ) );
	}

	public static function journals( $atts ) {
		$atts = shortcode_atts(
			array(
				'layout'    => 'grid',
				'publisher' => '',
				'year'      => '',
			),
			$atts,
			'journals'
		);

		$args = WJM_Advanced_Search::journal_query_args(
			array(
				'posts_per_page' => 50,
			)
		);

		if ( $atts['year'] ) {
			$args['year'] = absint( $atts['year'] );
		}

		$query = new WP_Query( $args );
		$class = 'list' === $atts['layout'] ? 'wjm-journals-list' : 'wjm-journals-grid';

		ob_start();
		echo '<div class="' . esc_attr( $class ) . '">';
		if ( $query->have_posts() ) {
			while ( $query->have_posts() ) {
				$query->the_post();
				$publisher = get_post_meta( get_the_ID(), '_sjm_publisher', true );
				if ( $atts['publisher'] && strcasecmp( $publisher, $atts['publisher'] ) !== 0 ) {
					continue;
				}
				echo '<article class="wjm-journal-card">';
				echo '<h3><a href="' . esc_url( get_permalink() ) . '">' . esc_html( get_the_title() ) . '</a></h3>';
				if ( $publisher ) {
					echo '<p class="wjm-publisher">' . esc_html( $publisher ) . '</p>';
				}
				$issn = get_post_meta( get_the_ID(), '_sjm_issn', true );
				if ( $issn ) {
					echo '<p class="wjm-issn">ISSN: ' . esc_html( $issn ) . '</p>';
				}
				echo '</article>';
			}
			wp_reset_postdata();
		} else {
			echo '<p>' . esc_html__( 'No journals found.', 'wisdom-journal-manager' ) . '</p>';
		}
		echo '</div>';
		return ob_get_clean();
	}

	public static function issues( $atts ) {
		$atts = shortcode_atts(
			array(
				'journal_id'    => 0,
				'volume'        => '',
				'special_issue' => '',
			),
			$atts,
			'issues'
		);

		$meta_query = array();
		if ( $atts['journal_id'] ) {
			$meta_query[] = array(
				'key'   => '_sjm_journal_id',
				'value' => absint( $atts['journal_id'] ),
			);
		}
		if ( '' !== $atts['volume'] ) {
			$meta_query[] = array(
				'key'   => '_sjm_volume',
				'value' => sanitize_text_field( $atts['volume'] ),
			);
		}
		if ( '' !== $atts['special_issue'] ) {
			$meta_query[] = array(
				'key'   => '_sjm_special_issue',
				'value' => $atts['special_issue'] ? '1' : '0',
			);
		}

		$query = new WP_Query(
			array(
				'post_type'      => 'sjm_issue',
				'post_status'    => 'publish',
				'posts_per_page' => 50,
				'meta_query'     => $meta_query,
			)
		);

		ob_start();
		echo '<ul class="wjm-issues">';
		if ( $query->have_posts() ) {
			while ( $query->have_posts() ) {
				$query->the_post();
				$vol = get_post_meta( get_the_ID(), '_sjm_volume', true );
				$num = get_post_meta( get_the_ID(), '_sjm_number', true );
				echo '<li><a href="' . esc_url( get_permalink() ) . '">' . esc_html( get_the_title() ) . '</a>';
				if ( $vol || $num ) {
					echo ' <span>(Vol. ' . esc_html( $vol ) . ' No. ' . esc_html( $num ) . ')</span>';
				}
				echo '</li>';
			}
			wp_reset_postdata();
		} else {
			echo '<li>' . esc_html__( 'No issues found.', 'wisdom-journal-manager' ) . '</li>';
		}
		echo '</ul>';
		return ob_get_clean();
	}

	public static function papers( $atts ) {
		$atts = shortcode_atts(
			array(
				'author'     => '',
				'keyword'    => '',
				'paper_type' => '',
			),
			$atts,
			'papers'
		);

		$args = array(
			'post_type'      => 'sjm_paper',
			'post_status'    => 'publish',
			'posts_per_page' => 50,
		);

		if ( $atts['keyword'] ) {
			$args['s'] = sanitize_text_field( $atts['keyword'] );
		}

		if ( $atts['paper_type'] ) {
			$args['meta_query'][] = array(
				'key'   => '_sjm_paper_type',
				'value' => sanitize_text_field( $atts['paper_type'] ),
			);
		}

		if ( $atts['author'] ) {
			global $wpdb;
			$author_id = absint( $atts['author'] );
			$link      = WJM_Database_Schema::table( 'paper_authors' );
			$ids       = $wpdb->get_col(
				$wpdb->prepare( "SELECT paper_id FROM {$link} WHERE author_id = %d", $author_id )
			);
			$args['post__in'] = $ids ? array_map( 'intval', $ids ) : array( 0 );
		}

		$args  = apply_filters( 'sjm_paper_query_args', $args );
		$query = new WP_Query( $args );

		ob_start();
		echo '<ul class="wjm-papers">';
		if ( $query->have_posts() ) {
			while ( $query->have_posts() ) {
				$query->the_post();
				echo '<li><a href="' . esc_url( get_permalink() ) . '">' . esc_html( get_the_title() ) . '</a></li>';
			}
			wp_reset_postdata();
		} else {
			echo '<li>' . esc_html__( 'No papers found.', 'wisdom-journal-manager' ) . '</li>';
		}
		echo '</ul>';
		return ob_get_clean();
	}

	public static function author_profile( $atts ) {
		$atts = shortcode_atts(
			array(
				'id' => 0,
			),
			$atts,
			'wjm_author_profile'
		);
		return WJM_Author_Profiles::render_profile( absint( $atts['id'] ) );
	}
}
