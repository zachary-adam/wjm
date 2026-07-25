<?php
/**
 * Per-journal SEO independence + visibility controls.
 *
 * Each journal can own its title templates, meta description, robots,
 * canonical, Open Graph, and Schema.org Article/Periodical markup —
 * without depending on a third-party SEO plugin (works alongside Yoast/RankMath if present).
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_SEO {

	public static function init() {
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_boxes' ) );
		add_action( 'save_post_sjm_journal', array( __CLASS__, 'save_journal' ), 25, 2 );
		add_action( 'save_post_sjm_paper', array( __CLASS__, 'save_paper' ), 25, 2 );
		add_action( 'wp_head', array( __CLASS__, 'output_head' ), 1 );
		add_filter( 'document_title_parts', array( __CLASS__, 'filter_title' ) );
		add_filter( 'wp_robots', array( __CLASS__, 'filter_robots' ) );
		add_action( 'init', array( __CLASS__, 'register_rewrite' ) );
		add_action( 'template_redirect', array( __CLASS__, 'serve_sitemap' ) );
		add_filter( 'wp_sitemaps_posts_query_args', array( __CLASS__, 'core_sitemap_args' ), 10, 2 );
	}

	/**
	 * Defaults for a journal's SEO pack.
	 *
	 * @return array
	 */
	public static function journal_defaults() {
		return array(
			'seo_title'       => '',
			'seo_description' => '',
			'seo_keywords'    => '',
			'robots_index'    => '1',
			'robots_follow'   => '1',
			'og_image'        => '',
			'canonical'       => '',
			'sitemap_include' => '1',
			'schema_type'     => 'Periodical',
		);
	}

	/**
	 * @param int $journal_id Journal ID.
	 * @return array
	 */
	public static function get_journal_seo( $journal_id ) {
		$raw = get_post_meta( $journal_id, '_sjm_seo', true );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		return array_merge( self::journal_defaults(), $raw );
	}

	public static function meta_boxes() {
		add_meta_box(
			'wjm_journal_seo',
			__( 'SEO & Visibility (independent)', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_journal_box' ),
			'sjm_journal',
			'normal',
			'default'
		);
		add_meta_box(
			'wjm_paper_seo',
			__( 'SEO overrides', 'wisdom-journal-manager' ),
			array( __CLASS__, 'render_paper_box' ),
			'sjm_paper',
			'side',
			'default'
		);
	}

	public static function render_journal_box( $post ) {
		$seo = self::get_journal_seo( $post->ID );
		wp_nonce_field( 'wjm_journal_seo', 'wjm_journal_seo_nonce' );
		$sitemap = home_url( '/wjm-sitemap-' . $post->ID . '.xml' );
		?>
		<p class="description"><?php esc_html_e( 'Each journal controls its own search visibility — independent of other journals on this site.', 'wisdom-journal-manager' ); ?></p>
		<table class="form-table">
			<tr>
				<th><label for="sjm_seo_title"><?php esc_html_e( 'SEO title', 'wisdom-journal-manager' ); ?></label></th>
				<td><input type="text" class="large-text" id="sjm_seo_title" name="sjm_seo_title" value="<?php echo esc_attr( $seo['seo_title'] ); ?>" placeholder="<?php echo esc_attr( get_the_title( $post ) ); ?>" /></td>
			</tr>
			<tr>
				<th><label for="sjm_seo_description"><?php esc_html_e( 'Meta description', 'wisdom-journal-manager' ); ?></label></th>
				<td><textarea class="large-text" rows="3" id="sjm_seo_description" name="sjm_seo_description"><?php echo esc_textarea( $seo['seo_description'] ); ?></textarea></td>
			</tr>
			<tr>
				<th><label for="sjm_seo_keywords"><?php esc_html_e( 'Keywords', 'wisdom-journal-manager' ); ?></label></th>
				<td><input type="text" class="large-text" id="sjm_seo_keywords" name="sjm_seo_keywords" value="<?php echo esc_attr( $seo['seo_keywords'] ); ?>" /></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Robots', 'wisdom-journal-manager' ); ?></th>
				<td>
					<label><input type="checkbox" name="sjm_robots_index" value="1" <?php checked( $seo['robots_index'], '1' ); ?> /> <?php esc_html_e( 'Index', 'wisdom-journal-manager' ); ?></label>
					&nbsp;
					<label><input type="checkbox" name="sjm_robots_follow" value="1" <?php checked( $seo['robots_follow'], '1' ); ?> /> <?php esc_html_e( 'Follow', 'wisdom-journal-manager' ); ?></label>
				</td>
			</tr>
			<tr>
				<th><label for="sjm_canonical"><?php esc_html_e( 'Canonical URL', 'wisdom-journal-manager' ); ?></label></th>
				<td><input type="url" class="large-text" id="sjm_canonical" name="sjm_canonical" value="<?php echo esc_attr( $seo['canonical'] ); ?>" placeholder="<?php echo esc_attr( get_permalink( $post ) ); ?>" /></td>
			</tr>
			<tr>
				<th><label for="sjm_og_image"><?php esc_html_e( 'Open Graph image URL', 'wisdom-journal-manager' ); ?></label></th>
				<td><input type="url" class="large-text" id="sjm_og_image" name="sjm_og_image" value="<?php echo esc_attr( $seo['og_image'] ); ?>" /></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Sitemap', 'wisdom-journal-manager' ); ?></th>
				<td>
					<label><input type="checkbox" name="sjm_sitemap_include" value="1" <?php checked( $seo['sitemap_include'], '1' ); ?> /> <?php esc_html_e( 'Include this journal + its papers in WJM sitemap', 'wisdom-journal-manager' ); ?></label>
					<p class="description"><a href="<?php echo esc_url( $sitemap ); ?>" target="_blank" rel="noopener"><?php echo esc_html( $sitemap ); ?></a></p>
				</td>
			</tr>
		</table>
		<?php
	}

	public static function render_paper_box( $post ) {
		$title   = get_post_meta( $post->ID, '_sjm_seo_title', true );
		$desc    = get_post_meta( $post->ID, '_sjm_seo_description', true );
		$noindex = get_post_meta( $post->ID, '_sjm_seo_noindex', true );
		$og      = get_post_meta( $post->ID, '_sjm_og_image', true );
		$press   = get_post_meta( $post->ID, '_sjm_press_blurb', true );
		wp_nonce_field( 'wjm_paper_seo', 'wjm_paper_seo_nonce' );
		?>
		<p>
			<label for="sjm_paper_seo_title"><strong><?php esc_html_e( 'SEO title', 'wisdom-journal-manager' ); ?></strong></label>
			<input type="text" class="widefat" id="sjm_paper_seo_title" name="sjm_paper_seo_title" value="<?php echo esc_attr( $title ); ?>" />
		</p>
		<p>
			<label for="sjm_paper_seo_description"><strong><?php esc_html_e( 'Meta description', 'wisdom-journal-manager' ); ?></strong></label>
			<textarea class="widefat" rows="3" id="sjm_paper_seo_description" name="sjm_paper_seo_description"><?php echo esc_textarea( $desc ); ?></textarea>
		</p>
		<p>
			<label for="sjm_paper_og_image"><strong><?php esc_html_e( 'Social card image URL', 'wisdom-journal-manager' ); ?></strong></label>
			<input type="url" class="widefat" id="sjm_paper_og_image" name="sjm_paper_og_image" value="<?php echo esc_attr( $og ); ?>" placeholder="https://…" />
		</p>
		<p>
			<label for="sjm_paper_press_blurb"><strong><?php esc_html_e( 'Press blurb', 'wisdom-journal-manager' ); ?></strong></label>
			<textarea class="widefat" rows="4" id="sjm_paper_press_blurb" name="sjm_paper_press_blurb" placeholder="<?php esc_attr_e( 'Short plain-language summary for journalists / social.', 'wisdom-journal-manager' ); ?>"><?php echo esc_textarea( $press ); ?></textarea>
		</p>
		<p>
			<label><input type="checkbox" name="sjm_paper_seo_noindex" value="1" <?php checked( $noindex, '1' ); ?> /> <?php esc_html_e( 'Noindex this paper', 'wisdom-journal-manager' ); ?></label>
		</p>
		<?php
	}

	public static function save_journal( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_journal_seo_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_journal_seo_nonce'] ) ), 'wjm_journal_seo' ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}

		$seo = array(
			'seo_title'       => isset( $_POST['sjm_seo_title'] ) ? sanitize_text_field( wp_unslash( $_POST['sjm_seo_title'] ) ) : '',
			'seo_description' => isset( $_POST['sjm_seo_description'] ) ? sanitize_textarea_field( wp_unslash( $_POST['sjm_seo_description'] ) ) : '',
			'seo_keywords'    => isset( $_POST['sjm_seo_keywords'] ) ? sanitize_text_field( wp_unslash( $_POST['sjm_seo_keywords'] ) ) : '',
			'robots_index'    => ! empty( $_POST['sjm_robots_index'] ) ? '1' : '0',
			'robots_follow'   => ! empty( $_POST['sjm_robots_follow'] ) ? '1' : '0',
			'og_image'        => isset( $_POST['sjm_og_image'] ) ? esc_url_raw( wp_unslash( $_POST['sjm_og_image'] ) ) : '',
			'canonical'       => isset( $_POST['sjm_canonical'] ) ? esc_url_raw( wp_unslash( $_POST['sjm_canonical'] ) ) : '',
			'sitemap_include' => ! empty( $_POST['sjm_sitemap_include'] ) ? '1' : '0',
			'schema_type'     => 'Periodical',
		);
		update_post_meta( $post_id, '_sjm_seo', $seo );
		unset( $post );
	}

	public static function save_paper( $post_id, $post ) {
		if ( ! isset( $_POST['wjm_paper_seo_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wjm_paper_seo_nonce'] ) ), 'wjm_paper_seo' ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		update_post_meta( $post_id, '_sjm_seo_title', isset( $_POST['sjm_paper_seo_title'] ) ? sanitize_text_field( wp_unslash( $_POST['sjm_paper_seo_title'] ) ) : '' );
		update_post_meta( $post_id, '_sjm_seo_description', isset( $_POST['sjm_paper_seo_description'] ) ? sanitize_textarea_field( wp_unslash( $_POST['sjm_paper_seo_description'] ) ) : '' );
		update_post_meta( $post_id, '_sjm_og_image', isset( $_POST['sjm_paper_og_image'] ) ? esc_url_raw( wp_unslash( $_POST['sjm_paper_og_image'] ) ) : '' );
		update_post_meta( $post_id, '_sjm_press_blurb', isset( $_POST['sjm_paper_press_blurb'] ) ? sanitize_textarea_field( wp_unslash( $_POST['sjm_paper_press_blurb'] ) ) : '' );
		update_post_meta( $post_id, '_sjm_seo_noindex', ! empty( $_POST['sjm_paper_seo_noindex'] ) ? '1' : '0' );
		unset( $post );
	}

	/**
	 * Resolve parent journal for a paper.
	 *
	 * @param int $paper_id Paper ID.
	 * @return int
	 */
	public static function journal_for_paper( $paper_id ) {
		$issue_id = (int) get_post_meta( $paper_id, '_sjm_issue_id', true );
		if ( $issue_id ) {
			return (int) get_post_meta( $issue_id, '_sjm_journal_id', true );
		}
		return (int) get_post_meta( $paper_id, '_sjm_journal_id', true );
	}

	public static function filter_title( $parts ) {
		if ( is_singular( 'sjm_journal' ) ) {
			$seo = self::get_journal_seo( get_the_ID() );
			if ( ! empty( $seo['seo_title'] ) ) {
				$parts['title'] = $seo['seo_title'];
			}
		}
		if ( is_singular( 'sjm_paper' ) ) {
			$custom = get_post_meta( get_the_ID(), '_sjm_seo_title', true );
			if ( $custom ) {
				$parts['title'] = $custom;
			}
		}
		return $parts;
	}

	public static function filter_robots( $robots ) {
		if ( is_singular( 'sjm_journal' ) ) {
			$seo = self::get_journal_seo( get_the_ID() );
			$robots['noindex'] = ( '1' !== $seo['robots_index'] );
			$robots['nofollow'] = ( '1' !== $seo['robots_follow'] );
		}
		if ( is_singular( 'sjm_paper' ) ) {
			if ( '1' === get_post_meta( get_the_ID(), '_sjm_seo_noindex', true ) ) {
				$robots['noindex'] = true;
			} else {
				$jid = self::journal_for_paper( get_the_ID() );
				if ( $jid ) {
					$seo = self::get_journal_seo( $jid );
					if ( '1' !== $seo['robots_index'] ) {
						$robots['noindex'] = true;
					}
				}
			}
		}
		return $robots;
	}

	public static function output_head() {
		if ( ! is_singular( array( 'sjm_journal', 'sjm_issue', 'sjm_paper' ) ) ) {
			return;
		}

		$post_id = get_the_ID();
		$type    = get_post_type( $post_id );

		if ( 'sjm_journal' === $type ) {
			$seo  = self::get_journal_seo( $post_id );
			$title = $seo['seo_title'] ? $seo['seo_title'] : get_the_title( $post_id );
			$desc  = $seo['seo_description'] ? $seo['seo_description'] : wp_trim_words( get_the_excerpt( $post_id ), 30 );
			$canon = $seo['canonical'] ? $seo['canonical'] : get_permalink( $post_id );
			$image = $seo['og_image'] ? $seo['og_image'] : ( get_the_post_thumbnail_url( $post_id, 'full' ) ?: '' );
			$keywords = $seo['seo_keywords'];
			self::print_meta( $title, $desc, $canon, $image, $keywords );
			self::print_schema_periodical( $post_id, $title, $desc, $canon );
			return;
		}

		if ( 'sjm_paper' === $type ) {
			$title = get_post_meta( $post_id, '_sjm_seo_title', true );
			if ( ! $title ) {
				$title = get_the_title( $post_id );
			}
			$desc = get_post_meta( $post_id, '_sjm_seo_description', true );
			if ( ! $desc ) {
				$desc = get_post_meta( $post_id, '_sjm_abstract', true );
			}
			$desc  = $desc ? wp_trim_words( wp_strip_all_tags( $desc ), 40 ) : '';
			$canon = get_permalink( $post_id );
			$image = get_post_meta( $post_id, '_sjm_og_image', true );
			if ( ! $image ) {
				$image = get_the_post_thumbnail_url( $post_id, 'full' ) ?: '';
			}
			$jid   = self::journal_for_paper( $post_id );
			if ( $jid && ! $image ) {
				$jseo = self::get_journal_seo( $jid );
				$image = $jseo['og_image'];
			}
			self::print_meta( $title, $desc, $canon, $image, '' );
			self::print_schema_scholarly( $post_id, $title, $desc, $canon );
		}
	}

	/**
	 * @param string $title Title.
	 * @param string $desc Description.
	 * @param string $canon Canonical.
	 * @param string $image Image URL.
	 * @param string $keywords Keywords.
	 */
	private static function print_meta( $title, $desc, $canon, $image, $keywords ) {
		if ( $desc ) {
			echo '<meta name="description" content="' . esc_attr( $desc ) . '" />' . "\n";
		}
		if ( $keywords ) {
			echo '<meta name="keywords" content="' . esc_attr( $keywords ) . '" />' . "\n";
		}
		if ( $canon ) {
			echo '<link rel="canonical" href="' . esc_url( $canon ) . '" />' . "\n";
		}
		echo '<meta property="og:type" content="article" />' . "\n";
		echo '<meta property="og:title" content="' . esc_attr( $title ) . '" />' . "\n";
		if ( $desc ) {
			echo '<meta property="og:description" content="' . esc_attr( $desc ) . '" />' . "\n";
		}
		if ( $canon ) {
			echo '<meta property="og:url" content="' . esc_url( $canon ) . '" />' . "\n";
		}
		if ( $image ) {
			echo '<meta property="og:image" content="' . esc_url( $image ) . '" />' . "\n";
			echo '<meta name="twitter:image" content="' . esc_url( $image ) . '" />' . "\n";
		}
		echo '<meta name="twitter:card" content="summary_large_image" />' . "\n";
		echo '<meta name="twitter:title" content="' . esc_attr( $title ) . '" />' . "\n";
		if ( $desc ) {
			echo '<meta name="twitter:description" content="' . esc_attr( $desc ) . '" />' . "\n";
		}
	}

	/**
	 * Public share / press kit for a paper.
	 *
	 * @param int $paper_id Paper ID.
	 * @return string
	 */
	public static function render_share_kit( $paper_id ) {
		$paper_id = absint( $paper_id );
		if ( ! $paper_id || 'sjm_paper' !== get_post_type( $paper_id ) ) {
			return '';
		}
		if ( 'publish' !== get_post_status( $paper_id ) ) {
			return '';
		}
		$url   = get_permalink( $paper_id );
		$title = get_the_title( $paper_id );
		$press = get_post_meta( $paper_id, '_sjm_press_blurb', true );
		if ( ! $press ) {
			$press = get_post_meta( $paper_id, '_sjm_abstract', true );
			$press = $press ? wp_trim_words( wp_strip_all_tags( $press ), 55 ) : $title;
		}
		$tw = 'https://twitter.com/intent/tweet?' . http_build_query(
			array(
				'text' => $title,
				'url'  => $url,
			)
		);
		$li = 'https://www.linkedin.com/sharing/share-offsite/?' . http_build_query( array( 'url' => $url ) );
		$em = 'mailto:?subject=' . rawurlencode( $title ) . '&body=' . rawurlencode( $press . "\n\n" . $url );
		ob_start();
		?>
		<section class="wjm-share-kit">
			<p class="wjm-eyebrow"><?php esc_html_e( 'Share', 'wisdom-journal-manager' ); ?></p>
			<h2 class="wjm-sec-title"><?php esc_html_e( 'Press & social', 'wisdom-journal-manager' ); ?></h2>
			<?php if ( $press ) : ?>
				<blockquote class="wjm-press-blurb"><?php echo esc_html( $press ); ?></blockquote>
			<?php endif; ?>
			<p class="wjm-share-actions">
				<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-copy="<?php echo esc_attr( $url ); ?>"><?php esc_html_e( 'Copy link', 'wisdom-journal-manager' ); ?></button>
				<a class="wjm-btn wjm-btn-secondary" href="<?php echo esc_url( $tw ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'X / Twitter', 'wisdom-journal-manager' ); ?></a>
				<a class="wjm-btn wjm-btn-secondary" href="<?php echo esc_url( $li ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'LinkedIn', 'wisdom-journal-manager' ); ?></a>
				<a class="wjm-btn wjm-btn-secondary" href="<?php echo esc_url( $em ); ?>"><?php esc_html_e( 'Email', 'wisdom-journal-manager' ); ?></a>
			</p>
		</section>
		<script>
		document.addEventListener('click',function(e){
			var b=e.target.closest('[data-wjm-copy]');
			if(!b||!navigator.clipboard)return;
			e.preventDefault();
			navigator.clipboard.writeText(b.getAttribute('data-wjm-copy')).then(function(){
				b.textContent='<?php echo esc_js( __( 'Copied', 'wisdom-journal-manager' ) ); ?>';
			});
		});
		</script>
		<?php
		return ob_get_clean();
	}

	private static function print_schema_periodical( $journal_id, $title, $desc, $url ) {
		$issn = get_post_meta( $journal_id, '_sjm_issn', true );
		$data = array(
			'@context'    => 'https://schema.org',
			'@type'       => 'Periodical',
			'name'        => $title,
			'description' => $desc,
			'url'         => $url,
		);
		if ( $issn ) {
			$data['issn'] = $issn;
		}
		$publisher = get_post_meta( $journal_id, '_sjm_publisher', true );
		if ( $publisher ) {
			$data['publisher'] = array(
				'@type' => 'Organization',
				'name'  => $publisher,
			);
		}
		echo '<script type="application/ld+json">' . wp_json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . '</script>' . "\n";
	}

	private static function print_schema_scholarly( $paper_id, $title, $desc, $url ) {
		$doi     = get_post_meta( $paper_id, '_sjm_doi', true );
		$authors = WJM_Author_Profiles::get_authors_for_paper( $paper_id );
		$creator = array();
		foreach ( $authors as $author ) {
			$entry = array(
				'@type' => 'Person',
				'name'  => trim( $author->first_name . ' ' . $author->last_name ),
			);
			if ( $author->orcid ) {
				$entry['sameAs'] = 'https://orcid.org/' . $author->orcid;
			}
			if ( $author->affiliation ) {
				$entry['affiliation'] = array(
					'@type' => 'Organization',
					'name'  => $author->affiliation,
				);
			}
			$creator[] = $entry;
		}

		$data = array(
			'@context'    => 'https://schema.org',
			'@type'       => 'ScholarlyArticle',
			'headline'    => $title,
			'description' => $desc,
			'url'         => $url,
			'datePublished' => get_the_date( 'c', $paper_id ),
			'author'      => $creator,
		);
		if ( $doi ) {
			$data['identifier'] = array(
				'@type' => 'PropertyValue',
				'propertyID' => 'DOI',
				'value' => $doi,
			);
			$data['sameAs'] = 'https://doi.org/' . $doi;
		}
		echo '<script type="application/ld+json">' . wp_json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . '</script>' . "\n";
	}

	public static function register_rewrite() {
		add_rewrite_rule( 'wjm-sitemap-([0-9]+)\\.xml$', 'index.php?wjm_sitemap=$matches[1]', 'top' );
		add_rewrite_tag( '%wjm_sitemap%', '([0-9]+)' );
	}

	public static function serve_sitemap() {
		$journal_id = absint( get_query_var( 'wjm_sitemap' ) );
		if ( ! $journal_id ) {
			return;
		}
		$seo = self::get_journal_seo( $journal_id );
		if ( '1' !== $seo['sitemap_include'] || 'publish' !== get_post_status( $journal_id ) ) {
			status_header( 404 );
			exit;
		}

		$urls = array();
		$urls[] = array(
			'loc'     => get_permalink( $journal_id ),
			'lastmod' => get_post_modified_time( 'c', true, $journal_id ),
		);

		$issues = get_posts(
			array(
				'post_type'      => 'sjm_issue',
				'posts_per_page' => -1,
				'fields'         => 'ids',
				'meta_key'       => '_sjm_journal_id',
				'meta_value'     => $journal_id,
			)
		);
		foreach ( $issues as $issue_id ) {
			$urls[] = array(
				'loc'     => get_permalink( $issue_id ),
				'lastmod' => get_post_modified_time( 'c', true, $issue_id ),
			);
			$papers = get_posts(
				array(
					'post_type'      => 'sjm_paper',
					'post_status'    => 'publish',
					'posts_per_page' => -1,
					'fields'         => 'ids',
					'meta_key'       => '_sjm_issue_id',
					'meta_value'     => $issue_id,
				)
			);
			foreach ( $papers as $paper_id ) {
				if ( '1' === get_post_meta( $paper_id, '_sjm_seo_noindex', true ) ) {
					continue;
				}
				$urls[] = array(
					'loc'     => get_permalink( $paper_id ),
					'lastmod' => get_post_modified_time( 'c', true, $paper_id ),
				);
			}
		}

		nocache_headers();
		header( 'Content-Type: application/xml; charset=UTF-8' );
		echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
		echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
		foreach ( $urls as $u ) {
			echo '<url><loc>' . esc_url( $u['loc'] ) . '</loc>';
			if ( ! empty( $u['lastmod'] ) ) {
				echo '<lastmod>' . esc_html( $u['lastmod'] ) . '</lastmod>';
			}
			echo '</url>' . "\n";
		}
		echo '</urlset>';
		exit;
	}

	/**
	 * Keep core WP sitemaps aware of our CPTs.
	 *
	 * @param array  $args Args.
	 * @param string $post_type Type.
	 * @return array
	 */
	public static function core_sitemap_args( $args, $post_type ) {
		if ( in_array( $post_type, array( 'sjm_journal', 'sjm_issue', 'sjm_paper' ), true ) ) {
			$args['post_status'] = 'publish';
		}
		return $args;
	}
}
