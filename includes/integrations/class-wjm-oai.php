<?php
/**
 * Minimal OAI-PMH 2.0 endpoint for published papers (oai_dc).
 *
 * URL: /wjm-oai?verb=Identify  or  /?wjm_oai=1&verb=Identify
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_OAI {

	public static function init() {
		add_action( 'init', array( __CLASS__, 'rewrite' ) );
		add_filter( 'query_vars', array( __CLASS__, 'query_vars' ) );
		add_action( 'template_redirect', array( __CLASS__, 'serve' ), 0 );
	}

	public static function rewrite() {
		add_rewrite_rule( '^wjm-oai/?$', 'index.php?wjm_oai=1', 'top' );
		if ( ! get_option( 'wjm_oai_rewrite_flushed' ) ) {
			flush_rewrite_rules( false );
			update_option( 'wjm_oai_rewrite_flushed', 1 );
		}
	}

	/**
	 * @param string[] $vars Vars.
	 * @return string[]
	 */
	public static function query_vars( $vars ) {
		$vars[] = 'wjm_oai';
		return $vars;
	}

	/**
	 * @return string
	 */
	public static function base_url() {
		return home_url( '/wjm-oai' );
	}

	/**
	 * @return bool
	 */
	private static function is_request() {
		if ( get_query_var( 'wjm_oai' ) || isset( $_GET['wjm_oai'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return true;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		return (bool) preg_match( '#/(index\.php/)?wjm-oai(/|\?|$)#', $uri );
	}

	public static function serve() {
		if ( ! self::is_request() ) {
			return;
		}

		$verb = isset( $_GET['verb'] ) ? sanitize_text_field( wp_unslash( $_GET['verb'] ) ) : 'Identify'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		nocache_headers();
		header( 'Content-Type: text/xml; charset=UTF-8' );
		echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
		echo '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.openarchives.org/OAI/2.0/ http://www.openarchives.org/OAI/2.0/OAI-PMH.xsd">' . "\n";
		echo '<responseDate>' . esc_html( gmdate( 'Y-m-d\TH:i:s\Z' ) ) . '</responseDate>' . "\n";
		echo '<request verb="' . esc_attr( $verb ) . '">' . esc_url( self::base_url() ) . '</request>' . "\n";

		switch ( $verb ) {
			case 'Identify':
				self::identify();
				break;
			case 'ListMetadataFormats':
				self::list_metadata_formats();
				break;
			case 'ListSets':
				self::list_sets();
				break;
			case 'ListIdentifiers':
				self::list_records( false );
				break;
			case 'ListRecords':
				self::list_records( true );
				break;
			case 'GetRecord':
				self::get_record();
				break;
			default:
				self::error( 'badVerb', 'Illegal OAI verb' );
		}
		echo '</OAI-PMH>';
		exit;
	}

	private static function identify() {
		echo '<Identify>';
		echo '<repositoryName>' . self::x( get_bloginfo( 'name' ) . ' — WJM' ) . '</repositoryName>';
		echo '<baseURL>' . esc_url( self::base_url() ) . '</baseURL>';
		echo '<protocolVersion>2.0</protocolVersion>';
		echo '<adminEmail>' . self::x( get_option( 'admin_email' ) ) . '</adminEmail>';
		echo '<earliestDatestamp>' . esc_html( self::earliest() ) . '</earliestDatestamp>';
		echo '<deletedRecord>no</deletedRecord>';
		echo '<granularity>YYYY-MM-DD</granularity>';
		echo '</Identify>' . "\n";
	}

	private static function list_metadata_formats() {
		echo '<ListMetadataFormats>';
		echo '<metadataFormat>';
		echo '<metadataPrefix>oai_dc</metadataPrefix>';
		echo '<schema>http://www.openarchives.org/OAI/2.0/oai_dc.xsd</schema>';
		echo '<metadataNamespace>http://www.openarchives.org/OAI/2.0/oai_dc/</metadataNamespace>';
		echo '</metadataFormat>';
		echo '<metadataFormat>';
		echo '<metadataPrefix>oai_openaire</metadataPrefix>';
		echo '<schema>https://www.openaire.eu/schema/repo-lit/4.0/openaire.xsd</schema>';
		echo '<metadataNamespace>http://namespace.openaire.eu/schema/oaire/</metadataNamespace>';
		echo '</metadataFormat>';
		echo '</ListMetadataFormats>' . "\n";
	}

	private static function list_sets() {
		$journals = get_posts(
			array(
				'post_type'      => 'sjm_journal',
				'post_status'    => 'publish',
				'posts_per_page' => 100,
			)
		);
		echo '<ListSets>';
		foreach ( $journals as $j ) {
			echo '<set><setSpec>journal:' . (int) $j->ID . '</setSpec><setName>' . self::x( $j->post_title ) . '</setName></set>';
		}
		echo '</ListSets>' . "\n";
	}

	/**
	 * @param bool $with_meta Include metadata body.
	 */
	private static function list_records( $with_meta ) {
		$prefix = isset( $_GET['metadataPrefix'] ) ? sanitize_text_field( wp_unslash( $_GET['metadataPrefix'] ) ) : 'oai_dc'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! in_array( $prefix, array( 'oai_dc', 'oai_openaire' ), true ) ) {
			self::error( 'cannotDisseminateFormat', 'Only oai_dc and oai_openaire are supported' );
			return;
		}
		$set   = isset( $_GET['set'] ) ? sanitize_text_field( wp_unslash( $_GET['set'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$from  = isset( $_GET['from'] ) ? sanitize_text_field( wp_unslash( $_GET['from'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$until = isset( $_GET['until'] ) ? sanitize_text_field( wp_unslash( $_GET['until'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$args = array(
			'post_type'      => 'sjm_paper',
			'post_status'    => 'publish',
			'posts_per_page' => 100,
			'orderby'        => 'modified',
			'order'          => 'DESC',
		);
		if ( $set && 0 === strpos( $set, 'journal:' ) ) {
			$args['meta_query'] = array(
				array(
					'key'   => '_sjm_journal_id',
					'value' => absint( substr( $set, 8 ) ),
				),
			);
		}
		if ( $from || $until ) {
			$args['date_query'] = array(
				array(
					'column'    => 'post_modified_gmt',
					'after'     => $from ? $from : '1970-01-01',
					'before'    => $until ? $until . ' 23:59:59' : '2100-01-01',
					'inclusive' => true,
				),
			);
		}
		$papers = get_posts( $args );
		if ( ! $papers ) {
			self::error( 'noRecordsMatch', 'No matching records' );
			return;
		}
		$tag = $with_meta ? 'ListRecords' : 'ListIdentifiers';
		echo '<' . $tag . '>';
		foreach ( $papers as $p ) {
			if ( $with_meta ) {
				echo '<record>';
				self::header_xml( $p );
				echo '<metadata>';
				self::emit_metadata( $p, $prefix );
				echo '</metadata></record>';
			} else {
				self::header_xml( $p );
			}
		}
		echo '</' . $tag . '>' . "\n";
	}

	private static function get_record() {
		$prefix = isset( $_GET['metadataPrefix'] ) ? sanitize_text_field( wp_unslash( $_GET['metadataPrefix'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$id     = isset( $_GET['identifier'] ) ? sanitize_text_field( wp_unslash( $_GET['identifier'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! in_array( $prefix, array( 'oai_dc', 'oai_openaire' ), true ) ) {
			self::error( 'cannotDisseminateFormat', 'Only oai_dc and oai_openaire are supported' );
			return;
		}
		$paper_id = 0;
		if ( preg_match( '/:paper:(\d+)$/', $id, $m ) ) {
			$paper_id = absint( $m[1] );
		}
		$p = $paper_id ? get_post( $paper_id ) : null;
		if ( ! $p || 'sjm_paper' !== $p->post_type || 'publish' !== $p->post_status ) {
			self::error( 'idDoesNotExist', 'Unknown identifier' );
			return;
		}
		echo '<GetRecord><record>';
		self::header_xml( $p );
		echo '<metadata>';
		self::emit_metadata( $p, $prefix );
		echo '</metadata></record></GetRecord>' . "\n";
	}

	/**
	 * @param WP_Post $p Paper.
	 * @param string  $prefix Metadata prefix.
	 */
	private static function emit_metadata( $p, $prefix ) {
		if ( 'oai_openaire' === $prefix ) {
			self::oai_openaire( $p );
		} else {
			self::oai_dc( $p );
		}
	}

	/**
	 * @param WP_Post $p Paper.
	 */
	private static function header_xml( $p ) {
		$jid = (int) get_post_meta( $p->ID, '_sjm_journal_id', true );
		echo '<header>';
		echo '<identifier>' . self::x( self::identifier( $p->ID ) ) . '</identifier>';
		echo '<datestamp>' . esc_html( get_post_modified_time( 'Y-m-d', true, $p ) ) . '</datestamp>';
		if ( $jid ) {
			echo '<setSpec>journal:' . $jid . '</setSpec>';
		}
		echo '</header>';
	}

	/**
	 * OpenAIRE-enriched Dublin Core (Literature Guidelines).
	 *
	 * @param WP_Post $p Paper.
	 */
	private static function oai_dc( $p ) {
		$abstract = get_post_meta( $p->ID, '_sjm_abstract', true );
		$doi      = get_post_meta( $p->ID, '_sjm_doi', true );
		$authors  = class_exists( 'WJM_Author_Profiles' ) ? WJM_Author_Profiles::get_authors_for_paper( $p->ID ) : array();
		$jid      = (int) get_post_meta( $p->ID, '_sjm_journal_id', true );
		$oa       = get_post_meta( $p->ID, '_sjm_open_access', true );
		$rights   = get_post_meta( $p->ID, '_sjm_access_rights', true );
		if ( ! $rights ) {
			$rights = $oa ? 'openAccess' : 'restrictedAccess';
		}
		$funder = get_post_meta( $p->ID, '_sjm_funder_name', true );
		$grant  = get_post_meta( $p->ID, '_sjm_funding_grant', true );
		$proj   = get_post_meta( $p->ID, '_sjm_project_id', true );
		$funding = get_post_meta( $p->ID, '_sjm_funding', true );
		$keywords = wp_get_post_terms( $p->ID, 'sjm_keyword', array( 'fields' => 'names' ) );

		echo '<oai_dc:dc xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.openarchives.org/OAI/2.0/oai_dc/ http://www.openarchives.org/OAI/2.0/oai_dc.xsd">';
		echo '<dc:title>' . self::x( $p->post_title ) . '</dc:title>';
		foreach ( $authors as $a ) {
			echo '<dc:creator>' . self::x( trim( $a->first_name . ' ' . $a->last_name ) ) . '</dc:creator>';
		}
		if ( $abstract ) {
			echo '<dc:description>' . self::x( wp_strip_all_tags( $abstract ) ) . '</dc:description>';
		}
		echo '<dc:date>' . esc_html( get_the_date( 'Y-m-d', $p ) ) . '</dc:date>';
		echo '<dc:type>info:eu-repo/semantics/article</dc:type>';
		echo '<dc:type>article</dc:type>';
		echo '<dc:identifier>' . self::x( get_permalink( $p ) ) . '</dc:identifier>';
		if ( $doi ) {
			echo '<dc:identifier>' . self::x( 'doi:' . $doi ) . '</dc:identifier>';
			echo '<dc:identifier>' . self::x( 'https://doi.org/' . $doi ) . '</dc:identifier>';
		}
		echo '<dc:language>' . self::x( substr( get_bloginfo( 'language' ), 0, 3 ) ) . '</dc:language>';
		echo '<dc:rights>info:eu-repo/semantics/' . self::x( $rights ) . '</dc:rights>';
		if ( $jid ) {
			echo '<dc:source>' . self::x( get_the_title( $jid ) ) . '</dc:source>';
			$publisher = get_post_meta( $jid, '_sjm_publisher', true );
			if ( $publisher ) {
				echo '<dc:publisher>' . self::x( $publisher ) . '</dc:publisher>';
			}
			$issn = get_post_meta( $jid, '_sjm_issn', true );
			if ( $issn ) {
				echo '<dc:source>ISSN:' . self::x( $issn ) . '</dc:source>';
			}
		}
		if ( ! is_wp_error( $keywords ) ) {
			foreach ( $keywords as $kw ) {
				echo '<dc:subject>' . self::x( $kw ) . '</dc:subject>';
			}
		}
		if ( $grant ) {
			echo '<dc:relation>' . self::x( $grant ) . '</dc:relation>';
		}
		if ( $proj ) {
			echo '<dc:relation>info:eu-repo/grantAgreement/' . self::x( $proj ) . '</dc:relation>';
		}
		if ( $funder ) {
			echo '<dc:relation>info:eu-repo/grantAgreement/' . self::x( $funder ) . '</dc:relation>';
		}
		if ( $funding && ! $grant ) {
			echo '<dc:description>' . self::x( 'Funding: ' . $funding ) . '</dc:description>';
		}
		$preprint = get_post_meta( $p->ID, '_sjm_preprint_url', true );
		if ( $preprint ) {
			echo '<dc:relation>' . self::x( $preprint ) . '</dc:relation>';
		}
		echo '</oai_dc:dc>';
	}

	/**
	 * Lightweight OpenAIRE literature resource (oaire namespace).
	 *
	 * @param WP_Post $p Paper.
	 */
	private static function oai_openaire( $p ) {
		$abstract = get_post_meta( $p->ID, '_sjm_abstract', true );
		$doi      = get_post_meta( $p->ID, '_sjm_doi', true );
		$authors  = class_exists( 'WJM_Author_Profiles' ) ? WJM_Author_Profiles::get_authors_for_paper( $p->ID ) : array();
		$oa       = get_post_meta( $p->ID, '_sjm_open_access', true );
		$rights   = get_post_meta( $p->ID, '_sjm_access_rights', true );
		if ( ! $rights ) {
			$rights = $oa ? 'openAccess' : 'restrictedAccess';
		}
		$grant  = get_post_meta( $p->ID, '_sjm_funding_grant', true );
		$funder = get_post_meta( $p->ID, '_sjm_funder_name', true );
		$proj   = get_post_meta( $p->ID, '_sjm_project_id', true );
		$jid    = (int) get_post_meta( $p->ID, '_sjm_journal_id', true );

		echo '<oaire:resource xmlns:oaire="http://namespace.openaire.eu/schema/oaire/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:datacite="http://datacite.org/schema/kernel-4" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">';
		echo '<dc:title>' . self::x( $p->post_title ) . '</dc:title>';
		foreach ( $authors as $a ) {
			echo '<datacite:creator><datacite:creatorName>' . self::x( trim( $a->last_name . ', ' . $a->first_name ) ) . '</datacite:creatorName>';
			if ( ! empty( $a->orcid ) ) {
				echo '<datacite:nameIdentifier nameIdentifierScheme="ORCID" schemeURI="https://orcid.org">' . self::x( $a->orcid ) . '</datacite:nameIdentifier>';
			}
			echo '</datacite:creator>';
		}
		if ( $abstract ) {
			echo '<dc:description>' . self::x( wp_strip_all_tags( $abstract ) ) . '</dc:description>';
		}
		echo '<datacite:date dateType="Issued">' . esc_html( get_the_date( 'Y-m-d', $p ) ) . '</datacite:date>';
		echo '<oaire:resourceType resourceTypeGeneral="literature" uri="http://purl.org/coar/resource_type/c_6501">journal article</oaire:resourceType>';
		echo '<datacite:identifier identifierType="URL">' . self::x( get_permalink( $p ) ) . '</datacite:identifier>';
		if ( $doi ) {
			echo '<datacite:identifier identifierType="DOI">' . self::x( $doi ) . '</datacite:identifier>';
		}
		echo '<oaire:licenseCondition uri="info:eu-repo/semantics/' . self::x( $rights ) . '">' . self::x( $rights ) . '</oaire:licenseCondition>';
		if ( $jid ) {
			echo '<dc:source>' . self::x( get_the_title( $jid ) ) . '</dc:source>';
		}
		if ( $funder || $grant || $proj ) {
			echo '<oaire:fundingReference>';
			if ( $funder ) {
				echo '<oaire:funderName>' . self::x( $funder ) . '</oaire:funderName>';
			}
			if ( $grant ) {
				echo '<oaire:awardNumber>' . self::x( $grant ) . '</oaire:awardNumber>';
			}
			if ( $proj ) {
				echo '<oaire:fundingStream>' . self::x( $proj ) . '</oaire:fundingStream>';
			}
			echo '</oaire:fundingReference>';
		}
		echo '</oaire:resource>';
	}

	/**
	 * @param int $paper_id Paper ID.
	 * @return string
	 */
	public static function identifier( $paper_id ) {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return 'oai:' . $host . ':paper:' . absint( $paper_id );
	}

	/**
	 * @return string
	 */
	private static function earliest() {
		$p = get_posts(
			array(
				'post_type'      => 'sjm_paper',
				'post_status'    => 'publish',
				'posts_per_page' => 1,
				'orderby'        => 'date',
				'order'          => 'ASC',
			)
		);
		return $p ? get_the_date( 'Y-m-d', $p[0] ) : gmdate( 'Y-m-d' );
	}

	/**
	 * @param string $code Code.
	 * @param string $msg Message.
	 */
	private static function error( $code, $msg ) {
		echo '<error code="' . esc_attr( $code ) . '">' . self::x( $msg ) . '</error>' . "\n";
	}

	/**
	 * @param string $s String.
	 * @return string
	 */
	private static function x( $s ) {
		return htmlspecialchars( (string) $s, ENT_XML1 | ENT_QUOTES, 'UTF-8' );
	}
}
