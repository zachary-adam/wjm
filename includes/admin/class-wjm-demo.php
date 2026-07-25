<?php
/**
 * One-click demo content importer.
 *
 * @package WisdomJournalManager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WJM_Demo {

	public static function init() {
		add_action( 'admin_post_wjm_import_demo', array( __CLASS__, 'handle_import' ) );
	}

	/**
	 * @return array Created IDs.
	 */
	public static function import() {
		$journal_id = wp_insert_post(
			array(
				'post_type'    => 'sjm_journal',
				'post_status'  => 'publish',
				'post_title'   => 'Shama Journal of Applied Inquiry',
				'post_content' => "A demonstration journal for Wisdom Journal Manager.\n\nThis sample content helps you explore submissions, peer review, issues, and public pages without starting from a blank site.",
				'post_name'    => 'shama-journal-of-applied-inquiry',
			)
		);

		update_post_meta( $journal_id, '_sjm_issn', '2456-0199' );
		update_post_meta( $journal_id, '_sjm_publisher', 'Shama Research' );
		update_post_meta( $journal_id, '_sjm_editorial_board', "Editor-in-Chief: A. Editor\nManaging Editor: B. Manager\nBoard: C. Scholar, D. Researcher" );

		$issue_id = wp_insert_post(
			array(
				'post_type'    => 'sjm_issue',
				'post_status'  => 'publish',
				'post_title'   => 'Volume 1, Issue 1 — Foundations',
				'post_content' => 'Inaugural issue of the demonstration journal.',
				'post_parent'  => $journal_id,
			)
		);
		update_post_meta( $issue_id, '_sjm_journal_id', $journal_id );
		update_post_meta( $issue_id, '_sjm_volume', '1' );
		update_post_meta( $issue_id, '_sjm_number', '1' );

		$papers = array(
			array(
				'title'    => 'Mapping Knowledge Systems Under Uncertainty',
				'abstract' => 'We introduce a practical framework for structuring evidence when sources conflict. Using graded trust and transparent assumptions, teams can produce auditable briefs suitable for academic and operational use.',
				'type'     => 'original_research',
				'status'   => 'published',
				'oa'       => '1',
				'doi'      => '10.1234/wjm.demo.001',
			),
			array(
				'title'    => 'Peer Review as a Public Good: Design Notes',
				'abstract' => 'This review synthesizes incentives for fair peer review in diamond OA journals and proposes lightweight workflows that editors can run without specialized infrastructure.',
				'type'     => 'review',
				'status'   => 'under_review',
				'oa'       => '1',
				'doi'      => '',
			),
			array(
				'title'    => 'A Short Note on Submission Portals',
				'abstract' => 'Authors need clarity: what is required, what is optional, and what happens next. We document a minimal submission checklist derived from editorial practice.',
				'type'     => 'letter',
				'status'   => 'submitted',
				'oa'       => '0',
				'doi'      => '',
			),
		);

		$paper_ids = array();
		foreach ( $papers as $i => $p ) {
			$pid = wp_insert_post(
				array(
					'post_type'    => 'sjm_paper',
					'post_status'  => 'published' === $p['status'] ? 'publish' : 'private',
					'post_title'   => $p['title'],
					'post_content' => "Demo body for «{$p['title']}».\n\nReplace this with real article content after you explore the workflow.",
					'post_author'  => get_current_user_id() ? get_current_user_id() : 1,
				)
			);
			update_post_meta( $pid, '_sjm_issue_id', $issue_id );
			update_post_meta( $pid, '_sjm_journal_id', $journal_id );
			update_post_meta( $pid, '_sjm_abstract', $p['abstract'] );
			update_post_meta( $pid, '_sjm_paper_type', $p['type'] );
			update_post_meta( $pid, '_sjm_open_access', $p['oa'] );
			update_post_meta( $pid, '_sjm_submission_date', gmdate( 'Y-m-d', strtotime( '-' . ( 30 - $i * 7 ) . ' days' ) ) );
			update_post_meta( $pid, '_sjm_funding', 'Demo funding — Shama Research internal seed.' );
			update_post_meta( $pid, '_sjm_conflicts', 'None declared.' );
			update_post_meta( $pid, '_sjm_ethics', 'Not applicable — conceptual work.' );
			update_post_meta( $pid, '_sjm_data_availability', 'No datasets generated.' );
			update_post_meta( $pid, '_sjm_page_range', ( 1 + $i * 12 ) . '–' . ( 12 + $i * 12 ) );
			if ( $p['doi'] ) {
				update_post_meta( $pid, '_sjm_doi', $p['doi'] );
			}
			update_post_meta( $pid, WJM_Workflow::META_STATUS, $p['status'] );
			if ( 'published' === $p['status'] ) {
				update_post_meta( $pid, '_sjm_acceptance_date', gmdate( 'Y-m-d', strtotime( '-10 days' ) ) );
				update_post_meta( $pid, '_sjm_citation_total', 3 + $i );
			}
			wp_set_object_terms( $pid, array( 'knowledge systems', 'open science', 'editorial practice' ), 'sjm_keyword', false );
			$paper_ids[] = $pid;

			if ( class_exists( 'WJM_Sync' ) ) {
				WJM_Sync::sync_paper( $pid );
			}
		}

		if ( class_exists( 'WJM_Author_Profiles' ) ) {
			$a1 = WJM_Author_Profiles::save_author(
				array(
					'first_name'  => 'Maaz',
					'last_name'   => 'Ahmad',
					'affiliation' => 'Shama Research',
					'orcid'       => '',
					'email'       => '',
				)
			);
			$a2 = WJM_Author_Profiles::save_author(
				array(
					'first_name'  => 'Zachary',
					'last_name'   => 'Adam',
					'affiliation' => 'Aethex / Shama Research',
					'orcid'       => '',
					'email'       => '',
				)
			);
			foreach ( $paper_ids as $pid ) {
				WJM_Author_Profiles::sync_paper_authors( $pid, array_filter( array( $a1, $a2 ) ) );
			}
		}

		if ( class_exists( 'WJM_Sync' ) ) {
			WJM_Sync::sync_journal( $journal_id );
			WJM_Sync::sync_issue( $issue_id );
		}

		WJM_Automated_Pages::ensure_catalog_page();
		WJM_Automated_Pages::ensure_submit_page();

		update_option( 'wjm_demo_imported_at', current_time( 'mysql', true ) );
		WJM_Audit::log(
			'info',
			'demo_imported',
			'Demo journal content imported.',
			array(
				'journal_id' => $journal_id,
				'issue_id'   => $issue_id,
				'papers'     => $paper_ids,
			)
		);

		return array(
			'journal_id' => $journal_id,
			'issue_id'   => $issue_id,
			'papers'     => $paper_ids,
		);
	}

	public static function handle_import() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'wisdom-journal-manager' ) );
		}
		check_admin_referer( 'wjm_import_demo' );
		$result = self::import();
		$paper  = ! empty( $result['papers'][0] ) ? absint( $result['papers'][0] ) : 0;
		wp_safe_redirect(
			admin_url(
				'edit.php?post_type=sjm_journal&page=wjm-getting-started&demo=1&journal=' . absint( $result['journal_id'] ) . ( $paper ? '&paper=' . $paper : '' )
			)
		);
		exit;
	}
}
