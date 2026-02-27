<?php
/**
 * Demo Content Generator for Wisdom Journal Manager
 * Creates realistic sample journals, issues, and papers for testing every feature.
 */

if (!defined('ABSPATH')) {
    exit;
}

// ── Register submenu ──────────────────────────────────────────────────────────
function sjm_demo_content_menu() {
    add_submenu_page(
        'edit.php?post_type=journal',
        'Demo Content',
        '🧪 Demo Content',
        'manage_options',
        'sjm-demo-content',
        'sjm_demo_content_page'
    );
}
add_action('admin_menu', 'sjm_demo_content_menu', 99);

// ── Handle form submissions ────────────────────────────────────────────────────
function sjm_handle_demo_content_action() {
    if (empty($_POST['sjm_demo_action'])) return;
    if (!check_admin_referer('sjm_demo_content_nonce')) return;
    if (!current_user_can('manage_options')) return;

    if ($_POST['sjm_demo_action'] === 'generate') {
        sjm_generate_demo_content();
        wp_safe_redirect(add_query_arg(['page' => 'sjm-demo-content', 'demo_done' => '1'], admin_url('admin.php')));
    } elseif ($_POST['sjm_demo_action'] === 'delete') {
        sjm_delete_demo_content();
        wp_safe_redirect(add_query_arg(['page' => 'sjm-demo-content', 'demo_deleted' => '1'], admin_url('admin.php')));
    }
    exit;
}
add_action('admin_init', 'sjm_handle_demo_content_action');

// ── Generate all demo content ─────────────────────────────────────────────────
function sjm_generate_demo_content() {

    // ── JOURNALS ──────────────────────────────────────────────────────────────
    $journals_data = [
        [
            'title'   => 'Journal of Artificial Intelligence Research',
            'content' => 'A premier peer-reviewed publication dedicated to research in artificial intelligence, machine learning, natural language processing, and computer vision. Published continuously since 2012.',
            'meta'    => [
                '_sjm_issn'               => '2345-6789',
                '_sjm_publisher'          => 'Tech Academic Press',
                '_sjm_subject_areas'      => 'Artificial Intelligence, Machine Learning, Computer Science',
                '_sjm_language'           => 'English',
                '_sjm_open_access'        => '1',
                '_sjm_peer_reviewed'      => '1',
                '_sjm_founding_year'      => '2012',
                '_sjm_impact_factor'      => '4.82',
                '_sjm_website'            => 'https://example.com/jair',
                '_sjm_subscription_model' => 'open_access',
            ],
        ],
        [
            'title'   => 'International Journal of Medical Sciences',
            'content' => 'A subscription-based multidisciplinary medical journal publishing original research, clinical studies, and systematic reviews across all areas of medicine and clinical practice.',
            'meta'    => [
                '_sjm_issn'               => '1234-5678',
                '_sjm_publisher'          => 'Global Health Publishing',
                '_sjm_subject_areas'      => 'Medicine, Clinical Research, Public Health',
                '_sjm_language'           => 'English',
                '_sjm_open_access'        => '',
                '_sjm_peer_reviewed'      => '1',
                '_sjm_founding_year'      => '2005',
                '_sjm_impact_factor'      => '3.41',
                '_sjm_website'            => 'https://example.com/ijms',
                '_sjm_subscription_model' => 'subscription',
            ],
        ],
        [
            'title'   => 'Environmental Science & Sustainability',
            'content' => 'An open-access journal covering environmental monitoring, climate change, biodiversity conservation, sustainable development goals, and renewable energy research.',
            'meta'    => [
                '_sjm_issn'               => '3456-7890',
                '_sjm_publisher'          => 'Green Earth Publishers',
                '_sjm_subject_areas'      => 'Environmental Science, Climate Change, Sustainability',
                '_sjm_language'           => 'English',
                '_sjm_open_access'        => '1',
                '_sjm_peer_reviewed'      => '1',
                '_sjm_founding_year'      => '2016',
                '_sjm_impact_factor'      => '3.97',
                '_sjm_website'            => 'https://example.com/ess',
                '_sjm_subscription_model' => 'open_access',
            ],
        ],
        [
            'title'   => 'Asian Economics Review',
            'content' => 'A leading peer-reviewed economics journal focusing on macroeconomic policy, financial markets, international trade, and development economics in the Asia-Pacific region.',
            'meta'    => [
                '_sjm_issn'               => '5678-9012',
                '_sjm_publisher'          => 'Pacific Academic Press',
                '_sjm_subject_areas'      => 'Economics, Finance, Trade Policy, Development',
                '_sjm_language'           => 'English',
                '_sjm_open_access'        => '',
                '_sjm_peer_reviewed'      => '1',
                '_sjm_founding_year'      => '2001',
                '_sjm_impact_factor'      => '2.19',
                '_sjm_website'            => 'https://example.com/aer',
                '_sjm_subscription_model' => 'hybrid',
            ],
        ],
        [
            'title'   => 'Linguistics & Language Studies',
            'content' => 'An international open-access journal covering theoretical and applied linguistics, sociolinguistics, second language acquisition, and multilingualism in the digital age.',
            'meta'    => [
                '_sjm_issn'               => '6789-0123',
                '_sjm_publisher'          => 'Language Institute Press',
                '_sjm_subject_areas'      => 'Linguistics, Sociolinguistics, Language Acquisition',
                '_sjm_language'           => 'French',
                '_sjm_open_access'        => '1',
                '_sjm_peer_reviewed'      => '1',
                '_sjm_founding_year'      => '2018',
                '_sjm_impact_factor'      => '1.74',
                '_sjm_website'            => 'https://example.com/lls',
                '_sjm_subscription_model' => 'open_access',
            ],
        ],
        [
            'title'   => 'Journal of Quantum Physics',
            'content' => 'A subscription-based journal publishing foundational and applied research in quantum mechanics, quantum computing, condensed matter, topological materials, and particle physics.',
            'meta'    => [
                '_sjm_issn'               => '7890-1234',
                '_sjm_publisher'          => 'Physics Society International',
                '_sjm_subject_areas'      => 'Physics, Quantum Mechanics, Particle Physics',
                '_sjm_language'           => 'German',
                '_sjm_open_access'        => '',
                '_sjm_peer_reviewed'      => '1',
                '_sjm_founding_year'      => '1998',
                '_sjm_impact_factor'      => '5.67',
                '_sjm_website'            => 'https://example.com/jqp',
                '_sjm_subscription_model' => 'subscription',
            ],
        ],
    ];

    $journal_ids = [];
    foreach ($journals_data as $jd) {
        $pid = wp_insert_post([
            'post_title'   => $jd['title'],
            'post_content' => $jd['content'],
            'post_status'  => 'publish',
            'post_type'    => 'journal',
        ]);
        if ($pid && !is_wp_error($pid)) {
            foreach ($jd['meta'] as $key => $val) update_post_meta($pid, $key, $val);
            update_post_meta($pid, '_sjm_demo_content', '1');
            $journal_ids[] = $pid;
        }
    }

    // ── ISSUES (2 per journal) ────────────────────────────────────────────────
    $issues_map = [
        0 => [ // AI Research
            ['title' => 'Volume 13, Issue 1 — January 2024',        'vol' => '13', 'num' => '1', 'year' => '2024', 'date' => '2024-01-15', 'special' => '',  'stitle' => ''],
            ['title' => 'Volume 12, Issue 4 — October 2023 (Special: LLMs)', 'vol' => '12', 'num' => '4', 'year' => '2023', 'date' => '2023-10-01', 'special' => '1', 'stitle' => 'Large Language Models in Science'],
        ],
        1 => [ // Medical Sciences
            ['title' => 'Volume 20, Issue 2 — April 2024',          'vol' => '20', 'num' => '2', 'year' => '2024', 'date' => '2024-04-01', 'special' => '',  'stitle' => ''],
            ['title' => 'Volume 19, Issue 3 — July 2023',           'vol' => '19', 'num' => '3', 'year' => '2023', 'date' => '2023-07-01', 'special' => '',  'stitle' => ''],
        ],
        2 => [ // Environmental
            ['title' => 'Volume 9, Issue 1 — March 2024',           'vol' => '9',  'num' => '1', 'year' => '2024', 'date' => '2024-03-01', 'special' => '',  'stitle' => ''],
            ['title' => 'Volume 8, Issue 2 — June 2023 (Special: Climate Policy)', 'vol' => '8', 'num' => '2', 'year' => '2023', 'date' => '2023-06-15', 'special' => '1', 'stitle' => 'Climate Crisis & Policy Response'],
        ],
        3 => [ // Economics
            ['title' => 'Volume 24, Issue 1 — February 2024',       'vol' => '24', 'num' => '1', 'year' => '2024', 'date' => '2024-02-01', 'special' => '',  'stitle' => ''],
            ['title' => 'Volume 23, Issue 4 — December 2023',       'vol' => '23', 'num' => '4', 'year' => '2023', 'date' => '2023-12-01', 'special' => '',  'stitle' => ''],
        ],
        4 => [ // Linguistics
            ['title' => 'Volume 7, Issue 1 — January 2024',         'vol' => '7',  'num' => '1', 'year' => '2024', 'date' => '2024-01-01', 'special' => '',  'stitle' => ''],
            ['title' => 'Volume 6, Issue 2 — August 2023 (Special: Digital Multilingualism)', 'vol' => '6', 'num' => '2', 'year' => '2023', 'date' => '2023-08-01', 'special' => '1', 'stitle' => 'Digital Age Multilingualism'],
        ],
        5 => [ // Physics
            ['title' => 'Volume 27, Issue 1 — February 2024',       'vol' => '27', 'num' => '1', 'year' => '2024', 'date' => '2024-02-15', 'special' => '',  'stitle' => ''],
            ['title' => 'Volume 26, Issue 3 — September 2023',      'vol' => '26', 'num' => '3', 'year' => '2023', 'date' => '2023-09-01', 'special' => '',  'stitle' => ''],
        ],
    ];

    $issue_ids = [];
    foreach ($journal_ids as $j_idx => $jid) {
        $issue_ids[$j_idx] = [];
        foreach ($issues_map[$j_idx] as $id) {
            $pid = wp_insert_post([
                'post_title'  => $id['title'],
                'post_status' => 'publish',
                'post_type'   => 'journal_issue',
            ]);
            if ($pid && !is_wp_error($pid)) {
                update_post_meta($pid, '_sjm_issue_journal',       $jid);
                update_post_meta($pid, '_sjm_issue_volume',        $id['vol']);
                update_post_meta($pid, '_sjm_issue_number',        $id['num']);
                update_post_meta($pid, '_sjm_issue_year',          $id['year']);
                update_post_meta($pid, '_sjm_publication_date',    $id['date']);
                update_post_meta($pid, '_sjm_special_issue',       $id['special']);
                update_post_meta($pid, '_sjm_special_issue_title', $id['stitle']);
                update_post_meta($pid, '_sjm_demo_content',        '1');
                $issue_ids[$j_idx][] = $pid;
            }
        }
    }

    // ── PAPERS (3 per journal = 18 total) ────────────────────────────────────
    $papers = [
        // ─── Journal 0: AI Research ───────────────────────────────────────────
        [
            'title'   => 'Transformer Architecture Scaling Laws for Scientific Text Classification',
            'type'    => 'Research Article',
            'abstract'=> 'We investigate scaling laws for transformer-based language models applied to scientific literature classification. Our experiments across 12 benchmark datasets demonstrate that model performance scales predictably with parameter count and training data volume, with domain-specific pre-training yielding 18% improvements over general corpora. Optimal compute allocation favors data scaling over parameter scaling beyond 1B parameters.',
            'authors' => 'Chen, Wei; Rodriguez, Maria; Patel, Arjun',
            'keywords'=> 'transformer, scaling laws, text classification, NLP, scientific literature',
            'doi'     => '10.12345/jair.2024.001',
            'oa'      => '1',
            'date'    => '2024-01-10',
            'jidx'    => 0, 'iidx' => 0,
        ],
        [
            'title'   => 'Reinforcement Learning from Human Feedback: A Systematic Review',
            'type'    => 'Review Article',
            'abstract'=> 'This systematic review examines 147 studies on reinforcement learning from human feedback (RLHF) published between 2017 and 2024. We identify key methodological trends, open challenges in reward modeling, and propose a unified taxonomy for RLHF evaluation protocols. The review highlights convergence on Constitutional AI and debate-based approaches for scalable oversight.',
            'authors' => 'Kim, Jiyeon; Hoffmann, Lars',
            'keywords'=> 'RLHF, reinforcement learning, human feedback, reward modeling, LLM alignment',
            'doi'     => '10.12345/jair.2023.012',
            'oa'      => '1',
            'date'    => '2023-10-05',
            'jidx'    => 0, 'iidx' => 1,
        ],
        [
            'title'   => 'Emergent Reasoning in Large Language Models: A Case Study on STEM Problem Solving',
            'type'    => 'Case Study',
            'abstract'=> 'We present a detailed case study examining emergent reasoning capabilities in GPT-4 class models on multi-step STEM problems. Using a novel evaluation framework comprising 2,400 problems across physics, chemistry, and mathematics, we characterize the boundaries of in-context learning and chain-of-thought prompting. Structured prompting outperforms direct approaches by 31% on multi-step calculus.',
            'authors' => 'Nakamura, Yuki; Osei, Kwame; Torres, Isabella',
            'keywords'=> 'emergent reasoning, LLM, chain-of-thought, STEM, in-context learning',
            'doi'     => '10.12345/jair.2024.003',
            'oa'      => '1',
            'date'    => '2024-01-20',
            'jidx'    => 0, 'iidx' => 0,
        ],
        // ─── Journal 1: Medical Sciences ──────────────────────────────────────
        [
            'title'   => 'Long-term Cardiovascular Outcomes After mRNA Vaccination: A Multicenter Cohort Study',
            'type'    => 'Research Article',
            'abstract'=> 'A multicenter prospective cohort study of 284,000 adults aged 18-75 followed over 24 months post-vaccination. We report all-cause cardiovascular event rates stratified by age, sex, and pre-existing conditions. No elevated risk of major adverse cardiovascular events was observed compared to matched unvaccinated controls (HR 0.94, 95% CI 0.88-1.01). Sub-group analysis confirms safety across high-risk comorbidity profiles.',
            'authors' => 'Thompson, Eleanor; Muller, Hans; Srivastava, Priya',
            'keywords'=> 'mRNA vaccine, cardiovascular outcomes, cohort study, safety monitoring, post-marketing surveillance',
            'doi'     => '10.12345/ijms.2024.008',
            'oa'      => '',
            'date'    => '2024-03-15',
            'jidx'    => 1, 'iidx' => 0,
        ],
        [
            'title'   => 'Gut Microbiome Composition and SSRI Response in Major Depressive Disorder',
            'type'    => 'Research Article',
            'abstract'=> 'This randomized controlled trial enrolled 312 patients with major depressive disorder initiating SSRI therapy. Metagenomics analysis at baseline, 8 weeks, and 24 weeks reveals that Lactobacillus rhamnosus abundance at baseline predicts treatment response (AUC 0.74). Dietary microbiome modulation augments antidepressant efficacy by 24% versus placebo in non-responders.',
            'authors' => 'Park, Soo-Yeon; Andersson, Erik; Diallo, Fatou',
            'keywords'=> 'gut microbiome, SSRI, depression, metagenomics, treatment response, Lactobacillus',
            'doi'     => '10.12345/ijms.2023.042',
            'oa'      => '',
            'date'    => '2023-07-20',
            'jidx'    => 1, 'iidx' => 1,
        ],
        [
            'title'   => 'Editorial: Precision Medicine in Oncology — The Road Ahead',
            'type'    => 'Editorial',
            'abstract'=> 'This editorial reflects on the transformative decade of precision oncology, from the first FDA approval of imatinib for CML to the current landscape of CAR-T therapies and tumor-agnostic treatments. We outline editorial priorities for 2024-2026, emphasizing liquid biopsy standardization, real-world evidence integration, and equitable access to targeted therapies in low-income settings.',
            'authors' => 'Thompson, Eleanor',
            'keywords'=> 'precision medicine, oncology, CAR-T, personalized therapy, editorial, liquid biopsy',
            'doi'     => '10.12345/ijms.2024.001',
            'oa'      => '1',
            'date'    => '2024-04-01',
            'jidx'    => 1, 'iidx' => 0,
        ],
        // ─── Journal 2: Environmental Science ────────────────────────────────
        [
            'title'   => 'Sea Surface Temperature Anomalies and Tropical Cyclone Intensification: 1990-2023',
            'type'    => 'Research Article',
            'abstract'=> 'Analysis of 33 years of satellite sea surface temperature data and cyclone track records shows that rapid intensification events have increased 41% in frequency since 2000. Multiple regression identifies SST anomalies above +0.8 degrees C as the primary predictor, accounting for 67% of variance in intensification rate. Projections under SSP5-8.5 suggest a further 28% increase by 2050.',
            'authors' => 'Vasquez, Carlos; O\'Brien, Siobhan; Liang, Mei',
            'keywords'=> 'sea surface temperature, tropical cyclones, rapid intensification, climate change, satellite',
            'doi'     => '10.12345/ess.2024.011',
            'oa'      => '1',
            'date'    => '2024-02-28',
            'jidx'    => 2, 'iidx' => 0,
        ],
        [
            'title'   => 'Carbon Capture and Utilization in Cement Manufacturing: A Life-Cycle Assessment',
            'type'    => 'Research Article',
            'abstract'=> 'We conduct a comprehensive life-cycle assessment of post-combustion carbon capture and mineralization at a representative European cement plant. Results show net CO2 reductions of 68-82% per tonne of cement. The energy penalty of 210 kWh/t CO2 is primarily offset by on-site renewable integration. Economic analysis indicates breakeven at a carbon price of EUR 87/t under current technology costs.',
            'authors' => 'Johansson, Petra; Abubakar, Musa',
            'keywords'=> 'carbon capture, cement, life cycle assessment, CO2, mineralization, decarbonization',
            'doi'     => '10.12345/ess.2023.028',
            'oa'      => '1',
            'date'    => '2023-05-10',
            'jidx'    => 2, 'iidx' => 1,
        ],
        [
            'title'   => 'Microplastic Accumulation in Deep-Sea Sediments of the South Atlantic Ocean',
            'type'    => 'Research Article',
            'abstract'=> 'Core samples from 18 deep-sea stations (2,200-5,600 m depth) in the South Atlantic reveal microplastic concentrations of 1.8-24.7 particles per gram dry sediment. Polyethylene and polypropylene dominate the particle composition. Sedimentation rate modeling suggests a doubling of microplastic flux every 8.4 years since 1995, with convergence zones showing 3.8x higher concentrations.',
            'authors' => 'Santos, Ana Luisa; Kovacs, Tomas; Yilmaz, Fatma',
            'keywords'=> 'microplastics, deep sea, sediment, South Atlantic, ocean pollution, polyethylene',
            'doi'     => '10.12345/ess.2024.007',
            'oa'      => '1',
            'date'    => '2024-03-05',
            'jidx'    => 2, 'iidx' => 0,
        ],
        // ─── Journal 3: Economics ─────────────────────────────────────────────
        [
            'title'   => 'Digital Currency Adoption and Financial Inclusion in Sub-Saharan Africa',
            'type'    => 'Research Article',
            'abstract'=> 'Using household survey data from 14 Sub-Saharan African countries (N=87,420), we examine determinants of mobile money and CBDC adoption. Instrumental variable estimates suggest a 10-percentage-point increase in mobile internet penetration raises financial inclusion by 6.2 percentage points among previously unbanked adults. Women-headed households show disproportionate gains with gender-sensitive product design.',
            'authors' => 'Nkosi, Themba; Chen, Xiaoyan; Alabi, Olumide',
            'keywords'=> 'CBDC, mobile money, financial inclusion, Sub-Saharan Africa, digital currency, banking',
            'doi'     => '10.12345/aer.2024.004',
            'oa'      => '',
            'date'    => '2024-01-25',
            'jidx'    => 3, 'iidx' => 0,
        ],
        [
            'title'   => 'Trade War Spillovers: The Effect of US-China Tariffs on ASEAN Export Patterns',
            'type'    => 'Research Article',
            'abstract'=> 'Difference-in-differences analysis of HS6-digit trade flows shows that US-China tariff escalation from 2018-2020 generated significant trade diversion to ASEAN economies. Vietnam, Malaysia, and Thailand captured the largest export gains in electronics (elasticity 2.3) and machinery (elasticity 1.8). Welfare decomposition shows net ASEAN gains of USD 48 billion across the tariff escalation period.',
            'authors' => 'Tanaka, Hiroshi; Reyes, Gloria',
            'keywords'=> 'trade war, US-China tariffs, ASEAN, trade diversion, difference-in-differences, welfare',
            'doi'     => '10.12345/aer.2023.019',
            'oa'      => '',
            'date'    => '2023-11-15',
            'jidx'    => 3, 'iidx' => 1,
        ],
        [
            'title'   => 'Monetary Policy Transmission in Post-Pandemic Economies: Evidence from 40 Countries',
            'type'    => 'Review Article',
            'abstract'=> 'This review synthesizes empirical evidence on monetary policy transmission across 40 economies from 2020 to 2024, characterized by historically high inflation and unconventional tools. We document structural breaks in interest rate pass-through, reduced effectiveness of QE at the zero lower bound, and amplified fiscal-monetary coordination needs. Policy implications for emerging markets are discussed.',
            'authors' => 'Weber, Klaus; Okonkwo, Chidinma',
            'keywords'=> 'monetary policy, post-pandemic, inflation, interest rate, transmission, quantitative easing',
            'doi'     => '10.12345/aer.2024.001',
            'oa'      => '1',
            'date'    => '2024-02-01',
            'jidx'    => 3, 'iidx' => 0,
        ],
        // ─── Journal 4: Linguistics ───────────────────────────────────────────
        [
            'title'   => 'Code-Switching Patterns in Multilingual Social Media: A Corpus Study',
            'type'    => 'Research Article',
            'abstract'=> 'We analyze a 4.2-million-token corpus of multilingual Twitter data to characterize intra-sentential code-switching across English-Spanish, English-Arabic, and English-Mandarin pairs. Matrix language frame analysis reveals systematic asymmetries in embedding language selection correlated with topic domain and audience design. Political and sports topics show the highest switching rates (38% and 31% of tokens respectively).',
            'authors' => 'Garcia, Elena; Huang, Jian; Ezzaher, Lamia',
            'keywords'=> 'code-switching, multilingualism, corpus linguistics, social media, matrix language frame',
            'doi'     => '10.12345/lls.2024.005',
            'oa'      => '1',
            'date'    => '2024-01-05',
            'jidx'    => 4, 'iidx' => 0,
        ],
        [
            'title'   => 'L2 Acquisition of Tonal Contrasts: A Longitudinal Study of Mandarin Learners',
            'type'    => 'Research Article',
            'abstract'=> 'A two-year longitudinal study of 68 English-speaking learners of Mandarin tracks tonal accuracy development using acoustic measurements and perceptual judgments. Results reveal a U-shaped trajectory for Tone 3 distinct from the monotonic improvement for Tones 1 and 4. Musical aptitude explains 34% of variance in final tonal proficiency, outweighing prior language learning history.',
            'authors' => 'Okonkwo, Adaeze; Li, Bingxuan',
            'keywords'=> 'second language acquisition, Mandarin tones, longitudinal study, phonology, L2, musical aptitude',
            'doi'     => '10.12345/lls.2023.018',
            'oa'      => '1',
            'date'    => '2023-08-10',
            'jidx'    => 4, 'iidx' => 1,
        ],
        [
            'title'   => 'Endangered Language Revitalization through Digital Immersion Programs: Lessons from Welsh',
            'type'    => 'Case Study',
            'abstract'=> 'An evaluation of Welsh-medium digital immersion programs targeting adult heritage speakers (N=1,200) over three years. Participants showed statistically significant gains in oral fluency (d=0.81) and written proficiency (d=0.67). Motivation and digital usage frequency are the strongest predictors. The model is adaptable to other European minority languages facing similar demographic pressures.',
            'authors' => 'Williams, Rhiannon; Kovacevic, Maja',
            'keywords'=> 'language revitalization, Welsh, endangered languages, digital immersion, heritage speakers',
            'doi'     => '10.12345/lls.2024.003',
            'oa'      => '1',
            'date'    => '2024-01-15',
            'jidx'    => 4, 'iidx' => 0,
        ],
        // ─── Journal 5: Quantum Physics ───────────────────────────────────────
        [
            'title'   => 'Topological Superconductivity in Hybrid Semiconductor-Superconductor Nanowires',
            'type'    => 'Research Article',
            'abstract'=> 'We report experimental evidence of topological superconductivity in InAs/Al hybrid nanowires with epitaxial interfaces. Tunneling conductance spectroscopy reveals zero-bias peaks consistent with Majorana zero modes persisting over a 200 mT field range at 20 mK. The soft gap hardness exceeds 0.97 and local density of states profiles are characterized by transport measurements. These results constitute a significant step toward topological qubit implementations.',
            'authors' => 'Petrov, Dmitri; Sorensen, Niels; Yamazaki, Takashi',
            'keywords'=> 'topological superconductivity, Majorana modes, InAs nanowire, quantum computing, transport',
            'doi'     => '10.12345/jqp.2024.002',
            'oa'      => '',
            'date'    => '2024-02-10',
            'jidx'    => 5, 'iidx' => 0,
        ],
        [
            'title'   => 'Observation of Non-Hermitian Skin Effect in Acoustic Metamaterials',
            'type'    => 'Research Article',
            'abstract'=> 'We experimentally realize the non-Hermitian skin effect in a 1D acoustic metamaterial with engineered gain and loss. The bulk-boundary correspondence breakdown is characterized by eigenvalue winding numbers and localization lengths. A 94% localization contrast between open and periodic boundary conditions is demonstrated. Our realization establishes acoustic platforms as versatile testbeds for non-Hermitian topology.',
            'authors' => 'Dubois, Anais; Wang, Fang; Schulz, Michael',
            'keywords'=> 'non-Hermitian, skin effect, acoustic metamaterial, topological, gain-loss, bulk-boundary',
            'doi'     => '10.12345/jqp.2023.031',
            'oa'      => '',
            'date'    => '2023-09-05',
            'jidx'    => 5, 'iidx' => 1,
        ],
        [
            'title'   => 'Quantum Error Correction on Superconducting Processors: A Short Communication',
            'type'    => 'Short Communication',
            'abstract'=> 'We benchmark surface code and repetition code implementations on 5 commercial superconducting quantum processors. Logical error rates per cycle range from 3.1e-3 to 8.7e-3, with threshold fidelities between 98.4-99.2%. Gate crosstalk is identified as the dominant error mechanism. A dynamical decoupling mitigation strategy reduces logical error rates by 38% without hardware modifications.',
            'authors' => 'Nguyen, Thi Lan; Ferreira, Bruno',
            'keywords'=> 'quantum error correction, surface code, superconducting qubits, logical qubit, threshold, decoupling',
            'doi'     => '10.12345/jqp.2024.001',
            'oa'      => '1',
            'date'    => '2024-02-15',
            'jidx'    => 5, 'iidx' => 0,
        ],
    ];

    // ── AUTHORS (real records in wp_sjm_authors for clickable profiles) ──────
    global $wpdb;
    $authors_table = $wpdb->prefix . 'sjm_authors';
    sjm_create_authors_table();

    $demo_authors_insert = [
        0 => ['first_name' => 'Wei',     'last_name' => 'Chen',     'email' => 'wei.chen@ailab.edu',        'affiliation' => 'MIT Laboratory for Artificial Intelligence',              'bio' => 'Associate Professor specializing in NLP and large language models. PhD from Carnegie Mellon 2015. 90+ publications, 12,000+ citations.',                         'website' => 'https://example.com/wchen',    'orcid' => '0000-0001-2345-6789'],
        1 => ['first_name' => 'Jiyeon',  'last_name' => 'Kim',      'email' => 'j.kim@kaist.ac.kr',         'affiliation' => 'KAIST School of Computing, South Korea',                  'bio' => 'Research Scientist working on RLHF and AI alignment. Previously at Google DeepMind. 40+ publications.',                                                         'website' => '',                             'orcid' => '0000-0002-3456-7890'],
        2 => ['first_name' => 'Eleanor', 'last_name' => 'Thompson',  'email' => 'e.thompson@oxfordmed.ac.uk','affiliation' => 'University of Oxford Medical School',                     'bio' => 'Professor of Clinical Research and Editor-in-Chief. Expertise in precision oncology and clinical trials. 180+ publications.',                                   'website' => 'https://example.com/ethompson','orcid' => '0000-0003-4567-8901'],
        3 => ['first_name' => 'Carlos',  'last_name' => 'Vasquez',  'email' => 'c.vasquez@scripps.edu',     'affiliation' => 'Scripps Institution of Oceanography, UC San Diego',       'bio' => 'Senior Research Scientist studying ocean-atmosphere interactions and climate change impacts on tropical cyclone intensification.',                               'website' => '',                             'orcid' => '0000-0004-5678-9012'],
        4 => ['first_name' => 'Themba',  'last_name' => 'Nkosi',    'email' => 't.nkosi@uct.ac.za',         'affiliation' => 'University of Cape Town, School of Economics',            'bio' => 'Associate Professor in Development Economics. Research focuses on financial inclusion and digital currencies in Sub-Saharan Africa.',                          'website' => 'https://example.com/tnkosi',   'orcid' => '0000-0005-6789-0123'],
        5 => ['first_name' => 'Elena',   'last_name' => 'Garcia',   'email' => 'e.garcia@uab.es',           'affiliation' => 'Universitat Autonoma de Barcelona, Department of Linguistics','bio' => 'Reader in Sociolinguistics. Specializes in multilingualism, code-switching, and computational corpus approaches to language variation.',                   'website' => '',                             'orcid' => '0000-0006-7890-1234'],
        6 => ['first_name' => 'Dmitri',  'last_name' => 'Petrov',   'email' => 'd.petrov@ethz.ch',          'affiliation' => 'ETH Zurich, Department of Physics',                       'bio' => 'Professor of Experimental Quantum Physics. Leads the Topological Quantum Materials group. ERC Advanced Grant recipient 2022.',                               'website' => 'https://example.com/dpetrov', 'orcid' => '0000-0007-8901-2345'],
    ];

    $author_id_map = [];
    foreach ($demo_authors_insert as $idx => $a) {
        $existing_id = $wpdb->get_var($wpdb->prepare("SELECT id FROM $authors_table WHERE orcid = %s", $a['orcid']));
        if ($existing_id) {
            $author_id_map[$idx] = (int) $existing_id;
        } else {
            $wpdb->insert($authors_table, [
                'first_name'  => $a['first_name'],
                'last_name'   => $a['last_name'],
                'email'       => $a['email'],
                'affiliation' => $a['affiliation'],
                'bio'         => $a['bio'],
                'website'     => $a['website'],
                'orcid'       => $a['orcid'],
            ]);
            $author_id_map[$idx] = (int) $wpdb->insert_id;
        }
    }
    update_option('sjm_demo_author_ids', array_values($author_id_map));

    // Map: paper array index (0-17) => [[author_index, is_corresponding], ...]
    $paper_author_map = [
        0  => [[0, '1'], [1, '0']],  // AI paper 0:      Chen (corr.), Kim
        1  => [[1, '1'], [0, '0']],  // AI paper 1:      Kim (corr.), Chen
        2  => [[0, '0']],            // AI paper 2:      Chen
        3  => [[2, '1']],            // Medical paper 0: Thompson (corr.)
        4  => [[2, '0']],            // Medical paper 1: Thompson
        5  => [[2, '1']],            // Medical paper 2: Thompson (corr.)
        6  => [[3, '1']],            // Env paper 0:     Vasquez (corr.)
        7  => [[3, '0']],            // Env paper 1:     Vasquez
        8  => [[3, '0']],            // Env paper 2:     Vasquez
        9  => [[4, '1']],            // Econ paper 0:    Nkosi (corr.)
        10 => [[4, '0']],            // Econ paper 1:    Nkosi
        11 => [[4, '0']],            // Econ paper 2:    Nkosi
        12 => [[5, '1']],            // Ling paper 0:    Garcia (corr.)
        13 => [[5, '0']],            // Ling paper 1:    Garcia
        14 => [[5, '0']],            // Ling paper 2:    Garcia
        15 => [[6, '1']],            // Quantum paper 0: Petrov (corr.)
        16 => [[6, '0']],            // Quantum paper 1: Petrov
        17 => [[6, '0']],            // Quantum paper 2: Petrov
    ];

    foreach ($papers as $paper_idx => $p) {
        $jid = $journal_ids[$p['jidx']] ?? 0;
        $iid = $issue_ids[$p['jidx']][$p['iidx']] ?? 0;

        $pid = wp_insert_post([
            'post_title'  => $p['title'],
            'post_status' => 'publish',
            'post_type'   => 'paper',
        ]);
        if ($pid && !is_wp_error($pid)) {
            update_post_meta($pid, '_sjm_paper_journal',       $jid);
            update_post_meta($pid, '_sjm_paper_issue',         $iid);
            update_post_meta($pid, '_sjm_paper_abstract',      $p['abstract']);
            update_post_meta($pid, '_sjm_paper_type',          $p['type']);
            update_post_meta($pid, '_sjm_paper_keywords',      $p['keywords']);
            update_post_meta($pid, '_sjm_paper_authors',       $p['authors']);
            update_post_meta($pid, '_sjm_paper_doi',           $p['doi']);
            update_post_meta($pid, '_sjm_paper_open_access',   $p['oa']);
            update_post_meta($pid, '_sjm_paper_peer_reviewed', '1');
            update_post_meta($pid, '_sjm_acceptance_date',     $p['date']);
            update_post_meta($pid, '_sjm_demo_content',        '1');

            // Link real author records so names are clickable
            if (isset($paper_author_map[$paper_idx])) {
                $authors_data = [];
                $order = 1;
                foreach ($paper_author_map[$paper_idx] as $ai) {
                    $a_idx = $ai[0];
                    if (isset($author_id_map[$a_idx])) {
                        $authors_data[] = [
                            'author_id'       => $author_id_map[$a_idx],
                            'role'            => 'Author',
                            'is_corresponding' => $ai[1],
                            'contributions'   => '',
                            'order'           => $order++,
                        ];
                    }
                }
                if (!empty($authors_data)) {
                    update_post_meta($pid, '_sjm_paper_authors_data', $authors_data);
                }
            }
        }
    }
}

// ── Delete all demo content ────────────────────────────────────────────────────
function sjm_delete_demo_content() {
    foreach (['journal', 'journal_issue', 'paper'] as $pt) {
        $posts = get_posts([
            'post_type'      => $pt,
            'posts_per_page' => -1,
            'meta_key'       => '_sjm_demo_content',
            'meta_value'     => '1',
        ]);
        foreach ($posts as $post) {
            wp_delete_post($post->ID, true);
        }
    }

    // Delete demo authors from custom table
    $demo_author_ids = get_option('sjm_demo_author_ids', []);
    if (!empty($demo_author_ids)) {
        global $wpdb;
        $authors_table = $wpdb->prefix . 'sjm_authors';
        foreach ($demo_author_ids as $aid) {
            $wpdb->delete($authors_table, ['id' => intval($aid)], ['%d']);
        }
        delete_option('sjm_demo_author_ids');
    }
}

// ── Admin page UI ─────────────────────────────────────────────────────────────
function sjm_demo_content_page() {
    if (!current_user_can('manage_options')) return;

    $demo_journals = get_posts(['post_type' => 'journal',       'posts_per_page' => -1, 'meta_key' => '_sjm_demo_content', 'meta_value' => '1']);
    $demo_issues   = get_posts(['post_type' => 'journal_issue', 'posts_per_page' => -1, 'meta_key' => '_sjm_demo_content', 'meta_value' => '1']);
    $demo_papers   = get_posts(['post_type' => 'paper',         'posts_per_page' => -1, 'meta_key' => '_sjm_demo_content', 'meta_value' => '1']);
    $total         = count($demo_journals) + count($demo_issues) + count($demo_papers);
    $has_demo      = $total > 0;
    ?>
    <div class="wrap wjm-modern-wrap">

        <div class="wjm-page-header">
            <div class="wjm-page-header-info">
                <h1 class="wjm-page-title">Demo Content</h1>
                <p class="wjm-page-subtitle">Generate realistic sample data to test every plugin feature</p>
            </div>
        </div>

        <?php if (isset($_GET['demo_done'])): ?>
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:12px 16px;margin-bottom:20px;color:#15803d;font-weight:500;">
            ✓ Demo content generated — 6 journals, 12 issues, 18 papers, and 7 author profiles created. Author names on paper pages are now clickable.
        </div>
        <?php elseif (isset($_GET['demo_deleted'])): ?>
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:12px 16px;margin-bottom:20px;color:#15803d;font-weight:500;">
            ✓ All demo content has been removed.
        </div>
        <?php endif; ?>

        <?php if ($has_demo): ?>

        <!-- ── Stats ── -->
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
            <?php
            $stat_cards = [
                ['label'=>'Journals',  'count'=>count($demo_journals), 'bg'=>'#f0fdf4','border'=>'#bbf7d0','color'=>'#15803d'],
                ['label'=>'Issues',    'count'=>count($demo_issues),   'bg'=>'#eff6ff','border'=>'#bfdbfe','color'=>'#1d4ed8'],
                ['label'=>'Papers',    'count'=>count($demo_papers),   'bg'=>'#faf5ff','border'=>'#e9d5ff','color'=>'#7c3aed'],
                ['label'=>'Total',     'count'=>$total,                'bg'=>'#fff7ed','border'=>'#fed7aa','color'=>'#c2410c'],
            ];
            foreach ($stat_cards as $sc): ?>
            <div style="background:<?php echo $sc['bg']; ?>;border:1px solid <?php echo $sc['border']; ?>;border-radius:6px;padding:20px;text-align:center;">
                <div style="font-size:32px;font-weight:700;color:<?php echo $sc['color']; ?>;"><?php echo $sc['count']; ?></div>
                <div style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;margin-top:4px;"><?php echo $sc['label']; ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- ── Journals table ── -->
        <div class="wjm-card" style="margin-bottom:24px;">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">Demo Journals</h2>
            </div>
            <div class="wjm-card-body" style="padding:0;">
                <table class="wjm-table">
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Publisher</th>
                            <th>Language</th>
                            <th>Access</th>
                            <th>IF</th>
                            <th>View</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($demo_journals as $journal):
                            $publisher = get_post_meta($journal->ID, '_sjm_publisher', true);
                            $lang      = get_post_meta($journal->ID, '_sjm_language', true);
                            $if        = get_post_meta($journal->ID, '_sjm_impact_factor', true);
                            $oa        = get_post_meta($journal->ID, '_sjm_open_access', true);
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html($journal->post_title); ?></strong></td>
                            <td style="color:#6b7280;"><?php echo esc_html($publisher); ?></td>
                            <td style="color:#6b7280;"><?php echo esc_html($lang); ?></td>
                            <td>
                                <?php if ($oa): ?>
                                    <span style="background:#f0fdf4;color:#15803d;border:1px solid #bbf7d0;border-radius:3px;padding:2px 8px;font-size:11px;font-weight:600;text-transform:uppercase;">Open Access</span>
                                <?php else: ?>
                                    <span style="background:#fff7ed;color:#c2410c;border:1px solid #fed7aa;border-radius:3px;padding:2px 8px;font-size:11px;font-weight:600;text-transform:uppercase;">Subscription</span>
                                <?php endif; ?>
                            </td>
                            <td style="color:#374151;font-weight:500;"><?php echo esc_html($if); ?></td>
                            <td><a href="<?php echo esc_url(get_permalink($journal->ID)); ?>" target="_blank" class="wjm-btn wjm-btn-sm wjm-btn-secondary">View ↗</a></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ── Delete form ── -->
        <form method="post" action="" onsubmit="return confirm('Delete all <?php echo $total; ?> demo items permanently?');">
            <?php wp_nonce_field('sjm_demo_content_nonce'); ?>
            <input type="hidden" name="sjm_demo_action" value="delete">
            <div class="wjm-card">
                <div class="wjm-card-body">
                    <p style="color:#6b7280;margin:0 0 16px;">Remove all demo journals, issues, and papers from the database.</p>
                    <button type="submit" class="wjm-btn" style="background:#dc2626;color:#fff;border-color:#dc2626;">
                        <span class="dashicons dashicons-trash" style="margin-top:3px;"></span> Delete All Demo Content (<?php echo $total; ?> items)
                    </button>
                </div>
            </div>
        </form>

        <?php else: ?>

        <!-- ── What will be created ── -->
        <div class="wjm-tip-grid" style="margin-bottom:28px;">
            <?php
            $tips = [
                ['icon' => '📖', 'count' => '6', 'noun' => 'Academic Journals',
                 'desc' => 'AI Research, Medical, Environmental, Economics, Linguistics, Quantum Physics — mix of open access & subscription, 3 languages'],
                ['icon' => '📚', 'count' => '12', 'noun' => 'Journal Issues',
                 'desc' => '2 issues per journal — regular and special issues, 2023–2024 dates, various volumes and numbers'],
                ['icon' => '📄', 'count' => '18', 'noun' => 'Research Papers',
                 'desc' => '3 per journal — Research Articles, Reviews, Case Studies, Editorials, Short Communications — realistic abstracts, DOIs, keywords, authors'],
            ];
            foreach ($tips as $t): ?>
            <div class="wjm-card" style="text-align:center;padding:24px 20px;">
                <div style="font-size:36px;margin-bottom:12px;"><?php echo $t['icon']; ?></div>
                <div style="font-size:28px;font-weight:700;color:#111827;line-height:1;"><?php echo $t['count']; ?></div>
                <div style="font-size:14px;font-weight:600;color:#374151;margin:6px 0 10px;"><?php echo $t['noun']; ?></div>
                <div style="font-size:13px;color:#6b7280;line-height:1.5;"><?php echo $t['desc']; ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- ── Feature coverage ── -->
        <div class="wjm-card" style="margin-bottom:24px;">
            <div class="wjm-card-header">
                <h2 class="wjm-card-title">Features Covered</h2>
            </div>
            <div class="wjm-card-body">
                <ul class="wjm-guide-ul">
                    <li>Journal grid &amp; list shortcodes — publisher, subject, language, access type, peer-review filters</li>
                    <li>Single journal page — basic info, academic metadata, subscription/OA badges, issues list</li>
                    <li>Issues shortcode — volume, year, special issue filters</li>
                    <li>Single issue page — publication details, embedded papers listing</li>
                    <li>Papers shortcode — type, author, keyword, year, journal filters</li>
                    <li>Single paper page — full abstract, DOI, author list, citation metadata</li>
                    <li>Multi-language journals — English, French, German</li>
                    <li>Open Access vs Subscription access models</li>
                    <li>All paper types: Research Article, Review Article, Case Study, Editorial, Short Communication</li>
                    <li>Special issues with custom titles</li>
                    <li>Peer-reviewed flag on all papers</li>
                </ul>
            </div>
        </div>

        <!-- ── Generate form ── -->
        <form method="post" action="">
            <?php wp_nonce_field('sjm_demo_content_nonce'); ?>
            <input type="hidden" name="sjm_demo_action" value="generate">
            <div class="wjm-card">
                <div class="wjm-card-body">
                    <p style="color:#6b7280;margin:0 0 16px;">This will add 36 new WordPress posts tagged as demo content. You can delete them all with one click afterwards.</p>
                    <button type="submit" class="wjm-btn wjm-btn-primary wjm-btn-lg">
                        <span class="dashicons dashicons-database-add" style="margin-top:3px;"></span> Generate Demo Content
                    </button>
                </div>
            </div>
        </form>

        <?php endif; ?>
    </div>
    <?php
}
