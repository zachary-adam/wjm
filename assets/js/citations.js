/**
 * Citation Management JavaScript
 * Handles AJAX operations for citation tracking
 */

(function($) {
    'use strict';

    let searchTimeout = null;

    $(document).ready(function() {

        // ========================================
        // PAPER SEARCH FOR CITATIONS
        // ========================================

        $('#wjm-citation-search').on('input', function() {
            const searchTerm = $(this).val().trim();

            clearTimeout(searchTimeout);

            if (searchTerm.length < 3) {
                $('#wjm-citation-search-results').html('');
                return;
            }

            // Show loading
            $('#wjm-citation-search-results').html('<p style="color: #646970;"><span class="spinner is-active" style="float: none; margin: 0 5px 0 0;"></span>Searching...</p>');

            searchTimeout = setTimeout(function() {
                searchPapers(searchTerm);
            }, 500);
        });

        /**
         * Search for papers via AJAX
         */
        function searchPapers(searchTerm) {
            $.ajax({
                url: wjmCitations.ajax_url,
                type: 'POST',
                data: {
                    action: 'wjm_search_papers_for_citation',
                    nonce: wjmCitations.nonce,
                    search_term: searchTerm
                },
                success: function(response) {
                    if (response.success) {
                        displaySearchResults(response.data);
                    } else {
                        $('#wjm-citation-search-results').html('<p style="color: #d63638;">No results found.</p>');
                    }
                },
                error: function() {
                    $('#wjm-citation-search-results').html('<p style="color: #d63638;">Search failed. Please try again.</p>');
                }
            });
        }

        /**
         * Display search results
         */
        function displaySearchResults(results) {
            const $resultsContainer = $('#wjm-citation-search-results');
            $resultsContainer.empty();

            if (results.length === 0) {
                $resultsContainer.html('<p style="color: #646970;">No papers found matching your search.</p>');
                return;
            }

            results.forEach(function(paper) {
                const authorText = paper.authors ? paper.authors : 'Unknown authors';
                const doiText = paper.doi ? `DOI: ${paper.doi}` : '';

                const $result = $(`
                    <div class="wjm-citation-search-result" data-paper-id="${paper.id}" data-doi="${paper.doi || ''}">
                        <strong>${escapeHtml(paper.title)}</strong>
                        <small>${escapeHtml(authorText)} (${paper.year})</small>
                        ${doiText ? `<br><small style="color: #2271b1;">${escapeHtml(doiText)}</small>` : ''}
                    </div>
                `);

                $result.on('click', function() {
                    selectPaper(paper);
                });

                $resultsContainer.append($result);
            });
        }

        /**
         * Select a paper from search results
         */
        function selectPaper(paper) {
            // Highlight selected
            $('.wjm-citation-search-result').css('background', '');
            $(event.target).closest('.wjm-citation-search-result').css('background', '#f0f6fc');

            // Store selected paper data
            $('#wjm-citation-search').data('selected-paper-id', paper.id);
            $('#wjm-citation-search').data('selected-doi', paper.doi || '');

            // Show confirmation
            $('#wjm-citation-search').val(paper.title);
        }

        // ========================================
        // ADD CITATION
        // ========================================

        $('#wjm-add-citation-btn').on('click', function() {
            const $btn = $(this);
            const citedPaperId = $('#wjm-citation-search').data('selected-paper-id') || '';
            const citedDoi = $('#wjm-citation-doi').val().trim() || $('#wjm-citation-search').data('selected-doi') || '';
            const citationText = $('#wjm-citation-text').val().trim();

            // Validate
            if (!citedPaperId && !citedDoi) {
                alert('Please select a paper from search or enter a DOI manually.');
                return;
            }

            // Disable button and show loading
            $btn.prop('disabled', true).text('Adding...');

            $.ajax({
                url: wjmCitations.ajax_url,
                type: 'POST',
                data: {
                    action: 'wjm_add_citation',
                    nonce: wjmCitations.nonce,
                    paper_id: wjmCitations.paper_id,
                    cited_paper_id: citedPaperId,
                    cited_doi: citedDoi,
                    citation_text: citationText
                },
                success: function(response) {
                    if (response.success) {
                        // Show success message
                        showNotice('Citation added successfully!', 'success');

                        // Clear form
                        $('#wjm-citation-search').val('').removeData('selected-paper-id').removeData('selected-doi');
                        $('#wjm-citation-doi').val('');
                        $('#wjm-citation-text').val('');
                        $('#wjm-citation-search-results').html('');

                        // Reload page to show updated citation list
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        showNotice(response.data || wjmCitations.strings.error, 'error');
                    }
                },
                error: function() {
                    showNotice(wjmCitations.strings.error, 'error');
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Add Citation');
                }
            });
        });

        // ========================================
        // DELETE CITATION
        // ========================================

        $(document).on('click', '.wjm-delete-citation', function() {
            if (!confirm(wjmCitations.strings.confirm_delete)) {
                return;
            }

            const $btn = $(this);
            const citationId = $btn.data('citation-id');
            const $row = $btn.closest('tr');

            $btn.prop('disabled', true).text('Deleting...');

            $.ajax({
                url: wjmCitations.ajax_url,
                type: 'POST',
                data: {
                    action: 'wjm_delete_citation',
                    nonce: wjmCitations.nonce,
                    citation_id: citationId
                },
                success: function(response) {
                    if (response.success) {
                        // Remove row with animation
                        $row.fadeOut(300, function() {
                            $(this).remove();

                            // Check if table is now empty
                            if ($('#wjm-citations-tbody tr').length === 0) {
                                location.reload(); // Reload to show "no citations" message
                            }
                        });

                        showNotice('Citation deleted successfully!', 'success');
                    } else {
                        showNotice(response.data || wjmCitations.strings.error, 'error');
                        $btn.prop('disabled', false).text('Delete');
                    }
                },
                error: function() {
                    showNotice(wjmCitations.strings.error, 'error');
                    $btn.prop('disabled', false).text('Delete');
                }
            });
        });

        // ========================================
        // VERIFY CITATION
        // ========================================

        $(document).on('click', '.wjm-verify-citation', function() {
            const $btn = $(this);
            const citationId = $btn.data('citation-id');
            const $row = $btn.closest('tr');

            $btn.prop('disabled', true).text('Verifying...');

            $.ajax({
                url: wjmCitations.ajax_url,
                type: 'POST',
                data: {
                    action: 'wjm_verify_citation',
                    nonce: wjmCitations.nonce,
                    citation_id: citationId
                },
                success: function(response) {
                    if (response.success) {
                        // Update status column
                        $row.find('td:nth-child(5)').html('<span style="color: #00a32a;">✓ Verified</span>');

                        // Remove verify button
                        $btn.fadeOut(300, function() {
                            $(this).remove();
                        });

                        showNotice('Citation verified successfully!', 'success');
                    } else {
                        showNotice(response.data || wjmCitations.strings.error, 'error');
                        $btn.prop('disabled', false).text('Verify');
                    }
                },
                error: function() {
                    showNotice(wjmCitations.strings.error, 'error');
                    $btn.prop('disabled', false).text('Verify');
                }
            });
        });

        // ========================================
        // HELPER FUNCTIONS
        // ========================================

        /**
         * Show admin notice
         */
        function showNotice(message, type) {
            const noticeClass = type === 'success' ? 'notice-success' : 'notice-error';

            const $notice = $(`
                <div class="notice ${noticeClass} is-dismissible" style="margin: 15px 0;">
                    <p>${escapeHtml(message)}</p>
                    <button type="button" class="notice-dismiss">
                        <span class="screen-reader-text">Dismiss this notice.</span>
                    </button>
                </div>
            `);

            $('.wjm-citations-wrapper').prepend($notice);

            // Auto-dismiss after 5 seconds
            setTimeout(function() {
                $notice.fadeOut(300, function() {
                    $(this).remove();
                });
            }, 5000);

            // Manual dismiss
            $notice.find('.notice-dismiss').on('click', function() {
                $notice.fadeOut(300, function() {
                    $(this).remove();
                });
            });
        }

        /**
         * Escape HTML to prevent XSS
         */
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
        }

    });

})(jQuery);
