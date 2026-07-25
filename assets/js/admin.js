(function ($) {
	'use strict';

	$(document).on('click', '.wjm-collab-submit', function (e) {
		e.preventDefault();
		var $box = $(this).closest('.wjm-collab');
		var note = $box.find('.wjm-collab-input').val();
		if (!note || typeof wjmAdmin === 'undefined') {
			return;
		}

		$.post(wjmAdmin.ajaxUrl, {
			action: 'wjm_add_collab_note',
			nonce: wjmAdmin.nonce,
			object_type: $box.data('object-type'),
			object_id: $box.data('object-id'),
			note: note
		}).done(function (resp) {
			if (!resp || !resp.success) {
				return;
			}
			var html = '<li><strong>' + resp.data.author + '</strong> <em>' + resp.data.time + '</em><p>' + resp.data.note + '</p></li>';
			$box.find('.wjm-collab-notes').prepend(html);
			$box.find('.wjm-collab-input').val('');
		});
	});

	$(document).on('click', '.wjm-transition-btn', function (e) {
		e.preventDefault();
		if (typeof wjmAdmin === 'undefined') {
			return;
		}
		var $btn = $(this);
		var paperId = $btn.data('paper-id');
		var to = $('#wjm_next_status').val();
		var note = $('#wjm_transition_note').val();
		var due = $('#wjm_revision_due').val() || '';

		$btn.prop('disabled', true);
		$.post(wjmAdmin.ajaxUrl, {
			action: 'wjm_transition_status',
			nonce: wjmAdmin.nonce,
			paper_id: paperId,
			to: to,
			note: note,
			revision_due: due
		}).done(function (resp) {
			if (resp && resp.success) {
				window.location.reload();
				return;
			}
			alert((resp && resp.data && resp.data.message) ? resp.data.message : 'Transition failed');
			$btn.prop('disabled', false);
		}).fail(function (xhr) {
			var msg = 'Transition failed';
			if (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) {
				msg = xhr.responseJSON.data.message;
			}
			alert(msg);
			$btn.prop('disabled', false);
		});
	});

	$(document).on('click', '.wjm-quick-transition', function (e) {
		e.preventDefault();
		if (typeof wjmAdmin === 'undefined') {
			return;
		}
		var $btn = $(this);
		var paperId = $btn.data('paper-id');
		var to = $btn.data('to');
		var note = $('#wjm_transition_note').val() || '';
		var due = $('#wjm_revision_due').val() || '';

		if (['accepted', 'rejected', 'desk_reject', 'revision'].indexOf(to) !== -1 && !note.trim()) {
			alert('Add a short decision note / letter before continuing.');
			return;
		}

		$btn.prop('disabled', true);
		$('.wjm-quick-transition').prop('disabled', true);
		$.post(wjmAdmin.ajaxUrl, {
			action: 'wjm_transition_status',
			nonce: wjmAdmin.nonce,
			paper_id: paperId,
			to: to,
			note: note,
			revision_due: due
		}).done(function (resp) {
			if (resp && resp.success) {
				window.location.reload();
				return;
			}
			alert((resp && resp.data && resp.data.message) ? resp.data.message : 'Transition failed');
			$('.wjm-quick-transition').prop('disabled', false);
		}).fail(function (xhr) {
			var msg = 'Transition failed';
			if (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) {
				msg = xhr.responseJSON.data.message;
			}
			alert(msg);
			$('.wjm-quick-transition').prop('disabled', false);
		});
	});
	$(document).on('click', '#wjm_load_letter', function (e) {
		e.preventDefault();
		var key = $('#wjm_letter_template').val();
		if (!key) {
			return;
		}
		var raw = $('#wjm-letter-json').text();
		if (!raw) {
			return;
		}
		try {
			var map = JSON.parse(raw);
			if (map[key]) {
				$('#wjm_transition_note').val(map[key]);
			}
		} catch (err) {
			return;
		}
	});
})(jQuery);
