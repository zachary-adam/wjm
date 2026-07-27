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

		$btn.prop('disabled', true);
		$.post(wjmAdmin.ajaxUrl, {
			action: 'wjm_transition_status',
			nonce: wjmAdmin.nonce,
			paper_id: paperId,
			to: to,
			note: note
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
})(jQuery);
