/**
 * Preprint URL / DOI transfer into submit form.
 */
(function () {
	document.addEventListener('click', function (e) {
		var btn = e.target.closest('[data-wjm-preprint-fetch]');
		if (!btn || typeof wjmPreprint === 'undefined') return;
		e.preventDefault();
		var input = document.getElementById('wjm_preprint');
		var msg = document.querySelector('[data-wjm-preprint-msg]');
		var url = input ? input.value.trim() : '';
		if (!url) {
			if (msg) {
				msg.hidden = false;
				msg.textContent = 'Enter a preprint URL or DOI first.';
			}
			return;
		}
		if (msg) {
			msg.hidden = false;
			msg.textContent = 'Fetching preprint…';
		}
		var body = new FormData();
		body.append('action', 'wjm_preprint_lookup');
		body.append('nonce', wjmPreprint.nonce);
		body.append('url', url);
		fetch(wjmPreprint.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
			.then(function (r) {
				return r.json();
			})
			.then(function (json) {
				if (!json || !json.success) {
					if (msg) msg.textContent = (json && json.data && json.data.message) || 'Lookup failed.';
					return;
				}
				var d = json.data;
				var title = document.getElementById('wjm_title');
				var abs = document.getElementById('wjm_abstract');
				var authors = document.getElementById('wjm_authors_text');
				if (title && d.title) title.value = d.title;
				if (abs && d.abstract) abs.value = d.abstract;
				if (authors && d.authors_text) authors.value = d.authors_text;
				if (input && d.preprint_url) input.value = d.preprint_url;
				if (msg) msg.textContent = 'Filled from ' + (d.source || 'preprint') + '. Review before submit.';
			})
			.catch(function () {
				if (msg) msg.textContent = 'Lookup failed.';
			});
	});
})();
