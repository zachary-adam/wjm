/**
 * ORCID lookup / works / fill on submission form.
 */
(function () {
	function msg(el, text, ok) {
		if (!el) return;
		el.hidden = !text;
		el.textContent = text || '';
		el.classList.toggle('wjm-notice-success', !!ok);
		el.classList.toggle('wjm-notice-error', !!text && !ok);
	}

	function fillFrom(data) {
		if (!data) return;
		var authors = document.getElementById('wjm_authors_text');
		var corr = document.getElementById('wjm_corresponding');
		var guestName = document.getElementById('wjm_guest_name');
		var guestEmail = document.getElementById('wjm_guest_email');
		if (authors && data.author_line) {
			var cur = (authors.value || '').trim();
			authors.value = cur ? cur + '\n' + data.author_line : data.author_line;
		}
		if (corr && data.email) corr.value = data.email;
		if (guestName && data.name) guestName.value = data.name;
		if (guestEmail && data.email) guestEmail.value = data.email;
	}

	function renderWorks(listEl, works) {
		if (!listEl) return;
		listEl.innerHTML = '';
		if (!works || !works.length) {
			listEl.hidden = true;
			return;
		}
		listEl.hidden = false;
		works.forEach(function (w) {
			var li = document.createElement('li');
			var meta = [w.year, w.type, w.doi].filter(Boolean).join(' · ');
			li.innerHTML =
				'<strong></strong> <span class="meta"></span> ' +
				'<button type="button" class="wjm-btn wjm-btn-secondary" data-wjm-use-work>Use title</button>';
			li.querySelector('strong').textContent = w.title || '';
			li.querySelector('.meta').textContent = meta ? '(' + meta + ')' : '';
			var btn = li.querySelector('[data-wjm-use-work]');
			btn.setAttribute('data-title', w.title || '');
			btn.setAttribute('data-doi', w.doi || '');
			btn.setAttribute('data-url', w.url || '');
			listEl.appendChild(li);
		});
	}

	document.addEventListener('click', function (e) {
		var useWork = e.target.closest('[data-wjm-use-work]');
		if (useWork) {
			e.preventDefault();
			var title = document.getElementById('wjm_title');
			var preprint = document.getElementById('wjm_preprint');
			if (title) title.value = useWork.getAttribute('data-title') || '';
			if (preprint && useWork.getAttribute('data-url')) {
				preprint.value = useWork.getAttribute('data-url');
			}
			var panel = useWork.closest('[data-wjm-orcid]');
			msg(panel && panel.querySelector('.wjm-orcid-msg'), 'Title filled from ORCID work.', true);
			return;
		}

		var fillBtn = e.target.closest('[data-wjm-orcid-fill]');
		if (fillBtn) {
			e.preventDefault();
			fillFrom({
				author_line: fillBtn.getAttribute('data-line'),
				name: fillBtn.getAttribute('data-name'),
				email: fillBtn.getAttribute('data-email'),
			});
			var panelFill = fillBtn.closest('[data-wjm-orcid]');
			msg(panelFill && panelFill.querySelector('.wjm-orcid-msg'), 'Author line filled from ORCID.', true);
			return;
		}

		var worksBtn = e.target.closest('[data-wjm-orcid-works]');
		if (worksBtn && typeof wjmOrcid !== 'undefined') {
			e.preventDefault();
			var panelW = worksBtn.closest('[data-wjm-orcid]');
			var inputW = panelW && panelW.querySelector('#wjm_orcid_lookup');
			var statusW = panelW && panelW.querySelector('.wjm-orcid-msg');
			var listW = panelW && panelW.querySelector('[data-wjm-orcid-works-list]');
			var orcidW = worksBtn.getAttribute('data-orcid') || (inputW ? inputW.value.trim() : '');
			if (!orcidW) {
				msg(statusW, 'Enter or connect an ORCID iD first.', false);
				return;
			}
			msg(statusW, 'Loading works…', true);
			var bodyW = new FormData();
			bodyW.append('action', 'wjm_orcid_works');
			bodyW.append('nonce', wjmOrcid.nonce);
			bodyW.append('orcid', orcidW);
			fetch(wjmOrcid.ajaxUrl, { method: 'POST', body: bodyW, credentials: 'same-origin' })
				.then(function (r) {
					return r.json();
				})
				.then(function (json) {
					if (!json || !json.success) {
						msg(statusW, (json && json.data && json.data.message) || 'Works lookup failed.', false);
						return;
					}
					renderWorks(listW, json.data.works || []);
					msg(statusW, (json.data.works || []).length ? 'Select a work to fill the title.' : 'No public works found.', true);
				})
				.catch(function () {
					msg(statusW, 'Works lookup failed.', false);
				});
			return;
		}

		var lookupBtn = e.target.closest('[data-wjm-orcid-lookup]');
		if (!lookupBtn || typeof wjmOrcid === 'undefined') return;
		e.preventDefault();
		var panel = lookupBtn.closest('[data-wjm-orcid]');
		var input = panel && panel.querySelector('#wjm_orcid_lookup');
		var status = panel && panel.querySelector('.wjm-orcid-msg');
		var orcid = input ? input.value.trim() : '';
		if (!orcid) {
			msg(status, 'Enter an ORCID iD.', false);
			return;
		}
		msg(status, 'Looking up…', true);
		var body = new FormData();
		body.append('action', 'wjm_orcid_lookup');
		body.append('nonce', wjmOrcid.nonce);
		body.append('orcid', orcid);
		fetch(wjmOrcid.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
			.then(function (r) {
				return r.json();
			})
			.then(function (json) {
				if (!json || !json.success) {
					msg(status, (json && json.data && json.data.message) || 'Lookup failed.', false);
					return;
				}
				fillFrom(json.data);
				msg(status, 'Filled from public ORCID record.', true);
			})
			.catch(function () {
				msg(status, 'Lookup failed.', false);
			});
	});
})();
