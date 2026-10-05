const $ = id => document.getElementById(id);
let current = null,
    offset = 0,
    historySequence = 0;
const names = {
    phishing: 'Phishing',
    sqli: 'SQL injection',
    xss: 'Cross-site scripting',
    command_injection: 'Command injection',
    path_traversal: 'Path traversal'
};
const examples = [
    ['Benign', 'http_request', 'GET /products?page=2 HTTP/1.1'],
    ['URL', 'url', 'https://github.com/openai'],
    ['SQLi', 'payload', "' OR 1=1--"],
    ['XSS', 'payload', '<script>alert(1)</script>'],
    ['Command', 'payload', 'localhost;whoami'],
    ['Traversal', 'payload', '../../etc/passwd']
];

function element(tag, text, cls) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (cls) el.className = cls;
    return el;
}
async function api(path, options) {
    const response = await fetch(path, options);
    let data;
    try {
        data = await response.json();
    } catch {
        throw Error('Could not read the server response.');
    }
    if (!response.ok) throw Error(typeof data.detail === 'string' ? data.detail : 'Check the input format and size, then try again.');
    return data;
}

function changed() {
    $('count').textContent = `${Array.from($('content').value).length} / 10,000`;
    $('body-label').hidden = $('kind').value !== 'payload';
    if (current) $('error').textContent = 'Input changed. Run analysis to update the displayed result.';
}
for (const [name, kind, text] of examples) {
    const b = element('button', name);
    b.type = 'button';
    b.onclick = () => {
        $('kind').value = kind;
        $('body-kind').value = 'text/plain';
        $('content').value = text;
        changed();
    };
    $('samples').append(b);
}
$('content').oninput = changed;
$('kind').onchange = changed;
$('body-kind').onchange = changed;

function render(r) {
    current = r;
    const root = $('result');
    root.replaceChildren();
    const top = element('div', undefined, 'verdict');
    top.append(element('h2', r.decision, r.decision), element('strong', r.risk_score === null ? '—' : `${r.risk_score.toFixed(0)} / 100`, 'score'));
    root.append(top, element('p', 'Experimental risk index · ' + r.analysis_ms + ' ms · ' + r.status, 'note'), element('p', 'Recommended decision only. No traffic action taken.', 'note'));
    for (const event of r.enforcement_events || []) root.append(element('p', `Integration acknowledged: ${event.action} (${event.mode} mode)`));
    for (const reason of r.reasons) root.append(element('p', reason));
    for (const [key, value] of Object.entries(r.category_scores)) {
        const row = element('div', undefined, 'signal');
        row.append(element('strong', names[key]), element('span', value === null ? ' · Not assessed' : ` · ${value.toFixed(1)}`));
        const bar = element('div', undefined, 'bar');
        const fill = element('span');
        fill.style.width = `${value||0}%`;
        bar.append(fill);
        row.append(bar);
        root.append(row);
    }
    const details = element('details');
    details.open = true;
    details.append(element('summary', 'Pattern evidence'));
    const rules = r.findings.filter(f => f.evidence_kind === 'rule');
    if (!rules.length) details.append(element('p', 'No explicit rule matched.'));
    for (const f of rules) {
        const row = element('div', undefined, 'signal');
        row.append(element('strong', f.summary), element('p', `${f.rule_id} · ${f.component} · ${f.view} view · ${f.start===null?'URL structure':`positions ${f.start}–${f.end}`}`));
        details.append(row);
    }
    root.append(details);
    const models = element('details');
    models.append(element('summary', 'ML analysis'));
    for (const [detector, signal] of Object.entries(r.model_signals)) {
        models.append(element('h3', detector === 'request' ? 'Request classifier' : 'Phishing classifier'));
        models.append(element('p', 'Experimental and uncalibrated · model scores are not verified threat probabilities.', 'note'));
        if (signal.probabilities)
            for (const [label, value] of Object.entries(signal.probabilities).sort((a, b) => b[1] - a[1])) models.append(element('p', `${label}: ${(value*100).toFixed(1)} / 100`));
        if (signal.probability !== undefined) models.append(element('p', `Model score: ${(signal.probability*100).toFixed(1)} / 100`));
        if (signal.note) models.append(element('p', signal.note, 'note'));
    }
    root.append(models);
    const coverage = element('details');
    coverage.append(element('summary', 'Analysis coverage and versions'));
    for (const [k, v] of Object.entries({
            ...r.coverage,
            ...r.versions
        })) coverage.append(element('p', `${k}: ${v}`, 'note'));
    root.append(coverage);
    $('export').hidden = false;
}
async function refresh() {
    const seq = ++historySequence;
    try {
        const [s, h] = await Promise.all([api('/api/v1/dashboard/summary'), api(`/api/v1/scans?limit=10&offset=${offset}` + ($('filter').value ? '&decision=' + encodeURIComponent($('filter').value) : ''))]);
        if (seq !== historySequence) return;
        $('history-error').textContent = '';
        $('total').textContent = s.total;
        $('enforced').textContent = s.enforced_blocks;
        $('allows').textContent = s.decisions.Allow;
        $('reviews').textContent = s.decisions.Review;
        $('blocks').textContent = s.decisions.Block;
        renderDashboard(s);
        $('history').replaceChildren();
        for (const r of h.items) {
            const tr = element('tr');
            tr.append(element('td', new Date(r.created_at).toLocaleString()), element('td', r.input_type), element('td', r.decision, r.decision));
            const td = element('td');
            const button = element('button', r.scan_id.slice(0, 8) + ' ↗');
            button.onclick = async () => {
                try {
                    render(await api('/api/v1/scans/' + r.scan_id));
                    $('error').textContent = 'Viewing a saved result; editor content has not been restored.';
                    $('result').scrollIntoView({
                        behavior: 'smooth',
                        block: 'center'
                    });
                } catch (e) {
                    $('history-error').textContent = e.message;
                }
            };
            td.append(button);
            tr.append(td);
            $('history').append(tr);
        }
        if (!h.items.length) {
            const tr = element('tr');
            const td = element('td', 'No scans yet for this filter.');
            td.colSpan = 4;
            tr.append(td);
            $('history').append(tr);
        }
        $('page').textContent = h.total ? `${offset+1}–${Math.min(offset+10,h.total)} of ${h.total}` : '0 scans';
        $('prev').disabled = offset === 0;
        $('next').disabled = offset + 10 >= h.total;
    } catch (e) {
        $('history-error').textContent = e.message;
    }
}
$('form').onsubmit = async event => {
    event.preventDefault();
    document.querySelectorAll('#form input,#form select,#form textarea,#form button').forEach(el => el.disabled = true);
    $('submit').textContent = 'Analysing…';
    $('error').textContent = '';
    try {
        const r = await api('/api/v1/scans', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                input_type: $('kind').value,
                content: $('content').value,
                content_type: $('body-kind').value
            })
        });
        render(r);
        offset = 0;
        await refresh();
    } catch (e) {
        $('error').textContent = e.message;
    } finally {
        document.querySelectorAll('#form input,#form select,#form textarea,#form button').forEach(el => el.disabled = false);
        $('submit').textContent = 'Analyse input ↗';
    }
};
$('export').onclick = () => {
    if (!current) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(current, null, 2)], {
        type: 'application/json'
    }));
    const a = element('a');
    a.href = url;
    a.download = 'Prahari-' + current.scan_id + '.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$('filter').onchange = () => {
    offset = 0;
    refresh();
};
$('prev').onclick = () => {
    offset = Math.max(0, offset - 10);
    refresh();
};
$('next').onclick = () => {
    offset += 10;
    refresh();
};
api('/ready').then(() => {
    $('health').textContent = 'Models connected';
}).catch(() => {
    $('health').textContent = 'Detector unavailable';
});
refresh();

setInterval(refresh, 10000);

function renderDashboard(s) {
    $('partial').textContent = s.partial_scans;
    $('mean-risk').textContent = s.mean_risk === null ? '—' : s.mean_risk.toFixed(1) + ' / 100';
    $('categories').replaceChildren();
    const max = Math.max(1, ...Object.values(s.rule_categories));
    for (const [category, count] of Object.entries(s.rule_categories)) {
        const row = element('div', undefined, 'signal');
        row.append(element('span', names[category] + ' · ' + count));
        const bar = element('div', undefined, 'bar');
        const fill = element('span');
        fill.style.width = (100 * count / max) + '%';
        bar.append(fill);
        row.append(bar);
        $('categories').append(row);
    }
    $('trend').replaceChildren();
    const peak = Math.max(1, ...s.daily.map(day => day.total));
    for (const day of s.daily) {
        const row = element('div', undefined, 'trend-row');
        row.append(element('span', day.date.slice(5)));
        const track = element('div', undefined, 'trend-track');
        for (const decision of ['Allow', 'Review', 'Block']) {
            const segment = element('span', undefined, 'trend-' + decision.toLowerCase());
            segment.style.width = (100 * day.decisions[decision] / peak) + '%';
            segment.title = decision + ': ' + day.decisions[decision];
            track.append(segment);
        }
        row.append(track, element('span', String(day.total)));
        $('trend').append(row);
    }
    $('trend').append(element('p', 'Green = Allow · Amber = Review · Red = Block', 'note'));
}
api('/api/v1/config').then(c => {
    $('policy').textContent = c.policy;
}).catch(() => {
    $('policy').textContent = 'Configuration unavailable';
});
