import http from 'node:http';
import {
    randomUUID
} from 'node:crypto';
import {
    readFileSync
} from 'node:fs';
const base = process.env.PRAHARI_URL || 'http://127.0.0.1:8000';
const key = process.env.PRAHARI_INTEGRATION_KEY;
if (!key) throw Error('Start using run_demo.py so both services share an integration key.');
const mode = process.env.PRAHARI_MODE || 'enforce';
if (!['enforce', 'monitor'].includes(mode)) throw Error('Invalid mode');
let reached = 0;
const stats = {
    allowed: 0,
    blocked: 0,
    held: 0,
    unavailable: 0,
    unacknowledged: 0
};
async function api(path, body) {
    const r = await fetch(base + path, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Prahari-Key': key
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5000)
    });
    if (!r.ok) {
        const error = Error('Scanner or acknowledgement unavailable');
        error.status = r.status;
        throw error;
    }
    return r.json();
}

function send(res, status, data) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify(data));
}
const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/') {
        res.writeHead(200, {
            'Content-Type': 'text/html',
            'Cache-Control': 'no-store'
        });
        return res.end(readFileSync(new URL('./index.html', import.meta.url)));
    }
    if (req.method === 'GET' && req.url === '/stats') return send(res, 200, {
        mode,
        handler_reached: reached,
        ...stats
    });
    if (req.method !== 'POST' || req.url !== '/submit') return send(res, 404, {
        error: 'Not found'
    });
    let chunks = [],
        size = 0;
    for await (const chunk of req) {
        size += chunk.length;
        if (size > 16000) return send(res, 413, {
            error: 'Input too large'
        });
        chunks.push(chunk);
    }
    let body;
    try {
        body = JSON.parse(Buffer.concat(chunks).toString());
        if (typeof body.content !== 'string' || !body.content.trim() || body.content.length > 10000 || !['payload', 'url'].includes(body.input_type)) throw Error();
    } catch {
        return send(res, 400, {
            error: 'Use content and input_type payload or url'
        });
    }
    let scan;
    try {
        scan = await api('/api/v1/scans', {
            input_type: body.input_type,
            content: body.content
        });
        if (!['Allow', 'Review', 'Block'].includes(scan.decision) || typeof scan.scan_id !== 'string') throw Error();
    } catch (error) {
        if (error.status === 422) return send(res, 422, {
            error: 'invalid_scan_input',
            handler_reached: reached,
            action: 'denied'
        });
        stats.unavailable++;
        return send(res, 503, {
            error: 'scanner_unavailable',
            handler_reached: reached,
            action: 'denied'
        });
    }
    const action = mode === 'monitor' ? 'allowed' : {
        Allow: 'allowed',
        Review: 'held',
        Block: 'blocked'
    } [scan.decision];
    // This counter is inside the application handler boundary. Denied inputs never reach it.
    if (action === 'allowed') reached++;
    stats[action]++;
    const event = {
        event_id: randomUUID(),
        scan_id: scan.scan_id,
        mode,
        action
    };
    let recorded = false;
    for (let i = 0; i < 2 && !recorded; i++) {
        try {
            await api('/api/v1/enforcement-events', event);
            recorded = true;
        } catch {}
    }
    if (!recorded) stats.unacknowledged++;
    send(res, action === 'allowed' ? 200 : action === 'blocked' ? 403 : 409, {
        decision: scan.decision,
        action,
        mode,
        scan_id: scan.scan_id,
        handler_reached: reached,
        acknowledgement_recorded: recorded
    });
});
server.requestTimeout = 15000;
server.listen(Number(process.env.DEMO_PORT || 3000), '127.0.0.1', () => console.log('Protected demo: http://127.0.0.1:' + (process.env.DEMO_PORT || 3000)));
