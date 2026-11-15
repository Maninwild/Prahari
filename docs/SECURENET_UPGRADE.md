# Prahari 2 — session and network behaviour prototype

This release adds working session telemetry, network-flow ingestion and incident investigation to the existing Prahari scanner. It targets the SecureNet theme “Artificial Intelligence-Based Real-Time Intrusion Detection Using Session and Network Behavioural Analysis.” It is a local prototype; an operational benchmark remains future work.

## Start and demonstrate

Use Python 3.12 and Node.js 22+. Extract this release into a new folder. Run `run_protected_demo.bat` on Windows or install `requirements.txt` in a virtual environment and run `python run_demo.py`.

1. Open http://127.0.0.1:3000/ and select **Simulate 5 failed logins**. This sends five HTTP requests to a demonstration endpoint that always returns 401. No password is submitted.
2. Open http://127.0.0.1:8000/ and scroll to **Session & network incidents**. Within the five-second refresh interval, inspect the authentication-failure evidence.
3. Select **Investigate**, **Resolve**, or **False positive**. Export the incident JSON. A new matching alert can reopen a resolved incident.
4. Submit the existing Block example three times to see an incident linked to actual scan evidence, in addition to individual protection decisions.
5. Follow the replay instructions below to demonstrate network port probing. Replay and live events are explicitly labelled and isolated.

The launcher generates a private integration key unless you supplied one. It saves a stable pseudonym secret in `data/pseudonym.key`. Keep that directory private and retain it across restarts if you need consistent identities.

## Network replay on Windows

To use a separate importer terminal, set the same integration key in both terminals before launching services. Generate your own private value; do not commit it. The pseudonym key may be read from the launcher's `data/pseudonym.key` when running from the same project folder.

Terminal 1, from the project folder:

```powershell
$env:PRAHARI_INTEGRATION_KEY = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
# Copy this value privately into terminal 2, or start terminal 2 with the same environment.
.\.venv\Scripts\python.exe run_demo.py
```

Terminal 2, with the same `PRAHARI_INTEGRATION_KEY` configured:

```powershell
.\.venv\Scripts\python.exe scripts/import_zeek.py examples/zeek-port-probe.jsonl --stream demo-network
```

The example is 12 authored failed connections to different destination ports using reserved documentation addresses. It is synthetic telemetry, not a capture of a real attack. Re-running it with the same stream and sensor IDs is idempotent while event records remain retained. Use the Replay filter on the dashboard.

## Live network sensor

Prahari consumes a Zeek JSON `conn.log`; it does not capture packets by itself. Configure a separate Zeek sensor on an authorized network to produce JSON connection logs, then run:

```powershell
.\.venv\Scripts\python.exe scripts/import_zeek.py "PATH\conn.log" --follow --stream live --sensor zeek-lab --checkpoint data/zeek-checkpoint.json
```

Provide the same `PRAHARI_PSEUDONYM_KEY` to the app and importer to correlate an origin address. Zeek can run on a Linux sensor while the application runs on Windows. For an existing authorized PCAP, Zeek documents `zeek -r capture.pcap LogAscii::use_json=T`; replay the resulting JSON `conn.log` without `--follow`.

The adapter uses connection start plus duration as the observation time. Connection logs arrive when Zeek emits them, typically at connection completion or timeout; detection is not packet-by-packet. Missing payload byte counts become zero. Flow byte direction is originator-to-responder; an outbound-volume alert does not prove exfiltration or external egress.

Follow mode checkpoints only acknowledged complete JSON lines. An incomplete final line is retried. A rejected event stops the adapter without advancing its checkpoint. Restart after correcting the issue. Rotation/truncation stops the adapter with an explicit message; restart selects the current file. Use a separate checkpoint per input/sensor/stream. Historical replay is sorted by completion time and limited to 100,000 flows per run. Ingestion rate limits still apply; large replays may need pacing or smaller batches.

Zeek field reference: https://docs.zeek.org/en/current/tutorial/logs.html

## Unified processing

1. A trusted adapter sends authenticated metadata to `POST /api/v1/telemetry`.
2. Schema validation checks timestamps, sizes, fields, and identifiers. Live events must be no more than 24 hours old or 30 seconds in the future.
3. An atomic SQLite transaction deduplicates the event and resolves any linked scan. Only existing scans can contribute web-rule evidence; a scan cannot be counted twice.
4. The service collects the actor's preceding five-minute window, within the same live/replay mode and stream. HTTP events also expose session-specific feature counts.
5. Behaviour rules and a separate HTTP/flow Isolation Forest evaluate the window. Up to 30 seconds of late arrival is accepted, using the latest observed time as the window end. Older events are rejected explicitly.
6. Evidence is grouped into the actor's recent incident across HTTP and flow sources. Risk is the maximum available linked-scan or behavioural signal score. The index is not a probability of compromise.
7. The dashboard presents evidence, source mode, pseudonymous actor, sessions, timeline, review state, and exports. HTTP request protection continues through the original scan/acknowledgement workflow.

Correlating actors by source address is approximate. NAT can merge users; proxies or differing observation points can prevent a match. The demo ignores forwarded client-IP headers. Sessions use signed random cookies and HMAC identifiers; clearing a cookie creates a new session but does not change the address-based actor. Use a stable shared pseudonym key and a common stream ID for cross-sensor correlation.

## Detection coverage

| Signal | Prototype threshold within five minutes |
|---|---|
| Authentication failures | At least 5 |
| Explicit web attack scans | At least 3 |
| Request burst | At least 60 HTTP events |
| Route probing | At least 15 distinct routes with at least 50% error responses |
| Port probing | At least 10 distinct destination ports with at least 50% failed connections |
| Host fan-out | At least 15 distinct destinations |
| Outbound volume | At least 50 MB originator bytes and an outbound/inbound ratio of at least 10 |
| Anomaly model | Isolation Forest rarity above the synthetic calibration set's 99th percentile; at least 5 events |

These thresholds are provisional. Benign scans, backups, load tests and shared gateways can trigger them. The demo sends only known route templates and maps unknown paths to `/unknown`; a real adapter needs its own safe route-template mapping before route-probing detection is useful.

## AI and evaluation boundary

Existing phishing Random Forest and request TF-IDF/Logistic Regression remain active. The new bundled Isolation Forest models use six aggregate features each and train on 1,200 generated windows per event kind. A separate 400-window generated calibration set per kind selects thresholds. Training is reproducible with `python -m scripts.train_behaviour` and does not happen at service startup.

The generated workload is an engineering fixture. No measured network intrusion accuracy, precision, recall or zero-day performance is claimed. Largest feature deviations shown in explanations are descriptive comparisons to the baseline, not causal attributions. Missing behaviour artifacts leave behavioural rules active and expose degraded model status. Model files are trusted local artifacts with integrity hashes, not signed releases.

Before a competition-grade evaluation, collect consented normal sessions and labelled lab attacks; derive the same window features; split by capture/session and time; fit on training data; tune only on validation data; freeze the model; evaluate on untouched captures. Compare rules-only, ML-only and hybrid results. Report precision, recall, false alerts per hour, time to detection, throughput, and latency. Include NAT, benign traffic bursts, backup transfers, sensor gaps and unseen workloads.

## Operations and limits

- Behaviour incidents always recommend Review and take no network action. The existing protected app can still block individual requests under the selected protection policy.
- SQLite is intended for a local single-instance deployment. Ingestion is bounded to 600 telemetry requests/minute per peer, 1,024 retained events per actor window, 100,000 telemetry rows and 10,000 incidents. Capacity errors are explicit.
- Telemetry rows expire seven days after receipt when another event is accepted. Live incidents expire after 30 days of inactivity on live ingestion. Replay incidents remain until database rotation. Incident timelines retain the latest 100 evidence snapshots; session/sensor lists retain up to 50 entries. Back up and rotate the stopped database when needed.
- The Node telemetry outbox persists up to 5,000 pending events. Temporary failures retry. Permanent 404/409/422 responses become visible in the bounded rejected-event log. Counters expose pending, rejected and overflow events. A process crash before outbox persistence can lose an event.
- HMAC source identities and session identities are stored instead of raw source addresses or cookies. Destination IPs, ports, route templates, timestamps and counters remain security-sensitive metadata. Never send secrets in route templates. The shared integration key identifies a trusted adapter trust domain; this is not multitenant authentication.
- No automatic retraining, automatic firewall action, raw packet capture, encrypted payload inspection, DNS-tunnel detector, production capacity guarantee or independent red-team validation is included.
- Existing v1 deck/video are retained as historical demonstration materials and do not show the v2 features. The current incident screenshot is `submission/screenshots/incidents-v2.png`.

## Validation

Executed in the Linux build environment:

- 27 Python tests: original scanner regression checks plus telemetry authentication, validation, deduplication, scan linkage, rolling-window expiry, lateness, scope isolation, session counts, HTTP/flow correlation, triage/reopen, persistence and model failure.
- Two Node tests: enforcement outbox and telemetry outbox retry/restart, permanent rejection visibility, signed-cookie reuse and tamper rejection.
- Live HTTP integration: Allow 200, Block 403, Review 409, handler isolation and scanner outage 503.
- Real Chromium: five failed-login requests, session incident, analyst review, JSON export, Zeek replay and duplicate replay, live-follow ingestion and cursor restart using a local log fixture, desktop and mobile layout.

Run `python -m unittest discover -s tests -v`, `node --test demo-app/*.test.mjs`, `python scripts/check_integration.py`. With Playwright and Chromium installed, run `python scripts/check_incidents.py` (optional `PRAHARI_BROWSER` path).

Windows launcher execution, an actual live Zeek capture and Docker execution still require validation on the deployment machine.
