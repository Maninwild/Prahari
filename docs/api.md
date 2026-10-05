# API reference

Base URL: `http://127.0.0.1:8000`. Interactive contracts and schemas: `/docs`; machine-readable schema: `/openapi.json` and `docs/openapi.json`.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | /health | Liveness and version |
| GET | /ready | 200 when both models load; 503 on model failure |
| GET | /api/v1/config | Non-secret active policy and bounds |
| POST | /api/v1/scans | Analyze and persist one unified result |
| GET | /api/v1/scans | Paginated history; decision, limit, offset |
| GET | /api/v1/scans/{scan_id} | Reopen saved analysis; 404 if absent |
| GET | /api/v1/dashboard/summary | Decision counts, risk, categories, trends, acknowledgements |
| POST | /api/v1/enforcement-events | Authenticated, idempotent adapter acknowledgement |

Scan body:

```json
{"input_type":"payload","content_type":"application/json","content":"{\"comment\":\"<script>alert(1)</script>\"}"}
```

`input_type`: url, http_request, or payload. `content_type`: text/plain (default), application/json, or application/x-www-form-urlencoded for payload input. HTTP request content type is read from the supplied headers. Fields beyond the schema are rejected. Responses include scan ID, timestamp, coverage, status, decision, category scores, findings, reasons, model signals, version identifiers, and analysis time. `action_taken` is none; acknowledged actions appear separately.

History: `?decision=Review&limit=20&offset=0`. Limit is 1–100. Original inputs are unavailable when reopening results. Category summary counts represent scans with rule evidence, with one count per scan/category; a scan can appear in multiple categories. Daily trends use UTC dates for the last seven days including today.

Acknowledgement body:

```json
{"event_id":"unique-adapter-id","scan_id":"32-character-hex-scan-id","mode":"enforce","action":"blocked"}
```

Pass `X-Prahari-Key` equal to the server's PRAHARI_INTEGRATION_KEY. Enforce actions must match Allow→allowed, Review→held, Block→blocked; monitor mode uses allowed. Exact retries succeed without double counting. Conflicting events return 409, incorrect actions 422, missing authentication 401, and missing scans 404.
