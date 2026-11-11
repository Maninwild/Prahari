# Security scope

Prahari is a local, single-user application with optional bearer authentication. It is not a certified firewall, exploit scanner or safe-browsing guarantee. Do not expose an unauthenticated workspace publicly.

- HTTP(S) URLs are validated but never fetched. There is no URL-fetch SSRF surface in the scanner.
- Attack content is inspected as text and rendered with textContent. The board has no shell execution or dynamic SQL construction.
- Immediate rule excerpts are removed before scanner persistence. The board stores accepted application content separately.
- Workspace bearer authentication protects `/api/` routes when configured. Integration credentials identify a trusted adapter with workspace-level access. There is no per-tenant authorization model.
- Origin checks reject cross-origin writes; Host validation mitigates DNS rebinding. Scan input, parameter count, depth and rate are bounded.
- ML-only results never Block. Rules can produce false positives and miss unknown or differently encoded attacks.
- Acknowledgements report what the trusted adapter says occurred. They are idempotent and retried, but not an exactly-once transaction with the business application.
- Use local filesystem permissions to protect model files, keys, board content and the database. Joblib artifacts must come from a trusted source; manifest hashes do not authenticate a publisher.
- Monitor mode permits successfully analysed requests even if the recommendation is Block. Scanner failure denies requests in both modes.

For deployment beyond localhost, add TLS, mandatory identity/access policy, retention controls, a reverse proxy with resource limits and workload-specific evaluation. Docker files default to localhost-published ports.
