# Feature assessment — broker + auth hook + data plane

Assessed locally: 2026-11-16. This file maps the tiered feature assessment onto
the verified state of this repository. It is a planning record, not a deployment
record — nothing here has been deployed.

## Baseline (what already exists — build on, don't rebuild)

| Feature | Status | Evidence |
|---|---|---|
| Project registry, memberships, project columns, 26 composite FKs | Live, verified | `migrations/001`, EXECUTION_LOG 2026-11-10 |
| Hasura read roles (`client_public`, `user`, `service_reader`), read-only, curated | Live | `IMPLEMENTATION_STATUS.md` permission probes |
| Storage membership-scoped buckets | Live (live upload unverified) | `migrations/002`, EXECUTION_LOG |
| Nhost Auth (user credentials, email verify, JWT) | Live | EXECUTION_LOG Phase C sign-off |
| WireGuard perimeter, backups, Neon parity | Live | EXECUTION_LOG Phases 3A/C, parity recheck |

## Tier 1 — MVP

| # | Item | Local state after this change set |
|---|---|---|
| 1 | Credential issuance & registry (hashed pairs, project-only + credential_kind + scopes, instant revocation) | Done in `003-api-credentials.sql` (+ scopes in `005-credential-scopes.sql`) + `scripts/create-project-api-key.py`; `003`/`005` bind to project_id + credential_kind + scopes with no environment column — environment is explicitly out of scope unless a new migration adds it; revocation is instant because the hook rechecks status per request |
| 2 | Token exchange endpoint (pk → client_public, sk → service_reader; short-lived RS256, jti issued) | Done in `broker/app.py`; `jti` (uuid4) added this change set. TTL 600s — deliberately stricter than the 15-minute bound; raising to 900s would loosen it, so 600s is kept |
| 3 | Auth hook endpoint validating both token families, fail-closed | Done in `broker/app.py` (`/internal/hasura-auth`); Nhost JWTs verified via Auth `/token/verify`; 503 on verifier/db unavailability so Hasura denies |
| 4 | Server-side claim derivation (never caller-supplied) | Done: role/project derived from the registry row only; `X-Hasura-Role` header may only narrow to the credential's own role |
| 5 | Hardened deployment (compose, loopback/WG-only, limits, healthcheck, fail-closed, log rotation) | Done in `compose.yml`: hook wired into Hasura CE, uid 10001, read-only rootfs, cap-drop ALL, no-new-privileges, healthcheck-gated ordering, json-file rotation |
| 6 | Decision audit log (jti, credential id, role, decision — never tokens/bodies) | Done this change set: `004-credential-decisions.sql` + `PostgresDecisionAudit`; INSERT-only grant to `nhost_broker` (write-only sink) |
| 7 | Rate limiting on exchange (per-credential caps even WG-only) | Done this change set: per-credential caps (public 30/min, service 10/min) on top of the existing per-IP limiter |

## Tier 2 — Production-grade (before any public exposure)

| # | Item | State |
|---|---|---|
| 1 | Token lifecycle: revocation latency = TTL (bounded), clock-skew, expired/tampered/wrong-env rejection matrix | Partially started: expired/tampered/wrong-project/revoked tests now scripted in `broker/test_app.py` (see that file for the living count, now 16+ and growing). Full section-2 matrix → rerunnable execution-log script still open |
| 2 | Key management & rotation: mode-600 keys, JWKS, kid-overlap rotation, compromise procedure | Open. Keys are owner-placed (standing rule 4); rotation procedure not yet written |
| 3 | Scope vocabulary enumerated 1:1 to Hasura roles | Done in `migrations/005-credential-scopes.sql` + `broker/app.py` + `scripts/create-project-api-key.py`: strict families `public={public_read}`→`client_public`, `service={service_read[,service_write]}`→`service_reader/service_writer`; enforced at issuance, exchange, and hook with downgrade-only inside a family. No credential-management HTTP endpoint by design (operator script only, no admin secret). Covered by 16 tests including cross-family mint/hook forgery and Nhost-role confinement. Hasura `service_writer` insert/update permissions are the next metadata change |
| 4 | Isolation test suite as code → execution log | Partially (unit level done this change set); staged end-to-end negative matrix against a live stack is open |
| 5 | Hook failure-mode proof (broker down → Hasura denies) + client behavior doc | Open. `depends_on: service_healthy` plus hook 503 path makes Hasura deny, but a staged proof is required |

## Tier 3 — Parity (later phases)

Not started, by design: Postgres RLS backstop, user-facing account surface,
self-service credential portal, storage signed-upload/quota/inventory parity,
write-path authorization decision, observability metrics + deny-spike alerting.

## Deliberately out of scope (owner decisions, retired)

- Paid Hasura edition — **retired**: Hasura CE + POST auth hook is the architecture.
  The `HASURA_GRAPHQL_JWT_SECRETS` dual-verifier idea is abandoned; both token
  families are verified by the hook instead.
- Payment/donation writes through Hasura — stays in Laravel permanently.
- MCP/AI/Functions — later roadmap phases (E/F/G), dependent on this landing.

## Deployment boundary

Everything above is a local draft. Deployment order remains the BROKER.md rollout
gate: backup → migrations 003/004/005 + nhost_broker role → broker up without switching Hasura
auth → staged exchange/revocation/expiry matrix → switch Hasura to the hook →
negative probes → only then client traffic. No cutover of Neon/WebView traffic is
authorized by this document.
