# Execution log — nhost-kamesh (contract v1.0, as amended toward full Nhost)

Owner-approved, phase-gated. All mutating steps were proposed before execution.
Secrets are never recorded here — only names, locations, and verification outcomes.

## Phase 3A — Postgres substrate close-out (approved, completed)
- Dropped leftover `_verify` table.
- Fresh canary (migrate-created, app-written incl. serial sequence): count=2.
- Survived `restart` AND full `down`/`up` recreation (volume retained, no `-v`): count=2 both times.
- `backup.sh` patched: pg_dump runs as container `postgres` user (dumps owned 70:70, not root);
  failure path removes stale empty files. Verified working.
- Isolated restore to `appdb_restore`: row-count live=2 restored=2. MATCH.
- All test artifacts removed (`appdb_restore`, canary, dump). `\dt` empty, `backups/` empty.
- Inventory: 4 compose projects, 14 containers — none touched. `stalwart-mail` unhealthy flag
  is pre-existing (3w uptime), unrelated.
- URL status: `db.888intelligence.org` resolves to 86.107.79.79; port correctly CLOSED
  externally pre-hardening; loopback binding holds.
- HELD (needs explicit approval): password rotation over session-log exposure.

## Phase B — Hasura GraphQL engine (approved as "begin", completed)
- Secrets generated into `.env` (600, never printed): `HASURA_ADMIN_USER`, `HASURA_ADMIN_PASSWORD`,
  `GRAPHQL_ADMIN_SECRET`, `JWT_SECRET` (HS256), `HASURA_PORT_HOST=8082`
  (8080 already bound on all interfaces by an unidentified host service — noted, not ours).
- `hasura_admin` role created live (LOGIN, non-superuser) + grants: CONNECT + CREATE on db,
  USAGE+CREATE on public, ALL on existing tables/sequences, default-privs ALL from
  postgres + migrate roles (future Laravel tables visible). Mirrored into `initdb/01-roles.sh`
  (guarded, idempotent) for rebuild fidelity.
- Service `graphql`: `nhost/graphql-engine:v2.46.0-ce` (pinned), `127.0.0.1:8082->8080`,
  384M/0.5 CPU, json-file 10m x3, `depends_on postgres healthy`. Console OFF, dev-mode OFF,
  telemetry OFF, log warn, PG pool 20 (of 100 max), APIs metadata+graphql+pgdump.
- Fixes during phase (all verified after):
  1. Dollar-quote heredoc over-escaping broke live role SQL → reran with plain CREATE ROLE.
  2. Compose `env_file` strips JSON double quotes → JWT single-quoted in `.env`;
     intermediate edit appended stray quotes to every line → repaired, `config -q` clean.
  3. `pg_track_table` string form `"public.t"` fails on v2.46 (misleading "no such table");
     object form `{"schema","name"}` works for all owners. Automation must use object form.
  4. `-ce` image has no wget/curl → healthcheck rewritten as bash `/dev/tcp` HTTP 200 probe.
- Verified: `/v1/version` = v2.46.0-ce; `hdb_catalog` in appdb only; track → GraphQL query
  → untrack round-trip on migrate-owned AND hasura-owned tables; both test tables dropped.
- Footprint: graphql ~130M/384M, postgres ~35M/768M. Disk 71% (12G free).
- Contract amendment (owner-approved direction): scope extended beyond postgres-only toward
  phased Nhost (Hasura → Auth → Storage → MCP/AI); "no Hasura" non-goal retired for Phase B+.

## Open decisions (blocking later phases)
- Password rotation: yes/no.
- SMTP for Auth (Phase C): Stalwart relay vs external sender.
- WireGuard (Phase W): laptop OS, key ceremony (a: owner-generated client keypair / b: agent-generated).
- DNS A record for db.888intelligence.org: keep (harmless, ports closed) or delete.
- Functions service: in or out. AI phase: OpenAI key + spend budget.

## Phase C close-out progress - 2026-11-07 (signed off 2026-11-07)
- WireGuard data path verified from the Mac: utun6 is 10.9.0.2/24, route to 10.9.0.1/32 uses utun6; Auth and Hasura /healthz both returned HTTP 200, PostgreSQL host port 5434 accepted TCP over VPN. VPS peer handshake was recent.
- Public-IP TCP probes to Nhost ports 4000, 5434, and 8082 timed out; Docker publishes these services only on 10.9.0.1 and loopback.
- Auth account state: exactly one user, verified. Existing account reused; no duplicate signup created.
- Signup remains disabled (AUTH_DISABLE_SIGNUP=true); duplicate-account signup probes returned 403 on both VPN and loopback binds.
- Bootstrap credential sign-in returned a JWT with user default role and user ID matching the verified Auth record.
- Temporary phase_c_jwt_canary table was created by hasura_admin, tracked in Hasura with a user select filter on X-Hasura-User-Id; JWT query returned the owner row and excluded the other row. Table was dropped and Hasura metadata untracked; follow-up check confirmed the table is absent.
- Open before Phase C sign-off: bootstrap password is still accepted and needs owner password reset. Auth verification reached /v1/verify, then redirected to / on AUTH_CLIENT_URL=http://10.9.0.1:4000, where the Auth API returns 404. Account is verified, so no duplicate verification email was sent. Set AUTH_CLIENT_URL to the actual WebView client/callback before the password-reset flow; owner must set the permanent password. Do not mark Phase C complete until this is verified.
- No production schema migration or WebView database cutover performed.

## Phase C close-out — 2026-11-07 (SIGNED OFF)
- Password rotation completed via owner-approved change. Route discovery during
  execution: Auth 0.52.0 (Go rewrite) exposes `/v1/signin/email-password` (slash form)
  and `/v1/user/password`; the hyphen form recorded earlier in these notes returns 404.
  Response nesting: token is at `session.accessToken` (not top-level `accessToken`).
- Change executed over loopback only; passwords never appeared in argv, ps, history,
  disk, or terminal output. Only HTTP status codes were captured.
- Evidence (HTTP codes): change-password = 200; sign-in with OLD bootstrap password = 401
  (rejected); sign-in with NEW password = 200. Bootstrap credential is dead.
- Interactive rotation helper committed at `scripts/change-auth-password.sh` (mode 700,
  syntax-checked, hidden prompts, stdin-only JSON, 0600 temp file, status-code-only
  output). Corrected for the 0.52 response shape. Safe for future owner-driven rotations.
- `/home/kamesh62/.bootstrap-pw` removed by owner; confirmed absent (ls: no such file).
- Phase C gate met: verified account, signup locked, JWT canary passed earlier, permanent
  password set and verified, bootstrap file deleted. Phase C COMPLETE.
- Open items carried forward (not Phase C blockers): AUTH_CLIENT_URL still points at
  Auth API root (404 page after verify) — set to the WebView callback before any future
  email verification flow; SMTP for verification emails still pending.
- Storage volume status at Phase C sign-off: 15 GB disk /dev/vdc attached 2026-11-07
  17:08. At that checkpoint it was blank and not yet formatted or mounted; Phase D setup
  is recorded in the following section.

## Phase D — Storage + MinIO (deployed, 2026-11-07)
- Owner selected the entire 15 GiB attached volume for Storage; this supersedes the earlier
  10 GB target. `/dev/vdc1` formatted ext4 (`nhost-storage`) and mounted persistently at
  `/srv/nhost-storage`; readiness marker confirms the dedicated mount. Current use ~228 KiB.
- Storage credentials are present in `.env` (mode 600); values intentionally not logged.
- Added `compose.storage.yml` profile with pinned `nhost/storage:0.7.2` and
  `nhost/minio:RELEASE.2025-02-28T09-55-16Z`. MinIO bind-mounts the dedicated filesystem;
  startup fails closed if its volume marker is absent. Storage API port 5000 binds only to
  loopback and `10.9.0.1`; MinIO port 9000 has no host publish. Services share
  `nhost-kamesh-net`. Compose config validation passed.
- Created Postgres `storage` schema owned by non-superuser `hasura_admin`; Storage migrations
  created `buckets`, `files`, `virus`, and `schema_migrations`. Hasura tracks the three
  application tables. Physical MinIO bucket `nhost` created; logical `default` bucket already
  existed with 50,000,000-byte per-file maximum.
- Private default permissions: role `user` may upload only to bucket `default`, with
  `uploaded_by_user_id` preset from `X-Hasura-User-Id`; select and delete are restricted to
  the same uploader and bucket. Update/replace and public-role access are absent.
- Permission canary passed using the Hasura-supported admin-secret plus simulated user-role
  headers: insert preset applied, owner saw row, another user saw none; canary metadata removed.
- End-to-end Storage canary used a short-lived synthetic HS256 user-role JWT held only in
  process memory (not an Auth login): upload HTTP 201, owner retrieval HTTP 200 with matching
  bytes, other-user retrieval denied (404), delete HTTP 204. Verified `storage.files` is empty
  and MinIO bucket has no objects after cleanup.
- VPN Mac request to `10.9.0.1:5000/v1/version` returned HTTP 200. Public-IP probes of 5000,
  9000, and 9001 did not connect. MinIO remains unpublished.
- Unauthenticated upload probe created no row but Storage 0.7.2 returned HTTP 500; logs
  identify missing Authorization header. Access was denied, but the status mapping is a
  remaining API polish/security-monitoring risk.
- Deployment caveat: first Compose invocation with the overlay recreated Postgres and Hasura
  dependencies. Both recovered; Postgres and Hasura are healthy, Auth/Hasura/Storage health
  probes return HTTP 200, and the verified Auth user remains present. No volume deletion or
  data wipe occurred. Manage Storage with the overlay and `--no-deps` to avoid dependency
  restarts. Do not use `down -v`.
- No production schema/data migration or WebView cutover performed.


## Neon application schema copied to Nhost (2026-11-08, schema-only)
- Inspected the deployed Vishwa Guru runtime. Its Postgres migration references
  `database/schema-neon/V1-schema.sql`, but that file is absent from the deployed app
  container. Used the live Neon database configured in the runtime as the schema source;
  connection values were not printed or recorded.
- Exported only Neon `public` schema with a PostgreSQL 18 client (`--schema-only`,
  `--no-owner`, `--no-acl`). Imported into Nhost `appdb` as one transaction. No row data,
  Neon Auth schemas, users, roles, ownership, grants, or destructive statements were copied.
  Existing Nhost `auth`, `storage`, and `hdb_catalog` schemas were preserved.
- Adapted the dump for PostgreSQL 16 by omitting its duplicate `CREATE SCHEMA public`,
  psql 18-only restriction markers, and `SET transaction_timeout` setting. The Nhost target
  had no pre-existing application objects in `public` at import time.
- Verified parity against Neon: 29 tables, 3 sequences, 15 enums / 76 enum labels, 455
  column definitions, 116 application constraints, 88 indexes, and the application-defined
  function match. Triggers and row-level policies are absent in both application schemas.
  PostgreSQL 18 reports `NOT NULL` as additional catalog constraint rows; PostgreSQL 16
  stores the same property on columns, and column nullability matches exactly.
- No application rows were migrated. Hasura metadata tracking/permissions for these new
  application tables have not been configured. The WebView runtime remains connected to
  Neon; no application connection, Auth, Storage, or Hasura platform settings were changed.
- Follow-up before cutover: restore the missing file-backed schema source in the Vishwa Guru
  project and configure/review Hasura tracking and least-privilege permissions. Keep Neon
  as the active runtime database until data migration and application-level verification are
  separately completed.


## Neon relational data baseline copied to Nhost (2026-11-08; cutover not performed)
- Source `public` data was exported from Neon in one consistent PostgreSQL snapshot and
  restored into Nhost `appdb` in one transaction. Target tables were empty before restore.
- 517 rows across 25 non-empty tables were imported into all 29 application tables; the
  4 remaining tables are empty in the source snapshot. The import included sequence states.
- Verification after restore: per-table row counts match the exported snapshot; content
  hashes match Neon for all 29 `public` tables at the time of the check; all 3 sequence
  states match. No row values were printed or logged.
- Neon `neon_auth` had no users, sessions, organizations, invitations, or memberships; it
  did contain one provider configuration row. That provider-specific configuration was not
  copied. Nhost Auth remains its own service and retains its existing user. `storage.files`
  remains empty pending migration of binary objects.
- Binary asset migration is still open. Neon `public.file_assets` has 140 active records:
  122 on `public`, 16 on `local`, and 2 on `s3`. The runtime filesystem has 164 files
  (~220 MB). SHA-256 matching found local content for 86 public records and all 16 local
  records; 36 public records and both s3 records have no matching bytes in the runtime
  filesystem. Of the 86 public matches, 44 are at a different path than the DB record.
  No file objects have been uploaded to Nhost Storage.
- Do not cut over the WebView yet. Neon remains live and can receive new writes after this
  snapshot. After binary assets are recovered and migrated, pause source writes, perform a
  final delta/sync and parity check, then handle Hasura tracking/permissions and cutover as
  separate reviewed steps. No runtime connection was changed in this task.


## Neon-to-Nhost parity recheck (2026-11-09)
- Read-only comparison of all 29 `public` tables: Neon=517 rows, Nhost=517 rows;
  per-table row counts and content hashes match. All 3 application sequence states match.
- No additional relational rows required copying at this checkpoint. Neon remains active;
  run one final parity check after pausing source writes immediately before cutover.
- Binary file migration remains open as recorded above; no Storage objects were uploaded.

## Project-scoped Hasura isolation foundation (2026-11-10; broker held at security gate)
- Added private project, membership, and Storage mapping registries with separate
  Vishwa Guru development, staging, and production ULIDs. Added `project_id` to
  22 project-owned tables, assigned existing rows to production, and validated
  26 composite project-safe foreign keys. Global reference and Laravel tables
  remain outside client GraphQL access.
- Added aggregate-only `campaign_progress` view and Hasura roles
  `client_public`, `user`, and `service_reader`. Public/service reads are scoped
  by signed project claim; user reads require active project membership. Roles
  have curated select permissions only; financial/admin tables and mutations
  are unavailable to clients. One existing verified Auth account has production
  owner membership; identity omitted here.
- Created logical `vg-development`, `vg-staging`, and `vg-production` Storage
  buckets and project mappings; retained `default`. Storage user permissions
  preserve uploader ownership and require active membership on mapped buckets.
  `storage.files` is empty. Public Storage access remains denied.
- Verified isolated migration against a restored database (29 tables, 517 rows),
  all 26 constraints, cross-project rejection, and Hasura permission probes
  (production campaigns=3, staging=0, member=3, nonmember=0, sensitive probe
  denied). Hasura stayed healthy (HTTP 200); no live service restart.
- Storage permission checks passed in staging; a live upload was not verified.
  Physical MinIO object inventory remains open. No existing `default` bucket
  permissions or contents were removed.
- **Security gate (updated 2026-11-16):** no broker, credentials, signing key,
  or broker route deployed; live Auth issuer configuration remains unchanged.
  Decision: CE + POST auth hook (paid edition retired; `HASURA_GRAPHQL_JWT_SECRETS`
  dual-verifier plan abandoned). Shared Auth HS256 broker signing remains
  prohibited. Tiered item status lives in `docs/FEATURE_ASSESSMENT.md`.
- `payment_providers` gained project IDs, but its global unique code and Laravel
  lookup contract were left unchanged; duplicate per-project provider configs
  remain a separately reviewed item. Neon, WebView, payments, DNS, and Nginx
  were not changed. Keep Neon active; no cutover.

## Broker Tier-1 close-out, local draft only (2026-11-16)
- Owner-approved preliminary change set (feature assessment → plan → execute).
  Scope: close Tier-1 code gaps in the broker draft and reconcile docs. NOTHING
  was deployed: no live Hasura/Auth/Postgres/Storage change, no keys generated,
  no Neon/WebView/WG/DNS touch.
- Implemented (broker/app.py): `jti` (uuid4) on all issued tokens; audience
  bound to the credential's project (`hasura:<project_id>`) and verified at the
  hook (cross-project replay rejected); decision audit sink
  (`PostgresDecisionAudit`, best-effort, never blocks a decision, stores no
  tokens/bodies); per-credential exchange rate caps (public 30/min, service
  10/min) on top of per-IP limits, with audit on denial; audit events issued /
  allowed / denied with reason details.
- Implemented (migration 004-credential-decisions.sql): `platform.credential_decisions`
  (decision, credential_id, role, jti, detail) with INSERT-only grant to
  `nhost_broker` — the runtime role cannot read or alter the audit trail.
  Additive; migrations 001–003 untouched.
- Verified: broker unit suite extended to 11 tests (negative matrix seeds:
  expired, tampered, cross-project audience, revoked-after-issue, role override,
  rate-limit trip, audit-row assertions) — 11/11 pass locally;
  `docker compose config -q` passes with placeholder env (temporary env file
  removed after check; repo still contains no `.env`).
- Documented: new `docs/FEATURE_ASSESSMENT.md` (tiered item-by-item status);
  README, BROKER.md, IMPLEMENTATION_STATUS.md, ROADMAP.md updated to record the
  CE + auth-hook decision (paid edition retired) and the new token/audit/rate
  behavior. TTL stays 600s (stricter than the assessment's 15-minute bound).
- Open / partial (tracked in FEATURE_ASSESSMENT.md Tier 2): staged end-to-end
  negative matrix against a live stack, key rotation/JWKS + compromise
  procedure, hook-failure-mode staged proof, formal scope vocabulary doc.
  Tier 3 (RLS backstop, portal, storage parity, write-path decision,
  observability) untouched by design.
