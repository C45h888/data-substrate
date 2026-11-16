# NHOST-KAMESH — Master Roadmap & Handover
# Written: 2026-11-07. This chat is being decommissioned; this file + docs/EXECUTION_LOG.md
# are the complete continuity record. No secrets in this file — only names/locations.

## 0. Mission (Contract v1.0, as amended by owner)

Self-hosted Nhost substrate on VPS 86.107.77.79 (user kamesh62), coexisting with
lain-plane services (Stalwart mail, temple-trust, harness-crypto-analysis). Postgres +
Hasura + Auth are the target core; Storage/MCP/AI/Functions are phased options.
Laravel keeps all business logic. No public DB. Private access via WireGuard.
Lain plane (/home/lain, /opt/stalwart data, nginx sites, other compose projects)
is read-only except where the owner explicitly approved a change (mail fix, UFW rules).

## 1. Status snapshot (verified, 2026-11-07)

| Layer | State | Notes |
|---|---|---|
| Postgres 16-alpine (`nhost-kamesh-postgres-1`) | healthy, 768M/1CPU, `127.0.0.1:5434` | Roles: postgres / laravel_app (DML) / laravel_migrate (DDL) / backup_worker (read) / hasura_admin (platform). Backup/restore proven. `backups/` is 70:70 (rotate via container exec). |
| Hasura graphql-engine v2.46.0-ce (`:8082` loopback) | healthy, 384M/0.5CPU | Console OFF, dev OFF, telemetry OFF, pool 20. Track/untrack/query proven. Object-form table refs REQUIRED (`{"schema","name"}`; string form fails). Healthcheck = bash /dev/tcp probe (image has no wget/curl). |
| Auth nhost/auth:0.52.0 (`:4000` loopback) | UP (healthz 200), no container healthcheck (distroless, no /bin/sh) | Migrations done (auth schema, 15 tables). SIGNUP DISABLED proven (403 signup-disabled). Needs AUTH_ENCRYPTION_KEY (set), Resend SMTP (key placed by owner). |
| Storage + MinIO | running, private | Storage API :5000 loopback/WireGuard; MinIO internal only. `/dev/vdc1` (15 GiB) mounted at `/srv/nhost-storage`; per-user default-bucket permissions and upload/retrieve/delete canary passed. Details in EXECUTION_LOG. |
| WireGuard server | STAGED, handshake blocked | wg0 up (10.9.0.1/24), peer + 51820/udp ALLOW present. Handshake never completes; RX=0 despite packets reaching eth0 (tcpdump proven). Suspects: UFW shadowing (H1) or crypto mismatch (H3). A dedicated agent now owns this. |
| Stalwart mail fix (approved lain change) | FIXED 2026-11-06, logged in /opt/stalwart/FIX-2026-11-06.md | MTA route `else=resend-smarthost` → local-domain branch added; restart applied; local delivery proven. OPEN: kamran password (owner UI step), admin cred rotation (owner), SPF/PTR/port-25 (owner dashboards). |
| Ports | 5434, 8082, 4000 loopback-only | NOTE: 0.0.0.0:8080 is nginx (mail admin), NOT free. 8082 chosen for Hasura for this reason. |

## 2. In-flight checklist (do these first, in order)

### 2a. WireGuard handshake (dedicated agent owns; unblock criteria)
- [ ] Resolve H1/H3: `sudo wg show wg0` (peer? handshake?) + `sudo ufw status verbose`
      BEFORE/AFTER ping burst (does the 51820 rule counter move?).
      Counter moves = crypto mismatch (regen laptop keypair); frozen = fix UFW order.
- [ ] Handshake completes; `ping 10.9.0.1` works from laptop.
- [ ] Rebind services to VPN IP (owner-approved compose change):
      add `10.9.0.1:5434:5432`, `10.9.0.1:8082:8080`, `10.9.0.1:4000:4000`
      mappings (KEEP loopback mappings). Only valid while wg0 exists.
- [ ] pg_hba: `hostssl appdb all 10.9.0.0/24 scram-sha-256` + `pg_reload_conf`
      (no restart needed). Rationale logged: WG is the encryption layer; no PG-TLS.
- [ ] Prove from laptop: psql to 10.9.0.1:5434, GraphQL + Auth over 10.9.0.1.
- [ ] Public probe: nothing new reachable (only pre-existing 80/443/25/465/587/993/8080).

### 2b. Auth completion (needs 2a done for the mail-click step)
- [ ] Create first user `kamransait41@gmail.com`: briefly set DISABLE_SIGNUP=false,
      restart auth, signup over VPN, re-enable (DISABLE_SIGNUP=true), restart,
      re-prove 403 refusal. (No admin-create endpoint found in 0.52; this is the
      documented workaround. Window: minutes, loopback/VPN-only.)
- [ ] Verification email via Resend lands in Gmail; owner clicks link OVER VPN.
- [ ] Login returns JWT; JWT against Hasura on canary table: own row ✅, others ❌.
- [ ] Cleanup canary. Update EXECUTION_LOG.md. Phase C sign-off.

### 2c. Owner actions (nobody else can do these)
- [ ] Rotate Stalwart admin password (was in handoff + one agent log line).
- [ ] Set kamran mailbox password (admin UI → Directory → Accounts).
- [ ] Squarespace DNS + HostBet ticket (SPF/PTR/port-25) — mail reputation only.
- [ ] Decide keep/delete `db.888intelligence.org` A record (harmless either way).

## 3. Remaining phases (each: sheet → owner approval → execute → verify → log)

- Phase D — Storage + MinIO COMPLETE (2026-11-07). Owner allocated the full 15 GiB
  volume `vol-b199824b54f7a383` to MinIO. API is loopback/WireGuard only; MinIO is
  Docker-internal. Private per-user upload/read/delete verified; no public access.
  Remaining: improve unauthenticated error status (currently HTTP 500) and establish
  an off-host MinIO backup before storing important files.
- Phase E — MCP server (agent access to org data). Needs: yes/no + permitted roles.
  Depends on C. Done = MCP client queries under a test user's permissions.
- Phase F — AI embeddings/agents. Needs: pgvector decision + OpenAI key + spend budget
  (only phase with recurring external cost). Depends on C.
- Phase G — Functions. DEFAULT: SKIP (logic lives in Laravel). Needs a concrete use case.
- Phase H — Constellation eval (Hasura replacement, ~90% less RAM). Trigger: Hasura
  footprint hurts. Note: alpha, no event triggers/Actions — evaluate, don't assume.
- Phase W (finalize) — WireGuard persistence (`wg-quick@wg0` enable via owner sudo),
  client configs for any additional devices, final access proof, decommission any
  temporary mappings.
- Cross-cutting: per-service hardening (caps, loopback/bindings, no dev mode, log
  rotation); MinIO backup story if Phase D lands; Laravel integration contract
  (STATE 6, NO prod cutover without explicit approval); §8 completion report (STATE 7).

## 4. Standing execution rules (from owner; bind every future agent)

1. Propose exact steps → owner approves → execute → report evidence → owner accepts.
2. Read-only by default; no mutations without explicit approval per phase.
3. Never `down -v`, never delete volumes, never touch lain-plane files/services
   except with explicit per-item approval (precedents: mail route fix, UFW allow).
4. Secrets: never print/log. Owner places credential VALUES (`.env`, `.creds`);
   agents use them via vars and verify by behavior, never by display.
5. Every phase ends in docs/EXECUTION_LOG.md with implemented/verified/partial/open.
6. Stop on any unresolved security/persistence/data-integrity question.

## 5. Key reference (no secrets)

- Project: /home/kamesh62/nhost (700) — compose.yml (640), .env (600),
  initdb/01-roles.sh, scripts/backup.sh, docs/, backups/ (70:70), config/ (reserved),
  wg/ (700: wg0.conf, server keys, all 600).
- Network/volume: nhost-kamesh-net (bridge, isolated), nhost-kamesh-pgdata.
- Secrets inventory (names only): POSTGRES_* / LARAVEL_APP|MIGRATE_* / BACKUP_* /
  HASURA_ADMIN_* / GRAPHQL_ADMIN_SECRET / JWT_SECRET / AUTH_ENCRYPTION_KEY /
  AUTH_SMTP_PASS (Resend key, owner-placed). Stalwart creds: /opt/stalwart/.creds.
- Images pinned: postgres:16-alpine, nhost/graphql-engine:v2.46.0-ce, nhost/auth:0.52.0.
- API quirks (paid for in debugging, do not rediscover):
  * Hasura 2.46: track/untrack needs object-form table refs; needs pre-created schemas.
  * Auth 0.52: routes are /v1/signin-email-password etc.; needs AUTH_ENCRYPTION_KEY
    (32-byte hex); needs pre-created `auth` schema; signup-disabled = 403 (correct);
    no shell in image (no container healthcheck possible); SMTP_SECURE=false + 587.
  * Stalwart v0.16: config in RocksDB, managed via x:* JMAP methods (x:MtaRoute,
    x:Domain, x:Account...); webadmin at 127.0.0.1:8081; strategy changes need restart.
  * Compose env_file strips JSON double-quotes: JWT_SECRET must be single-quoted.
- Neighbors (DO NOT TOUCH): harness-crypto-analysis (6), stalwart (mail.888intelligence.org),
  vishwa-guru-webview-kernel/temple-trust (6). Three Postgres instances coexist
  (:5434 ours, :5433 harness, temple internal). Disk ~70%, RAM avail ~3.8G (2026-11-07).

## Project-scoped Hasura access (2026-11-10)
- Foundation deployed: project/environment registry, project IDs on owned tables,
  safe aggregate view, curated read-only Hasura roles, membership checks, and
  logical per-environment Storage buckets. See
  `docs/api-gateway/project-isolation/IMPLEMENTATION_STATUS.md`.
- Broker/token exchange is not deployed. Hasura CE v2.46 cannot use the planned
  multiple JWT verifier configuration. Owner decision required: CE auth hook or
  licensed multi-verifier edition. Keep WebView on Neon until broker and staging
  isolation/revocation/expiry checks pass.
- Open verification: live Storage upload path, physical MinIO object inventory,
  and project-specific payment provider uniqueness/lookup design.
