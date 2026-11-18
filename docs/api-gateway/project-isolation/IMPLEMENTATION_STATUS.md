# Project-scoped Hasura access — implementation status

Date: 2026-11-10 (broker status updated 2026-11-16)

## Implemented

- Created private `platform.projects`, `platform.project_memberships`, and
  `platform.project_storage_buckets` registries. Added development, staging,
  and production ULIDs for Vishwa Guru.
- Added `project_id` to 22 project-owned application tables, assigned existing
  Vishwa Guru rows to production, and added 26 validated composite foreign keys.
  Global reference data and Laravel operational tables remain outside client
  GraphQL access.
- Added `public.campaign_progress` as an aggregate-only campaign view.
- Added Hasura roles `client_public`, `user`, and `service_reader` with curated
  select permissions. Public and service access is project-claim filtered;
  user access is filtered by active project membership. No client mutations
  were granted. Financial and administrative tables remain unavailable.
- Added three logical Storage buckets and project/environment mappings while
  leaving the existing `default` bucket in place. Updated Hasura Storage user
  permissions to retain uploader ownership and require project membership for
  the new buckets. Public Storage access is absent.
- Added a production owner membership for the existing verified Auth account.
  Identity details are intentionally omitted from this log.
- The reusable metadata script now accepts `OWNER_AUTH_USER_ID` from the
  operator's environment instead of embedding a personal email address.
- Backed up the database and Hasura metadata before changes. Applied the schema
  and metadata changes without restarting the live Hasura service.

## Verification evidence

- Isolated restored database: 29 public tables and 517 rows; migration applied,
  26 project foreign keys validated, and a cross-project relationship attempt
  was rejected.
- Live project metadata: three project environments; existing campaigns map to
  production. Hasura health remained HTTP 200.
- Permission checks: production campaign reads returned 3 rows; staging returned
  0; an active member read returned 3; nonmember read returned 0. Financial
  table probes and public-role mutations were denied.
- Storage metadata checks: user reads preserve the default bucket behavior and
  restrict new mapped buckets to active members. Nonmember reads returned 0 and
  public Storage access was denied. The live `storage.files` table is empty.
- A staged Storage permission canary passed, but a live upload was not verified;
  do not treat Storage uploads as production-ready based on this check alone.
- Neon and the WebView were not changed. No payment logic, DNS, Nginx, or live
  Auth issuer configuration was changed.

## Not implemented / security gate (updated 2026-11-16)

- Architecture decision recorded: Hasura CE + POST auth hook; the paid
  multi-verifier edition is retired. The broker draft in `broker/` implements
  the hook and verifies both token families itself; the
  `HASURA_GRAPHQL_JWT_SECRETS` dual-verifier plan is abandoned.
- The broker is a reviewed local draft only. No signing key, credential, or
  broker route is deployed, and live Hasura still uses its existing Auth issuer.
  Tier-1 code gaps (jti, project-bound audience, decision audit log,
  per-credential rate caps) are closed in the draft; see
  `docs/FEATURE_ASSESSMENT.md` for the item-by-item status.
- Do not issue broker RS tokens on any live system until migration 004 is
  applied on the target, the broker is deployed behind the rollout gate in
  `BROKER.md`, and the staged negative matrix passes.
- Migration 005 enforces strict scope families: public={public_read}→client_public, service={service_read[,service_write]}→service_reader/service_writer, enforced at issuance/exchange/hook. Credential issuance is operator-script-only by design (no HTTP credential-management endpoint, no admin secret).
- Reusing the Auth HS256 signing key for the broker remains prohibited: the
  broker signs with its own owner-placed RS256 key pair.
- Physical MinIO bucket/object inventory was not completed. No Storage object
  canary was uploaded live; existing `default` bucket permissions were retained.
- `payment_providers` is tagged with project IDs, but existing global unique
  provider-code/lookup behavior was not changed. Fully project-specific duplicate
  provider configuration needs a separate reviewed migration.

## Rollout boundary

This is a server-side data/permission foundation, not a completed broker rollout.
Keep the WebView on Neon and do not cut over application traffic. Next decision:
choose CE auth hook (with its per-request verifier dependency) or a licensed
Hasura edition with native multiple JWT verifiers. Then implement broker and
prove issuer separation, revocation, expiry, and project isolation in staging.

