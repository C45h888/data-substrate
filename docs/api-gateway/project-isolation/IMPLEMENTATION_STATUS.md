# Project-scoped Hasura access — implementation status

Date: 2026-11-10

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

## Not implemented / security gate

- No credential-broker service, public/private client credentials, signing key,
  broker route, or broker token exchange has been deployed.
- The planned `HASURA_GRAPHQL_JWT_SECRETS` dual-verifier configuration is not
  supported by the deployed Hasura Community Edition runtime according to the
  official edition documentation. The temporary test confirmed it cannot verify
  both issuers as configured. Live Hasura still uses its existing Auth issuer.
- Do not issue broker RS256 tokens until an approved CE-compatible auth hook is
  deployed and tested, or the engine is upgraded to an edition supporting
  multiple JWT verifiers. Reusing the Auth HS256 signing key for the broker is
  not recommended because it would let the broker forge user tokens.
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
