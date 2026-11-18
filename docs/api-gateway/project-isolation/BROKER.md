# Project API credential broker

Status: implementation draft, reviewed against docs/FEATURE_ASSESSMENT.md
(2026-11-16); do not deploy until the staged test matrix passes. This service is
separate from Auth's /v1/* routes. Architecture decision: Hasura CE + this POST
auth hook (the paid multi-verifier edition is retired).

## Identities

- A pub_... key is a public identifier for one project/environment. It can
  exchange for a 10-minute client_public token and can read only the curated
  public tables already granted to that role.
- A svc_... key is a secret held only by a trusted server. It exchanges for a
  10-minute service_reader token. The service role remains read-only.
- Real Nhost user JWTs continue to map to Hasura's user role. The user role's
  existing project-membership permission remains authoritative.
- No credential grants Hasura admin access. The browser must never receive a
  service secret or admin secret.

## Runtime interface

POST https://api.888intelligence.org/broker/v1/token

Public client request:

    {"key_id":"pub_<issued-id>"}

Trusted service request:

    {"key_id":"svc_<issued-id>","key_secret":"<secret shown once>"}

Both return a short-lived bearer JWT and expiry. Tokens contain a project claim,
one fixed Hasura role, issuer, audience, expiry, and a unique `jti`. The audience
is bound to the credential's project (`hasura:<project_id>`), so a token can
never be replayed against another project. A caller cannot choose a project or
role in the request. Revoking the credential also rejects already issued tokens
because the internal Hasura auth hook checks credential status on each request.
Token TTL is 600 seconds — deliberately stricter than the 15-minute bound in the
feature assessment.

Rate limits: the exchange endpoint is capped per client IP (60/min public,
10/min service) AND per credential (30/min public keys, 10/min service keys),
so one leaked key cannot be cycled rapidly even from a shared WireGuard address.
Nginx remains the outer perimeter limiter.

Decision audit: every exchange and hook decision (`issued` / `allowed` /
`denied`, with credential id, role, jti, and a short reason) is appended to
`platform.credential_decisions` (migration 004). The table stores no tokens or
request bodies, and `nhost_broker` holds INSERT only — the broker cannot read
or alter the trail. Audit writes are best-effort: a failed write is logged but
never blocks or changes an auth decision (availability over audit completeness).

Hasura calls POST http://credential-broker:8000/internal/hasura-auth over the
private Docker network. The hook validates broker JWTs and asks Nhost Auth's
internal /token/verify endpoint to validate user JWTs before reading their
claims. It returns only the narrow session variables required by the existing
Hasura permissions. Fail closed if a verifier or database is unavailable.

## Database and secrets

- Apply migrations 003-api-credentials.sql (registry), 004-credential-decisions.sql
  (decision audit table), then 005-credential-scopes.sql (strict scope families:
  public holds exactly {public_read}, service holds service_read and optionally
  service_write) after project migration 001.
- The runtime role nhost_broker has SELECT only on the credential registry and
  INSERT only on the decision audit table.
- Generate a separate RS256 key pair for the broker. Never reuse Nhost's HS256
  signing secret. Keys live as kid-named pairs in the owner-placed, mode-600 key
  directory: `<kid>.private.pem` / `<kid>.public.pem` (see `broker/keys.py`).
  The broker hot-reloads the directory, signs with the newest kid, verifies
  with every loaded kid, and publishes them at
  `/.well-known/jwks.json`. A directory holding only `private.pem` /
  `public.pem` is accepted as kid `legacy` for the first deployment.

## Key rotation and compromise procedure

1. Place the new `<kid>.private.pem` / `<kid>.public.pem` pair alongside the
   current one. Overlap is safe: old tokens keep verifying while new
   exchanges mint with the newest kid.
2. Confirm `/.well-known/jwks.json` lists both kids, then watch the decision
   audit until tokens with the old `kid` stop appearing (past the 600s TTL
   plus 60s skew leeway).
3. Remove the old pair. Revocation of a single credential needs no rotation:
   revoke the row and the hook rejects its tokens immediately.
4. On suspected private-key compromise: revoke every credential minted under
   that kid, rotate in a fresh pair, retire the compromised pair, and treat
   the TTL window as the maximum exposure bound.

## Caller retry policy (hook 503 semantics)

- The broker never retries internally: Auth `/token/verify` and database
  failures fail fast to 503 so Hasura denies. Retry lives caller-side.
- On 503, callers of idempotent reads may retry with bounded attempts
  (default 3, exponential backoff with jitter). Do not retry non-idempotent
  operations; do not retry 401s (a 401 is a credential/scope decision, and
  retrying it is a leak signal, not recovery).
- Sustained `rate_limit_*` denials in the decision audit are the
  credential-leak signal: investigate the credential, then revoke and
  reissue rather than raising caps.
- Run scripts/create-project-api-key.py with a privileged
  BROKER_KEY_ADMIN_DATABASE_URL only in an operator shell. A service secret is
  printed once. Do not redirect or log that output. The key id can be shared;
  the service secret must remain in a server-side secret manager.
- Key creation/revocation is an operator operation, not a public endpoint.

## Rollout gate

1. Back up Postgres and Hasura metadata. Create the dedicated DB role, apply the
   additive migration, and verify its grants.
2. Deploy the broker without switching Hasura authentication. Verify its
   health, key exchange, expiry, and revocation against a staging project.
3. Configure Hasura CE to use the POST auth hook, then verify public, service,
   and existing Nhost user JWTs plus negative cross-project and sensitive-table
   probes. Revert the Hasura auth-hook settings if any existing user-token probe
   fails.
4. Only after those checks should clients call the new broker and Hasura routes.

The existing Laravel Razorpay checkout endpoint remains the owner of checkout
and payment writes. Hasura roles do not receive financial-table mutations.
