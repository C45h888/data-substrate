# Project API credential broker

Status: implementation draft; do not deploy until reviewed and the staged tests
pass. This service is separate from Auth's /v1/* routes.

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
one fixed Hasura role, issuer, audience, and expiry. A caller cannot choose a
project or role in the request. Revoking the credential also rejects already
issued tokens because the internal Hasura auth hook checks credential status on
each request.

Hasura calls POST http://credential-broker:8000/internal/hasura-auth over the
private Docker network. The hook validates broker JWTs and asks Nhost Auth's
internal /token/verify endpoint to validate user JWTs before reading their
claims. It returns only the narrow session variables required by the existing
Hasura permissions. Fail closed if a verifier or database is unavailable.

## Database and secrets

- Apply migration 003-api-credentials.sql after project migration 001.
- The runtime role nhost_broker has SELECT only on the credential registry.
- Generate a separate RS256 key pair for the broker. Never reuse Nhost's HS256
  signing secret. The private key is mounted read-only at
  /run/broker-keys/private.pem; the public key is mounted at
  /run/broker-keys/public.pem.
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
