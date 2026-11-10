# Nhost data substrate

Infrastructure and database configuration for the self-hosted Nhost stack:
PostgreSQL, Hasura, Auth, and Storage/MinIO. This repository contains the
reviewable substrate and deployment notes, not application code or production
database contents.

## Security and scope

- This repository is public. It must never contain `.env` files, credentials,
  private keys, database dumps, Hasura metadata backups, auth reset scripts, or
  customer data.
- Supply secrets locally through a mode-0600 `.env` file. Start from
  `.env.example`; replace every placeholder before deploying.
- The manifests bind database and API ports to the WireGuard interface. Do not
  change them to wildcard/public binds.
- Neon remains the active application database. This repo does not perform a
  WebView cutover.

## Contents

- `compose.yml`, `compose.storage.yml`: pinned runtime services and resource
  limits.
- `initdb/`: PostgreSQL role/bootstrap setup.
- `scripts/`: database backup helper.
- `docs/api-gateway/project-isolation/migrations/`: project registry,
  project-scoped columns/constraints, aggregate view, and Storage mappings.
- `docs/api-gateway/project-isolation/*metadata.py`: Hasura metadata and
  permission setup utilities. Review the deployment notes before running them.
- `apply-live-metadata.py` requires `OWNER_AUTH_USER_ID` to be supplied from
  the target Auth database; it does not embed an account email or UUID.
- `docs/api-gateway/project-isolation/IMPLEMENTATION_STATUS.md`: implemented
  scope, verification evidence, and open security gates.

## Current architecture

Projects are isolated at the Hasura API layer. Client roles are read-only and
limited to curated fields. Public/service roles require a signed project claim;
the `user` role additionally requires active project membership. Sensitive
financial and administrative tables remain unavailable to client roles.

The credential broker is not implemented. The deployed Hasura Community Edition
configuration cannot verify both the existing Nhost Auth JWT issuer and a
separate broker issuer using the planned multi-verifier setting. Resolve the
auth-hook versus licensed-edition decision before issuing broker tokens.

## Review before deployment

These files document a running system and include deployment-specific service
names, ports, and project IDs. Confirm them against the target host before using
the scripts. Back up the database and Hasura metadata first. Never use
`docker compose down -v` on a data-bearing environment.
