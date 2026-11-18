#!/usr/bin/env python3
"""Create/revoke project credentials; requires a privileged DSN only at run time.

Issuance is operator-only by design. There is no HTTP credential-management
endpoint and no admin secret: the only way to create or revoke a credential
is this script with a privileged DSN in an operator shell. The broker's
HTTP surface is exchange (/v1/token) plus the internal auth hook.
"""
import argparse
import hashlib
import os
import secrets
import sys

import psycopg


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--create", choices=("public", "service"))
    action.add_argument("--revoke", metavar="CREDENTIAL_ID")
    parser.add_argument("--project-id")
    parser.add_argument(
        "--scopes",
        default=None,
        help="Comma-separated scopes (public: public_read only; service: service_read plus optional public_read,service_write)",
    )
    args = parser.parse_args()
    dsn = os.environ.get("BROKER_KEY_ADMIN_DATABASE_URL")
    if not dsn:
        print("BROKER_KEY_ADMIN_DATABASE_URL must be supplied in the operator environment.", file=sys.stderr)
        return 2

    with psycopg.connect(dsn) as conn:
        if args.revoke:
            changed = conn.execute(
                """UPDATE platform.api_credentials
                   SET status='revoked', revoked_at=now()
                   WHERE credential_id=%s AND status='active'""",
                (args.revoke,),
            ).rowcount
            if changed != 1:
                print("REVOKE=NO_CHANGE")
                return 1
            print("REVOKE=OK; existing tokens are rejected by the auth hook.")
            return 0

        if not args.project_id:
            parser.error("--project-id is required with --create")
        project = conn.execute(
            "SELECT id FROM platform.projects WHERE id=%s", (args.project_id,)
        ).fetchone()
        if not project:
            print("KEY_CREATE=FAILED; project not found.")
            return 1

        if args.scopes:
            scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
        else:
            scopes = ["public_read"] if args.create == "public" else ["service_read"]
        allowed = {"public_read"} if args.create == "public" else {"service_read", "service_write"}
        if not scopes or any(s not in allowed for s in scopes):
            print("KEY_CREATE=FAILED; invalid scopes for credential kind.")
            return 1
        if args.create == "service" and "service_read" not in scopes:
            print("KEY_CREATE=FAILED; service credentials must include service_read.")
            return 1

        prefix = "pub" if args.create == "public" else "svc"
        credential_id = prefix + "_" + secrets.token_urlsafe(18)
        secret = secrets.token_urlsafe(32) if args.create == "service" else None
        digest = hashlib.sha256(secret.encode()).digest() if secret else None
        conn.execute(
            """INSERT INTO platform.api_credentials
               (credential_id, project_id, credential_kind, secret_hash, scopes)
               VALUES (%s, %s, %s, %s, %s)""",
            (credential_id, args.project_id, args.create, digest, scopes),
        )
    if secret:
        print("KEY_CREATE=OK; credential_id=" + credential_id)
        print("KEY_SECRET=" + secret)
        print("Store the secret in the trusted server's secret manager; it cannot be shown again.")
    else:
        print("KEY_CREATE=OK; public_key=" + credential_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
