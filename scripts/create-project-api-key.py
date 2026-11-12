#!/usr/bin/env python3
"""Create/revoke project credentials; requires a privileged DSN only at run time."""
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

        prefix = "pub" if args.create == "public" else "svc"
        credential_id = prefix + "_" + secrets.token_urlsafe(18)
        secret = secrets.token_urlsafe(32) if args.create == "service" else None
        digest = hashlib.sha256(secret.encode()).digest() if secret else None
        conn.execute(
            """INSERT INTO platform.api_credentials
               (credential_id, project_id, credential_kind, secret_hash)
               VALUES (%s, %s, %s, %s)""",
            (credential_id, args.project_id, args.create, digest),
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
