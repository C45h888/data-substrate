#!/usr/bin/env python3
"""Owner-run: set a new Nhost Auth password using the CURRENT ticket from the DB.

Unlike reset-auth-password.py (which needs the ticket copy-pasted from the
reset email), this reads the active passwordReset ticket directly from the
auth.users table via docker exec. No ticket handling by hand at all.

Secrets (ticket + passwords) are only held in memory, never printed or saved.
"""
import getpass
import json
import subprocess
import sys
import urllib.error
import urllib.request

CONTAINER = "nhost-kamesh-postgres-1"
PGUSER = "postgres"
DB = "appdb"
URL = "http://127.0.0.1:4000/v1/user/password"  # local, bypasses the public domain


def fetch_ticket() -> tuple[str, str]:
    """Return (ticket, expiry) of the current passwordReset ticket from the DB."""
    sql = (
        "SELECT ticket, ticket_expires_at::text FROM auth.users "
        "WHERE ticket LIKE 'passwordReset:%' ORDER BY updated_at DESC LIMIT 1;"
    )
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "psql", "-U", PGUSER, "-d", DB, "-Atc", sql],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if not out or "|" not in out:
        print("RESET=STOPPED; no passwordReset ticket found in DB — request a reset email first")
        sys.exit(1)
    ticket, expires = out.split("|", 1)
    return ticket, expires


ticket, expires_at = fetch_ticket()
print(f"Found active passwordReset ticket (expires {expires_at})")

password = getpass.getpass("Choose a new password (hidden): ")
confirm = getpass.getpass("Confirm new password (hidden): ")
if password != confirm:
    password = confirm = ticket = ""
    print("RESET=STOPPED; passwords did not match")
    sys.exit(1)

body = json.dumps({"newPassword": password, "ticket": ticket}).encode()
password = confirm = ticket = ""

request = urllib.request.Request(
    URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        print("RESET=OK; HTTP", response.status, "; tokens/passwords not printed or saved")
        print("Existing Auth sessions are revoked; sign in again to obtain a fresh JWT.")
except urllib.error.HTTPError as error:
    print("RESET=FAILED; HTTP", error.code, "; response details withheld")
    sys.exit(2)
except Exception:
    print("RESET=FAILED; connection error; details withheld")
    sys.exit(3)
