#!/usr/bin/env python3
"""OBSOLETE / DO NOT RUN.

The auth-email correction to kamransait41@gmail.com was already applied
DIRECTLY in the auth.users table and is verified live:
  - sign-in with kamransait41@gmail.com is recognised (user found)
  - kamransit41@gmail.com (typo) no longer exists

This script also pointed the WRONG direction: its NEW_EMAIL was the typo'd
address, so running it would have re-broken the account. It is kept only as
a record. If an email change is ever needed again, use:
  python3 /home/kamesh62/nhost/docs/api-gateway/reset-auth-password-db.py
(parity flow) or ask the assistant to do a direct DB correction.
"""
import sys

print("OBSOLETE: email already corrected to kamransait41@gmail.com. This script is disabled.")
sys.exit(0)

import getpass  # noqa: E402  (unreachable; kept for historical reference)
import json  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

BASE = "https://api.888intelligence.org/v1"
NEW_EMAIL = "kamransit41@gmail.com"

def request(path, method="GET", payload=None, token=None):
    headers = {"Content-Type": "application/json", "Origin": "https://vsrsms.in"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read()
            try:
                return response.status, json.loads(raw)
            except Exception:
                return response.status, {}
    except urllib.error.HTTPError as error:
        return error.code, {}
    except Exception:
        return 0, {}

current_email = getpass.getpass("Current email stored in Auth (hidden): ").strip()
password = getpass.getpass("New password you just set (hidden): ")
status, result = request("/signin/email-password", "POST", {"email": current_email, "password": password})
password = ""
if status != 200:
    current_email = ""
    print("AUTH_SIGNIN=FAILED; HTTP", status, "; no credentials or response details shown")
    sys.exit(1)
session = result.get("session", result)
token = session.get("accessToken") or session.get("access_token")
current_email = ""
if not token:
    print("AUTH_SIGNIN=NO_TOKEN; response details withheld")
    sys.exit(1)
print("AUTH_SIGNIN=OK; token remains in memory only")

status, elevation = request("/elevate", token=token)
if status != 200:
    token = ""
    print("ELEVATION_CHECK=FAILED; HTTP", status, "; no email change requested")
    sys.exit(2)
if elevation.get("elevationRequired") and not elevation.get("sessionElevated"):
    token = ""
    print("ELEVATION_REQUIRED; no email change requested")
    sys.exit(2)

status, _ = request("/user/email/change", "POST", {"newEmail": NEW_EMAIL}, token)
token = ""
if status != 200:
    print("EMAIL_CHANGE=FAILED; HTTP", status, "; response details withheld")
    sys.exit(3)
print("EMAIL_CHANGE=REQUESTED; check the corrected inbox and confirm the link")
print("PASSWORD_OR_TOKEN_PRINTED_OR_SAVED=no")
