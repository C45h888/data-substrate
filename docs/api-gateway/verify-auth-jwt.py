#!/usr/bin/env python3
"""Interactive, read-only Nhost Auth -> Hasura JWT smoke test.
Prompts for credentials without echo; never prints or persists the access token.
"""
import getpass
import json
import sys
import urllib.error
import urllib.request

BASE = "https://api.888intelligence.org"

def post(path, payload, token=None):
    headers = {"Content-Type": "application/json", "Origin": "https://vsrsms.in"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read())
        except Exception:
            body = {}
        return error.code, body

email = input("Nhost Auth email: ").strip()
password = getpass.getpass("Nhost Auth password (hidden): ")
status, response = post("/v1/signin/email-password", {"email": email, "password": password})
password = ""
if status != 200:
    print("AUTH_SIGNIN=FAILED; HTTP", status, "; credentials and response body withheld")
    sys.exit(1)
session = response.get("session", response)
token = session.get("accessToken") or session.get("access_token")
if not token:
    print("AUTH_SIGNIN=NO_ACCESS_TOKEN; response details withheld")
    sys.exit(1)
print("AUTH_SIGNIN=OK; access token remains in memory only")

query = "query { campaigns(limit: 10, order_by: {display_order: asc}) { id slug title state } }"
status, result = post("/v1/graphql", {"query": query}, token)
errors = result.get("errors", [])
if status != 200 or errors:
    code = errors[0].get("extensions", {}).get("code", "graphql-error") if errors else "http-error"
    print("HASURA_USER_QUERY=DENIED;", code)
    sys.exit(2)
rows = result.get("data", {}).get("campaigns", [])
print("HASURA_USER_QUERY=OK; campaign rows:", len(rows))

status, denied = post("/v1/graphql", {"query": "query { donations(limit: 1) { id } }"}, token)
errors = denied.get("errors", [])
if errors:
    code = errors[0].get("extensions", {}).get("code", "graphql-error")
    print("SENSITIVE_TABLE_PROBE=DENIED;", code)
else:
    print("SENSITIVE_TABLE_PROBE=UNEXPECTEDLY_ALLOWED")
    sys.exit(3)
print("JWT_PRINTED_OR_SAVED=no")
