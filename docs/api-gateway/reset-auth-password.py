#!/usr/bin/env python3
"""Set a new Nhost Auth password using a one-time passwordReset ticket.
Prompts hide both ticket and password; neither is printed or persisted.
"""
import getpass
import json
import sys
import urllib.error
import urllib.request

URL = "https://api.888intelligence.org/v1/user/password"
ticket = getpass.getpass("Password-reset ticket from your email URL (hidden): ").strip()
if not ticket.startswith("passwordReset:"):
    print("RESET=STOPPED; ticket must start with passwordReset:")
    sys.exit(1)
password = getpass.getpass("Choose a new password (hidden): ")
confirm = getpass.getpass("Confirm new password (hidden): ")
if password != confirm:
    password = confirm = ticket = ""
    print("RESET=STOPPED; passwords did not match")
    sys.exit(1)
body = json.dumps({"newPassword": password, "ticket": ticket}).encode()
password = confirm = ticket = ""
request = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
body = b""
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
