#!/usr/bin/env bash
# Owner-run interactive Auth password change (Phase C close-out).
# Security properties:
#   - passwords are read with hidden prompts, never echoed
#   - passwords/JSON are passed to curl via STDIN, never via argv (not visible in ps)
#   - the JWT is passed via a 0600 temp file, deleted on exit
#   - only HTTP status codes and PASS/FAIL verdicts are printed
#   - nothing secret is written to disk
set -euo pipefail

AUTH="http://127.0.0.1:4000"
EMAIL="kamransait41@gmail.com"
MINLEN=9   # AUTH_PASSWORD_MIN_LENGTH

TMPDIR_SEC=$(mktemp -d)
chmod 700 "$TMPDIR_SEC"
cleanup() { rm -rf "$TMPDIR_SEC"; unset CUR NEW1 NEW2 TOKEN || true; }
trap cleanup EXIT

prompt() { read -rsp "$1" "$2"; echo >&2; }

prompt "Current (bootstrap) password: " CUR
prompt "New password: " NEW1
prompt "New password (repeat): " NEW2
echo >&2

[ "$NEW1" = "$NEW2" ] || { echo "ABORT: new passwords do not match" >&2; exit 1; }
[ "${#NEW1}" -ge "$MINLEN" ] || { echo "ABORT: new password shorter than $MINLEN characters" >&2; exit 1; }

echo "1) Signing in with the CURRENT password..."
signin_code=$(jq -nc --arg e "$EMAIL" --arg p "$CUR" '{email:$e,password:$p}' \
  | curl -s --noproxy '*' -m 15 -o "$TMPDIR_SEC/signin.json" -w '%{http_code}' \
      -X POST "$AUTH/v1/signin/email-password" \
      -H 'Content-Type: application/json' --data-binary @-)
if ! TOKEN=$(jq -r '.session.accessToken // empty' "$TMPDIR_SEC/signin.json" 2>/dev/null) || [ -z "$TOKEN" ]; then
  rm -f "$TMPDIR_SEC/signin.json"
  echo "FAIL: sign-in with current password did not return a token (HTTP $signin_code)." >&2
  echo "      401 = wrong current password; 429 = rate-limited; 000 = network issue." >&2
  echo "      Nothing was changed. Check the current password and try again." >&2
  exit 1
fi
rm -f "$TMPDIR_SEC/signin.json"
printf '%s\n' "Authorization: Bearer $TOKEN" > "$TMPDIR_SEC/auth.hdr"
chmod 600 "$TMPDIR_SEC/auth.hdr"

echo "2) Changing password..."
jq -nc --arg p "$NEW1" '{newPassword:$p}' \
  | curl -s --noproxy '*' -m 15 -o "$TMPDIR_SEC/chpw.out" -w '%{http_code}' \
      -X POST "$AUTH/v1/user/password" \
      -H @"$TMPDIR_SEC/auth.hdr" -H 'Content-Type: application/json' --data-binary @- \
  > "$TMPDIR_SEC/chpw.code"
chpw_code=$(cat "$TMPDIR_SEC/chpw.code")
rm -f "$TMPDIR_SEC/chpw.out" "$TMPDIR_SEC/chpw.code"

if [ "$chpw_code" = "200" ]; then
  echo "   -> password change: HTTP 200 OK"
else
  echo "FAIL: password change returned HTTP ${chpw_code:-unknown}. Nothing verified; retry." >&2
  exit 1
fi

echo "3) Verifying the OLD password is now REJECTED..."
jq -nc --arg e "$EMAIL" --arg p "$CUR" '{email:$e,password:$p}' \
  | curl -s --noproxy '*' -m 15 -o /dev/null -w '%{http_code}' \
      -X POST "$AUTH/v1/signin/email-password" \
      -H 'Content-Type: application/json' --data-binary @- > "$TMPDIR_SEC/old.code"
old_code=$(cat "$TMPDIR_SEC/old.code")
rm -f "$TMPDIR_SEC/old.code"

echo "4) Verifying the NEW password is ACCEPTED..."
jq -nc --arg e "$EMAIL" --arg p "$NEW1" '{email:$e,password:$p}' \
  | curl -s --noproxy '*' -m 15 -o /dev/null -w '%{http_code}' \
      -X POST "$AUTH/v1/signin/email-password" \
      -H 'Content-Type: application/json' --data-binary @- > "$TMPDIR_SEC/new.code"
new_code=$(cat "$TMPDIR_SEC/new.code")
rm -f "$TMPDIR_SEC/new.code"

echo
echo "RESULT (status codes only):"
echo "  change-password       : $chpw_code (expected 200)"
echo "  old-password sign-in  : $old_code (expected 401/403 = rejected)"
echo "  new-password sign-in  : $new_code (expected 200 = accepted)"

if [ "$chpw_code" = "200" ] && [ "$old_code" != "200" ] && [ "$new_code" = "200" ]; then
  echo "PASS: password changed; old credential rejected; new credential works."
  echo "Next: remove the bootstrap file with:  rm -i /home/kamesh62/.bootstrap-pw"
  exit 0
fi
echo "INCONCLUSIVE: see status codes above." >&2
exit 1
