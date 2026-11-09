#!/usr/bin/env bash
# Private loopback authentication smoke; a disposable user database only.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
USERS="$PWD/target/debug/fedup-users"
AUTH="$PWD/target/debug/fedup-auth"
for file in "$USERS" "$AUTH"; do
  [[ -x "$file" ]] || { echo "missing $file" >&2; exit 2; }
done
umask 077
TMP="$(mktemp -d)"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

"$USERS" init "$TMP/accounts"
SECRET="test-password-long-enough-$(date +%s)"
NEW_SECRET="second-secret-long-enough-$(date +%s)"
printf '%s\n' "$SECRET" | "$USERS" add "$TMP/accounts" family1 --password-stdin
[[ "$(stat -c '%a' "$TMP/accounts")" == "700" ]]
[[ "$(stat -c '%a' "$TMP/accounts/users.sqlite3")" == "600" ]]
if grep -aFq "$SECRET" "$TMP/accounts/users.sqlite3"; then
  echo "SECRET LEAK: plaintext password found in account database" >&2
  exit 1
fi
if printf '%s\n' "$SECRET" | "$USERS" add "$TMP/accounts" family1 --password-stdin >/dev/null 2>&1; then
  echo "duplicate user account accepted" >&2; exit 1
fi
PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
"$AUTH" serve "$TMP/accounts" "$PORT" --behind-https-proxy >"$TMP/server.log" 2>&1 &
PID="$!"
BASE="http://127.0.0.1:$PORT/api/fedup/v1/login"
for _ in $(seq 1 50); do
  if curl -fsS --noproxy '*' --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then break; fi
  if curl --noproxy '*' -s --max-time 1 -o /dev/null "$BASE" 2>/dev/null; then break; fi
  sleep 0.1
done
check() {
  local user="$1" pass="$2" expected="$3" code
  code="$(python3 - "$BASE" "$user" "$pass" <<'PY'
import json,sys,urllib.error,urllib.request
url,user,password=sys.argv[1:]
payload=json.dumps({"username":user,"password":password}).encode()
req=urllib.request.Request(url,data=payload,method="POST",headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req,timeout=6) as result:
        print(result.status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
)"
  if [[ "$code" != "$expected" ]]; then
    echo "unexpected login HTTP response $code (wanted $expected)" >&2
    cat "$TMP/server.log" >&2; exit 1
  fi
}
check family1 "$SECRET" 204
check family1 incorrect-password-123 401
check unknown "$SECRET" 401
"$USERS" disable "$TMP/accounts" family1
check family1 "$SECRET" 401
"$USERS" enable "$TMP/accounts" family1
printf '%s\n' "$NEW_SECRET" | "$USERS" password "$TMP/accounts" family1 --password-stdin
check family1 "$SECRET" 401
check family1 "$NEW_SECRET" 204
echo "FedUp user accounts and loopback login: PASS (Argon2id, deny, disable, rotate)"
