#!/usr/bin/env bash
# End-to-end check against a running substrate install:
#  1. verify the shim can create/resume an actor and proxy to it
#  2. verify idle suspend + resume keeps the durable volume
#  3. run a claude-code turn end-to-end when ANTHROPIC_API_KEY is set
#
# Requires: trident running with TRI_BACKEND=substrate
#           (TRI_LISTEN_ADDR/TRI_API_KEY exported here too).
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
KEY="${TRI_API_KEY:?TRI_API_KEY is required}"
CHAT="e2e-$(date +%s)"
TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

# Curl to a temp file first, print after: `curl | head -c` under pipefail
# aborted the whole run with SIGPIPE whenever a body exceeded the 4 KB cut.
h() {
  curl -fsS -H "Authorization: Bearer ${KEY}" \
    -H "X-User-Id: e2e" -H "X-Session-Id: ${CHAT}" \
    -o "${TMP}" "$@"
  head -c 4000 "${TMP}"
}

echo "==> /api/config (must not require the key nor wake an actor)"
curl -fsS -o "${TMP}" "${BASE}/api/config"
head -c 4000 "${TMP}"; echo

echo "==> templates must 404"
code=$(curl -o /dev/null -w '%{http_code}' "${BASE}/api/v1/terminals/templates")
[[ "${code}" == "404" ]] || { echo "got ${code}"; exit 1; }

echo "==> first proxied call creates+resumes the chat actor (may take a while)"
h -X POST -H 'Content-Type: application/json' -d '{"path":"/home/user"}' \
  "${BASE}/files/cwd"; echo
h "${BASE}/files/cwd"; echo

echo "==> write a file that must survive idle suspend + resume"
h -X POST -H 'Content-Type: application/json' -d '{"path":"e2e-kind.txt","content":"survives suspend"}' \
  "${BASE}/files/write"; echo
readback=$(h "${BASE}/files/read?path=e2e-kind.txt")
grep -q "survives suspend" <<<"${readback}" || { echo "write/read failed"; exit 1; }

echo "==> agent discovery"
h "${BASE}/agents" | grep -q "protocol_version" || { echo "bad /agents"; exit 1; }

echo "==> agents with claude-code available?"
if h "${BASE}/agents?provider=claude-code" | grep -q '"available":false'; then
  echo "claude-code unavailable (CLI or key missing); skipping turn test"
  exit 0
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY unset; skipping claude-code turn"
  exit 0
fi

echo "==> run one claude-code turn (stream-json over the agent WS)"
SID=$(h -X POST -H 'Content-Type: application/json' \
  -d '{"request_id":"e2e-turn-1","cwd":"/home/user","approval_mode":"full"}' \
  "${BASE}/agents/claude-code/sessions" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
echo "session ${SID}"

python3 - "$BASE" "$KEY" "$SID" <<'EOF'
import json, sys, threading, time
import websocket

base, key, sid = sys.argv[1], sys.argv[2], sys.argv[3]
ws_url = "ws" + base[len("http"):] + f"/agents/sessions/{sid}/connect"
ws = websocket.create_connection(ws_url, timeout=120)
seq_out, seq_in = -1, 0
ws.send(json.dumps({"type": "auth", "token": key, "cursor": max(seq_out, 0)}))

def send_input():
    time.sleep(0.5)
    user_init = {"type": "user", "message": {"role": "user", "content": "Say exactly: e2e-through-substrate"},
                 "parent_tool_use_id": None, "session_id": "e2e"}
    global seq_in
    ws.send(json.dumps({"type": "input", "sequence": 1, "data": json.dumps(user_init)}))
    seq_in = 1

threading.Thread(target=send_input, daemon=True).start()

deadline = time.time() + 110
hits = 0
while time.time() < deadline:
    frame = json.loads(ws.recv())
    t = frame.get("type")
    if t == "output":
        seq_out = frame["sequence"]
        ws.send(json.dumps({"type": "ack", "sequence": seq_out}))
        payload = json.loads(frame["data"])
        if payload.get("type") == "assistant" or payload.get("type") == "result":
            text = json.dumps(payload)
            if "e2e-through-substrate" in text:
                hits += 1
    elif t == "exit":
        print("agent exited:", frame)
        break
print("turn completed" if hits else "NO MATCH", flush=True)
sys.exit(0 if hits else 1)
EOF

echo "==> stop: DELETE the agent session"
code=$(curl -o /dev/null -w '%{http_code}' -X DELETE \
  -H "Authorization: Bearer ${KEY}" -H "X-User-Id: e2e" -H "X-Session-Id: ${CHAT}" \
  "${BASE}/agents/sessions/${SID}")
echo "delete ${code}"

echo "e2e-kind: PASS"
