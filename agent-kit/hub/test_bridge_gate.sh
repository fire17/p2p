#!/bin/sh
# agent-bridge.py trust gate: the trusted.json whitelist and the from-mode=bypass claim. Offline, fakes only:
# a fake ccpeer module (PYTHONPATH) records the from-mode the bridge claims for every send.
# Rule under test: claim from-mode=bypass ONLY into a route marked +bypass AND only for a sender the gate trusts
# (whitelist entry of the same via class; tunnel entries also need the uplink pin of their session).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/bridge-gate-test.XXXXXX"); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/fakepy"
pass=0 fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); echo "PASS $2"; else fail=$((fail+1)); echo "FAIL $2"; fi; }

# ---- fake ccpeer: every live peer in $FAKE_PEERS; send_to logs {to, mode, text} per frame to $FAKE_CCPEER_LOG.
# A peer named codex-* is a Codex record: send_to then writes peerbridge's inbound event to $FAKE_PB_HOME/events.jsonl
# as $FAKE_INJECT says (ok | fail | policy | silent).
cat > "$T/fakepy/ccpeer.py" <<'EOF'
import json, os, uuid
_last = {}
STATE_DIR = os.environ.get("FAKE_PB_HOME", "/nonexistent")
def records():
    return [dict({"name": n, "ref": "abcdef123456", "sessionId": "sid-" + n, "address": "uds:/x/" + n,
                  "messagingSocketPath": "/x/" + n, "pid": 1}, **({"harness": "codex"} if n.startswith("codex-") else {}))
            for n in os.environ.get("FAKE_PEERS", "").split(",") if n]
def resolve(to, recs=None):
    return [r for r in (records() if recs is None else recs) if r["name"] == to or r["sessionId"] == to]
def envelope(text, frm, from_name, from_mode=None):
    mode = from_mode if from_mode else "none"
    _last["mode"] = mode
    return '<cross-session-message from="%s" from-name="%s" from-mode="%s">\n%s\n</cross-session-message>' % (
        frm, from_name, mode, text)
def user_frame(frm, env, session_id=None, msg_id=None):
    return {"type": "user", "from": frm, "session_id": session_id, "msg_id": msg_id or str(uuid.uuid4()),
            "message": {"role": "user", "content": env}}
def send_to(rec, frames):
    with open(os.environ["FAKE_CCPEER_LOG"], "a") as f:
        for fr in frames:
            env = fr["message"]["content"]
            mode = env.split('from-mode="', 1)[1].split('"', 1)[0] if 'from-mode="' in env else "none"
            f.write(json.dumps({"to": rec["name"], "mode": mode, "text": env}) + "\n")
    how = os.environ.get("FAKE_INJECT", "ok")
    if rec.get("harness") == "codex" and how != "silent":
        ok, detail = {"ok": (True, "injected: started a new Codex turn (t1)"),
                      "fail": (None, "Codex app-server unreachable: [Errno 111] refused"),
                      "policy": (False, "target is not exposed by its owner's local peerbridge policy")}[how]
        with open(os.path.join(STATE_DIR, "events.jsonl"), "a") as f:
            for fr in frames:
                f.write(json.dumps({"ev": "inbound", "msgId": fr["msg_id"], "ok": ok, "detail": detail}) + "\n")
EOF

export FAKE_CCPEER_LOG="$T/sent.log" FAKE_PEERS="peer-yes,peer-no" PYTHONPATH="$T/fakepy" AGENT_HUB="$T/hub"
ROOT="$T/hub"
mkdir -p "$ROOT"

# put a message into <to>'s inbox as if it arrived over <via> ('' local, 'link:<x>', 'tunnel')
inject() {  # to from text via
  python3 - "$HERE/hub.py" "$ROOT" "$1" "$2" "$3" "$4" <<'EOF'
import importlib.util, sys
s = importlib.util.spec_from_file_location("agent_hub", sys.argv[1]); h = importlib.util.module_from_spec(s)
s.loader.exec_module(h)
h.Hub(sys.argv[2]).deliver(sys.argv[3], sys.argv[4], sys.argv[5], via=sys.argv[6])
EOF
}
# mode claimed for the send whose text contains $1 (or MISSING)
mode_of() {
  python3 - "$FAKE_CCPEER_LOG" "$1" <<'EOF'
import json, sys
try:
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
except OSError:
    rows = []
hit = [r for r in rows if sys.argv[2] in r["text"]]
print(hit[-1]["mode"] if len(hit) == 1 else "MISSING" if not hit else "DUP")
EOF
}
trust() { cat > "$ROOT/trusted.json"; }
BR() { python3 "$HERE/agent-bridge.py" --root "$ROOT" "$@"; }
MAPS="--map r-yes=peer:peer-yes+bypass --map r-no=peer:peer-no"
run() { OUT=$(BR $MAPS --once "$@" 2>&1); echo "$OUT" | sed 's/^/    /'; }

# ---- 1. --gate none (default): no claim even for a whitelisted sender into a +bypass route
printf '{"log":["test"],"senders":[{"name":"t-*","via":"local"}]}\n' | trust
inject r-yes t-a "tok-none-1" ""
run
[ "$(mode_of tok-none-1)" = none ]; ok $? "gate none: no bypass claim, even for a trusted sender into +bypass"
echo "$OUT" | grep -q "^NOTE --gate none: no from-mode=bypass claim into r-yes"; ok $? "gate none: startup NOTE names the +bypass routes"

# ---- 2. --gate trusted: whitelisted local sender -> bypass only into the +bypass route
inject r-yes t-a "tok-tr-yes" ""
inject r-no t-a "tok-tr-no" ""
python3 "$HERE/hub.py" here x-a --harness test >/dev/null   # registered, so the refusal notice can reach it
inject r-yes x-a "tok-untrusted" ""
inject r-yes hub "tok-hubnotice" "hub"
run --gate trusted
[ "$(mode_of tok-tr-yes)" = bypass ]; ok $? "trusted: local whitelisted sender claims bypass into +bypass route"
[ "$(mode_of tok-tr-no)" = none ]; ok $? "trusted: never a claim into a route not marked +bypass"
[ "$(mode_of tok-untrusted)" = MISSING ]; ok $? "trusted: sender not on the whitelist is refused, not sent"
[ "$(mode_of tok-hubnotice)" = MISSING ]; ok $? "trusted: via=hub notices are never trusted (refused into +bypass)"
echo "$OUT" | grep -q "^TRUSTED .*1 sender rule"; ok $? "trusted: TRUSTED line on load"
echo "$OUT" | grep -q "^REFUSE r-yes <- x-a .*sender not in trusted.json"; ok $? "refuse: REFUSE line names route, sender, reason"
grep -l "NOT DELIVERED r-yes .*It is not retried" "$ROOT"/inbox/x-a/*.json >/dev/null 2>&1; ok $? "refuse: sender gets one NOT DELIVERED notice (not retried)"
! ls "$ROOT/inbox/r-yes" | grep -q '\.json$'; ok $? "refuse: refused message leaves the inbox (no retry loop)"
inject r-yes x-b "tok-hol-untrusted" ""
inject r-yes t-b "tok-hol-trusted" ""
run --gate trusted
[ "$(mode_of tok-hol-trusted)" = bypass ] && [ "$(mode_of tok-hol-untrusted)" = MISSING ]; ok $? "refuse: an older untrusted message never blocks a trusted one behind it"

# ---- 3. via class must match: tunnel/link messages never ride a local entry
inject r-yes t-a "tok-tun-as-local" "tunnel"
inject r-yes t-a@lap "tok-link-as-local" "link:lap"
run --gate trusted
[ "$(mode_of tok-tun-as-local)" = MISSING ]; ok $? "class: tunnel message with a whitelisted local name gets no claim"
[ "$(mode_of tok-link-as-local)" = MISSING ]; ok $? "class: link message with a whitelisted local name gets no claim"

# ---- 4. link entries
printf '{"log":["test"],"senders":[{"name":"l-*","via":"link:*"},{"name":"m-*","via":"link:lap"}]}\n' | trust
inject r-yes l-a@lap "tok-link-any" "link:lap"
inject r-yes m-a@lap "tok-link-named" "link:lap"
inject r-yes m-a@far "tok-link-other" "link:far"
inject r-yes l-a "tok-local-as-link" ""
inject r-yes l-a "tok-tunnel-as-link" "tunnel"
run --gate trusted
[ "$(mode_of tok-link-any)" = bypass ]; ok $? "link: link:* entry trusts its names over any link"
[ "$(mode_of tok-link-named)" = bypass ] && [ "$(mode_of tok-link-other)" = MISSING ]; ok $? "link: link:<name> entry trusts only that link"
[ "$(mode_of tok-local-as-link)" = MISSING ] && [ "$(mode_of tok-tunnel-as-link)" = MISSING ]; ok $? "link: local and tunnel messages never ride a link entry"
echo "$OUT" | grep -q "^TRUSTED .*2 sender rule"; ok $? "reload: trusted.json re-read after it changed"

# ---- 5. tunnel entries need the uplink pin of their session
printf '{"log":["test"],"senders":[{"name":"helper","via":"tunnel","session":"join-SECRETKEY1"}]}\n' | trust
inject r-yes helper "tok-tun-nopin" "tunnel"
run --gate trusted
[ "$(mode_of tok-tun-nopin)" = MISSING ]; ok $? "tunnel: no uplink pin -> no claim"
! echo "$OUT" | grep -q SECRETKEY1; ok $? "tunnel: the join key is never printed"
mkdir -p "$ROOT/uplinks"; printf '{"peer":"OTHERKEY"}\n' > "$ROOT/uplinks/helper.pin.json"
inject r-yes helper "tok-tun-wrongpin" "tunnel"
run --gate trusted
[ "$(mode_of tok-tun-wrongpin)" = MISSING ]; ok $? "tunnel: uplink pinned to another key -> no claim"
printf '{"peer":"SECRETKEY1"}\n' > "$ROOT/uplinks/helper.pin.json"
inject r-yes helper "tok-tun-pinned" "tunnel"
inject r-yes helper "tok-tun-entry-local" ""
inject r-yes helper@lap "tok-tun-entry-link" "link:lap"
run --gate trusted
[ "$(mode_of tok-tun-pinned)" = bypass ]; ok $? "tunnel: pinned to the entry's key -> bypass"
[ "$(mode_of tok-tun-entry-local)" = MISSING ] && [ "$(mode_of tok-tun-entry-link)" = MISSING ]; ok $? "tunnel: a tunnel entry never trusts the same name locally or over a link"
! echo "$OUT" | grep -q SECRETKEY1; ok $? "tunnel: the pinned key is never printed"

# ---- 6. fail closed: missing, broken, invalid
rm -f "$ROOT/trusted.json"
inject r-yes helper "tok-missing" "tunnel"
run --gate trusted
[ "$(mode_of tok-missing)" = MISSING ] && echo "$OUT" | grep -q "^ERROR trusted.json: .*missing: nobody trusted"; ok $? "fail closed: missing file -> nobody trusted + ERROR"
printf '{"senders": [ {"name": "t-*", "via": "local"},' | trust
inject r-yes t-a "tok-broken" ""
run --gate trusted
[ "$(mode_of tok-broken)" = MISSING ] && echo "$OUT" | grep -q "^ERROR trusted.json: .*unreadable"; ok $? "fail closed: broken JSON -> nobody trusted + ERROR"
printf '{"senders":[{"name":"t-*","via":"local"},{"name":"helper","via":"tunnel"}]}\n' | trust
inject r-yes t-a "tok-invalid" ""
run --gate trusted
[ "$(mode_of tok-invalid)" = MISSING ] && echo "$OUT" | grep -q 'needs "session"'; ok $? "fail closed: tunnel entry without session rejects the whole file"
printf '{"senders":[{"name":"t-*","via":"anywhere"}]}\n' | trust
inject r-yes t-a "tok-badvia" ""
run --gate trusted
[ "$(mode_of tok-badvia)" = MISSING ] && echo "$OUT" | grep -q '"via" must be'; ok $? "fail closed: unknown via rejects the whole file"

# ---- 7. --gate all: everyone, but still only into +bypass routes
inject r-yes x-a "tok-all-yes" "tunnel"
inject r-no x-a "tok-all-no" ""
run --gate all
[ "$(mode_of tok-all-yes)" = bypass ] && [ "$(mode_of tok-all-no)" = none ]; ok $? "gate all: bypass for any sender, only into +bypass"
echo "$OUT" | grep -q "^WARNING --gate all"; ok $? "gate all: startup WARNING"

# ---- 8. config: gate key, --gate override, bad values, herdr+bypass refused
printf '{"senders":[{"name":"t-*","via":"local"}]}\n' | trust
printf '{"gate":"trusted","agents":[{"name":"r-yes","adapter":"ccpeer","peer":"peer-yes","bypass":true}]}\n' > "$T/cfg.json"
inject r-yes t-a "tok-cfg-gate" ""
OUT=$(BR --config "$T/cfg.json" --once 2>&1)
[ "$(mode_of tok-cfg-gate)" = bypass ]; ok $? "config: \"gate\": \"trusted\" + \"bypass\": true works"
inject r-yes t-a "tok-cfg-override" ""
OUT=$(BR --config "$T/cfg.json" --gate none --once 2>&1)
[ "$(mode_of tok-cfg-override)" = none ]; ok $? "config: --gate on the command line wins over the config"
BR $MAPS --gate mine --once >/dev/null 2>&1; [ $? = 2 ]; ok $? "config: unknown --gate refused"
printf '{"gate":"yes","agents":[{"name":"r-yes","peer":"peer-yes"}]}\n' > "$T/cfg2.json"
BR --config "$T/cfg2.json" --once >/dev/null 2>&1; [ $? = 2 ]; ok $? "config: unknown \"gate\" refused"
BR --map r-h=herdr:main:p1+bypass --once >/dev/null 2>&1; [ $? = 2 ]; ok $? "config: +bypass on a herdr route refused"
printf '{"agents":[{"name":"r-h","adapter":"herdr","session":"main","pane":"p1","bypass":true}]}\n' > "$T/cfg3.json"
BR --config "$T/cfg3.json" --once >/dev/null 2>&1; [ $? = 2 ]; ok $? "config: \"bypass\": true on a herdr adapter refused"

# ---- 9. herdr fallback on a +bypass route types only for trusted senders
mkdir -p "$T/bin" "$T/herdr"
cat > "$T/bin/herdr" <<'HEOF'
#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_HERDR_DIR"]; a = sys.argv[3:]
if a[:2] == ["agent", "get"]:
    print(json.dumps({"result": {"agent": {"pane_id": a[2], "agent_status": "idle"}}}))
elif a[:2] == ["agent", "read"]:
    print(json.dumps({"result": {"text": "> "}}))
elif a[:2] == ["agent", "prompt"]:
    with open(os.path.join(d, "typed.log"), "a") as f: f.write(json.dumps({"pane": a[2], "text": a[3]}) + "\n")
else:
    sys.exit(9)
HEOF
chmod +x "$T/bin/herdr"
printf '{"senders":[{"name":"t-*","via":"local"}]}\n' | trust
printf '{"herdr_session":"main","agents":[{"name":"r-fb","adapter":"auto","peer":"peer-gone+bypass","pane":"p1"}]}\n' > "$T/fb.json"
inject r-fb x-a "tok-fb-untrusted" "tunnel"
OUT=$(PATH="$T/bin:$PATH" FAKE_HERDR_DIR="$T/herdr" BR --config "$T/fb.json" --gate trusted --once 2>&1); RC=$?
echo "$OUT" | sed 's/^/    /'
[ $RC = 0 ] && ! grep -q tok-fb-untrusted "$T/herdr/typed.log" 2>/dev/null && echo "$OUT" | grep -q "^REFUSE r-fb .*sender not in trusted.json"
ok $? "fallback: untrusted sender is never typed into a +bypass pane (refused)"
inject r-fb x-a "tok-fb-untrusted-none" "tunnel"
OUT=$(PATH="$T/bin:$PATH" FAKE_HERDR_DIR="$T/herdr" BR --config "$T/fb.json" --gate none --once 2>&1); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "^HOLD r-fb .*only for senders the gate trusts"; ok $? "fallback: --gate none holds it instead"
ls "$ROOT/inbox/r-fb" | grep -q '\.json$'; ok $? "fallback: held message stays in the inbox"
! grep -q tok-fb-untrusted-none "$T/herdr/typed.log" 2>/dev/null; ok $? "fallback: --gate none types nothing into a +bypass pane"
rm -f "$ROOT"/inbox/r-fb/*.json
inject r-fb t-a "tok-fb-trusted" ""
OUT=$(PATH="$T/bin:$PATH" FAKE_HERDR_DIR="$T/herdr" BR --config "$T/fb.json" --gate trusted --once 2>&1)
grep -q tok-fb-trusted "$T/herdr/typed.log" 2>/dev/null; ok $? "fallback: trusted sender is typed when the native peer is gone"

# ---- 10. dry-run shows the claim it would make, sends nothing
inject r-yes t-a "tok-dry" ""
OUT=$(BR $MAPS --gate trusted --once --dry-run 2>&1)
echo "$OUT" | grep -q "^DRY r-yes <- t-a .*from-mode=bypass (dry-run, not sent)" && [ "$(mode_of tok-dry)" = MISSING ]
ok $? "dry-run: reports from-mode=bypass, sends nothing"

# ---- 10b. +trusted routes (Codex without approvals): only trusted senders, whatever the gate and the adapter
printf '{"senders":[{"name":"t-*","via":"local"}]}\n' | trust
inject r-to t-a "tok-to-trusted" ""
inject r-to x-a "tok-to-untrusted" "tunnel"
OUT=$(BR --map r-to=peer:peer-no+trusted --gate trusted --once 2>&1)
[ "$(mode_of tok-to-trusted)" = none ] && [ "$(mode_of tok-to-untrusted)" = MISSING ] \
  && echo "$OUT" | grep -q "^REFUSE r-to <- x-a .*trusted senders only"; ok $? "+trusted peer: trusted sender delivered (no bypass claim), untrusted refused"
echo "$OUT" | grep -q "^BRIDGE r-to=ccpeer+trusted " && echo "$OUT" | grep -q "^NOTE +trusted: r-to"; ok $? "+trusted peer: BRIDGE + NOTE lines name it"
inject r-to x-a "tok-to-gnone-bad" "tunnel"
inject r-to t-a "tok-to-gnone-trusted" ""
OUT=$(BR --map r-to=peer:peer-no+trusted --gate none --once 2>&1)
[ "$(mode_of tok-to-gnone-bad)" = MISSING ] && [ "$(mode_of tok-to-gnone-trusted)" = none ]; ok $? "+trusted peer: --gate none still refuses untrusted senders"
inject r-to x-a "tok-to-all" "tunnel"
OUT=$(BR --map r-to=peer:peer-no+trusted --gate all --once 2>&1)
[ "$(mode_of tok-to-all)" = none ]; ok $? "+trusted peer: --gate all lets everyone through (still no bypass claim)"
printf '{"agents":[{"name":"r-tc","adapter":"ccpeer","peer":"peer-no","trusted_only":true}]}\n' > "$T/to.json"
inject r-tc x-a "tok-to-cfg" "tunnel"
OUT=$(BR --config "$T/to.json" --gate trusted --once 2>&1)
[ "$(mode_of tok-to-cfg)" = MISSING ] && echo "$OUT" | grep -q "^REFUSE r-tc"; ok $? "+trusted: \"trusted_only\": true in the config works"
printf '{"agents":[{"name":"r-tc","adapter":"ccpeer","peer":"peer-no","trusted_only":"yes"}]}\n' > "$T/to2.json"
BR --config "$T/to2.json" --once >/dev/null 2>&1; [ $? = 2 ]; ok $? "+trusted: non-boolean trusted_only refused"

python3 "$HERE/hub.py" here t-a --harness test >/dev/null   # registered, so NOT CONFIRMED/DELIVERED notices reach it
# ---- 10c. herdr routes: +trusted, the composer draft check, UNSURE sends, deferred stop
cat > "$T/bin/herdr" <<'HEOF'
#!/usr/bin/env python3
import json, os, sys, time
d = os.environ["FAKE_HERDR_DIR"]; a = sys.argv[3:]
if a[:2] == ["agent", "get"]:
    time.sleep(float(os.environ.get("FAKE_GET_SLEEP") or 0))
    print(json.dumps({"result": {"agent": {"pane_id": a[2], "agent_status": "idle"}}}))
elif a[:2] == ["agent", "read"]:
    try: screen = open(os.path.join(d, a[2] + ".screen"), encoding="utf-8").read()
    except OSError: screen = "> "
    print(json.dumps({"result": {"text": screen}}))
elif a[:2] == ["agent", "prompt"]:
    with open(os.path.join(d, "typed.log"), "a") as f: f.write(json.dumps({"pane": a[2], "text": a[3]}) + "\n")
    sys.exit(int(os.environ.get("FAKE_SEND_RC") or 0))
else:
    sys.exit(9)
HEOF
chmod +x "$T/bin/herdr"
HB() { PATH="$T/bin:$PATH" FAKE_HERDR_DIR="$T/herdr" BR "$@"; }
typed_has() { grep -q "$1" "$T/herdr/typed.log" 2>/dev/null; }
inject r-ht x-a "tok-ht-untrusted" "tunnel"
inject r-ht t-a "tok-ht-trusted" ""
OUT=$(HB --map r-ht=herdr:main:p1+trusted --gate trusted --once 2>&1)
! typed_has tok-ht-untrusted && typed_has tok-ht-trusted && echo "$OUT" | grep -q "^REFUSE r-ht <- x-a"; ok $? "+trusted herdr: untrusted sender never typed, trusted one typed"
HB --map r-hb=herdr:main:p1+bypass+trusted --once >/dev/null 2>&1; [ $? = 2 ]; ok $? "+trusted herdr: +bypass on a herdr route still refused"

printf '\342\224\200\342\224\200\n\342\200\272 half typed by the user\n  ? for shortcuts\n' > "$T/herdr/p2.screen"
inject r-dr t-a "tok-draft" ""
OUT=$(HB --map r-dr=herdr:main:p2 --once 2>&1); RC=$?
echo "$OUT" | sed 's/^/    /'
[ $RC = 1 ] && ! typed_has tok-draft && echo "$OUT" | grep -q "^HOLD r-dr .*draft is in the composer" \
  && ls "$ROOT/inbox/r-dr" | grep -q '\.json$'; ok $? "draft: Codex composer holds text -> HOLD, nothing typed, message waits"
! grep -rq "half typed" "$ROOT/inbox/t-a" 2>/dev/null && ! echo "$OUT" | grep -q "half typed"; ok $? "draft: the draft text is never logged nor sent to the sender"
printf '\342\200\272 Ask Codex to do anything\n' > "$T/herdr/p2.screen"
OUT=$(HB --map r-dr=herdr:main:p2 --once 2>&1)
typed_has tok-draft; ok $? "draft: the Codex placeholder counts as an empty composer (typed)"
printf '\342\224\202 > \342\224\202\n\342\224\202 > also typed \342\224\202\n' > "$T/herdr/p2.screen"
inject r-dr t-a "tok-draft-cc" ""
OUT=$(HB --map r-dr=herdr:main:p2 --once 2>&1)
! typed_has tok-draft-cc && echo "$OUT" | grep -q "^HOLD r-dr .*draft"; ok $? "draft: Claude box composer row with text -> HOLD (last glyph row wins)"
printf '{"herdr_session":"main","agents":[{"name":"r-dr","adapter":"herdr","pane":"p2","composer_check":false}]}\n' > "$T/nodraft.json"
rm -f "$ROOT"/inbox/r-dr/.claims/* 2>/dev/null
OUT=$(HB --config "$T/nodraft.json" --once 2>&1)
typed_has tok-draft-cc; ok $? "draft: \"composer_check\": false skips the check"

inject r-un t-a "tok-unsure" ""
OUT=$(FAKE_SEND_RC=3 HB --map r-un=herdr:main:p1 --once 2>&1)
echo "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -q "^UNSURE r-un <- t-a .*herdr send rc=3; it may have been typed; not retried" \
  && ! ls "$ROOT/inbox/r-un" | grep -q '\.json$'; ok $? "unsure: send rc != 0 after herdr ran -> UNSURE, not put back"
OUT=$(FAKE_SEND_RC=3 HB --map r-un=herdr:main:p1 --once 2>&1)
[ "$(grep -c tok-unsure "$T/herdr/typed.log")" = 1 ]; ok $? "unsure: never typed a second time"
grep -l "NOT CONFIRMED r-un .*It is not retried" "$ROOT"/inbox/t-a/*.json >/dev/null 2>&1; ok $? "unsure: sender gets one NOT CONFIRMED notice"

inject r-sg t-a "tok-sigterm" ""
PATH="$T/bin:$PATH" FAKE_HERDR_DIR="$T/herdr" FAKE_GET_SLEEP=2 python3 "$HERE/agent-bridge.py" --root "$ROOT" \
  --map r-sg=herdr:main:p1 > "$T/sig.out" 2>&1 &
BP=$!
sleep 1; kill -TERM $BP; wait $BP; RC=$?
sed 's/^/    /' "$T/sig.out"
[ $RC = 0 ] && typed_has tok-sigterm && grep -q "^DELIVER r-sg <- t-a" "$T/sig.out"; ok $? "stop: SIGTERM mid-message waits for that message (delivered, not stranded in read/)"

# ---- 10d. Codex peers: delivered only once peerbridge's events.jsonl shows the inject worked
mkdir -p "$T/pb"; : > "$T/pb/events.jsonl"
CX() { FAKE_PB_HOME="$T/pb" FAKE_PEERS="codex-a" BR --map r-cx=peer:codex-a --once 2>&1; }
inject r-cx t-a "tok-cx-ok" ""
OUT=$(FAKE_INJECT=ok CX)
echo "$OUT" | grep -q "^DELIVER r-cx <- t-a .*via=ccpeer"; ok $? "codex: inject ok in events.jsonl -> DELIVER"
inject r-cx t-a "tok-cx-fail" ""
OUT=$(FAKE_INJECT=fail CX); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "^HOLD r-cx .*codex inject failed: Codex app-server unreachable" \
  && ls "$ROOT/inbox/r-cx" | grep -q '\.json$'; ok $? "codex: inject failed -> HOLD, message back in the inbox"
grep -l "NOT DELIVERED r-cx .*retried" "$ROOT"/inbox/t-a/*.json >/dev/null 2>&1; ok $? "codex: sender gets a NOT DELIVERED notice"
OUT=$(FAKE_INJECT=policy CX)
echo "$OUT" | grep -q "^REFUSE r-cx .*codex inject refused" && ! ls "$ROOT/inbox/r-cx" | grep -q '\.json$'; ok $? "codex: policy refusal -> REFUSE (not retried)"
inject r-cx t-a "tok-cx-silent" ""
OUT=$(FAKE_INJECT=silent CX)
echo "$OUT" | grep -q "^UNSURE r-cx .*no inject within 10 s" && ! ls "$ROOT/inbox/r-cx" | grep -q '\.json$'; ok $? "codex: no inject event -> UNSURE, not resent"
rm -f "$T/pb/events.jsonl"
inject r-cx t-a "tok-cx-noevents" ""
OUT=$(FAKE_INJECT=silent CX)
echo "$OUT" | grep -q "^DELIVER r-cx"; ok $? "codex: no events.jsonl at all -> delivered as before (nothing to confirm with)"

# ---- 11. source hygiene
python3 -c "import sys; sys.exit(0 if all(b < 128 for f in sys.argv[1:] for b in open(f,'rb').read()) else 1)" \
  "$HERE/agent-bridge.py" "$HERE/trusted.example.json" "$HERE/test_bridge_gate.sh"; ok $? "source: ASCII only"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if isinstance(d.get('senders'), list) and isinstance(d.get('log'), list) else 1)" \
  "$HERE/trusted.example.json"; ok $? "trusted.example.json: valid JSON with log + senders"
echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
