#!/usr/bin/env python3
"""agent-bridge: hand each agent's hub messages to its harness the most NATIVE way, herdr typing only as fallback.
Python 3.8+, standard library only.

  agent-bridge.py --config bridge.json            run forever (heartbeat + deliver, one log line per delivery)
  agent-bridge.py --config bridge.json --once     one pass, then exit (exit 1 if any message is held)
  agent-bridge.py --config bridge.json --dry-run  read-only: show what WOULD be delivered and how; claims,
                                                  sends, types and heartbeats nothing (combine with --once)

For every configured name the bridge keeps the name present in the hub (agents/<name>.json heartbeat) and
claims its inbox (hub.claim, exactly once across readers), then delivers each message as

  [<from> via hub] <text>
  (reply: python3 <hub.py> send <from> "<answer>" --from <name>)

Adapters, per name:
  ccpeer  Claude Code's own cross-session protocol (codex-bridge/peerbridge/ccpeer.py): resolve(peer) must find
          exactly one live session; the text goes in as a <cross-session-message> user frame on its socket.
          A Codex thread made reachable with `pb expose --thread <id>` is a ccpeer peer too: same path.
  herdr   fallback only: type one cleaned line into a herdr pane. Before typing, `herdr agent get` must say
          the pane is in an allowed state (default: idle) AND the pane's visible screen must show no dialog
          (herdr can report a pane idle while a trust/permission/picker dialog is up). Otherwise nothing is
          typed: the message goes back to the inbox and is retried later (backoff 5 s .. 60 s); the sender
          gets one NOT DELIVERED notice per message.
  auto    ccpeer first; herdr only when ccpeer is not importable, the peer is not live/unique, or the send fails.

Config (JSON). Either shape works:
  {"hub_root": "...", "herdr_session": "work",
   "agents": [{"name": "desk-codex",  "adapter": "ccpeer", "peer": "desk-codex"},
              {"name": "desk-claude", "adapter": "herdr", "session": "work", "pane": "w1:p2"},
              {"name": "desk-rc",     "adapter": "auto", "peer": "desk-rc", "pane": "w1:p3"}]}
  {"herdr_session": "work", "agents": {"desk-rc": {"peer": "desk-rc", "pane": "rc"}}}
     (dict form: adapter defaults to auto with both peer and pane, else whichever one is given)
Optional top-level keys: hub_root (else --root, $AGENT_HUB, the hub's default), peerbridge (folder holding
ccpeer.py; default ../codex-bridge/peerbridge next to this file; a ccpeer on PYTHONPATH wins over the default),
herdr (binary, default "herdr"), herdr_send (argv template after `herdr --session S`, default
["agent", "prompt", "{pane}", "{text}"]; e.g. ["pane", "run", "{pane}", "{text}"] for herdr 0.7),
herdr_ok_states (default ["idle"]), dialog_markers (extra lower-case screen phrases that mean "dialog up"),
herdr_max_chars (default 4000), poll (s, default 1), heartbeat (s, default 10), reply_cmd (default
"python3 <abs path of hub.py>"). Per agent: harness, note, session, pane, peer, herdr_send, herdr_ok_states.

Messages are DATA: nothing here runs message text. Commands are fixed argv lists (no shell). The peer key that
ccpeer reads to authenticate is never printed. Do not also run `hub.py ear` for a bridged name: two readers of
one inbox split its messages between them (each message still reaches exactly one).
"""
import argparse, importlib.util, json, os, re, shlex, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
HUB_PY = os.path.join(HERE, "hub.py")
ADAPTERS = ("ccpeer", "herdr", "auto")
DEFAULT_SEND = ["agent", "prompt", "{pane}", "{text}"]
# Phrases on a pane's visible screen that mean a dialog/menu owns the keyboard (lower case).
DIALOG_MARKERS = [
    "enter to select", "esc to cancel", "enter to confirm", "do you want to proceed", "do you want to make this edit",
    "do you want to create", "do you trust", "trust the files", "trust this folder", "yes, and don't ask again",
    "press enter to continue", "(y/n)", "[y/n]", "allow once", "approve this", "select an option",
]
RETRY_MIN, RETRY_MAX = 5.0, 60.0
CMD_TIMEOUT = 15


def load_hub():
    """hub.py as a module (not a subprocess). Its own name would clash with peerbridge/hub.py, so load by path."""
    spec = importlib.util.spec_from_file_location("agent_hub", HUB_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hub = load_hub()


def log(line):
    print(line, flush=True)


def load_ccpeer(path):
    """ccpeer module or (None, reason). An explicit config path goes first on sys.path; the default goes last,
    so a ccpeer already on PYTHONPATH (tests, custom installs) wins over it."""
    if path:
        sys.path.insert(0, os.path.abspath(path))
    else:
        sys.path.append(os.path.abspath(os.path.join(HERE, "..", "codex-bridge", "peerbridge")))
    try:
        import ccpeer
        return ccpeer, ""
    except Exception as e:  # missing, or broken on this OS
        return None, type(e).__name__


class Target:
    def __init__(self, name, spec, top):
        self.name = name
        self.adapter = spec.get("adapter") or ("auto" if spec.get("peer") and spec.get("pane")
                                               else "herdr" if spec.get("pane") else "ccpeer")
        if self.adapter not in ADAPTERS:
            raise ValueError(f"{name}: adapter must be one of {', '.join(ADAPTERS)}")
        self.peer = str(spec.get("peer") or "")
        self.session = str(spec.get("session") or top.get("herdr_session") or "")
        self.pane = str(spec.get("pane") or "")
        if self.adapter in ("ccpeer", "auto") and not self.peer:
            raise ValueError(f"{name}: adapter {self.adapter} needs \"peer\"")
        if self.adapter == "herdr" and not (self.session and self.pane):
            raise ValueError(f"{name}: adapter herdr needs \"session\" (or top-level herdr_session) and \"pane\"")
        self.harness = str(spec.get("harness") or "")
        self.note = str(spec.get("note") or f"via agent-bridge ({self.adapter})")
        self.send_tpl = list(spec.get("herdr_send") or top.get("herdr_send") or DEFAULT_SEND)
        if not all(isinstance(x, str) for x in self.send_tpl) or "{text}" not in self.send_tpl:
            raise ValueError(f"{name}: herdr_send must be a list of strings with a \"{{text}}\" element")
        self.ok_states = [str(s) for s in (spec.get("herdr_ok_states") or top.get("herdr_ok_states") or ["idle"])]
        self.hold_until = 0.0
        self.backoff = RETRY_MIN
        self.noticed = set()  # message ids whose sender already got a NOT DELIVERED notice

    def herdr_ready(self):
        return bool(self.session and self.pane)


def parse_config(path):
    with open(path, encoding="utf-8-sig") as f:
        top = json.load(f)
    if isinstance(top, list):
        top = {"agents": top}
    agents = top.get("agents")
    if isinstance(agents, dict):
        agents = [dict(v, name=k) for k, v in agents.items()]
    if not isinstance(agents, list) or not agents:
        raise ValueError("config needs a non-empty \"agents\" list or object")
    targets, seen = [], set()
    for spec in agents:
        name = str(spec.get("name") or "")
        if not hub.NAME_RE.match(name):
            raise ValueError(f"bad agent name {name!r}")
        if name in seen:
            raise ValueError(f"{name} listed twice")
        seen.add(name)
        targets.append(Target(name, spec, top))
    return top, targets


class Bridge:
    def __init__(self, top, targets, root, dry_run=False):
        self.top, self.targets, self.dry = top, targets, dry_run
        self.hub = hub.Hub(root)
        self.ccpeer, self.ccpeer_why = load_ccpeer(top.get("peerbridge"))
        self.herdr = str(top.get("herdr") or "herdr")
        self.markers = DIALOG_MARKERS + [str(m).lower() for m in (top.get("dialog_markers") or [])]
        self.max_chars = int(top.get("herdr_max_chars") or 4000)
        self.reply_cmd = str(top.get("reply_cmd") or "python3 " + shlex.quote(HUB_PY))
        self.started = time.time()

    # ---- text ----
    def compose(self, t, m, one_line):
        frm = hub.one_line(m.get("from"), 130) or "unknown"
        lines = [hub.clean(x) for x in hub.utf8ok(m.get("text", "")).splitlines()] or [""]
        reply = f"(reply: {self.reply_cmd} send {shlex.quote(frm)} \"<answer>\" --from {t.name})"
        if not one_line:
            return f"[{frm} via hub] " + "\n".join(lines) + "\n" + reply
        body = " ".join(" ".join(x.split()) for x in lines if x.strip())
        return f"[{frm} via hub] {body} {reply}"

    # ---- ccpeer ----
    def ccpeer_target(self, t):
        """(record, "") when exactly one live peer matches, else (None, reason)."""
        if self.ccpeer is None:
            return None, f"ccpeer unavailable ({self.ccpeer_why})"
        try:
            recs = self.ccpeer.resolve(t.peer)
        except Exception as e:
            return None, f"resolve failed ({type(e).__name__})"
        if len(recs) != 1:
            return None, f"peer {hub.one_line(t.peer, 64)!r}: {len(recs)} live matches"
        return recs[0], ""

    def send_ccpeer(self, t, rec, m):
        frm = "hub:" + re.sub(r"[^A-Za-z0-9_.-]", "_", str(m.get("from") or "unknown"))[:120]
        env = self.ccpeer.envelope(self.compose(t, m, one_line=False), frm, str(m.get("from") or ""), None)
        self.ccpeer.send_to(rec, [self.ccpeer.user_frame(frm, env, rec.get("sessionId"))])

    # ---- herdr ----
    def herdr_run(self, t, *args):
        argv = [self.herdr, "--session", t.session] + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=CMD_TIMEOUT,
                              encoding="utf-8", errors="replace")

    @staticmethod
    def strings(obj):
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from Bridge.strings(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from Bridge.strings(v)

    @staticmethod
    def find_key(obj, key):
        if isinstance(obj, dict):
            if isinstance(obj.get(key), str):
                return obj[key]
            for v in obj.values():
                r = Bridge.find_key(v, key)
                if r is not None:
                    return r
        elif isinstance(obj, list):
            for v in obj:
                r = Bridge.find_key(v, key)
                if r is not None:
                    return r
        return None

    def pane_check(self, t):
        """"" when the pane may be typed into now, else the reason it may not. Unsure means no."""
        try:
            r = self.herdr_run(t, "agent", "get", t.pane)
        except (OSError, subprocess.SubprocessError) as e:
            return f"herdr get failed ({type(e).__name__})"
        if r.returncode != 0:
            return f"herdr get rc={r.returncode}"
        try:
            state = self.find_key(json.loads(r.stdout), "agent_status") or "unknown"
        except ValueError:
            state = "unknown"
        if state not in t.ok_states:
            return f"state={hub.one_line(state, 32)}"
        try:
            r = self.herdr_run(t, "agent", "read", t.pane, "--source", "visible", "--lines", "25")
        except (OSError, subprocess.SubprocessError) as e:
            return f"herdr read failed ({type(e).__name__})"
        if r.returncode != 0:
            return f"herdr read rc={r.returncode}"
        try:
            screen = "\n".join(self.strings(json.loads(r.stdout)))
        except ValueError:
            screen = r.stdout
        low = screen.lower()
        hit = next((mk for mk in self.markers if mk in low), None)
        if hit:
            return f"state={state} but dialog on screen ({hit!r})"
        return ""

    def send_herdr(self, t, m, path):
        text = self.compose(t, m, one_line=True)
        if len(text) > self.max_chars:
            text = text[:self.max_chars] + f" ... (truncated; full message: {path})"
        argv = [text if x == "{text}" else t.pane if x == "{pane}" else x for x in t.send_tpl]
        r = self.herdr_run(t, *argv)
        if r.returncode != 0:
            raise RuntimeError(f"herdr send rc={r.returncode}")

    # ---- one message ----
    def route(self, t, m, path):
        """("ok", via, detail) | ("hold", reason, retry) -- 'hold' leaves the message for a later retry."""
        why = []
        if t.adapter in ("ccpeer", "auto"):
            rec, err = self.ccpeer_target(t)
            if rec is not None:
                peer = f"{hub.one_line(rec.get('name'), 64)}[{str(rec.get('ref', ''))[:6]}]"
                if self.dry:
                    return "ok", "ccpeer", f"peer={peer} (dry-run, not sent)"
                try:
                    self.send_ccpeer(t, rec, m)
                    return "ok", "ccpeer", f"peer={peer}"
                except Exception as e:
                    err = f"ccpeer send failed ({type(e).__name__})"
            why.append(err)
            if t.adapter == "ccpeer" or not t.herdr_ready():
                return "hold", "; ".join(why), True
        reason = self.pane_check(t)
        if reason:
            why.append(f"herdr pane {hub.one_line(t.pane, 40)} not typed: {reason}")
            return "hold", "; ".join(why), True
        where = f"session={hub.one_line(t.session, 40)} pane={hub.one_line(t.pane, 40)}"
        if self.dry:
            return "ok", "herdr", where + " (dry-run, not typed)"
        try:
            self.send_herdr(t, m, path)
        except (OSError, subprocess.SubprocessError, RuntimeError) as e:
            why.append(str(e) if isinstance(e, RuntimeError) else f"herdr send failed ({type(e).__name__})")
            return "hold", "; ".join(why), True
        return "ok", "herdr", where + (f" (native skipped: {why[0]})" if why else "")

    def notify_sender(self, t, m, reason):
        """One NOT DELIVERED notice per held message, back through the hub (never to a notice: no ping-pong)."""
        mid, frm = str(m.get("id") or ""), str(m.get("from") or "")
        if (self.dry or not frm or frm.partition("@")[0] == t.name or mid in t.noticed
                or str(m.get("text", "")).startswith("NOT DELIVERED")):
            return
        t.noticed.add(mid)
        text = f"NOT DELIVERED {t.name} (id={mid}): {reason}. It waits in the hub and is retried."
        try:
            kind, name, row = hub.resolve(self.hub, frm)
            if kind == "local":
                self.hub.deliver(name, t.name, text)
            elif kind == "mesh":
                hub.deliver_mesh(self.hub, row, t.name, text)
        except (ValueError, OSError):
            pass

    # ---- passes ----
    def pending(self, t):
        """Dry-run: waiting messages, oldest first, read without claiming."""
        d = self.hub.inbox(t.name)
        try:
            names = sorted(f for f in os.listdir(d) if f.endswith(".json") and not f.startswith("."))
        except OSError:
            return
        for fn in names:
            m = hub.read_json(os.path.join(d, fn))
            if isinstance(m, dict):
                yield m, os.path.join(d, fn)

    def deliver_all(self, t):
        """Returns how many messages were held back for a retry."""
        if time.time() < t.hold_until:
            return 1
        source = self.pending(t) if self.dry else self.hub.claim(t.name)
        for m, path in source:
            res = self.route(t, m, path)
            mid, frm = hub.one_line(m.get("id"), 32), hub.one_line(m.get("from"), 130)
            if res[0] == "ok":
                tag = "DRY" if self.dry else "DELIVER"
                log(f"{tag} {t.name} <- {frm} id={mid} via={res[1]} {res[2]} ({len(str(m.get('text', '')))} chars)")
                t.backoff = RETRY_MIN
                continue
            if not self.dry:
                try:
                    self.hub.release(path)
                except OSError as e:
                    log(f"ERROR {t.name} id={mid}: could not put back in the inbox ({type(e).__name__}); it is in read/")
            log(f"HOLD {t.name} <- {frm} id={mid}: {res[1]}; retry in {int(t.backoff)}s")
            self.notify_sender(t, m, res[1])
            t.hold_until = time.time() + t.backoff
            t.backoff = min(RETRY_MAX, t.backoff * 2)
            return 1
        return 0

    def beat(self):
        if self.dry:
            return
        for t in self.targets:
            self.hub.heartbeat(t.name, t.harness or t.adapter, t.note, started=self.started)

    def step(self):
        return sum(self.deliver_all(t) for t in self.targets)

    def check_names(self):
        for t in self.targets:  # a local agent may not take a tunnel link's name (hub.py exits with the reason)
            self.hub.check_local_name(t.name)


def main(argv=None):
    p = argparse.ArgumentParser(prog="agent-bridge.py", description="deliver hub messages natively (see file header)")
    p.add_argument("--config", required=True, help="JSON config (see the file header)")
    p.add_argument("--root", help="hub folder (overrides hub_root in the config)")
    p.add_argument("--once", action="store_true", help="one pass, then exit (1 if anything is held)")
    p.add_argument("--dry-run", action="store_true", help="claim, send and write nothing; log what would happen")
    a = p.parse_args(argv)
    try:
        top, targets = parse_config(a.config)
    except (OSError, ValueError) as e:
        print(f"agent-bridge: config: {e}", file=sys.stderr)
        return 2
    root = a.root or top.get("hub_root") or hub.default_root()
    br = Bridge(top, targets, root, dry_run=a.dry_run)
    br.check_names()
    cc = "ccpeer ok" if br.ccpeer else f"ccpeer unavailable ({br.ccpeer_why})"
    log(f"BRIDGE {', '.join(f'{t.name}={t.adapter}' for t in targets)} on {br.hub.root}; {cc}"
        + ("; DRY-RUN" if a.dry_run else ""))
    poll = float(top.get("poll") or 1)
    every = float(top.get("heartbeat") or 10)
    br.beat()
    if a.once:
        return 1 if br.step() else 0
    hub.leave_on_signals()
    last = time.time()
    try:
        while True:
            br.step()
            if time.time() - last >= every:
                br.beat()
                last = time.time()
            time.sleep(poll)
    except KeyboardInterrupt:
        pass
    finally:
        if not a.dry_run:
            for t in targets:
                br.hub.bye(t.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
