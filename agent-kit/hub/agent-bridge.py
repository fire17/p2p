#!/usr/bin/env python3
"""agent-bridge: hand each agent's hub messages to its harness the most NATIVE way, herdr typing only as fallback.
Python 3.8+, standard library only.

  agent-bridge.py --config bridge.json            run forever (heartbeat + deliver, one log line per delivery)
  agent-bridge.py --map NAME=ROUTE [--map ...]    same, routes from the command line instead of (or on top of) a config
  agent-bridge.py ... --once                      one pass, then exit (exit 1 if any message is held)
  agent-bridge.py ... --dry-run                   read-only: show what WOULD be delivered and how; claims, sends,
                                                  types and heartbeats nothing (combine with --once)
  agent-bridge.py ... --gate none|trusted|all     who may claim from-mode=bypass into +bypass routes (see Gate)

  --map shorthand:  NAME=peer:<peer or session id>[+bypass][+trusted]   (adapter ccpeer)
                    NAME=herdr:<herdr session>:<pane>[+trusted]          (adapter herdr; the pane id may hold ':')

For every configured name the bridge keeps the name present in the hub (agents/<name>.json heartbeat) and
claims its inbox (hub.claim, exactly once across readers), then delivers each message as

  [<from> via hub] <text>
  (reply: python3 <hub.py> send <from> "<answer>" --from <name>)

Adapters, per name:
  ccpeer  Claude Code's own cross-session protocol (codex-bridge/peerbridge/ccpeer.py): resolve(peer) must find
          exactly one live session; the text goes in as a <cross-session-message> user frame on its socket.
          A Codex thread made reachable with `pb expose --thread <id>` is a ccpeer peer too: use the thread id
          as "peer". Restarting that Codex pane drops the exposure: run `pb expose --thread <id>` again.
  herdr   fallback only: type one cleaned line into a herdr pane. Before typing, `herdr agent get` must say
          the pane is in an allowed state (default: idle) AND the pane's visible screen must show no dialog
          (herdr can report a pane idle while a trust/permission/picker dialog is up) AND no draft in the
          composer (an idle pane may hold the user's half-typed text: typing would append to it and submit both).
          Otherwise nothing is typed: the message goes back to the inbox and is retried later (backoff 5 s .. 60 s).
          A send that fails once herdr ran (timeout, rc != 0) may still have typed the text, so it is NOT retried
          (no duplicate instruction): the log says UNSURE, the sender gets one "NOT CONFIRMED" notice, and the
          message stays in the inbox's read/ folder.
  auto    ccpeer first; herdr only when ccpeer is not importable, the peer is not live/unique, or the send fails.
          Typed text is the pane owner's own input (no peer-message approval hold), so on a +bypass route herdr
          types only for senders the gate trusts; anyone else's message waits for the native path.
A message that cannot be delivered is never dropped: it stays in the inbox for a retry, the log says HOLD, and
the sender gets one "NOT DELIVERED <name> (id=...): <reason>" notice over the hub (an ERROR line if even that fails).
A Codex peer (record harness/entrypoint "codex") counts as delivered only when peerbridge's events.jsonl shows the
inject succeeded (it sends no receipt to a hub sender): a failed inject is HOLD (retried), a policy refusal is
REFUSE, no answer within 10 s is UNSURE. A stop signal (SIGTERM from agent-bridge-start.sh, Ctrl+C) that lands while
a message is being handled waits until that message is finished, so no claimed message is left behind in read/.

Gate (from-mode). Claude Code holds a peer message behind an approval prompt when the envelope claims more than
the receiving session runs: from-mode=bypass into a NON-bypass (e.g. auto-mode) session is held too. So the
bridge claims from-mode=bypass only into routes marked +bypass (the target runs bypassPermissions) and only when
the gate lets the sender through; otherwise it claims nothing.
With --gate trusted, a message from an untrusted sender into a +bypass route is REFUSED, not sent: unclaimed, it
would stop that session at Claude Code's "deliver this message?" prompt and block the pane until a human answers.
The sender gets one NOT DELIVERED notice; the message is not retried (it stays in the inbox's read/ folder).
  --gate none     (default) never claim bypass
  --gate trusted  claim for senders whitelisted in <hub root>/trusted.json (re-read whenever it changes):
                    {"log": ["<who approved what, when>", ...],
                     "senders": [{"name": "<fnmatch pattern>", "via": "local" | "link:*" | "link:<link>" | "tunnel",
                                  "session": "join-<KEY>"   (tunnel entries only, required)}]}
                  A message's via class ('' = local, 'link:<x>', 'tunnel') must equal the entry's, so a tunnel
                  message never rides a local/link entry. A tunnel entry counts only while the hub uplink named
                  <sender> has pinned exactly that peer (uplinks/<sender>.pin.json "peer" == KEY). A missing or
                  broken file means nobody is trusted, and an ERROR line says so.
  --gate all      claim for every sender (only for a hub nobody else can write to)
+trusted (route flag, any adapter: "trusted_only": true, or a "+trusted" suffix on "peer" / the --map route):
  only senders trusted.json lets through (every sender with --gate all) reach this route, whatever the gate; anyone
  else's message is REFUSED like above. For targets that run without approvals but carry no from-mode hold of
  their own, e.g. a Codex started with -a never / danger-full-access (peer or herdr route).

Config (JSON). Either shape works:
  {"hub_root": "...", "herdr_session": "work", "gate": "trusted",
   "agents": [{"name": "desk-codex",  "adapter": "ccpeer", "peer": "<codex thread id>"},
              {"name": "desk-claude", "adapter": "ccpeer", "peer": "desk-claude", "bypass": true},
              {"name": "desk-tui",    "adapter": "herdr", "session": "work", "pane": "w1:p2"},
              {"name": "desk-rc",     "adapter": "auto", "peer": "desk-rc+bypass", "pane": "w1:p3"}]}
  {"herdr_session": "work", "agents": {"desk-rc": {"peer": "desk-rc", "pane": "rc", "bypass": true}}}
     (dict form: adapter defaults to auto with both peer and pane, else whichever one is given)
  +bypass: "bypass": true, or a "+bypass" suffix on "peer" (ccpeer/auto only: herdr typing has no from-mode).
  +trusted: "trusted_only": true, or a "+trusted" suffix on "peer" (see Gate).
Optional top-level keys: hub_root (else --root, $AGENT_HUB, the hub's default), gate (--gate wins), peerbridge
(folder holding ccpeer.py; default ../codex-bridge/peerbridge next to this file; a ccpeer on PYTHONPATH wins over
the default), herdr (binary, default "herdr"), herdr_send (argv template after `herdr --session S`, default
["agent", "prompt", "{pane}", "{text}"]; e.g. ["pane", "run", "{pane}", "{text}"] for herdr 0.7),
herdr_ok_states (default ["idle"]), dialog_markers (extra lower-case screen phrases that mean "dialog up"),
prompt_glyphs (extra composer prompt glyphs), composer_placeholders (extra lower-case prefixes an EMPTY composer
shows), composer_check (default true; false = skip the draft check),
herdr_max_chars (default 4000), poll (s, default 1), heartbeat (s, default 10), reply_cmd (default
"python3 <abs path of hub.py>"). Per agent: harness, note, session, pane, peer, bypass, trusted_only, herdr_send,
herdr_ok_states, composer_check.

hub.py is loaded BY PATH from this folder (peerbridge ships a different hub.py; an import by name could pick it).
Messages are DATA: nothing here runs message text. Commands are fixed argv lists (no shell). The peer key that
ccpeer reads to authenticate, and the join keys in trusted.json, are never printed. Do not also run `hub.py ear`
for a bridged name: two readers of one inbox split its messages between them (each message still reaches one).
"""
import argparse, fnmatch, importlib.util, json, os, re, shlex, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
HUB_PY = os.path.join(HERE, "hub.py")
ADAPTERS = ("ccpeer", "herdr", "auto")
GATES = ("none", "trusted", "all")
BYPASS = "+bypass"
TRUSTED = "+trusted"
UNTRUSTED = ("sender not in trusted.json: this route runs bypassPermissions, and an unclaimed message would stop "
             "it at an approval prompt")
UNTRUSTED_ONLY = "sender not in trusted.json: this route takes messages from trusted senders only (+trusted)"
DEFAULT_SEND = ["agent", "prompt", "{pane}", "{text}"]
# Phrases on a pane's visible screen that mean a dialog/menu owns the keyboard (lower case).
DIALOG_MARKERS = [
    "enter to select", "esc to cancel", "enter to confirm", "do you want to proceed", "do you want to make this edit",
    "do you want to create", "do you trust", "trust the files", "trust this folder", "yes, and don't ask again",
    "press enter to continue", "(y/n)", "[y/n]", "allow once", "approve this", "select an option",
    "would you like to proceed", "would you like to run", "would you like to make", "no, and tell",
]
# Composer prompt glyphs: Claude Code ">" / U+276F, Codex U+203A. The composer row is the LAST visible line that
# starts with one (after box-drawing chars); any text on it that is not a known placeholder is the user's draft.
PROMPT_GLYPHS = [">", "\u276f", "\u203a"]
PLACEHOLDERS = [  # lower case, prefix match after whitespace is collapsed
    'try "', "press up to", "ask codex to do anything", "ask a follow-up question", "explain this codebase",
    "summarize recent commits", "implement {feature}", "find and fix a bug in @filename", "write tests for @filename",
    "improve documentation in @filename", "run /review on my current changes", "use /skills to list available skills",
]
BOX_CHARS = " \t\u00a0\u2502\u2503\u2551|"
RETRY_MIN, RETRY_MAX = 5.0, 60.0
CMD_TIMEOUT = 15
SEND_TIMEOUT = 30   # `agent prompt` may run past CMD_TIMEOUT on a slow server; a kill there means UNSURE
CONFIRM_S = 10.0    # how long a Codex inject may take to show up in peerbridge's events.jsonl


def load_hub():
    """hub.py as a module (not a subprocess). Its own name would clash with peerbridge/hub.py, so load by path."""
    spec = importlib.util.spec_from_file_location("agent_hub", HUB_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hub = load_hub()


def log(line):
    print(line, flush=True)


class Stop:
    """Deferred stop: a signal while a message is being handled (busy) only sets `asked`; the bridge stops once that
    message is finished. Raising inside route() would leave the claimed message in read/ with nobody to retry it."""
    busy = asked = False


def _stop(*_):
    Stop.asked = True
    if not Stop.busy:
        raise KeyboardInterrupt


def leave_on_signals():
    """hub.leave_on_signals with the deferred stop: Ctrl+C, SIGTERM, a closed console end the loop via `finally: bye`."""
    for n in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
        if hasattr(signal, n):
            try:
                signal.signal(getattr(signal, n), _stop)
            except (ValueError, OSError):
                pass


def until_stop(source):
    """Claim the next message only while no stop was asked (runs before the claim generator moves the next one)."""
    for item in source:
        yield item
        if Stop.asked:
            return


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
        self.bypass = spec.get("bypass", False)
        if not isinstance(self.bypass, bool):
            raise ValueError(f"{name}: \"bypass\" must be true or false")
        self.trusted_only = spec.get("trusted_only", False)
        if not isinstance(self.trusted_only, bool):
            raise ValueError(f"{name}: \"trusted_only\" must be true or false")
        while self.peer.endswith(BYPASS) or self.peer.endswith(TRUSTED):
            if self.peer.endswith(BYPASS):
                self.peer, self.bypass = self.peer[:-len(BYPASS)], True
            else:
                self.peer, self.trusted_only = self.peer[:-len(TRUSTED)], True
        if self.bypass and self.adapter == "herdr":
            raise ValueError(f"{name}: +bypass needs a ccpeer/auto route (herdr typing carries no from-mode)")
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
        cc = spec.get("composer_check", top.get("composer_check", True))
        if not isinstance(cc, bool):
            raise ValueError(f"{name}: \"composer_check\" must be true or false")
        self.composer_check = cc
        self.sending = False  # a send to the harness has started for the message being routed
        self.hold_until = 0.0
        self.backoff = RETRY_MIN
        self.noticed = set()  # message ids whose sender already got a NOT DELIVERED notice

    def herdr_ready(self):
        return bool(self.session and self.pane)


def parse_map(spec):
    """--map shorthand -> an agent spec: NAME=peer:<peer>[+bypass][+trusted] | NAME=herdr:<session>:<pane>[+trusted]."""
    name, eq, target = str(spec).partition("=")
    kind, _, rest = target.partition(":")
    if eq and kind == "peer" and rest:
        return {"name": name, "adapter": "ccpeer", "peer": rest}      # Target strips +bypass / +trusted suffixes
    session, _, pane = rest.partition(":")
    only = pane.endswith(TRUSTED)
    if only:
        pane = pane[:-len(TRUSTED)]
    if eq and kind == "herdr" and session and pane:
        if pane.endswith(BYPASS):
            raise ValueError(f"--map {spec!r}: +bypass needs a peer route (herdr typing carries no from-mode)")
        return {"name": name, "adapter": "herdr", "session": session, "pane": pane, "trusted_only": only}
    raise ValueError(f"bad --map {spec!r}: want NAME=peer:<peer>[+bypass][+trusted] or "
                     "NAME=herdr:<session>:<pane>[+trusted]")


def load_config(path):
    """The config file as a dict ({} when there is none)."""
    if not path:
        return {}
    with open(path, encoding="utf-8-sig") as f:
        top = json.load(f)
    if isinstance(top, list):
        top = {"agents": top}
    if not isinstance(top, dict):
        raise ValueError("config must be a JSON object (or a list of agents)")
    return top


def build_targets(top, maps=()):
    agents = top.get("agents", [])
    if isinstance(agents, dict):
        if not all(isinstance(v, dict) for v in agents.values()):
            raise ValueError("every entry of the \"agents\" object must be an object")
        agents = [dict(v, name=k) for k, v in agents.items()]
    if not isinstance(agents, list):
        raise ValueError("\"agents\" must be a list or an object")
    agents = list(agents) + [parse_map(m) for m in maps]
    if not agents:
        raise ValueError("no agents: the config needs a non-empty \"agents\" list or object, or give --map")
    targets, seen = [], set()
    for spec in agents:
        if not isinstance(spec, dict):
            raise ValueError("every agent must be an object")
        name = str(spec.get("name") or "")
        if not hub.NAME_RE.match(name):
            raise ValueError(f"bad agent name {name!r}")
        if name in seen:
            raise ValueError(f"{name} listed twice")
        seen.add(name)
        targets.append(Target(name, spec, top))
    return targets


def parse_config(path, maps=()):
    top = load_config(path)
    return top, build_targets(top, maps)


class Trusted:
    """The trusted-senders whitelist, <hub root>/trusted.json (format: file header, Gate). Re-read whenever its
    mtime or size changes; missing or broken = nobody trusted, with one ERROR line per change of that state."""

    def __init__(self, root):
        self.root, self.path = root, os.path.join(root, "trusted.json")
        self.stamp, self.senders, self.error = "unread", [], None

    def load(self):
        try:
            st = os.stat(self.path)
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        except FileNotFoundError:
            stamp = None
        except OSError as e:
            stamp = ("stat failed", type(e).__name__)
        if stamp == self.stamp:
            return
        self.stamp = stamp
        if stamp is None:
            return self.fail("missing")
        try:
            with open(self.path, encoding="utf-8-sig") as f:
                self.senders = self.validate(json.load(f))
        except (OSError, ValueError) as e:
            return self.fail(f"unreadable ({hub.one_line(e, 200)})")
        self.error = None
        rules = ", ".join(f"{hub.one_line(e['name'], 64)}/{hub.one_line(e['via'], 64)}"
                          + ("/pinned-session" if e["via"] == "tunnel" else "") for e in self.senders)
        log(f"TRUSTED {self.path}: {len(self.senders)} sender rule(s){': ' + rules if rules else ''}")

    def fail(self, why):
        self.senders, self.error = [], f"{self.path} {why}: nobody trusted, bypass is claimed for no one"
        log(f"ERROR trusted.json: {self.error}")

    @staticmethod
    def validate(d):
        if not isinstance(d, dict) or not isinstance(d.get("senders"), list):
            raise ValueError('want {"log": [...], "senders": [...]}')
        out = []
        for i, e in enumerate(d["senders"]):
            if not isinstance(e, dict):
                raise ValueError(f"senders[{i}] is not an object")
            name, via = e.get("name"), e.get("via")
            if not isinstance(name, str) or not name:
                raise ValueError(f"senders[{i}] needs a \"name\" pattern")
            if not (via in ("local", "tunnel") or (isinstance(via, str) and via.startswith("link:") and len(via) > 5)):
                raise ValueError(f"senders[{i}] ({name!r}): \"via\" must be local, link:<link or pattern> or tunnel")
            session = e.get("session")
            if via == "tunnel" and not (isinstance(session, str) and session.startswith("join-") and len(session) > 5):
                raise ValueError(f"senders[{i}] ({name!r}): a tunnel entry needs \"session\": \"join-<KEY>\"")
            out.append({"name": name, "via": via, "session": session if via == "tunnel" else None})
        return out

    def pinned_peer(self, uplink):
        """The far-end key the hub uplink <uplink> pinned (uplinks/<uplink>.pin.json "peer"), or None."""
        if not hub.NAME_RE.fullmatch(uplink):  # fullmatch: NAME_RE's "$" would let a trailing newline through
            return None
        p = hub.read_json(os.path.join(self.root, "uplinks", uplink + ".pin.json"))
        peer = p.get("peer") if isinstance(p, dict) else None
        return peer if isinstance(peer, str) and peer else None

    def allows(self, m):
        self.load()
        via, frm = m.get("via") or "", str(m.get("from") or "").partition("@")[0]
        if not isinstance(via, str) or not hub.NAME_RE.fullmatch(frm):
            return False
        cls = "local" if via == "" else "tunnel" if via == "tunnel" else via if via.startswith("link:") else None
        if cls is None:  # e.g. via=hub (the hub's own notices): never trusted
            return False
        for e in self.senders:
            ev = e["via"]
            if not (ev == cls or (cls.startswith("link:") and ev.startswith("link:") and fnmatch.fnmatchcase(cls, ev))):
                continue
            if not fnmatch.fnmatchcase(frm, e["name"]):
                continue
            if ev == "tunnel" and self.pinned_peer(frm) != e["session"][len("join-"):]:
                continue
            return True
        return False


class Bridge:
    def __init__(self, top, targets, root, dry_run=False, gate="none"):
        self.top, self.targets, self.dry = top, targets, dry_run
        if gate not in GATES:
            raise ValueError(f"gate must be one of {', '.join(GATES)}")
        self.gate = gate
        self.hub = hub.Hub(root)
        self.trusted = Trusted(self.hub.root)
        self.ccpeer, self.ccpeer_why = load_ccpeer(top.get("peerbridge"))
        self.herdr = str(top.get("herdr") or "herdr")
        self.markers = DIALOG_MARKERS + [str(m).lower() for m in (top.get("dialog_markers") or [])]
        self.glyphs = PROMPT_GLYPHS + [str(g) for g in (top.get("prompt_glyphs") or []) if str(g).strip()]
        self.placeholders = PLACEHOLDERS + [" ".join(str(x).lower().split())
                                            for x in (top.get("composer_placeholders") or []) if str(x).strip()]
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
            hint = " (pb list; a restarted Codex pane needs `pb expose --thread <id>` again)" if not recs else ""
            return None, f"peer {hub.one_line(t.peer, 64)!r}: {len(recs)} live matches{hint}"
        return recs[0], ""

    def from_mode(self, t, m):
        """"bypass" only into a +bypass route and only when the gate lets this sender through, else None (no claim):
        Claude Code holds a message whose from-mode claims more than the receiving session runs."""
        if not t.bypass or self.gate == "none":
            return None
        return "bypass" if self.gate == "all" or self.trusted.allows(m) else None

    def refuses(self, t, mode):
        """--gate trusted: an untrusted sender's message into a +bypass route is refused (see Gate)."""
        return t.bypass and self.gate == "trusted" and mode != "bypass"

    def refuses_only(self, t, m):
        """+trusted route: refused unless trusted.json lets the sender through (--gate all: everyone), any gate."""
        return t.trusted_only and not (self.gate == "all" or self.trusted.allows(m))

    def send_ccpeer(self, t, rec, m, mode):
        """None when sent (and, for a Codex peer, injected), else a route() result: hold, refuse or unsure."""
        frm = "hub:" + re.sub(r"[^A-Za-z0-9_.-]", "_", str(m.get("from") or "unknown"))[:120]
        env = self.ccpeer.envelope(self.compose(t, m, one_line=False), frm, str(m.get("from") or ""), mode)
        frame = self.ccpeer.user_frame(frm, env, rec.get("sessionId"))
        events = self.codex_events(rec)
        try:
            off = os.path.getsize(events) if events else 0
        except OSError:
            events = None
        t.sending = True
        self.ccpeer.send_to(rec, [frame])
        mid = frame.get("msg_id") if isinstance(frame, dict) else None
        return self.confirm_inject(events, off, mid) if events and isinstance(mid, str) and mid else None

    def codex_events(self, rec):
        """peerbridge's events.jsonl for a Codex peer (peerbridge sends no receipt to a hub: sender, so this file is
        the only record of whether the inject worked), or None: not Codex, or no such file (then: as before)."""
        if "codex" not in (rec.get("harness"), rec.get("entrypoint")):
            return None
        state = getattr(self.ccpeer, "STATE_DIR", None)
        path = os.path.join(state, "events.jsonl") if isinstance(state, str) and state else None
        return path if path and os.path.isfile(path) else None

    @staticmethod
    def confirm_inject(path, off, mid):
        """Wait up to CONFIRM_S for peerbridge's {"ev": "inbound", "msgId": mid} line written after `off`."""
        deadline = time.time() + CONFIRM_S
        while True:
            try:
                with open(path, "rb") as f:
                    f.seek(off)
                    chunk = f.read()
            except OSError:
                chunk = b""
            for line in chunk.splitlines():
                try:
                    e = json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if not (isinstance(e, dict) and e.get("ev") == "inbound" and e.get("msgId") == mid):
                    continue
                if e.get("ok") is True:
                    return None
                why = hub.one_line(str(e.get("detail") or "no detail").partition(":")[0], 120)
                if e.get("ok") is False and "policy" in why:
                    return "refuse", f"codex inject refused: {why}", False
                return "hold", f"codex inject failed: {why}", True   # turn/start never ran: a retry is safe
            if time.time() >= deadline:
                return "unsure", (f"sent to the Codex peer, but peerbridge reported no inject within {int(CONFIRM_S)} s;"
                                  " it may still arrive"), False
            time.sleep(0.2)

    # ---- herdr ----
    def herdr_run(self, t, *args, timeout=CMD_TIMEOUT):
        argv = [self.herdr, "--session", t.session] + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
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
        if t.composer_check and self.draft_on(screen):
            return f"state={state} but a draft is in the composer"   # never the draft text itself: this reaches the sender
        return ""

    def draft_on(self, screen):
        """True when the composer row (the last line starting with a prompt glyph) holds text that is not a placeholder.
        No composer row found: False, as before this check (the state and dialog checks still apply)."""
        row = None
        for line in screen.splitlines():
            s = line.strip(BOX_CHARS)
            g = next((g for g in self.glyphs if s == g or s.startswith(g + " ") or s.startswith(g + "\u00a0")), None)
            if g:
                row = s[len(g):]
        if row is None:
            return False
        text = " ".join(row.strip(BOX_CHARS).split()).lower()
        return bool(text) and not any(text.startswith(p) for p in self.placeholders)

    def send_herdr(self, t, m, path):
        text = self.compose(t, m, one_line=True)
        if len(text) > self.max_chars:
            text = text[:self.max_chars] + f" ... (truncated; full message: {path})"
        argv = [text if x == "{text}" else t.pane if x == "{pane}" else x for x in t.send_tpl]
        t.sending = True
        r = self.herdr_run(t, *argv, timeout=SEND_TIMEOUT)
        if r.returncode != 0:
            raise RuntimeError(f"herdr send rc={r.returncode}")

    # ---- one message ----
    def route(self, t, m, path):
        """("ok", via, detail) | ("hold", reason, retry) | ("refuse", reason, False) -- hold = retry later, refuse = never."""
        why = []
        t.sending = False
        if self.refuses_only(t, m):
            return "refuse", UNTRUSTED_ONLY, False
        if t.adapter in ("ccpeer", "auto"):
            rec, err = self.ccpeer_target(t)
            if rec is not None:
                mode = self.from_mode(t, m)
                if self.refuses(t, mode):
                    return "refuse", UNTRUSTED, False
                peer = f"{hub.one_line(rec.get('name'), 64)}[{str(rec.get('ref', ''))[:6]}] from-mode={mode or 'none'}"
                if self.dry:
                    return "ok", "ccpeer", f"peer={peer} (dry-run, not sent)"
                try:
                    res = self.send_ccpeer(t, rec, m, mode)
                    return res or ("ok", "ccpeer", f"peer={peer}")
                except Exception as e:
                    err = f"ccpeer send failed ({type(e).__name__})"
            why.append(err)
            if t.adapter == "ccpeer" or not t.herdr_ready():
                return "hold", "; ".join(why), True
            if self.refuses(t, self.from_mode(t, m)):
                return "refuse", UNTRUSTED, False
            if t.bypass and self.from_mode(t, m) != "bypass":
                # typed text is the pane owner's own input: in a bypass session it skips the approval hold that
                # Claude Code puts on an unclaimed peer message, so only a sender the gate trusts may be typed
                why.append("herdr typing into a +bypass route is only for senders the gate trusts")
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
        except OSError as e:  # herdr never started: nothing typed, a retry is safe
            why.append(f"herdr send failed ({type(e).__name__})")
            return "hold", "; ".join(why), True
        except (subprocess.SubprocessError, RuntimeError) as e:
            # herdr ran (timed out / rc != 0): the server may have typed and submitted it anyway, so a retry
            # could run the instruction twice. Not retried; the sender is told it may or may not have landed.
            why.append((str(e) if isinstance(e, RuntimeError) else f"herdr send {type(e).__name__}")
                       + "; it may have been typed")
            return "unsure", "; ".join(why), False
        return "ok", "herdr", where + (f" (native skipped: {why[0]})" if why else "")

    def notify_sender(self, t, m, reason, retried=True, head="NOT DELIVERED"):
        """One NOT DELIVERED (or NOT CONFIRMED) notice per held message, back through the hub (never to a notice:
        no ping-pong)."""
        mid, frm = str(m.get("id") or ""), str(m.get("from") or "")
        if (self.dry or not frm or frm.partition("@")[0] == t.name or mid in t.noticed
                or str(m.get("text", "")).startswith(("NOT DELIVERED", "NOT CONFIRMED"))):
            return
        t.noticed.add(mid)
        text = f"{head} {t.name} (id={mid}): {reason}. " + (
            "It waits in the hub and is retried." if retried else "It is not retried.")
        try:
            kind, name, row = hub.resolve(self.hub, frm)
            if kind == "local":
                self.hub.deliver(name, t.name, text)
            elif kind == "mesh":
                hub.deliver_mesh(self.hub, row, t.name, text)
            else:
                raise ValueError("sender not on this hub or its mesh")
        except (ValueError, OSError) as e:
            log(f"ERROR {t.name} id={hub.one_line(mid, 32)}: NOT DELIVERED notice to {hub.one_line(frm, 130)} failed "
                f"({hub.one_line(e, 160)})" + ("; the message still waits in the inbox" if retried else ""))

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
        Stop.busy = True
        try:
            return self.deliver_pass(t)
        finally:
            Stop.busy = False
            if Stop.asked:  # a stop signal came in while a message was being handled: stop now it is finished
                raise KeyboardInterrupt

    def deliver_pass(self, t):
        source = self.pending(t) if self.dry else self.hub.claim(t.name)
        for m, path in until_stop(source):
            try:
                res = self.route(t, m, path)
            except BaseException:  # a crash (or Ctrl+C in --once) before any send: put it back, never strand it
                if not self.dry and not t.sending:
                    try:
                        self.hub.release(path)
                    except OSError:
                        pass
                elif not self.dry:
                    log(f"ERROR {t.name} id={hub.one_line(m.get('id'), 32)}: interrupted mid-send; left in read/")
                raise
            mid, frm = hub.one_line(m.get("id"), 32), hub.one_line(m.get("from"), 130)
            if res[0] == "ok":
                tag = "DRY" if self.dry else "DELIVER"
                log(f"{tag} {t.name} <- {frm} id={mid} via={res[1]} {res[2]} ({len(str(m.get('text', '')))} chars)")
                t.backoff = RETRY_MIN
                continue
            if res[0] == "refuse":
                log(f"REFUSE {t.name} <- {frm} id={mid}: {res[1]}")
                self.notify_sender(t, m, res[1], retried=False)
                continue
            if res[0] == "unsure":
                log(f"UNSURE {t.name} <- {frm} id={mid}: {res[1]}; not retried, left in read/ {path}")
                self.notify_sender(t, m, res[1], retried=False, head="NOT CONFIRMED")
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

    def check_gate(self):
        """Startup: load trusted.json (ERROR if missing/broken) and say what the gate does to +bypass routes."""
        marked = [t.name for t in self.targets if t.bypass]
        only = [t.name for t in self.targets if t.trusted_only]
        if only:
            log(f"NOTE +trusted: {', '.join(only)} take messages only from senders in trusted.json"
                + (" (--gate all: every sender)" if self.gate == "all" else ""))
            if self.gate != "all":
                self.trusted.load()
        if self.gate == "none":
            if marked:
                log(f"NOTE --gate none: no from-mode=bypass claim into {', '.join(marked)} (+bypass); "
                    "use --gate trusted to claim it for senders in trusted.json")
            return
        if not marked:
            log(f"NOTE --gate {self.gate}: no route is marked +bypass, so no message claims from-mode=bypass")
        if self.gate == "all":
            log("WARNING --gate all: every sender claims from-mode=bypass into the +bypass routes")
            return
        self.trusted.load()


def main(argv=None):
    p = argparse.ArgumentParser(prog="agent-bridge.py", description="deliver hub messages natively (see file header)")
    p.add_argument("--config", help="JSON config (see the file header)")
    p.add_argument("--map", action="append", default=[], metavar="NAME=ROUTE",
                   help="NAME=peer:<peer>[+bypass] | NAME=herdr:<session>:<pane>; repeatable; adds to --config")
    p.add_argument("--gate", choices=GATES, help="who may claim from-mode=bypass into +bypass routes "
                   "(default: the config's \"gate\", else none)")
    p.add_argument("--root", help="hub folder (overrides hub_root in the config)")
    p.add_argument("--once", action="store_true", help="one pass, then exit (1 if anything is held)")
    p.add_argument("--dry-run", action="store_true", help="claim, send and write nothing; log what would happen")
    a = p.parse_args(argv)
    if not a.config and not a.map:
        print("agent-bridge: give --config and/or --map", file=sys.stderr)
        return 2
    try:
        top, targets = parse_config(a.config, a.map)
        gate = a.gate or top.get("gate") or "none"
        if gate not in GATES:
            raise ValueError(f"gate must be one of {', '.join(GATES)}")
    except (OSError, ValueError) as e:
        print(f"agent-bridge: config: {e}", file=sys.stderr)
        return 2
    root = a.root or top.get("hub_root") or hub.default_root()
    br = Bridge(top, targets, root, dry_run=a.dry_run, gate=gate)
    br.check_names()
    cc = "ccpeer ok" if br.ccpeer else f"ccpeer unavailable ({br.ccpeer_why})"
    routes = ", ".join(f"{t.name}={t.adapter}" + (BYPASS if t.bypass else "") + (TRUSTED if t.trusted_only else "")
                       for t in targets)
    log(f"BRIDGE {routes} on {br.hub.root}; {cc}; gate={gate}" + ("; DRY-RUN" if a.dry_run else ""))
    br.check_gate()
    poll = float(top.get("poll") or 1)
    every = float(top.get("heartbeat") or 10)
    br.beat()
    if a.once:
        return 1 if br.step() else 0
    leave_on_signals()
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
