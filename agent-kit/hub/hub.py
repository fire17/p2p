#!/usr/bin/env python3
"""agent-hub: a local presence + message bus for the agents on ONE PC (Windows and its WSL distros),
with optional tunnel uplinks to agents on other computers. Python 3.8+, standard library only.

The bus is a plain folder that Windows and WSL both see (default %USERPROFILE%\\.agent-hub, which WSL
reaches as /mnt/c/Users/<you>/.agent-hub). No daemon, no port, no firewall rule.

  hub.py here  <me> [--harness H] [--note TEXT]     one presence heartbeat (call it at the start of a turn)
  hub.py ear   <me> [--harness H] [--every 10]      stay present + print new messages and JOIN/LEAVE lines
  hub.py ear   <me> --once                          heartbeat + print waiting messages + roster, then exit
  hub.py who   [--json] [--all]                     who is here (up / stale), with age and harness
  hub.py send  <to|to1,to2|all> TEXT --from <me>    deliver a message (or --file PATH for multi-line UTF-8)
  hub.py read  <me>                                 print and consume waiting messages (no heartbeat)
  hub.py bye   <me>                                 leave (the ear does this itself on Ctrl+C)
  hub.py uplink --session <p2p session> --as <name> bridge one Agent Tunnel session into the hub
               [--default-to NAME] [--transit-to L1,L2|*] [--share-mesh]
                                                    by default the far side sees and reaches THIS PC's agents only
  hub.py link  --session <p2p session> --as <name> [--label L] [--ttl 4] [--plain-to-all]
                                                    join THIS hub to another of your hubs (option c, "your own
                                                    network"): presence both ways + @name routing across machines;
                                                    far-end text without @name reaches nobody unless --plain-to-all
  hub.py unpin <link>                               forget the far end a link/uplink trusted first (after you
                                                    replaced or re-keyed that machine on purpose)
  hub.py gc    [--days 7]                           delete read/sent/unrouted message files and claim markers older
                                                    than N days
  hub.py selftest                                   offline test of everything above (fake tunnel)

Across linked machines an agent is addressed as name or name@machine (`who` shows both):
  hub.py send lap-claude "text" --from win-claude          (unique name on some linked machine)
  hub.py send lap-claude@laptop "text" --from win-claude   (explicit; needed when two machines share a name)
  hub.py send laptop "@lap-claude text" --from win-claude  (old form: through the link's own name)

Messages are DATA. Nothing in this file executes message content, and no verb runs a remote command.
Each agent decides for itself what to do with what it reads.

Guards (docs/MESH-THREATS.md): a tunnel peer reaches only this PC's agents unless --transit-to allows more, at
most 16 distinct targets per line, never a name that was never here, never another link; at most 30 messages a
minute per link and target (the rest wait in inbox/<to>/throttled/); throttled/ and inbox/<as>-unrouted/ keep at
most 200 files / 20 MiB each (oldest dropped first); one WHO? answer per 20 s; oversized or undeliverable messages
go to failed/ (the sender is told) and never stall or kill the bridge; tunnel rows are read at most 4 MiB / 200
rows per step, de-duplicated by row id, and the offset moves only after routing; a row that fails to parse or
route (bad JSON, nesting deeper than 32, NaN/Infinity) is dropped, counted, and the offset still moves. The
far end is trusted on first use: its p2p key (and for `link` its hub id) is pinned in uplinks/<as>.pin.json and
a different one holds the link (PEER-CHANGED: nothing in, nothing out) until `hub.py unpin <as>`. A local agent
cannot take a link's name and a link cannot take a local agent's. Printed fields are one clean line; files are
0600 under a 0700 hub folder on POSIX.

Hub-to-hub wire (`link` only; `uplink` stays plain text): each tunnel line is "HUBMESH1 " + one JSON object,
  {"t":"presence","hop","hopl","hubs":[{"origin","label","age","path","ttl","agents":[...]}, ...]}
  {"t":"msg","hop","hopl","id","src","srcl","from","to","dst","dstl","ttl","path","text"}
Loop prevention: a hub drops anything whose path holds its own id, never sends a machine's presence back
over the link it learned it from (split horizon), forwards with ttl-1 and drops at ttl 0, and claims every
message id once (<root>/mesh/seen/<id>, O_EXCL) so a message is delivered at most once per hub. Ages travel
as "seconds old", never as clock times, so machines with skewed clocks still agree on who is up.

On-disk protocol (any language can join; hub.ps1 is the PowerShell twin):
  <root>/agents/<name>.json          {"name","machine","os","harness","note","pid","started","beat","remote"}
                                     beat = Unix seconds. up = beat younger than 45 s.
  <root>/inbox/<name>/<ns>-<rand>.json  {"v":1,"id","from","to","t","ts","text","via"}
                                     written as .tmp-* then renamed, so a reader never sees half a file.
  <root>/inbox/<name>/claims/<fn>.claim  empty claim marker for message <fn>, created with O_CREAT|O_EXCL
                                     (hub.ps1: FileMode.CreateNew). Only the reader that created it moves <fn>
                                     into inbox/<name>/read/ and prints it, so two readers of one name never
                                     print the same message twice. (A rename alone is not enough: on Windows two
                                     readers' renames of one file can both report success.) Markers stay until
                                     gc. A marker older than 120 s whose <fn> is still in the inbox means its
                                     claimer died before the move: the next reader takes over by exclusively
                                     creating <fn>.claim.1 (then .claim.2, ...). Putting a claimed message back
                                     (a failed tunnel send) deletes its markers first, then moves it back.
  <root>/mesh/hub.json               {"id": 16 hex, "label"}: this hub (one per PC; Windows and WSL share it)
  <root>/mesh/peers/<id>.json        another machine's presence snapshot, written by the link that heard it
"""
import argparse, calendar, json, os, platform, re, shlex, shutil, socket, subprocess, sys, tempfile, time, uuid

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STALE_S = 45            # a heartbeat older than this is "stale"
CLAIM_STALE_S = 120     # a claim marker this old whose message is still in the inbox: its claimer died (hub.ps1 same)
FORGET_S = 24 * 3600    # `who` hides agents silent for longer than this (unless --all)
MAX_BYTES = 1024 * 1024 # the tunnel refuses messages over 1 MiB (p2p-tunnel.js send --file)
HUBID_RE = re.compile(r"^[a-f0-9]{16}$")
MSGID_RE = re.compile(r"^[a-f0-9]{8,32}$")
MESH_TAG = "HUBMESH1 "  # a tunnel line starting with this is a hub-to-hub envelope (JSON), never chat
MESH_TTL = 4            # presence and messages cross at most this many links
MESH_MAX_TTL = 8
MESH_FRESH_S = 100      # a machine whose presence snapshot is older than this shows its agents as stale
MESH_FORGET_S = 600     # ...and drops out of `who` after this
MESH_PUSH_S = 30        # a link re-sends presence at least this often (sooner on any change)
MAX_TARGETS = 16        # distinct @targets one line may name
MAX_ROWS = 200          # tunnel rows a bridge handles per step
READ_CAP = 4 << 20      # bytes of tunnel inbox a bridge reads per step
RATE_N, RATE_S = 30, 60 # per sender and target: at most RATE_N deliveries per RATE_S seconds through a bridge
WHO_EVERY = 20          # a bridge answers WHO? at most this often; extra asks are folded into the next answer
KEEP_IDS = 512          # tunnel row ids remembered per generation (replayed rows are skipped)
SPILL_FILES, SPILL_BYTES = 200, 20 << 20   # cap per throttled/ and <as>-unrouted/ folder; the oldest go first
WIRE_DEPTH = 32         # a hub envelope nested deeper than this is dropped unparsed
AGE_MAX = 1e6           # ages from the wire are clamped to 0..AGE_MAX seconds

for _s in (sys.stdout, sys.stderr):   # Hebrew/emoji on a Windows console must never crash a reader
    try: _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass

def out(line): print(line, flush=True)

# C0/C1 controls, bidi marks/overrides/isolates, and invisible characters a model reads but a person cannot see
# (zero-width, word joiner, BOM, interlinear annotation, the TAG block U+E0000-E007F, variation selectors
# U+FE00-FE0F and U+E0100-E01EF).
_CTRL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069"
                   "\ufe00-\ufe0f\ufeff\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
def clean(s):
    """Remote text is data: drop terminal-control, bidi-override and invisible characters before printing it."""
    return _CTRL.sub("", str(s))

def utf8ok(s):
    """Lone surrogates (valid JSON, invalid UTF-8) would crash every writer: replace them."""
    return str(s).encode("utf-8", "replace").decode("utf-8")

def one_line(s, n):
    """Remote text shown in a roster column: control/bidi stripped, whitespace (incl. U+2028) collapsed, capped."""
    return clean(" ".join(str(s if s is not None else "").split()))[:n]

def safe_label(s, fallback="hub"):
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(s or ""))[:64].strip("-._")
    return s if NAME_RE.match(s) else fallback

def _stop(*_): raise KeyboardInterrupt
def leave_on_signals():
    """Ctrl+C, a Monitor stop (SIGTERM) or a closed console all end the loop through `finally: bye`."""
    import signal
    for n in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
        if hasattr(signal, n):
            try: signal.signal(getattr(signal, n), _stop)
            except (ValueError, OSError): pass
def die(msg, code=2): print("hub: " + msg, file=sys.stderr, flush=True); sys.exit(code)
def iso(ts=None): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))

def is_wsl():
    try:
        with open("/proc/sys/kernel/osrelease") as f: return "microsoft" in f.read().lower()
    except Exception: return False

def win_profile_from_wsl():
    """The Windows %USERPROFILE% as a WSL path, e.g. /mnt/c/Users/<you>. None if interop is off."""
    try:
        raw = subprocess.run(["cmd.exe", "/c", "echo %USERPROFILE%"], capture_output=True, text=True,
                             cwd="/mnt/c", timeout=15).stdout.strip()
        if not raw or "%" in raw: return None
        return subprocess.run(["wslpath", "-u", raw], capture_output=True, text=True, timeout=15).stdout.strip() or None
    except Exception: return None

def default_root():
    if os.environ.get("AGENT_HUB"): return os.environ["AGENT_HUB"]
    if is_wsl():
        prof = win_profile_from_wsl()
        if not prof: die("inside WSL but cannot find the Windows profile; set AGENT_HUB=/mnt/c/Users/<you>/.agent-hub")
        return os.path.join(prof, ".agent-hub")
    return os.path.join(os.path.expanduser("~"), ".agent-hub")

def machine_label():
    host = socket.gethostname().split(".")[0]
    return host + ("-wsl" if is_wsl() else "")

def check_name(n):
    if not NAME_RE.match(n or ""): die(f"bad name {n!r}: letters, digits, . _ - (max 64), e.g. win-claude or wsl-codex")
    return n

def read_json(p):
    try:
        with open(p, encoding="utf-8-sig") as f: return json.load(f)
    except Exception: return None

def open_private(path, mode="w"):
    """A new file only this user can read (0600 on POSIX), never one that already exists."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    return open(fd, mode, encoding="utf-8", errors="replace", newline="\n")

def write_atomic(path, obj):
    d = os.path.dirname(path); os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = os.path.join(d, ".tmp-" + uuid.uuid4().hex)
    with open_private(tmp) as f: json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)

class Hub:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.agents = os.path.join(self.root, "agents")
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        if os.name != "nt":   # messages are private: other local users must not read the hub (no-op on drvfs)
            try:
                st = os.stat(self.root)
                if st.st_uid == os.getuid() and st.st_mode & 0o077: os.chmod(self.root, 0o700)
            except OSError: pass
        os.makedirs(self.agents, mode=0o700, exist_ok=True)

    # ---- presence ----
    def heartbeat(self, name, harness="", note="", remote=False, machine=None, started=None, extra=None):
        p = os.path.join(self.agents, name + ".json"); old = read_json(p) or {}
        rec = {"name": name, "machine": machine or machine_label(), "os": platform.system().lower() + ("-wsl" if is_wsl() else ""),
               "harness": harness or old.get("harness", ""), "note": note or old.get("note", ""), "pid": os.getpid(),
               "started": started or old.get("started") or time.time(), "beat": time.time(), "remote": bool(remote)}
        if extra: rec.update(extra)
        write_atomic(p, rec); return rec

    def bye(self, name):
        try: os.remove(os.path.join(self.agents, name + ".json"))
        except FileNotFoundError: pass

    def roster(self, include_old=False):
        now, rows = time.time(), []
        for fn in sorted(os.listdir(self.agents)):
            if not fn.endswith(".json") or fn.startswith("."): continue
            r = read_json(os.path.join(self.agents, fn))
            if not isinstance(r, dict) or not NAME_RE.match(str(r.get("name", ""))): continue
            try: age = now - float(r.get("beat") or 0)
            except (TypeError, ValueError): continue
            if age > FORGET_S and not include_old: continue
            for k in ("machine", "harness", "note", "os"): r[k] = str(r.get(k) or "")   # other writers may leave nulls
            r["age"] = max(0, int(age)); r["state"] = "up" if age <= STALE_S else "stale"
            if r.get("remote") and r.get("link") == "down": r["state"] = "link-down"
            if r.get("remote") and r.get("link") == "peer-changed": r["state"] = "peer-changed"
            rows.append(r)
        return rows

    def up_names(self, local_only=False):
        return {r["name"] for r in self.roster() if r["state"] == "up" and not (local_only and r.get("remote"))}

    # ---- messages ----
    def inbox(self, name): return os.path.join(self.root, "inbox", name)

    def deliver(self, to, frm, text, via="", extra=None, folder=""):
        """Write one message into inbox/<to>/ (or a sub-folder readers do not claim). ValueError if too large."""
        text = utf8ok(text)
        if len(text.encode("utf-8")) > MAX_BYTES: raise ValueError("message exceeds 1 MiB")
        ts = time.time(); mid = uuid.uuid4().hex[:12]
        msg = {"v": 1, "id": mid, "from": frm, "to": to, "t": iso(ts), "ts": ts, "text": text, "via": via}
        if extra: msg.update(extra)
        write_atomic(os.path.join(self.inbox(to), folder, f"{time.time_ns():020d}-{mid}.json"), msg)
        return mid

    def local_row(self, name):
        """agents/<name>.json with its age, or None."""
        r = read_json(os.path.join(self.agents, name + ".json"))
        if not isinstance(r, dict): return None
        try: r["age"] = time.time() - float(r.get("beat") or 0)
        except (TypeError, ValueError): r["age"] = 1e12
        return r

    def check_local_name(self, name):
        """A local agent may not take the name of a tunnel link (its messages would leave the machine)."""
        r = self.local_row(name)
        if r and r.get("remote") and r["age"] < FORGET_S:
            die(f"{name!r} is the name of a tunnel link on this hub ({clean(r.get('note', ''))[:60]}); pick another "
                f"name, or `hub.py bye {name}` if that link is gone for good")
        return name

    def check_bridge_name(self, name, session):
        """A link may not take a local agent's name, nor the name of another link that is running."""
        r = self.local_row(name)
        if not r: return name
        if not r.get("remote") and r["age"] < FORGET_S:
            die(f"{name!r} is a local agent on this hub; give the link another name (--as), e.g. the other machine's name")
        if r.get("remote") and r["age"] <= STALE_S and (r.get("session") != session or r.get("host") != machine_label()):
            die(f"a link named {name!r} is already running (session {clean(r.get('session', '?'))[:40]}); stop it first")
        return name

    # ---- mesh (other machines, heard through `link`) ----
    def mesh_path(self, *p): return os.path.join(self.root, "mesh", *p)

    def identity(self, label=None, create=True):
        """This hub's {"id","label"}. One hub per PC: Windows and WSL share the folder, so they share the id."""
        p = self.mesh_path("hub.json")
        for _ in range(40):
            rec = read_json(p)
            if isinstance(rec, dict) and HUBID_RE.match(str(rec.get("id", ""))) and NAME_RE.match(str(rec.get("label", ""))):
                if label and safe_label(label) != rec["label"]:
                    rec["label"] = safe_label(label); write_atomic(p, rec)
                return rec
            if not os.path.exists(p):
                if not create: return None
                os.makedirs(os.path.dirname(p), exist_ok=True)
                rec = {"id": uuid.uuid4().hex[:16], "label": safe_label(label or socket.gethostname().split(".")[0])}
                try:
                    with open(p, "x", encoding="utf-8") as f: json.dump(rec, f)   # "x": two first-runs cannot both win
                    return rec
                except FileExistsError: pass
            time.sleep(0.05)   # being written by the other side right now
        die(f"cannot read {p}; delete it to give this hub a new id")

    def mark_seen(self, mid):
        """True the first time this hub sees message id `mid` (atomic across processes), False after."""
        d = self.mesh_path("seen"); os.makedirs(d, mode=0o700, exist_ok=True)
        try: os.close(os.open(os.path.join(d, mid), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)); return True
        except FileExistsError: return False

    def mesh_peers(self):
        """Other machines' presence snapshots, each with eff_age = seconds since its origin made it."""
        d, now, rows = self.mesh_path("peers"), time.time(), []
        if not os.path.isdir(d): return rows
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".json") or fn.startswith("."): continue
            r = read_json(os.path.join(d, fn))
            try: r["eff_age"] = float(r["age"]) + max(0.0, now - float(r["rx"]))
            except (TypeError, ValueError, KeyError): continue
            if r["eff_age"] > MESH_FORGET_S or not isinstance(r.get("agents"), list) or not isinstance(r.get("path"), list): continue
            rows.append(r)
        return rows

    def mesh_roster(self):
        """Agents on linked machines, as roster rows (remote, mesh, addr = name@machine)."""
        links = {r["name"]: r for r in self.roster(include_old=True) if r.get("remote")}
        rows, peers = [], self.mesh_peers()
        labels = [p.get("label") for p in peers]
        for p in peers:
            lk = links.get(p.get("via")); link_up = bool(lk) and lk["state"] == "up"
            for ag in p["agents"]:
                try: age = int(float(ag.get("age") or 0) + p["eff_age"])
                except (TypeError, ValueError, AttributeError): continue
                if not link_up: state = "link-down"
                elif p["eff_age"] <= MESH_FRESH_S and ag.get("state") == "up": state = "up"
                else: state = "stale"
                rows.append({"name": ag["name"], "machine": str(ag.get("machine") or ""), "harness": str(ag.get("harness") or ""),
                             "note": str(ag.get("note") or ""), "os": "", "age": age, "state": state, "remote": True,
                             "mesh": True, "hub": p.get("label", ""), "hub_id": p.get("origin", ""), "via": p.get("via", ""),
                             "hops": len(p["path"]), "addr": f"{ag['name']}@{p.get('label', '')}",
                             "dup": labels.count(p.get("label")) > 1})
        return rows

    def full_roster(self, include_old=False):
        return self.roster(include_old) + self.mesh_roster()

    def claim(self, name):
        """Yield (msg, path) for each waiting message, oldest first, each exactly once across readers."""
        d = self.inbox(name)
        if not os.path.isdir(d): return
        done = os.path.join(d, "read"); os.makedirs(done, exist_ok=True)
        os.makedirs(os.path.join(d, "claims"), exist_ok=True)
        rows = []
        for fn in os.listdir(d):
            if fn.endswith(".json") and not fn.startswith("."):
                m = read_json(os.path.join(d, fn))
                if m is None: continue        # still being written by a slow filesystem: next poll
                rows.append((float(m.get("ts") or 0), fn, m))
        for _, fn, m in sorted(rows):
            mk = self.claim_marker(d, fn)
            if mk is None: continue                    # another reader holds this message
            src, dst = os.path.join(d, fn), os.path.join(done, fn)
            moved = False
            for _ in range(40):
                try: os.replace(src, dst); moved = True; break
                except FileNotFoundError: break        # gone (a reader that took over a stale marker): not ours
                except PermissionError: time.sleep(0.05)   # Windows: another reader has it open to read it
            if moved: yield m, dst
            elif os.path.exists(src):                  # still in use after 2 s: give it back to the next poll
                os.remove(mk); print(f"hub: {src} stayed in use for 2 s; left in the inbox", file=sys.stderr)

    @staticmethod
    def marker(inbox, fn, k):
        """Generation k of the claim marker for message `fn` in folder `inbox` (inbox/<name>)."""
        return os.path.join(inbox, "claims", fn + ".claim" + (f".{k}" if k else ""))

    def claim_marker(self, inbox, fn):
        """Exclusively create the claim marker for message `fn` (see the header); its path, or None if another
        reader holds a live one."""
        k = 0
        while True:
            mk = self.marker(inbox, fn, k)
            try: os.close(os.open(mk, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)); return mk
            except FileExistsError: pass
            except PermissionError: return None        # Windows: that marker is being deleted right now; next poll
            try: age = time.time() - os.path.getmtime(mk)
            except FileNotFoundError: continue         # released just now: try this generation again
            if age < CLAIM_STALE_S: return None
            k += 1                                     # its claimer died before the move: take over

    def release(self, path):
        """Put a claimed message (read/<fn>) back in the inbox for a retry: markers first, so no reader
        ever sees it in the inbox under a stale marker."""
        inbox, fn = os.path.dirname(os.path.dirname(path)), os.path.basename(path); k = 0
        while True:
            try: os.remove(self.marker(inbox, fn, k)); k += 1
            except FileNotFoundError: break
        os.replace(path, os.path.join(inbox, fn))

    def prune(self, d, max_files=SPILL_FILES, max_bytes=SPILL_BYTES, known=None):
        """Keep at most max_files messages / max_bytes in folder d, dropping the oldest first. Returns how many went.
        `known` ({file: size}, kept by the caller between calls) saves a stat per file: over 9p each one costs ms."""
        try: names = sorted(f for f in os.listdir(d) if f.endswith(".json") and not f.startswith("."))   # <ns>- = age order
        except FileNotFoundError: return 0
        known = {} if known is None else known
        for f in set(known) - set(names): del known[f]
        for f in names:
            if f not in known:
                try: known[f] = os.path.getsize(os.path.join(d, f))
                except FileNotFoundError: known[f] = 0          # claimed meanwhile
        sizes = [known[f] for f in names]
        total, n = sum(sizes), 0
        for f, size in zip(names, sizes):
            if len(names) - n <= max_files and total <= max_bytes: break
            try: os.remove(os.path.join(d, f))
            except FileNotFoundError: pass
            known.pop(f, None); total -= size; n += 1
        return n

    def gc(self, days):
        cut, n = time.time() - days * 86400, 0
        inbox = os.path.join(self.root, "inbox")
        for base, _, files in os.walk(inbox):
            spill = os.path.dirname(base) == inbox and base.endswith("-unrouted")    # nobody claims these
            if os.path.basename(base) not in ("read", "claims", "sent", "failed", "throttled") and not spill: continue
            for fn in files:
                p = os.path.join(base, fn)
                try:
                    if os.path.getmtime(p) < cut: os.remove(p); n += 1
                except OSError: pass
        seen, cut2 = self.mesh_path("seen"), time.time() - max(days, 2) * 86400   # dedupe ids outlive any ttl
        for fn in (os.listdir(seen) if os.path.isdir(seen) else []):
            try:
                if os.path.getmtime(os.path.join(seen, fn)) < cut2: os.remove(os.path.join(seen, fn)); n += 1
            except OSError: pass
        return n

def fmt_msg(m, path=None):
    text = str(m.get("text", ""))
    lines = text.splitlines() or [""]
    first = clean(lines[0]); hidden = len(lines[0]) - len(first)
    body = first if len(lines) == 1 else first + f"  (+{len(lines) - 1} more lines: {path})"
    if hidden: body += f"  ({hidden} hidden/control char{'s' if hidden != 1 else ''} removed)"
    via = f" via={one_line(m['via'], 64)}" if m.get("via") else ""
    return (f"MSG from={one_line(m.get('from'), 130)} to={one_line(m.get('to'), 64)} id={one_line(m.get('id'), 32)}{via} :: {body}")

def roster_key(r): return one_line(r.get("addr") or r["name"], 130)

def fmt_roster(rows):
    """One clean line per agent: every field may come from another process or machine, so all are sanitized."""
    if not rows: return "nobody here"
    def note(r):
        if r.get("mesh"):
            n = f"via {one_line(r['via'], 64)}, {r['hops']} hop{'s' if r['hops'] != 1 else ''}" + \
                ("; TWO MACHINES USE THIS NAME" if r.get("dup") else "") + ("; " + one_line(r["note"], 300) if r.get("note") else "")
        else: n = one_line(r.get("note", ""), 300)
        return "  " + n if n else ""
    return "\n".join(f"{r['state']:<9} {roster_key(r):<22} {one_line(r.get('machine', ''), 128):<20} {one_line(r.get('harness', ''), 128):<10} "
                     f"age {r['age']}s{note(r)}" for r in rows)

def json_rows(rows):
    """`who --json`: same rows, every string control/bidi/invisible-free."""
    return [{k: (clean(v) if isinstance(v, str) else v) for k, v in r.items()} for r in rows]

def resolve(hub, target):
    """'name' or 'name@machine' -> ("local", name, row|None) | ("mesh", name, mesh_row) | (None, name, None).
    A local agent wins over a same-named one elsewhere; a name on two other machines needs @machine (ValueError)."""
    name, _, label = str(target).partition("@")
    if not NAME_RE.match(name) or (label and not NAME_RE.match(label)): raise ValueError(f"bad name {target!r}")
    own = hub.identity(create=False)
    if label and own and label == own["label"]: label = ""
    local = {r["name"]: r for r in hub.roster(include_old=True)}
    if not label and name in local: return "local", name, local[name]
    cands = [r for r in hub.mesh_roster() if r["name"] == name and (not label or r["hub"] == label)]
    if label and len(cands) > 1:
        raise ValueError(f"two linked machines call themselves {label!r}; fix their --label before sending by name@machine")
    if len(cands) > 1:
        raise ValueError(f"{name!r} is on several machines ({', '.join(r['addr'] for r in cands)}); add @machine")
    return ("mesh", name, cands[0]) if cands else (None, name, None)

def deliver_mesh(hub, row, frm, text, via=""):
    """Hand a message for an agent on another machine to the link that leads there."""
    return hub.deliver(row["via"], frm, text, via=via, extra=mesh_extra(row))

# ---------------------------------------------------------------- verbs
def cmd_send(hub, a):
    frm = check_name(a.frm)
    if a.file:
        try:
            with open(a.file, "rb") as f: text = f.read().decode("utf-8-sig")
        except Exception as e: die(f"cannot read UTF-8 file: {e}")
    elif a.text is not None: text = a.text
    else: die("send needs TEXT or --file PATH")
    if len(utf8ok(text).encode("utf-8")) > MAX_BYTES: die("message exceeds 1 MiB")
    if a.to == "all":
        targets = sorted(hub.up_names(local_only=True) - {frm})   # broadcasts stay on this PC
        if not targets: out("nobody else is up; nothing sent"); return 0
    else:
        targets = list(dict.fromkeys(t for t in a.to.split(",") if t))    # a,a,a is one delivery
        if len(targets) > MAX_TARGETS: die(f"{len(targets)} targets; at most {MAX_TARGETS} per send (use all, or several sends)")
    for t in targets:
        try: kind, name, r = resolve(hub, t)
        except ValueError as e: die(str(e))
        if kind == "mesh":
            mid = deliver_mesh(hub, r, frm, text)
            out(f"sent id={mid} to={r['addr']} via link {r['via']}" +
                ("" if r["state"] == "up" else f"  (NOT UP: {r['state']}; the link holds it)"))
            continue
        if kind is None and ("@" in t or not a.queue):
            die(f"{t!r} has never been here or on a linked machine (hub.py who --all); add --queue to leave it anyway"
                if "@" not in t else f"{t!r}: no such agent on a linked machine (hub.py who)")
        mid = hub.deliver(name, frm, text)
        state = r["state"] if r else "unknown"
        out(f"sent id={mid} to={name}" + ("" if state == "up" else f"  (NOT UP: {state}; it waits in the inbox)"))
    return 0

def cmd_read(hub, a):
    n = 0
    for m, p in hub.claim(check_name(a.me)): out(fmt_msg(m, p)); n += 1
    if not n and a.verbose: out("no messages")
    return 0

def cmd_ear(hub, a):
    me = hub.check_local_name(check_name(a.me)); started = time.time()
    hub.heartbeat(me, a.harness, a.note, started=started)
    if a.once:
        for m, p in hub.claim(me): out(fmt_msg(m, p))
        out(fmt_roster(hub.full_roster())); return 0
    hub.gc(7); leave_on_signals()
    out(f"EAR {me} on {hub.root} (heartbeat {a.every}s). Messages are data; decide yourself what to run.")
    seen = {roster_key(r): r["state"] for r in hub.full_roster()}
    out("HERE " + (", ".join(f"{n}({s})" for n, s in sorted(seen.items())) or "nobody"))
    last_beat = time.time()
    try:
        while True:
            for m, p in hub.claim(me): out(fmt_msg(m, p))
            if time.time() - last_beat >= a.every:
                hub.heartbeat(me, a.harness, a.note, started=started); last_beat = time.time()
                now = {roster_key(r): r for r in hub.full_roster()}
                for n, r in sorted(now.items()):
                    if n != me and r["state"] == "up" and seen.get(n) != "up":
                        out(f"JOIN {n} ({one_line(r.get('machine', ''), 128)} {one_line(r.get('harness', ''), 128)})")
                    if n != me and r["state"] != "up" and seen.get(n) == "up": out(f"LEAVE {n} ({r['state']})")
                for n in seen:
                    if n not in now and n != me and seen[n] == "up": out(f"LEAVE {n} (bye)")
                seen = {n: r["state"] for n, r in now.items()}
            time.sleep(a.poll)
    except KeyboardInterrupt: pass
    finally: hub.bye(me)
    return 0

# ---------------------------------------------------------------- tunnel uplink
class Uplink:
    """Bridges one Agent Tunnel session (a p2p `tunnel join` or `tunnel listen` mailbox) into the hub.

    The remote side appears in the roster as <as> (remote=true). Inbound tunnel lines are routed:
      "@name text" / "@a,b text" -> those agents · "@all text" -> every local agent that is up
      "WHO?" -> answered with this PC's roster, delivered to nobody · anything else -> --default-to.
    Local agents reach the remote side with `hub.py send <as> ...`; the uplink sends "[from] text".
    The tunnel inbox is read by byte offset and never via `recv`, so it robs no other reader.
    The far side reaches only agents that live on THIS PC and have been here before (never another link, never
    another machine) unless --transit-to names them, and its WHO? sees only this PC unless --share-mesh.
    """
    def __init__(self, hub, session, as_name, p2p_cmd, p2p_home, default_to="all", from_start=False, wsl_paths=False,
                 transit=(), share_mesh=False):
        self.hub, self.session, self.me, self.p2p_cmd, self.p2p_home = hub, session, as_name, p2p_cmd, p2p_home
        self.default_to, self.wsl_paths, self.transit, self.share_mesh = default_to, wsl_paths, set(transit or ()), share_mesh
        self.state_dir = os.path.join(hub.root, "uplinks"); os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        self.off_path = os.path.join(self.state_dir, as_name + ".offset.json")
        self.pin_path = os.path.join(self.state_dir, as_name + ".pin.json")
        self.from_start, self.last_roster, self.last_push = from_start, None, 0.0
        self.started, self.peers, self.tag, self.host = time.time(), "", "UPLINK", machine_label()
        self.off, self.held, self.hub_hold, self.last_who, self.who_pending = {}, None, None, 0.0, False
        self.rate, self.throttled = {}, set()
        self.bad_rows, self.spill_files, self.spill_bytes, self.spill_known = 0, SPILL_FILES, SPILL_BYTES, {}

    def mailbox(self):
        base = os.path.join(self.p2p_home, "tunnel", self.session)
        cur = read_json(os.path.join(base, "current.json")) or {}
        gid = str(cur.get("id") or "")
        if not re.fullmatch(r"[a-f0-9]{32}", gid): return None, None, {}
        d = os.path.join(base, gid)
        return gid, os.path.join(d, "inbox.jsonl"), read_json(os.path.join(d, "state.json")) or {}

    def link_state(self, st):
        beat = float(st.get("beat") or 0) / 1000.0     # p2p state.json beat is in ms; live() wants < 15 s
        alive = bool(st) and not st.get("stopped") and not st.get("error") and time.time() - beat < 15
        return "up" if alive and st.get("connected") else "down"

    def p2p(self, *args, timeout=60):
        env = dict(os.environ, P2P_HOME=self.p2p_home) if not self.wsl_paths else dict(os.environ)
        try: return subprocess.run(self.p2p_cmd + list(args), capture_output=True, text=True, timeout=timeout, env=env,
                                   encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired: return subprocess.CompletedProcess(args, 124, "", "timeout")
        except FileNotFoundError as e: return subprocess.CompletedProcess(args, 127, "", str(e))

    def send_remote(self, text):
        tmp = os.path.join(self.state_dir, ".out-" + uuid.uuid4().hex + ".txt")
        with open_private(tmp) as f: f.write(text)
        path = tmp
        if self.wsl_paths:
            path = subprocess.run(["wslpath", "-w", tmp], capture_output=True, text=True).stdout.strip() or tmp
        try: r = self.p2p("tunnel", "send", "--file", path, "--name", self.session, "--wait", "20", timeout=45)
        finally:
            try: os.remove(tmp)
            except OSError: pass
        return r.returncode, (r.stdout + r.stderr).strip()[-300:]

    # ---- trust on first use: the far end's p2p key
    def pins(self):
        p = read_json(self.pin_path); return p if isinstance(p, dict) else {}

    def pinned_by_other(self, field, value):
        """The name of ANOTHER link/uplink of this hub whose pin has field == value, else None."""
        for fn in sorted(os.listdir(self.state_dir)):
            if fn.endswith(".pin.json") and fn != self.me + ".pin.json":
                p = read_json(os.path.join(self.state_dir, fn))
                if isinstance(p, dict) and p.get(field) == value: return fn[:-len(".pin.json")]
        return None

    def check_peer(self, st):
        """The tunnel peer key seen first is pinned in uplinks/<as>.pin.json. A different key (someone else won the
        race for a leaked key after a listener restart) holds the link: nothing routed in, nothing sent out."""
        key = st.get("peerKey")
        if not isinstance(key, str) or not key: return True     # not connected yet
        pin = self.pins(); want = pin.get("peer")
        if not want:
            pin["peer"] = key; write_atomic(self.pin_path, pin); self.held = None
            out(f"{self.tag} {self.me}: far end key {clean(key)[:64]} pinned (trust on first use)"); return True
        if key == want:
            if self.held: out(f"{self.tag} {self.me}: the pinned far end is back; link released")
            self.held = None; return True
        if self.held != key:
            self.held = key
            out(f"{self.tag} {self.me} PEER-CHANGED: the tunnel peer is now {clean(key)[:64]}, but this link pinned "
                f"{clean(want)[:64]}. Holding: nothing is routed in or sent out. If you replaced or re-keyed that machine "
                f"yourself: hub.py unpin {self.me}")
        return False

    # ---- inbound
    def inbound(self):
        """[(row or None, offset just past it)] for complete tunnel rows after the saved offset, at most READ_CAP bytes
        and MAX_ROWS rows per step. None = skip it (terminal frame, not JSON, oversized). The caller commits each
        offset only after handling the row, so a crash replays a row instead of losing it; row ids stop the replay."""
        gid, inbox, st = self.mailbox()
        if not gid: return []
        off = read_json(self.off_path) or {}
        if off.get("gen") != gid:     # first run or a new tunnel generation: a new generation's inbox starts empty
            size = os.path.getsize(inbox) if os.path.exists(inbox) else 0
            start = 0 if (self.from_start or off.get("gen")) else size
            off = {"gen": gid, "offset": start, "ids": []}; write_atomic(self.off_path, off)
            if start: out(f"UPLINK {self.me}: starting at the end of the tunnel inbox ({start} B of history skipped; --from-start replays it)")
        if not isinstance(off.get("offset"), int) or off["offset"] < 0: off["offset"] = 0
        self.off, pos = off, off["offset"]
        try:
            with open(inbox, "rb") as f:
                f.seek(pos); data = f.read(READ_CAP)
                if b"\n" not in data and len(data) == READ_CAP:     # one row longer than READ_CAP: skip it whole
                    end = pos + len(data)
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk: return []                      # still being written: next step
                        i = chunk.find(b"\n")
                        if i >= 0: end += i + 1; break
                        end += len(chunk)
                    out(f"{self.tag} {self.me}: dropped an oversized tunnel row ({end - pos} B)")
                    return [(None, end)]
        except FileNotFoundError: return []
        rows = []
        for line in data.split(b"\n")[:-1][:MAX_ROWS]:    # after the last newline: a row still being written
            pos += len(line) + 1
            try: r = json.loads(line.decode("utf-8"))
            except Exception: rows.append((None, pos)); continue
            if not isinstance(r, dict) or r.get("channel") == "term" or not isinstance(r.get("text"), str):
                rows.append((None, pos)); continue
            r["text"] = utf8ok(r["text"])
            if len(r["text"].encode("utf-8")) > MAX_BYTES - 512:
                out(f"{self.tag} {self.me}: dropped an oversized tunnel row ({len(r['text'].encode('utf-8'))} B)")
                rows.append((None, pos)); continue
            rows.append((r, pos))
        return rows

    def commit(self, end, rid=None):
        self.off["offset"] = end
        if rid:
            ids = self.off.get("ids")
            if not isinstance(ids, list): ids = self.off["ids"] = []
            ids.append(rid); del ids[:-KEEP_IDS]
        write_atomic(self.off_path, self.off)

    def route(self, text):
        t = text.strip()
        if t.upper() in ("WHO?", "WHO"): return "who", [], text
        if t.startswith("PRESENCE "): return "presence", [], t[len("PRESENCE "):]
        m = re.match(r"^@([A-Za-z0-9._,@-]+)\s+(.*)$", text, re.S)
        if m:
            names, body = m.group(1), m.group(2)
            if names == "all": return "all", sorted(self.hub.up_names(local_only=True)), body
            ok = lambda n: NAME_RE.match(n.partition("@")[0]) and (not n.partition("@")[2] or NAME_RE.match(n.partition("@")[2]))
            return "deliver", list(dict.fromkeys(n for n in names.split(",") if ok(n))), body
        if not self.default_to: return "plain", [], text      # a link: plain text reaches nobody unless --plain-to-all
        if self.default_to == "all": return "all", sorted(self.hub.up_names(local_only=True)), text
        return "deliver", [self.default_to], text

    @staticmethod
    def wire(frm, text):
        """Tag the sender, keeping a leading @address first so the far side's hub can still route it."""
        m = re.match(r"^(@[A-Za-z0-9._,@-]+)\s+(.*)$", text, re.S)
        return f"{m.group(1)} [{frm}] {m.group(2)}" if m else f"[{frm}] {text}"

    def roster_line(self):
        """Agents that are up: this PC's by name; with --share-mesh (always on a `link`) also name@machine."""
        rows = self.hub.full_roster() if self.share_mesh else self.hub.roster()
        rows = [r for r in rows if r["state"] == "up" and (r.get("mesh") or not r.get("remote"))]
        return "PRESENCE " + (" ".join(f"{roster_key(r)}({one_line(r.get('machine', ''), 64)}/{one_line(r.get('harness', ''), 32) or '?'})"
                                       for r in rows) or "nobody")

    def unrouted(self, text, why):
        out(f"{self.tag} {self.me}: {clean(why)[:160]} for {clean(text[:60])!r}; kept in inbox/{self.me}-unrouted")
        self.hub.deliver(self.me + "-unrouted", self.me, text, via="tunnel")
        self.spill(self.hub.inbox(self.me + "-unrouted"))

    def spill(self, d):
        n = self.hub.prune(d, self.spill_files, self.spill_bytes, self.spill_known.setdefault(d, {}))
        if n: out(f"{self.tag} {self.me}: {d} over {self.spill_files} files / {self.spill_bytes} B: dropped the {n} oldest")

    def may_transit(self, name):
        """--transit-to: names of other links, or machine labels, this peer may reach (* = all)."""
        return "*" in self.transit or name in self.transit

    def allow_mesh(self, row):
        """May this peer reach an agent on another of the owner's machines? A plain uplink: only with --transit-to."""
        return self.may_transit(row["hub"])

    def give(self, to, frm, text, key, via, extra=None, notice=False):
        """Deliver, at most RATE_N per RATE_S seconds per key = (this link, target): two agents auto-replying to each
        other across a link stop burning tokens. The rest wait in inbox/<to>/throttled/ (capped; gc sweeps it)."""
        now = time.time(); q = [t for t in self.rate.get(key, []) if now - t < RATE_S]
        if len(self.rate) > 4096: self.rate = {k: v for k, v in self.rate.items() if v and now - v[-1] < RATE_S}
        if len(q) >= RATE_N:
            self.rate[key] = q
            self.hub.deliver(to, frm, text, via=via, extra=extra, folder="throttled")
            self.spill(os.path.join(self.hub.inbox(to), "throttled"))
            if key not in self.throttled:
                self.throttled.add(key)
                out(f"{self.tag} {self.me}: {one_line(key[0], 130)} -> {one_line(key[1], 130)}: over {RATE_N} a minute; "
                    f"the rest wait in inbox/{to}/throttled/ (a reply loop?)")
                if notice:
                    self.hub.deliver(to, "hub", f"HUB-NOTICE more than {RATE_N} messages a minute from {key[0]}; the rest wait "
                                     f"in inbox/{to}/throttled/. If you are auto-replying to each other, stop.", via="hub")
            return False
        q.append(now); self.rate[key] = q; self.throttled.discard(key)
        self.hub.deliver(to, frm, text, via=via, extra=extra); return True

    def answer_who(self):
        """At most one WHO? answer per WHO_EVERY seconds; asks in between are folded into the next answer."""
        if not self.who_pending or time.time() - self.last_who < WHO_EVERY: return
        self.who_pending, self.last_who = False, time.time()
        rc, info = self.send_remote(self.roster_line()); out(f"{self.tag} {self.me}: WHO? answered rc={rc}")

    def handle(self, text, row=None):
        kind, targets, body = self.route(text)
        if kind == "who": self.who_pending = True; self.answer_who(); return
        if kind == "presence":   # the far side's roster (another hub): shown in `who`, delivered to nobody
            self.peers = one_line(body, 1000); out(f"UPLINK {self.me}: far side has {self.peers}"); return
        if kind == "plain": self.unrouted(text, "text without @name (this link delivers it to nobody)"); return
        if not targets: self.unrouted(text, "nobody up"); return
        if kind == "deliver" and len(targets) > MAX_TARGETS:
            self.unrouted(text, f"{len(targets)} targets (at most {MAX_TARGETS})"); return
        done, why = [], []
        for t in targets:
            try: kind, name, r = resolve(self.hub, t)
            except ValueError as e: why.append(str(e)); continue
            if kind == "local" and name == self.me: why.append("addressed to this link itself"); continue
            if kind == "mesh":
                if not self.allow_mesh(r): why.append(f"{r['addr']} is on another machine (not in --transit-to)"); continue
                if self.give(r["via"], self.me, body, (self.me, r["addr"]), "tunnel", mesh_extra(r)): done.append(r["addr"])
            elif kind == "local":
                if r.get("remote") and not self.may_transit(name): why.append(f"{name} is another link (not in --transit-to)"); continue
                if self.give(name, self.me, body, (self.me, name), "tunnel", notice=True): done.append(name)
            else: why.append(f"no agent {t} here")
        if why: self.unrouted(text, "; ".join(why[:3]) + (f" (+{len(why) - 3} more)" if len(why) > 3 else ""))
        if done: out(f"UPLINK {self.me} -> {','.join(done)}: {clean(body.splitlines()[0][:80]) if body else ''}")

    def beat(self, link):
        note = f"uplink {self.session}" + (f"; there: {self.peers}" if self.peers else "")
        self.hub.heartbeat(self.me, "tunnel", note, remote=True, machine="remote", started=self.started,
                           extra={"link": link, "peers": self.peers, "session": self.session, "host": self.host})

    # ---- outbound
    def outgoing(self, m):
        """The tunnel line for one hub message addressed to this uplink (None = drop it)."""
        return self.wire(m.get("from"), m.get("text", ""))

    def undeliverable(self, m, p, why):
        """A message that can never cross: park it in failed/ (gc sweeps it), tell a local sender, never stall the queue."""
        d = os.path.join(self.hub.inbox(self.me), "failed"); os.makedirs(d, mode=0o700, exist_ok=True)
        try: os.replace(p, os.path.join(d, os.path.basename(p)))
        except OSError: pass
        frm, mid = str(m.get("from") or ""), one_line(m.get("id"), 32)
        out(f"{self.tag} {self.me}: UNDELIVERABLE id={mid} from {one_line(frm, 130)}: {why}")
        r = self.hub.local_row(frm) if NAME_RE.match(frm) and frm != self.me else None
        if r and not r.get("remote"):
            self.hub.deliver(frm, self.me, f"UNDELIVERABLE id={mid} to {self.me}: {why}. Kept in inbox/{self.me}/failed/", via="hub")

    def flush(self):
        for m, p in self.hub.claim(self.me):
            line = self.outgoing(m)
            if line is None: continue
            if len(line.encode("utf-8")) > MAX_BYTES:
                self.undeliverable(m, p, "too large for the tunnel once tagged (max 1 MiB)"); continue
            rc, info = self.send_remote(line)
            if rc == 0: out(f"{self.tag} {one_line(m.get('from'), 130)} -> {self.me}: sent")
            elif rc == 2 and ("exceeds 1 MiB" in info or "UTF-8" in info):    # the tunnel will never take this one
                self.undeliverable(m, p, f"the tunnel refused it ({clean(info)[-120:]})")
            else:   # no ack, peer gone, daemon down, timeout: put it back; the next step retries it; never lose a message
                self.hub.release(p)
                out(f"{self.tag} {self.me}: send failed rc={rc} ({clean(info)[-160:]}); will retry"); break

    def push(self):
        line = self.roster_line()
        if line != self.last_roster and time.time() - self.last_push >= 20:
            rc, _ = self.send_remote(line)
            if rc == 0: self.last_roster, self.last_push = line, time.time(); out(f"UPLINK pushed {line}")

    def step(self):
        gid, _, st = self.mailbox(); link = self.link_state(st) if gid else "down"
        if gid and not self.check_peer(st): link = "peer-changed"
        if link != "peer-changed":
            for row, end in self.inbound():
                rid = row.get("id") if row is not None and isinstance(row.get("id"), str) else None
                if rid and rid in (self.off.get("ids") or []):
                    out(f"{self.tag} {self.me}: dropped replayed tunnel row {clean(rid)[:32]}"); self.commit(end); continue
                if row is not None:
                    # Any failure in one row drops that row (counted) and the offset still moves past it: a row that
                    # always fails must not crash the bridge and be replayed forever. A stop (KeyboardInterrupt) is
                    # not caught, so a row the bridge was stopped in the middle of is read again.
                    try: self.handle(row["text"], row)
                    except Exception as e:
                        self.bad_rows += 1
                        out(f"{self.tag} {self.me}: dropped a row ({self.bad_rows} so far): {type(e).__name__}: {clean(str(e))[:160]}")
                self.commit(end, rid)
            if self.hub_hold: link = "peer-changed"
        self.beat(link)
        if link == "up": self.flush(); self.push(); self.answer_who()
        return link

    def close(self): pass

def mesh_extra(row):
    return {"mesh": {"to": row["name"], "dst": row["hub_id"], "dstl": row["hub"]}}

def default_p2p(wsl_interop):
    if os.name == "nt": return [os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), ".local", "bin", "p2p.cmd")]
    if wsl_interop:
        prof = win_profile_from_wsl() or die("cannot find the Windows profile from WSL")
        win = subprocess.run(["wslpath", "-w", os.path.join(prof, ".local", "bin", "p2p.cmd")], capture_output=True, text=True).stdout.strip()
        return ["cmd.exe", "/c", win]
    found = shutil.which("p2p") or os.path.expanduser("~/.local/bin/p2p")
    return [found]

def _str(v, n, rx=None):
    return v if isinstance(v, str) and len(v) <= n and (rx is None or rx.match(v)) else None

def _int(v, lo, hi):
    return v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None

def _path(v):
    return v if isinstance(v, list) and 1 <= len(v) <= 16 and all(_str(h, 16, HUBID_RE) for h in v) else None

def _age(v):
    """A wire age in seconds, clamped to 0..AGE_MAX; None if it is not a number (NaN included)."""
    if isinstance(v, bool): return None
    try: f = float(v)
    except (TypeError, ValueError): return None
    return None if f != f else max(0.0, min(f, AGE_MAX))

def _no_constant(c): raise ValueError(f"{c} is not allowed on the wire")

def wire_json(s):
    """Parse one hub envelope. ValueError if it is not JSON, holds NaN/Infinity, or nests deeper than WIRE_DEPTH
    (checked on the text first, so a hostile row never reaches json.loads' recursion)."""
    depth = 0
    for m in re.finditer(r'"(?:[^"\\]|\\.)*"|[\[\]{}]', s):
        c = m.group()
        if c in "[{":
            depth += 1
            if depth > WIRE_DEPTH: raise ValueError(f"envelope nested deeper than {WIRE_DEPTH}")
        elif c in "]}": depth -= 1
    return json.loads(s, parse_constant=_no_constant)

def wire_snapshot(s):
    """Validate one presence snapshot from the wire. Returns a clean copy, or None. Nothing in it is trusted."""
    if not isinstance(s, dict): return None
    origin, path, ttl = _str(s.get("origin"), 16, HUBID_RE), _path(s.get("path")), _int(s.get("ttl"), 0, MESH_MAX_TTL)
    agents = s.get("agents")
    if origin is None or path is None or ttl is None or path[0] != origin or not isinstance(agents, list) or len(agents) > 256:
        return None
    age = _age(s.get("age"))
    if age is None: return None
    rows = []
    for ag in agents:
        if not isinstance(ag, dict) or not _str(ag.get("name"), 64, NAME_RE): continue
        aa = _age(ag.get("age") or 0)
        if aa is None: continue
        aa = int(aa)
        rows.append({"name": ag["name"], "machine": one_line(ag.get("machine"), 64), "harness": one_line(ag.get("harness"), 32),
                     "note": one_line(ag.get("note"), 120), "age": aa, "state": "up" if ag.get("state") == "up" else "stale"})
    return {"origin": origin, "label": safe_label(s.get("label")), "age": age, "path": path, "ttl": ttl, "agents": rows}

def row_wait(row):
    """Seconds a tunnel row waited in inbox.jsonl: its "rx" is stamped by this machine's own p2p daemon."""
    try: return max(0.0, time.time() - calendar.timegm(time.strptime(str(row["rx"])[:19], "%Y-%m-%dT%H:%M:%S")))
    except (TypeError, ValueError, KeyError): return 0.0

class Link(Uplink):
    """Hub <-> hub over ONE tunnel session: option (c), the owner's own network of machines.

    Both ends run `link`. Each end pushes presence: its own agents plus the machines it hears through its
    OTHER links (never back over the link it heard them on), so main <- laptop and main <- second gives every
    machine the full picture. Messages for an agent elsewhere travel as envelopes, hop by hop, toward the
    machine that announced that agent. Plain (non-envelope) lines route like `uplink`, so `WHO?` and
    `@name text` / `@name@machine text` typed by a person at the far end keep working; plain text without an
    @name reaches NO agent (it waits in inbox/<as>-unrouted) unless the link runs with --plain-to-all.
    """
    def __init__(self, hub, session, as_name, p2p_cmd, p2p_home, label=None, ttl=MESH_TTL, from_start=False, wsl_paths=False,
                 transit=(), plain_to_all=False):
        super().__init__(hub, session, as_name, p2p_cmd, p2p_home, "all" if plain_to_all else None, from_start, wsl_paths,
                         transit, share_mesh=True)
        self.ident = hub.identity(label=label)
        self.ttl = max(1, min(MESH_MAX_TTL, int(ttl)))
        self.peer_id, self.peer_label, self.last_sig, self.last_far = None, "", None, None
        self.min_push, self.dropped, self.loop_drops, self.tag = 3.0, 0, 0, "LINK"

    def env(self, **kw):
        e = {"hop": self.ident["id"], "hopl": self.ident["label"]}; e.update(kw)
        return MESH_TAG + json.dumps(e, ensure_ascii=False, separators=(",", ":"))

    def drop(self, why): self.dropped += 1; out(f"LINK {self.me}: dropped: {why}")

    def peer_file(self, origin): return self.hub.mesh_path("peers", origin + ".json")

    def allow_mesh(self, row): return True     # the far end is one of the owner's own machines: the mesh is the point

    def accept_hub(self, hop, hopl):
        """Trust on first use, per link: the first far hub id is pinned in uplinks/<as>.pin.json. Another id later
        holds the link (PEER-CHANGED); an id that another link of this hub pinned is refused (reach it through that one)."""
        pin = self.pins(); want = pin.get("hub")
        if want and hop != want:
            if self.hub_hold != hop:
                self.hub_hold = hop
                out(f"LINK {self.me} PEER-CHANGED: the far end now says it is hub {hop} ({safe_label(hopl)}), but this link "
                    f"pinned {want}. Holding: nothing is routed in or sent out. If you replaced that machine's hub yourself: "
                    f"hub.py unpin {self.me}")
            return False
        owner = self.pinned_by_other("hub", hop)
        if owner: self.drop(f"the far end claims hub {hop}, which is pinned to link {owner}"); return False
        if not want:
            pin.update(hub=hop, hub_label=safe_label(hopl)); write_atomic(self.pin_path, pin)
            out(f"LINK {self.me}: far end hub {safe_label(hopl)} ({hop}) pinned (trust on first use)")
        self.hub_hold = None
        return True

    # ---- presence
    def snapshots(self):
        me = self.ident["id"]
        agents = [{"name": r["name"], "machine": r["machine"][:64], "harness": r["harness"][:32], "note": one_line(r["note"], 120),
                   "age": r["age"], "state": r["state"]} for r in self.hub.roster() if not r.get("remote")]
        snaps = [{"origin": me, "label": self.ident["label"], "age": 0, "path": [me], "ttl": self.ttl, "agents": agents}]
        for p in self.hub.mesh_peers():
            if p.get("via") == self.me: continue                            # split horizon
            if self.peer_id and (p.get("origin") == self.peer_id or self.peer_id in p["path"]): continue
            ttl = int(p.get("ttl") or 0) - 1
            if ttl <= 0 or p["eff_age"] > MESH_FRESH_S or me in p["path"] or len(p["path"]) >= 16: continue
            snaps.append({"origin": p["origin"], "label": p["label"], "age": int(p["eff_age"]), "path": p["path"] + [me],
                          "ttl": ttl, "agents": p["agents"]})
        return snaps

    def push(self):
        snaps = self.snapshots(); now = time.time()
        sig = json.dumps([[s["origin"], s["label"], s["ttl"], len(s["path"]), sorted((a["name"], a["state"], a["harness"]) for a in s["agents"])]
                          for s in snaps], sort_keys=True)
        if not ((sig != self.last_sig and now - self.last_push >= self.min_push) or now - self.last_push >= MESH_PUSH_S): return
        rc, info = self.send_remote(self.env(t="presence", hubs=snaps))
        if rc != 0: out(f"LINK {self.me}: presence push failed rc={rc} ({info})"); return
        if sig != self.last_sig:
            out(f"LINK {self.me}: presence pushed ({len(snaps)} machine(s), {sum(len(s['agents']) for s in snaps)} agent(s))")
        self.last_sig, self.last_push = sig, now

    def on_presence(self, e, waited=0.0):
        hubs = e.get("hubs")
        if not isinstance(hubs, list): self.drop("presence without hubs"); return
        me, now, heard = self.ident["id"], time.time(), set()
        for raw in hubs[:64]:
            s = wire_snapshot(raw)
            if s is None: self.drop("malformed presence snapshot"); continue
            if s["origin"] == me or me in s["path"] or s["ttl"] <= 0: self.loop_drops += 1; continue   # loop / expired
            if s["path"][-1] != self.peer_id: self.drop("presence path does not end at the sending hub"); continue
            owner = self.pinned_by_other("hub", s["origin"])
            if owner: self.drop(f"origin {s['origin']} is pinned to link {owner}"); continue
            heard.add(s["origin"]); s["age"] += waited   # + the time it sat in the tunnel inbox before we read it
            old = read_json(self.peer_file(s["origin"]))
            if isinstance(old, dict) and old.get("via") != self.me:     # another link has a route: it stays until forgotten
                try: old_age = float(old["age"]) + now - float(old["rx"])
                except (TypeError, ValueError, KeyError): old_age = 1e9
                if old_age <= MESH_FORGET_S: continue                   # no silent takeover by a later claim
            write_atomic(self.peer_file(s["origin"]), dict(s, via=self.me, rx=now))
        self.forget(keep=heard)   # a push is the neighbour's full view: what it no longer says is gone
        far = ", ".join(f"{p['label']}:{len(p['agents'])}" for p in self.hub.mesh_peers() if p.get("via") == self.me)
        if far != self.last_far: self.last_far = far; out(f"LINK {self.me}: machines through this link: {far or 'none'}")

    def forget(self, keep=()):
        d = self.hub.mesh_path("peers")
        for fn in (os.listdir(d) if os.path.isdir(d) else []):
            rec = read_json(os.path.join(d, fn))
            if isinstance(rec, dict) and rec.get("via") == self.me and rec.get("origin") not in keep:
                try: os.remove(os.path.join(d, fn))
                except OSError: pass

    def close(self): self.forget()

    # ---- messages
    def on_msg(self, e):
        me, own = self.ident["id"], self.ident["label"]
        mid, src, path = _str(e.get("id"), 32, MSGID_RE), _str(e.get("src"), 16, HUBID_RE), _path(e.get("path"))
        ttl, frm, to, text = _int(e.get("ttl"), 0, MESH_MAX_TTL), _str(e.get("from"), 64, NAME_RE), e.get("to"), e.get("text")
        dst, dstl = e.get("dst"), e.get("dstl")
        if (None in (mid, src, path, ttl, frm) or not isinstance(text, str) or len(text.encode("utf-8")) > MAX_BYTES
                or not (to == "*" or _str(to, 64, NAME_RE)) or path[0] != src or path[-1] != self.peer_id
                or not (dst is None or _str(dst, 16, HUBID_RE)) or not (dstl is None or _str(dstl, 64, NAME_RE))):
            self.drop("malformed message envelope"); return
        if src == me or me in path: self.drop(f"message {mid} looped back"); return
        if ttl <= 0: self.drop(f"message {mid} ttl expired"); return
        if not self.hub.mark_seen(mid): self.drop(f"duplicate message {mid}"); return
        sender = f"{frm}@{safe_label(e.get('srcl'))}"   # shown to the reader; the far end chooses it, so never a rate key
        fwd = {k: e[k] for k in ("t", "id", "src", "srcl", "from", "to", "dst", "dstl", "ttl", "path") if k in e}
        here = (dst == me) if dst is not None else (dstl is None or dstl == own)
        if here:
            if to == "*":
                targets = [t for t in sorted(self.hub.up_names(local_only=True))
                           if self.give(t, sender, text, (self.me, t), f"link:{self.me}", notice=True)]
                if not self.hub.up_names(local_only=True): self.unrouted(text, "nobody up")
                elif targets: out(f"LINK {self.me}: {sender} -> {','.join(targets)}")
                return
            try: kind, name, r = resolve(self.hub, to)
            except ValueError as err: self.unrouted(text, clean(str(err))); return
            if kind == "local":
                if r.get("remote") and not self.may_transit(name): self.unrouted(text, f"{name} is another link (not in --transit-to)"); return
                if self.give(name, sender, text, (self.me, name), f"link:{self.me}", notice=True): out(f"LINK {self.me}: {sender} -> {name}")
                return
            if kind is None or dst is not None or dstl is not None: self.unrouted(text, f"no agent {to!r} here"); return
            if r["via"] == self.me: self.unrouted(text, f"{r['addr']} is back the way it came"); return
            fwd["dst"], fwd["dstl"] = r["hub_id"], r["hub"]
            if self.give(r["via"], sender, text, (self.me, r["addr"]), f"link:{self.me}", {"mesh": {"env": fwd}}):
                out(f"LINK {self.me}: forwarding {sender} -> {r['addr']} via {r['via']}")
            return
        route = next((p for p in self.hub.mesh_peers() if p.get("origin") == dst or (dst is None and p.get("label") == dstl)), None)
        if route is None or route.get("via") == self.me: self.unrouted(text, f"no route to {dstl or dst}"); return
        if self.give(route["via"], sender, text, (self.me, f"{to}@{route['label']}"), f"link:{self.me}", {"mesh": {"env": fwd}}):
            out(f"LINK {self.me}: forwarding {sender} -> {to}@{route['label']} via {route['via']}")

    def outgoing(self, m):
        me, text = self.ident["id"], str(m.get("text", ""))
        mesh = m.get("mesh") if isinstance(m.get("mesh"), dict) else {}
        if isinstance(mesh.get("env"), dict):          # forwarding someone else's message one hop further
            e = dict(mesh["env"]); e["path"] = list(e.get("path") or []) + [me]; e["ttl"] = int(e.get("ttl") or 0) - 1
            if e["ttl"] <= 0: out(f"LINK {self.me}: dropped: message {e.get('id')} ttl expired"); return None
        else:
            to, dst, dstl = mesh.get("to"), mesh.get("dst"), mesh.get("dstl")
            if not to:                                  # sent to the link's own name: "@name[@machine] text", else everyone there
                mm = re.match(r"^@([A-Za-z0-9._-]+)(?:@([A-Za-z0-9._-]+))?\s+(.*)$", text, re.S)
                if mm: to, dstl, text, dst = mm.group(1), mm.group(2), mm.group(3), None
                else: to, dst, dstl = "*", self.peer_id, None
            frm = m.get("from") if NAME_RE.match(str(m.get("from") or "")) else "unknown"
            e = {"t": "msg", "id": uuid.uuid4().hex, "src": me, "srcl": self.ident["label"], "from": frm,
                 "to": to, "dst": dst, "dstl": dstl, "ttl": self.ttl, "path": [me]}
            self.hub.mark_seen(e["id"])
        e["text"] = text
        return self.env(**e)      # flush() parks it in failed/ if the envelope makes it too large

    def inbound(self):
        """Like the uplink, but a link's FIRST run on a tunnel replays the hub envelopes already waiting (the far
        hub's presence, messages for us) and skips only the chat history (rows before "chat_from"). Dedupe makes a
        replay harmless."""
        gid, inbox, _ = self.mailbox(); off = read_json(self.off_path) or {}
        first = bool(gid) and not off.get("gen") and not self.from_start
        if first: self.from_start = True
        try: rows = super().inbound()
        finally:
            if first: self.from_start = False
        if first:
            try: self.off["chat_from"] = os.path.getsize(inbox)
            except OSError: self.off["chat_from"] = 0
            write_atomic(self.off_path, self.off)
            out(f"LINK {self.me}: first start on this tunnel: hub envelopes waiting are replayed, "
                f"{self.off['chat_from']} B of chat history skipped")
        cut = self.off.get("chat_from") if isinstance(self.off.get("chat_from"), int) else 0
        return [(None if r is not None and end <= cut and not r["text"].startswith(MESH_TAG) else r, end) for r, end in rows]

    def handle(self, text, row=None):
        if self.hub_hold and not self.pins().get("hub"): self.hub_hold = None    # unpinned: meet the far end afresh
        if self.hub_hold: self.drop(f"link held (PEER-CHANGED); `hub.py unpin {self.me}` accepts the new far end"); return
        if not text.startswith(MESH_TAG): return super().handle(text, row)
        try: e = wire_json(text[len(MESH_TAG):])
        except ValueError: e = None
        if not isinstance(e, dict): self.drop("malformed envelope"); return
        hop = _str(e.get("hop"), 16, HUBID_RE)
        if hop is None: self.drop("envelope without a hub id"); return
        if hop == self.ident["id"]: self.drop("own envelope came back (is this hub linked to itself?)"); return
        if hop != self.peer_id:
            if not self.accept_hub(hop, e.get("hopl")): return
            self.peer_id, self.peer_label, self.last_sig = hop, safe_label(e.get("hopl")), None   # (re)met: push now
            out(f"LINK {self.me}: the far end is hub {self.peer_label} ({hop})")
        if e.get("t") == "presence": self.on_presence(e, waited=row_wait(row))
        elif e.get("t") == "msg": self.on_msg(e)
        else: self.drop("unknown envelope type")

    def beat(self, link):
        note = f"link {self.session}" + (f"; far end: {self.peer_label}" if self.peer_label else "")
        self.hub.heartbeat(self.me, "link", note, remote=True, machine="link", started=self.started,
                           extra={"link": link, "peer_hub": self.peer_id or "", "peers": "", "session": self.session, "host": self.host})

def tunnel_args(a):
    interop = bool(a.wsl_interop)
    if a.p2p_home: home = a.p2p_home
    elif interop: home = os.path.join(win_profile_from_wsl() or die("no Windows profile"), ".p2p")
    else: home = os.environ.get("P2P_HOME") or os.path.join(os.path.expanduser("~"), ".p2p")
    cmd = shlex.split(a.p2p, posix=(os.name != "nt")) if a.p2p else default_p2p(interop)
    return home, cmd, interop

def run_bridge(hub, a, br, banner):
    if not br.mailbox()[0]: die(f"no tunnel session {a.session!r} under {br.p2p_home} (look in {os.path.join(br.p2p_home, 'tunnel')})", 5)
    leave_on_signals(); out(banner)
    last = None
    try:
        while True:
            link = br.step()
            if link != last: out(f"LINK {br.me} {link.upper()}"); last = link
            if a.once: return 0
            time.sleep(a.poll)
    except KeyboardInterrupt: pass
    finally:
        if not a.once: br.close()
        hub.bye(br.me)
    return 0

def transit_arg(v):
    names = [n for n in (v or "").split(",") if n]
    for n in names:
        if n != "*": check_name(n)
    return names

def cmd_uplink(hub, a):
    me = check_name(a.as_name); check_name(a.session); hub.check_bridge_name(me, a.session)
    home, cmd, interop = tunnel_args(a)
    up = Uplink(hub, a.session, me, cmd, home, a.default_to, a.from_start, wsl_paths=interop,
                transit=transit_arg(a.transit_to), share_mesh=a.share_mesh)
    return run_bridge(hub, a, up, f"UPLINK {me} <-> tunnel {a.session} (p2p home {home}). Text only; nothing received is executed. "
                                  f"Far side sees {'every linked machine' if a.share_mesh else 'this PC only'}; reaches "
                                  f"{', '.join(up.transit) if up.transit else 'this PC only'}.")

def cmd_link(hub, a):
    me = check_name(a.as_name); check_name(a.session); hub.check_bridge_name(me, a.session)
    if a.label: check_name(a.label)
    home, cmd, interop = tunnel_args(a)
    lk = Link(hub, a.session, me, cmd, home, label=a.label, ttl=a.ttl, from_start=a.from_start, wsl_paths=interop,
              transit=transit_arg(a.transit_to), plain_to_all=a.plain_to_all)
    return run_bridge(hub, a, lk, f"LINK {me} <-> tunnel {a.session}: this hub is {lk.ident['label']} ({lk.ident['id']}), "
                                  f"ttl {lk.ttl}. Presence and messages only; nothing received is executed.")

# ---------------------------------------------------------------- selftest
def selftest():
    import contextlib, io
    ok = []
    def check(cond, label):
        ok.append(bool(cond)); out(("PASS " if cond else "FAIL ") + label)
    root = tempfile.mkdtemp(prefix="agent-hub-test-")
    try:
        hub = Hub(root)
        hub.heartbeat("win-claude", "claude"); hub.heartbeat("wsl-codex", "codex")
        hub.heartbeat("old-agent", "claude")
        rec = read_json(os.path.join(hub.agents, "old-agent.json")); rec["beat"] = time.time() - 300
        write_atomic(os.path.join(hub.agents, "old-agent.json"), rec)
        st = {r["name"]: r["state"] for r in hub.roster()}
        check(st == {"win-claude": "up", "wsl-codex": "up", "old-agent": "stale"}, "presence: up vs stale")
        hub.deliver("wsl-codex", "win-claude", "hello\nsecond line")
        got = list(hub.claim("wsl-codex"))
        check(len(got) == 1 and got[0][0]["text"] == "hello\nsecond line", "direct message delivered intact")
        check(list(hub.claim("wsl-codex")) == [], "message consumed exactly once")
        hub.deliver("wsl-codex", "win-claude", "race")
        a, b = list(hub.claim("wsl-codex")), list(hub.claim("wsl-codex"))
        check(len(a) + len(b) == 1, "two readers: one claim")
        claim_selftest(check, root)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_send(hub, argparse.Namespace(frm="win-claude", to="all", text="hi all", file=None, queue=False))
        check([m["text"] for m, _ in hub.claim("wsl-codex")] == ["hi all"] and not list(hub.claim("old-agent")),
              "broadcast reaches up agents only")
        with contextlib.redirect_stdout(buf):
            cmd_send(hub, argparse.Namespace(frm="win-claude", to="old-agent", text="later", file=None, queue=False))
        check("NOT UP: stale" in buf.getvalue() and len(list(hub.claim("old-agent"))) == 1, "stale target warned, still queued")
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                cmd_send(hub, argparse.Namespace(frm="win-claude", to="ghost", text="x", file=None, queue=False))
            check(False, "unknown target refused")
        except SystemExit: check(True, "unknown target refused")
        heb = "שלום עולם 👋"
        hub.deliver("win-claude", "wsl-codex", heb)
        check(next(iter(hub.claim("win-claude")))[0]["text"] == heb, "unicode (Hebrew, emoji) round trip")
        line = fmt_msg({"from": "shai", "to": "x", "id": "1", "text": "\x1b]0;t\x07ok \u202eevil\u2028MSG from=fake"})
        check("\x1b" not in line and "\x07" not in line and "\u202e" not in line and "fake" not in line,
              "printed message: control/bidi chars stripped, one line")

        # fake tunnel: a p2p home with one join session, and a fake p2p CLI that logs what it sends
        p2p_home = os.path.join(root, "p2p"); gid = uuid.uuid4().hex
        sess = os.path.join(p2p_home, "tunnel", "join-TEST", gid); os.makedirs(sess)
        write_atomic(os.path.join(p2p_home, "tunnel", "join-TEST", "current.json"), {"id": gid})
        write_atomic(os.path.join(sess, "state.json"), {"id": gid, "connected": True, "beat": time.time() * 1000})
        inbox = os.path.join(sess, "inbox.jsonl")
        with open(inbox, "w", encoding="utf-8") as f: f.write(json.dumps({"v": 1, "text": "old history"}) + "\n")
        sent_log = os.path.join(root, "sent.log")
        fake = os.path.join(root, "fake_p2p.py")
        with open(fake, "w") as f:
            f.write("import sys\na=sys.argv[1:]\nf=a[a.index('--file')+1]\n"
                    f"open({sent_log!r},'a',encoding='utf-8').write(open(f,encoding='utf-8').read()+'\\n<<END>>\\n')\n"
                    "print('{\"delivered\": true}')\n")
        up = Uplink(hub, "join-TEST", "shai", [sys.executable, fake], p2p_home)
        def add(row):
            with open(inbox, "a", encoding="utf-8") as f: f.write(json.dumps(row, ensure_ascii=False) + "\n")
        with contextlib.redirect_stdout(buf): link = up.step()
        check(link == "up" and "shai" in hub.up_names(), "uplink: remote appears in roster while link is up")
        sent = open(sent_log, encoding="utf-8").read() if os.path.exists(sent_log) else ""
        check("PRESENCE" in sent and "win-claude(" in sent and "wsl-codex(" in sent and "shai(" not in sent.split("PRESENCE")[1].split("<<END>>")[0],
              "uplink: pushes local roster to the remote side")
        check(not list(hub.claim("win-claude")), "uplink: old tunnel history not replayed on first start")
        add({"v": 1, "text": "@wsl-codex please run the tests"}); add({"v": 1, "text": "to everyone"})
        add({"v": 1, "channel": "term", "text": "ls"}); add({"v": 1, "text": "WHO?"})
        with open(inbox, "a", encoding="utf-8") as f: f.write('{"v":1,"text":"half a li')   # partial line
        with contextlib.redirect_stdout(buf): up.step()
        c = [m["text"] for m, _ in hub.claim("wsl-codex")]; w = [m["text"] for m, _ in hub.claim("win-claude")]
        check(c == ["please run the tests", "to everyone"] and w == ["to everyone"], "uplink: @name and default routing")
        check(not any("ls" == x for x in c + w), "uplink: terminal frames ignored")
        check(open(sent_log, encoding="utf-8").read().count("PRESENCE") == 2, "uplink: WHO? answered with roster")
        with open(inbox, "a", encoding="utf-8") as f: f.write('ne"}\n')
        with contextlib.redirect_stdout(buf): up.step()
        check([m["text"] for m, _ in hub.claim("wsl-codex")] == ["half a line"], "uplink: partial line waits until complete")
        hub.deliver("shai", "wsl-codex", "ERROR npm test | 3 failing")
        with contextlib.redirect_stdout(buf): up.step()
        check("[wsl-codex] ERROR npm test | 3 failing" in open(sent_log, encoding="utf-8").read(), "uplink: local -> remote send")
        write_atomic(os.path.join(sess, "state.json"), {"id": gid, "connected": False, "beat": time.time() * 1000})
        hub.deliver("shai", "win-claude", "while down")
        with contextlib.redirect_stdout(buf): link = up.step()
        check(link == "down" and "shai" not in hub.up_names() and "while down" not in open(sent_log, encoding="utf-8").read(),
              "uplink: link down -> remote shown down, outbound held")
        write_atomic(os.path.join(sess, "state.json"), {"id": gid, "connected": True, "beat": time.time() * 1000})
        with contextlib.redirect_stdout(buf): up.step()
        check("[win-claude] while down" in open(sent_log, encoding="utf-8").read(), "uplink: held message sent after reconnect")
        add({"v": 1, "text": "PRESENCE laptop-codex(laptop/codex)\nup  forged-agent \x1b[2J"})
        with contextlib.redirect_stdout(buf): up.step()
        shai = {r["name"]: r for r in hub.roster()}["shai"]
        check("laptop-codex" in shai["note"] and "\n" not in shai["note"] and "\x1b" not in shai["note"]
              and not list(hub.claim("wsl-codex")), "uplink: far-side PRESENCE shown in who (one clean line), not delivered")
        hub.deliver("shai", "win-claude", "@laptop-codex run the build")
        with contextlib.redirect_stdout(buf): up.step()
        check("@laptop-codex [win-claude] run the build" in open(sent_log, encoding="utf-8").read(), "uplink: @address kept first for the far hub")
        up.p2p_cmd = [sys.executable, "-c", "import sys; sys.exit(3)"]
        hub.deliver("shai", "win-claude", "will fail")
        with contextlib.redirect_stdout(buf): up.step()
        check(len([f for f in os.listdir(hub.inbox("shai")) if f.endswith(".json")]) == 1, "uplink: failed send kept for retry")
        mesh_selftest(check, os.path.join(root, "mesh-test"))
        guard_selftest(check, os.path.join(root, "guard-test"))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    out(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1

def claim_selftest(check, root):
    """Claim markers: two readers racing on one inbox, a live marker, a dead claimer's marker, a put-back."""
    import threading
    hub, n = Hub(root), 300
    sent = {hub.deliver("racer", "win-claude", f"race {i}") for i in range(n)}
    got, gate, deadline = ([], []), threading.Barrier(2), time.time() + 60
    def reader(k):   # each thread is its own reader (own Hub); on Windows a bare rename let both win ~2/3 of these
        h = Hub(root); gate.wait()
        while time.time() < deadline and any(f.endswith(".json") for f in os.listdir(h.inbox("racer"))):
            got[k].extend(m["id"] for m, _ in h.claim("racer"))
    ts = [threading.Thread(target=reader, args=(k,)) for k in (0, 1)]
    for t in ts: t.start()
    for t in ts: t.join()
    ids = got[0] + got[1]
    check(len(ids) == n and set(ids) == sent, f"claim race: {n} messages, two readers ({len(got[0])}+{len(got[1])}), "
          f"{len(ids) - len(set(ids))} duplicated, {len(sent - set(ids))} lost")
    box = hub.inbox("racer")
    def one(text):
        hub.deliver("racer", "win-claude", text)
        return [f for f in os.listdir(hub.inbox("racer")) if f.endswith(".json")][0]
    fn = one("held")
    open(Hub.marker(box, fn, 0), "x").close()                 # another reader holds it right now
    check(not list(hub.claim("racer")) and os.path.exists(os.path.join(hub.inbox("racer"), fn)),
          "claim: a live marker held by another reader is respected")
    old = time.time() - CLAIM_STALE_S - 5
    os.utime(Hub.marker(box, fn, 0), (old, old))               # ...and that reader died before moving it
    a, b = [m["text"] for m, _ in hub.claim("racer")], list(hub.claim("racer"))
    check(a == ["held"] and not b and os.path.exists(Hub.marker(box, fn, 1)), "claim: a dead claimer's marker is taken over once")
    one("retry me")
    (m, p), = list(hub.claim("racer")); hub.release(p)
    check([m["text"] for m, _ in hub.claim("racer")] == ["retry me"], "claim: a released message is claimed again at once")

def mesh_selftest(check, root):
    """Three hubs, main <- laptop and main <- second, over fake tunnels that append to each other's inbox.jsonl."""
    import contextlib, io
    buf = io.StringIO()
    fake = os.path.join(root, "fake_link.py"); os.makedirs(root)
    with open(fake, "w") as f:   # argv: <far inbox.jsonl> <count log> tunnel send --file F ...
        f.write("import json,sys\na=sys.argv\ntext=open(a[a.index('--file')+1],encoding='utf-8').read()\n"
                "open(a[1],'a',encoding='utf-8').write(json.dumps({'v':1,'text':text},ensure_ascii=False)+'\\n')\n"
                "open(a[2],'a',encoding='utf-8').write('x\\n')\nprint('{\"delivered\": true}')\n")
    count_log = os.path.join(root, "count.log")
    def session(tag, name):
        home = os.path.join(root, "p2p-" + tag); gid = uuid.uuid4().hex
        d = os.path.join(home, "tunnel", name, gid); os.makedirs(d)
        write_atomic(os.path.join(home, "tunnel", name, "current.json"), {"id": gid})
        open(os.path.join(d, "inbox.jsonl"), "w").close()
        return home, d
    def set_link(d, up=True): write_atomic(os.path.join(d, "state.json"), {"connected": up, "beat": time.time() * 1000})
    M, L, S = (Hub(os.path.join(root, n)) for n in ("m", "l", "s"))
    for h, lab in ((M, "main"), (L, "laptop"), (S, "second")): h.identity(lab)
    ids = {n: h.identity()["id"] for n, h in (("M", M), ("L", L), ("S", S))}
    sess = {k: session(*k) for k in (("m", "laptop"), ("l", "join-A"), ("m", "second"), ("s", "join-B"), ("m", "helper"))}
    inbox = lambda k: os.path.join(sess[k][1], "inbox.jsonl")
    pair = {("m", "laptop"): ("l", "join-A"), ("l", "join-A"): ("m", "laptop"), ("m", "second"): ("s", "join-B"), ("s", "join-B"): ("m", "second")}
    def mk(h, k, as_name):
        lk = Link(h, k[1], as_name, [sys.executable, fake, inbox(pair[k]), count_log], sess[k][0], from_start=True)
        lk.min_push = 0; return lk
    m_l, l_m, m_s, s_m = mk(M, ("m", "laptop"), "laptop"), mk(L, ("l", "join-A"), "main"), mk(M, ("m", "second"), "second"), mk(S, ("s", "join-B"), "main")
    helper_log = os.path.join(root, "helper-out.jsonl")
    helper = Uplink(M, "helper", "helper", [sys.executable, fake, helper_log, os.path.join(root, "helper.count")], sess[("m", "helper")][0], from_start=True)
    links = [m_l, l_m, m_s, s_m]
    def rounds(n=4):
        for k in sess: set_link(sess[k][1])
        for _ in range(n):
            for lk in links + [helper]:
                with contextlib.redirect_stdout(buf): lk.step()
    def agents(h): return {r.get("addr") or r["name"]: r for r in h.full_roster()}
    def texts(h, name): return [(m["from"], m["text"]) for m, _ in h.claim(name)]
    M.heartbeat("m-claude", "claude"); L.heartbeat("l-codex", "codex"); L.heartbeat("l-claude", "claude"); S.heartbeat("s-claude", "claude")
    rounds()
    lv, sv, mv = agents(L), agents(S), agents(M)
    check({"m-claude@main", "s-claude@second"} <= set(lv) and lv["s-claude@second"]["state"] == "up", "mesh: laptop sees main AND second (relayed)")
    check({"l-codex@laptop", "l-claude@laptop", "m-claude@main"} <= set(sv), "mesh: second sees laptop (relayed) and main")
    check({"l-codex@laptop", "s-claude@second"} <= set(mv) and mv["l-codex@laptop"]["via"] == "laptop", "mesh: main sees both, each via its own link")
    check(lv["s-claude@second"]["hops"] == 2 and lv["m-claude@main"]["hops"] == 1, "mesh: hop counts (direct 1, relayed 2)")
    roster_txt = fmt_roster(L.full_roster())
    check("s-claude@second" in roster_txt and "via main, 2 hops" in roster_txt, "mesh: `who` prints name@machine and the route")
    peer_ids = lambda h: sorted(fn[:-5] for fn in os.listdir(h.mesh_path("peers")))
    check(peer_ids(M) == sorted([ids["L"], ids["S"]]) and peer_ids(L) == sorted([ids["M"], ids["S"]]) and peer_ids(S) == sorted([ids["M"], ids["L"]]),
          "mesh: each hub knows exactly the 2 others, never itself")
    n0 = sum(1 for _ in open(count_log)); rounds(6); n1 = sum(1 for _ in open(count_log))
    check(n1 == n0, f"mesh: quiet network is quiet (no echo: {n1 - n0} sends in 6 idle rounds)")
    with contextlib.redirect_stdout(buf): cmd_send(L, argparse.Namespace(frm="l-codex", to="s-claude", text="tests pass on laptop", file=None, queue=False))
    rounds()
    got = texts(S, "s-claude")
    check(got == [("l-codex@laptop", "tests pass on laptop")], "mesh: laptop -> second by bare name, through main, exactly once")
    check(not texts(M, "m-claude") and not texts(L, "l-claude"), "mesh: no stray copies on main or laptop")
    with contextlib.redirect_stdout(buf): cmd_send(S, argparse.Namespace(frm="s-claude", to="l-codex@laptop", text="ack", file=None, queue=False))
    rounds()
    check(texts(L, "l-codex") == [("s-claude@second", "ack")], "mesh: reply by name@machine")
    with contextlib.redirect_stdout(buf): cmd_send(M, argparse.Namespace(frm="m-claude", to="laptop", text="@l-claude build please", file=None, queue=False))
    rounds()
    check(texts(L, "l-claude") == [("m-claude@main", "build please")], "mesh: old form `send laptop \"@name text\"`")
    rows = [json.loads(x) for x in open(inbox(("s", "join-B")), encoding="utf-8")]
    last_msg = [r for r in rows if r["text"].startswith(MESH_TAG) and '"t":"msg"' in r["text"]][-1]
    with open(inbox(("s", "join-B")), "a", encoding="utf-8") as f: f.write(json.dumps(last_msg) + "\n")
    d0 = s_m.dropped; rounds(2)
    check(not texts(S, "s-claude") and s_m.dropped == d0 + 1, "mesh: replayed envelope dropped as duplicate")
    def inject(k, obj):
        with open(inbox(k), "a", encoding="utf-8") as f: f.write(json.dumps({"v": 1, "text": MESH_TAG + json.dumps(obj)}) + "\n")
    lp0 = l_m.loop_drops
    inject(("l", "join-A"), {"t": "presence", "hop": ids["M"], "hubs": [{"origin": ids["L"], "label": "laptop", "age": 0, "path": [ids["L"], ids["M"]], "ttl": 3, "agents": [{"name": "ghost", "age": 0, "state": "up"}]},
                                                                     {"origin": ids["S"], "label": "second", "age": 0, "path": [ids["S"], ids["L"], ids["M"]], "ttl": 3, "agents": []}]})
    rounds(1)
    check(l_m.loop_drops == lp0 + 2 and "ghost@laptop" not in agents(L) and "ghost" not in agents(L), "mesh: presence with own id in path dropped (loop)")
    inject(("l", "join-A"), {"t": "msg", "hop": ids["M"], "id": uuid.uuid4().hex, "src": ids["S"], "srcl": "second", "from": "s-claude", "to": "l-codex",
                             "dst": None, "dstl": None, "ttl": 2, "path": [ids["S"], ids["L"], ids["M"]], "text": "looped"})
    inject(("l", "join-A"), {"t": "msg", "hop": ids["M"], "id": uuid.uuid4().hex, "src": ids["S"], "srcl": "second", "from": "s-claude", "to": "l-codex",
                             "dst": None, "dstl": None, "ttl": 0, "path": [ids["S"], ids["M"]], "text": "expired"})
    rounds(1)
    check(not texts(L, "l-codex"), "mesh: looped and ttl-0 messages dropped")
    write_atomic(M.mesh_path("peers", "00000000000000aa.json"), {"origin": "00000000000000aa", "label": "far", "age": 0, "rx": time.time(),
                 "path": ["00000000000000aa", ids["L"]], "ttl": 1, "via": "laptop", "agents": []})
    snaps = m_s.snapshots(); relayed = {s["origin"]: s for s in snaps}
    check("00000000000000aa" not in relayed and relayed[ids["L"]]["ttl"] == MESH_TTL - 1 and relayed[ids["L"]]["path"] == [ids["L"], ids["M"]],
          "mesh: ttl decremented per hop; ttl-1 snapshot not relayed")
    os.remove(M.mesh_path("peers", "00000000000000aa.json"))
    inject(("l", "join-A"), {"t": "presence", "hop": ids["M"], "hubs": [{"origin": "00000000000000bb", "label": "x\u202e\x1b[2J", "age": "nan?", "path": ["00000000000000bb", ids["M"]], "ttl": 2, "agents": []},
                                                                     {"origin": "00000000000000cc", "label": "evil\u202elabel", "age": 1, "path": ["00000000000000cc", ids["M"]], "ttl": 2,
                                                                      "agents": [{"name": "\x1b[2Jbad", "age": 0}, {"name": "ok-agent", "machine": "M\u2028up  forged", "harness": "\x07h", "age": 0, "state": "up"}]}]})
    with open(inbox(("l", "join-A")), "a", encoding="utf-8") as f: f.write(json.dumps({"v": 1, "text": MESH_TAG + "{not json"}) + "\n")
    rounds(1)
    cc = read_json(L.mesh_path("peers", "00000000000000cc.json")) or {}
    check(not os.path.exists(L.mesh_path("peers", "00000000000000bb.json")) and [a["name"] for a in cc.get("agents", [])] == ["ok-agent"]
          and cc.get("label") == "evil-label" and "\u2028" not in cc["agents"][0]["machine"] and "\x07" not in cc["agents"][0]["harness"],
          "mesh: hostile presence validated (bad age/name dropped, label + fields cleaned)")
    m_l.last_push = 0; rounds(2)   # main's periodic re-push (every MESH_PUSH_S) no longer carries cc: it is forgotten
    check(not os.path.exists(L.mesh_path("peers", "00000000000000cc.json")), "mesh: machine no longer announced is forgotten")
    S.heartbeat("dup", "codex"); L.heartbeat("dup", "claude"); rounds()
    try: resolve(M, "dup"); amb = False
    except ValueError as e: amb = "dup@laptop" in str(e) and "dup@second" in str(e)
    with contextlib.redirect_stdout(buf): cmd_send(M, argparse.Namespace(frm="m-claude", to="dup@second", text="only you", file=None, queue=False))
    rounds()
    check(amb and texts(S, "dup") == [("m-claude@main", "only you")] and not texts(L, "dup"), "mesh: same name on two machines -> must use name@machine")
    L.bye("l-claude"); rounds()
    check("l-claude@laptop" not in agents(M) and "l-claude@laptop" not in agents(S), "mesh: agent leaving laptop disappears on main and second")
    def helper_says(*lines):
        with open(inbox(("m", "helper")), "a", encoding="utf-8") as f:
            for ln in lines: f.write(json.dumps({"v": 1, "text": ln}) + "\n")
    helper_says("@l-codex hello from the helper", "@laptop @l-claude relay this", "WHO?")
    rounds()
    check(not texts(L, "l-codex") and not texts(L, "l-claude") and len(texts(M, "helper-unrouted")) == 2,
          "guard 18b/#1: helper uplink cannot reach another machine or another link by default")
    who_rows = [json.loads(x)["text"] for x in open(helper_log, encoding="utf-8") if x.strip()]
    check(who_rows and "m-claude(" in who_rows[-1] and "@" not in who_rows[-1], "guard 18a: helper's WHO? lists this PC only (no name@machine)")
    helper.transit, helper.share_mesh, helper.last_who = {"laptop"}, True, 0
    helper_says("@l-codex hello from the helper", "@s-claude not you", "WHO?")
    rounds()
    who_rows = [json.loads(x)["text"] for x in open(helper_log, encoding="utf-8") if x.strip()]
    check(texts(L, "l-codex") == [("helper@main", "hello from the helper")] and not texts(S, "s-claude"),
          "mesh+uplink: --transit-to laptop lets the helper reach laptop (and only laptop)")
    check("l-codex@laptop(" in who_rows[-1] and "s-claude@second(" in who_rows[-1] and "m-claude(" in who_rows[-1],
          "mesh+uplink: --share-mesh WHO? lists all machines")
    helper.transit, helper.share_mesh = set(), False
    # 18c: a third link on main tries to take over the laptop's route (claims its hub id, or relays its origin)
    hev, dev = session("m", "evil"); set_link(dev)
    ev = Link(M, "evil", "evil", [sys.executable, fake, os.path.join(root, "evil-out.jsonl"), os.path.join(root, "evil.count")], hev)
    def evil(obj):
        with open(os.path.join(dev, "inbox.jsonl"), "a", encoding="utf-8") as f: f.write(json.dumps({"v": 1, "text": MESH_TAG + json.dumps(obj)}) + "\n")
    evil({"t": "presence", "hop": ids["L"], "hopl": "laptop", "hubs": [{"origin": ids["L"], "label": "laptop", "age": 0, "path": [ids["L"]], "ttl": 4,
          "agents": [{"name": "l-codex", "age": 0, "state": "up"}]}]})
    evil_id = "00000000000000ee"
    evil({"t": "presence", "hop": evil_id, "hopl": "evil", "hubs": [{"origin": ids["L"], "label": "laptop", "age": 0, "path": [ids["L"], evil_id], "ttl": 3,
          "agents": [{"name": "l-codex", "age": 0, "state": "up"}]}]})
    lbuf = io.StringIO()
    with contextlib.redirect_stdout(lbuf): ev.step()
    pl = read_json(M.mesh_path("peers", ids["L"] + ".json")) or {}
    with contextlib.redirect_stdout(buf): cmd_send(M, argparse.Namespace(frm="m-claude", to="l-codex", text="for the real laptop", file=None, queue=False))
    waiting = lambda n: [f for f in os.listdir(M.inbox(n)) if f.endswith(".json")] if os.path.isdir(M.inbox(n)) else []
    check(pl.get("via") == "laptop" and lbuf.getvalue().count("pinned to link laptop") == 2 and len(waiting("laptop")) == 1 and not waiting("evil"),
          "guard 18c: route hijack refused (hub id and origin pinned to link laptop)")
    rounds()
    check(texts(L, "l-codex") == [("m-claude@main", "for the real laptop")], "guard 18c: message still goes to the real laptop")
    ev.close(); M.bye("evil")
    set_link(sess[("m", "laptop")][1], up=False)
    with contextlib.redirect_stdout(buf): m_l.step()
    check(agents(M)["l-codex@laptop"]["state"] == "link-down" and agents(M)["s-claude@second"]["state"] == "up", "mesh: link down -> that machine's agents show link-down")
    with contextlib.redirect_stdout(buf): cmd_send(M, argparse.Namespace(frm="m-claude", to="l-codex", text="held", file=None, queue=False))
    with contextlib.redirect_stdout(buf): m_l.step()
    held = len([f for f in os.listdir(M.inbox("laptop")) if f.endswith(".json")]) == 1
    rounds()
    check(held and texts(L, "l-codex") == [("m-claude@main", "held")], "mesh: message held while link down, delivered after reconnect")
    X = Hub(os.path.join(root, "x")); X.identity("late"); X.heartbeat("x-agent", "codex")
    hx, dx = session("x", "join-X")
    old_rx = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 50))
    with open(os.path.join(dx, "inbox.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"v": 1, "text": "hello", "rx": old_rx}) + "\n")
        f.write(json.dumps({"v": 1, "rx": old_rx, "text": MESH_TAG + json.dumps({"t": "presence", "hop": ids["M"], "hopl": "main", "hubs": [
            {"origin": ids["M"], "label": "main", "age": 0, "path": [ids["M"]], "ttl": 4, "agents": [{"name": "m-claude", "age": 1, "state": "up"}]}]})}) + "\n")
    set_link(dx); lx = Link(X, "join-X", "main", [sys.executable, fake, os.path.join(root, "x-out.jsonl"), count_log], hx)
    with contextlib.redirect_stdout(buf): lx.step()
    xr = agents(X).get("m-claude@main", {})
    check(xr.get("state") == "up" and xr.get("age", 0) >= 50 and not texts(X, "x-agent"),
          "mesh: late-starting link replays waiting hub envelopes (true age kept), skips old chat")
    xin, M_id = os.path.join(dx, "inbox.jsonl"), ids["M"]
    def x_says(*lines):
        with open(xin, "a", encoding="utf-8") as f:
            for ln in lines: f.write(json.dumps({"v": 1, "text": ln}) + "\n")
    def x_step():
        try:
            with contextlib.redirect_stdout(buf): lx.step()
            return True
        except Exception: return False
    hub_m = '"hop":"%s","hopl":"main","hubs":[{"origin":"%s","label":"main","path":["%s"],"ttl":4,' % (M_id, M_id, M_id)
    d0 = lx.dropped
    x_says(MESH_TAG + '{"t":"presence","hop":"%s","x":%s%s}' % (M_id, "[" * 5000, "]" * 5000),
           MESH_TAG + '{"t":"presence",' + hub_m + '"age":Infinity,"agents":[]}]}',
           MESH_TAG + '{"t":"presence",' + hub_m + '"age":0,"agents":[{"name":"m-claude","age":1e999,"state":"up"}]}]}',
           "@x-agent good after bad")
    alive = x_step()
    check(alive and (read_json(lx.off_path) or {}).get("offset") == os.path.getsize(xin) and lx.dropped == d0 + 2
          and texts(X, "x-agent") == [("main", "good after bad")] and agents(X).get("m-claude@main", {}).get("age", 0) >= AGE_MAX,
          "guard (a): 5000-deep envelope, NaN/Infinity and 1e999 ages: no crash, offset advanced, next line delivered")
    x_says("hello everyone, no @name")
    plain_dropped = x_step() and not texts(X, "x-agent") and [t for _, t in texts(X, "main-unrouted")] == ["hello everyone, no @name"]
    lx.default_to = "all"; x_says("hello again, no @name"); x_step(); lx.default_to = None
    check(plain_dropped and texts(X, "x-agent") == [("main", "hello again, no @name")],
          "guard (c): a link delivers far-end text without @name to nobody (kept in <as>-unrouted) unless --plain-to-all")
    lx.rate, lx.spill_files = {}, 3
    x_says(*[MESH_TAG + json.dumps({"t": "msg", "hop": M_id, "id": uuid.uuid4().hex, "src": M_id, "srcl": "main", "from": f"rot{i}",
                                    "to": "x-agent", "dst": None, "dstl": None, "ttl": 2, "path": [M_id], "text": f"rotating {i}"})
             for i in range(RATE_N + 6)])
    x_step(); lx.spill_files = SPILL_FILES
    w = [t for _, t in texts(X, "x-agent")]; thd = os.path.join(X.inbox("x-agent"), "throttled")
    th = os.listdir(thd) if os.path.isdir(thd) else []
    check(len([t for t in w if t.startswith("rotating")]) == RATE_N and sum(t.startswith("HUB-NOTICE") for t in w) == 1 and len(th) == 3,
          "guard (b): the rate key is the link, so rotating from= does not lift the limit; throttled/ is capped (oldest dropped)")
    m_l.close()
    check(ids["L"] not in peer_ids(M) and ids["S"] in peer_ids(M), "mesh: stopping a link forgets only what it brought")

def guard_selftest(check, root):
    """docs/MESH-THREATS.md mitigations, one assertion each: a throwaway hub, a fake tunnel, a fake p2p CLI."""
    import contextlib, io
    buf = io.StringIO(); os.makedirs(root)
    sent_log, fake = os.path.join(root, "sent.log"), os.path.join(root, "fake_p2p.py")
    with open(fake, "w") as f:
        f.write("import sys\na=sys.argv[1:]\nf=a[a.index('--file')+1]\n"
                f"open({sent_log!r},'a',encoding='utf-8').write(open(f,encoding='utf-8').read()+'\\n<<END>>\\n')\n"
                "print('{\"delivered\": true}')\n")
    def sends(): return open(sent_log, encoding="utf-8").read().count("<<END>>") if os.path.exists(sent_log) else 0
    def sent(): return open(sent_log, encoding="utf-8").read() if os.path.exists(sent_log) else ""
    hub = Hub(os.path.join(root, "hub")); hub.heartbeat("win-claude", "claude"); hub.heartbeat("wsl-codex", "codex")
    home, gid = os.path.join(root, "p2p"), uuid.uuid4().hex
    sess = os.path.join(home, "tunnel", "join-G", gid); os.makedirs(sess)
    write_atomic(os.path.join(home, "tunnel", "join-G", "current.json"), {"id": gid})
    def state(**kw): write_atomic(os.path.join(sess, "state.json"), dict({"connected": True, "beat": time.time() * 1000, "peerKey": "AAAA"}, **kw))
    inbox = os.path.join(sess, "inbox.jsonl"); open(inbox, "w").close(); state()
    def add(text, **kw):
        with open(inbox, "a", encoding="utf-8") as f: f.write(json.dumps(dict({"v": 1, "text": text}, **kw), ensure_ascii=False) + "\n")
    up = Uplink(hub, "join-G", "helper", [sys.executable, fake], home)
    def step():
        with contextlib.redirect_stdout(buf): return up.step()
    def got(name): return [m["text"] for m, _ in hub.claim(name)]
    def dies(fn):
        try:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()): fn()
            return False
        except SystemExit: return True
    ns = lambda **kw: argparse.Namespace(**dict({"file": None, "queue": False}, **kw))
    step()
    n0 = sends()
    own = hub.identity()["label"]
    add("@wsl-codex,wsl-codex,wsl-codex,wsl-codex once please"); add(f"@helper,helper,helper@{own} echo me")
    add("@" + ",".join(f"n{i}" for i in range(MAX_TARGETS + 1)) + " too many")
    up.transit = {"*"}; step(); up.transit = set()     # even with transit to everything, never back to itself
    with contextlib.redirect_stdout(buf): cmd_send(hub, ns(frm="win-claude", to="wsl-codex,wsl-codex", text="local once"))
    check(got("wsl-codex") == ["once please", "local once"] and sends() == n0 and len(got("helper-unrouted")) == 2
          and dies(lambda: cmd_send(hub, ns(frm="win-claude", to=",".join(f"n{i}" for i in range(MAX_TARGETS + 1)), text="x"))),
          "guard #2: @a,a,a delivered once, @self never reflected, more than 16 targets refused")
    add("@ghost1,ghost2,future7 planted text"); step()
    check(not any(os.path.isdir(hub.inbox(n)) for n in ("ghost1", "ghost2", "future7", "n0")) and len(got("helper-unrouted")) == 1,
          "guard #11: no inbox planted for names that were never here (one unrouted copy)")
    hub.heartbeat("laptop", "tunnel", remote=True, machine="remote", extra={"link": "up", "session": "s2", "host": "elsewhere"})
    add("@laptop @lap-claude read your notes"); step()
    blocked = not got("laptop") and len(got("helper-unrouted")) == 1
    up.transit = {"laptop"}; add("@laptop @lap-claude now allowed"); step(); up.transit = set()
    check(blocked and got("laptop") == ["@lap-claude now allowed"], "guard #1: a peer reaches another link only with --transit-to")
    check(dies(lambda: hub.check_bridge_name("win-claude", "join-X")) and dies(lambda: hub.check_local_name("helper"))
          and dies(lambda: hub.check_bridge_name("laptop", "join-G")) and not dies(lambda: hub.check_bridge_name("helper", "join-G")),
          "guard #3: link vs local agent names cannot collide; a restart of the same link is allowed")
    hub.bye("laptop")
    add("@wsl-codex " + "x" * (MAX_BYTES + 10)); add("@wsl-codex after the big one")
    with open(inbox, "a", encoding="utf-8") as f: f.write('{"v":1,"text":"@wsl-codex bad \\ud800 surrogate"}\n')
    step()
    try: hub.deliver("wsl-codex", "x", "x" * (MAX_BYTES + 1)); raised = False
    except ValueError: raised = True
    check(raised and got("wsl-codex") == ["after the big one", "bad ? surrogate"],
          "guard #4: oversized row and a lone surrogate are skipped/repaired; deliver raises, never exits; the bridge lives")
    add("@wsl-codex " + "y" * (READ_CAP + 100)); add("@wsl-codex after the huge one"); step(); step()
    check(got("wsl-codex") == ["after the huge one"], "guard #4: a row longer than the 4 MiB read cap is skipped whole (next step)")
    add("@wsl-codex replay me", id="0123456789abcdef"); add("@wsl-codex replay me", id="0123456789abcdef"); step()
    once = got("wsl-codex") == ["replay me"]
    add("@wsl-codex survive a crash", id="00000000000000c1")
    def boom(text, row=None): raise KeyboardInterrupt("simulated stop between read and deliver")
    up.handle = boom
    try: step()
    except KeyboardInterrupt: pass
    del up.handle; step()
    check(once and got("wsl-codex") == ["survive a crash"], "guard #13: a replayed row id is delivered once; a stop before routing loses nothing")
    hub.deliver("helper", "wsl-codex", "z" * (MAX_BYTES - 2)); time.sleep(0.01); hub.deliver("helper", "wsl-codex", "second")
    n0 = sends(); step()
    failed = os.listdir(os.path.join(hub.inbox("helper"), "failed")); w = got("wsl-codex")
    check(sends() == n0 + 1 and "[wsl-codex] second" in sent() and len(failed) == 1 and len(w) == 1 and w[0].startswith("UNDELIVERABLE"),
          "guard #6: a message too big for the tunnel goes to failed/ (sender told) and does not block the next")
    real = up.p2p_cmd
    up.p2p_cmd = [sys.executable, "-c", "import sys; print('p2p tunnel: message exceeds 1 MiB', file=sys.stderr); sys.exit(2)"]
    hub.deliver("helper", "win-claude", "refused for good"); step(); up.p2p_cmd = real
    check(len(os.listdir(os.path.join(hub.inbox("helper"), "failed"))) == 2 and got("win-claude")[0].startswith("UNDELIVERABLE"),
          "guard #6: a permanent tunnel refusal (rc 2) is parked, not retried forever")
    hidden = "ok​\U000e0049\U000e0047\U000e004e⁠﻿؜"
    check(clean(hidden) == "ok" and fmt_msg({"from": "a", "to": "b", "id": "1", "text": hidden}).endswith(":: ok  (7 hidden/control chars removed)"),
          "guard #7: zero-width, BOM, ALM and TAG-block characters stripped, and the reader is told")
    vs = "a" + chr(0xFE0F) + "b" + chr(0xE0100) + "c" + chr(0xFE00) + chr(0xE01EF)
    check(clean(vs) == "abc" and fmt_msg({"from": "a", "to": "b", "id": "1", "text": vs}).endswith(":: abc  (4 hidden/control chars removed)"),
          "guard (d): variation selectors U+FE00-FE0F and U+E0100-E01EF stripped, and the reader is told")
    hub.heartbeat("esc-agent", "\x1b[2J\x1b]0;pwned\x07codex", note="‮evil\x9b[31m")
    msg = {"from": "\x1b]8;;http://x\x07win-admin", "to": "b\x1b[1m", "id": "\x1b[2J", "via": "‮x", "text": "hi"}
    printed = fmt_roster(hub.full_roster()) + fmt_msg(msg) + json.dumps(json_rows(hub.full_roster()), ensure_ascii=False)
    check(not [c for c in printed if (ord(c) < 0x20 and c != "\n") or 0x7f <= ord(c) <= 0x9f or c in "‮⁦‎"],
          "guard #8: every printed field (from/to/id/via, machine/harness/note, who --json) is control/bidi free")
    hub.bye("esc-agent")
    n0 = sends(); state(peerKey="BBBB"); add("@wsl-codex from a stranger"); hub.deliver("helper", "win-claude", "not for strangers")
    link = step()
    row = {r["name"]: r for r in hub.roster()}["helper"]
    held = link == "peer-changed" and row["state"] == "peer-changed" and not got("wsl-codex") and sends() == n0 and "PEER-CHANGED" in buf.getvalue()
    with contextlib.redirect_stdout(buf): main(["--root", hub.root, "unpin", "helper"])
    step()
    check(held and got("wsl-codex") == ["from a stranger"] and "not for strangers" in sent() and up.pins().get("peer") == "BBBB",
          "guard #5/#9: a new tunnel peer key holds the link (nothing in or out) until `hub.py unpin`")
    up.last_roster, up.last_push, up.last_who = up.roster_line(), time.time(), 0
    n0 = sends()
    for _ in range(30): add("WHO?")
    step(); first = sends() - n0
    add("WHO?"); step(); still = sends() - n0
    up.last_who -= WHO_EVERY + 1; step()
    check(first == 1 and still == 1 and sends() - n0 == 2, "guard #10: 30 WHO? -> 1 answer; more within 20 s are folded into one later answer")
    up.rate = {}
    for i in range(RATE_N + 1): add(f"@wsl-codex ping {i}")
    step()
    w = got("wsl-codex"); th = os.listdir(os.path.join(hub.inbox("wsl-codex"), "throttled"))
    check(len([x for x in w if x.startswith("ping")]) == RATE_N and len(th) == 1 and sum(x.startswith("HUB-NOTICE") for x in w) == 1,
          "guard #14: at most 30 a minute per sender and target; the rest wait in throttled/ with one notice")
    for i in range(MAX_ROWS + 5): add(f"@wsl-codex row {i}")
    up.rate = {}; step(); a = len(got("wsl-codex")); up.rate = {}; step(); b = len(got("wsl-codex"))
    check(a == min(MAX_ROWS, RATE_N) + (1 if MAX_ROWS > RATE_N else 0) and b == 5, "guard #4: at most 200 tunnel rows per step; the rest next step")
    got("helper-unrouted"); spill = hub.inbox("helper-unrouted")
    up.spill_files = 5
    for i in range(8): add(f"@ghost{i} spill {i}")
    step(); by_count = sorted(read_json(os.path.join(spill, f))["text"] for f in os.listdir(spill) if f.endswith(".json"))
    up.spill_files, up.spill_bytes = 100, 3000
    for i in range(4): add(f"@ghost{i} " + str(i) * 1000)
    step(); by_bytes = [f for f in os.listdir(spill) if f.endswith(".json")]
    up.spill_files, up.spill_bytes = SPILL_FILES, SPILL_BYTES
    old = time.time() - 8 * 86400; hub.deliver("wsl-codex", "win-claude", "unread, a week old")
    for d in (spill, hub.inbox("wsl-codex")):
        for f in os.listdir(d):
            if f.endswith(".json"): os.utime(os.path.join(d, f), (old, old))
    hub.gc(7)
    check(by_count == [f"@ghost{i} spill {i}" for i in range(3, 8)] and len(by_bytes) == 2
          and not [f for f in os.listdir(spill) if f.endswith(".json")] and got("wsl-codex") == ["unread, a week old"],
          "guard (b): <as>-unrouted keeps the newest files within its file and byte caps; gc sweeps it, never a live inbox")
    if os.name != "nt":
        old = os.umask(0o022)
        try:
            pre = os.path.join(root, "perm"); os.makedirs(pre, mode=0o755); os.chmod(pre, 0o755)
            h2 = Hub(pre); h2.heartbeat("p-agent"); h2.deliver("p-agent", "x", "private")
            modes = [os.stat(h2.root).st_mode & 0o777] + [os.stat(os.path.join(d, f)).st_mode & 0o777 for d, _, fs in os.walk(h2.root) for f in fs]
        finally: os.umask(old)
        check(modes[0] == 0o700 and len(modes) == 3 and all(m == 0o600 for m in modes[1:]), "guard #12: hub folder 0700, files 0600 (POSIX)")

# ---------------------------------------------------------------- main
def main(argv=None):
    p = argparse.ArgumentParser(prog="hub.py", description="local agent presence + message bus (see the file header)")
    p.add_argument("--root", help="hub folder (default: $AGENT_HUB, else the Windows profile's .agent-hub)")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("here"); s.add_argument("me"); s.add_argument("--harness", default=""); s.add_argument("--note", default="")
    s = sub.add_parser("ear"); s.add_argument("me"); s.add_argument("--harness", default=""); s.add_argument("--note", default="")
    s.add_argument("--every", type=float, default=10); s.add_argument("--poll", type=float, default=1); s.add_argument("--once", action="store_true")
    s = sub.add_parser("who"); s.add_argument("--json", action="store_true"); s.add_argument("--all", action="store_true")
    s = sub.add_parser("send"); s.add_argument("to"); s.add_argument("text", nargs="?"); s.add_argument("--from", dest="frm", required=True)
    s.add_argument("--file"); s.add_argument("--queue", action="store_true")
    s = sub.add_parser("read"); s.add_argument("me"); s.add_argument("-v", "--verbose", action="store_true")
    s = sub.add_parser("bye"); s.add_argument("me")
    s = sub.add_parser("gc"); s.add_argument("--days", type=float, default=7)
    s = sub.add_parser("uplink"); s.add_argument("--session", required=True); s.add_argument("--as", dest="as_name", required=True)
    s.add_argument("--p2p", help="p2p command line (default: the installed launcher)"); s.add_argument("--p2p-home")
    s.add_argument("--default-to", default="all"); s.add_argument("--from-start", action="store_true")
    s.add_argument("--transit-to", default="", help="other links / machine labels the far side may reach (comma list, * = all; default none)")
    s.add_argument("--share-mesh", action="store_true", help="WHO?/PRESENCE also list agents on your other linked machines")
    s.add_argument("--wsl-interop", action="store_true", help="run inside WSL against the WINDOWS p2p install")
    s.add_argument("--poll", type=float, default=2); s.add_argument("--once", action="store_true")
    s = sub.add_parser("link", help="link this hub to another of your hubs over one tunnel session")
    s.add_argument("--session", required=True); s.add_argument("--as", dest="as_name", required=True)
    s.add_argument("--label", help="this machine's name in other hubs' `who` (default: host name; remembered)")
    s.add_argument("--ttl", type=int, default=MESH_TTL, help=f"max links a message or presence crosses (1-{MESH_MAX_TTL})")
    s.add_argument("--p2p", help="p2p command line (default: the installed launcher)"); s.add_argument("--p2p-home")
    s.add_argument("--from-start", action="store_true")
    s.add_argument("--transit-to", default="", help="other links on THIS hub the far machine may write to (default none)")
    s.add_argument("--plain-to-all", action="store_true",
                   help="far-end text without @name goes to every local agent that is up (default: to nobody; "
                        "it waits in inbox/<as>-unrouted)")
    s.add_argument("--wsl-interop", action="store_true", help="run inside WSL against the WINDOWS p2p install")
    s.add_argument("--poll", type=float, default=2); s.add_argument("--once", action="store_true")
    s = sub.add_parser("unpin", help="forget the far end a link or uplink pinned (trust the next one on first use)")
    s.add_argument("name")
    sub.add_parser("selftest")
    a = p.parse_args(argv)
    if a.cmd == "selftest": return selftest()
    if not a.cmd: p.print_help(); return 2
    hub = Hub(a.root or default_root())
    if a.cmd == "here":
        r = hub.heartbeat(hub.check_local_name(check_name(a.me)), a.harness, a.note); out(f"here {r['name']} on {r['machine']} ({hub.root})"); return 0
    if a.cmd == "ear": return cmd_ear(hub, a)
    if a.cmd == "who":
        rows = hub.full_roster(include_old=a.all)
        out(json.dumps(json_rows(rows), ensure_ascii=False) if a.json else fmt_roster(rows)); return 0
    if a.cmd == "send": return cmd_send(hub, a)
    if a.cmd == "read": return cmd_read(hub, a)
    if a.cmd == "bye": hub.bye(check_name(a.me)); out(f"bye {a.me}"); return 0
    if a.cmd == "gc": out(f"removed {hub.gc(a.days)} old message files"); return 0
    if a.cmd == "uplink": return cmd_uplink(hub, a)
    if a.cmd == "link": return cmd_link(hub, a)
    if a.cmd == "unpin":
        pin = os.path.join(hub.root, "uplinks", check_name(a.name) + ".pin.json")
        old = read_json(pin)
        try: os.remove(pin)
        except FileNotFoundError: out(f"{a.name}: nothing pinned"); return 0
        out(f"unpinned {a.name} (was {one_line(json.dumps(old), 200)}); its next far end is trusted on first use"); return 0
    return 2

if __name__ == "__main__":
    sys.exit(main())
