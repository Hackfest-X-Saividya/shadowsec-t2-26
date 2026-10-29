"""Zday Protocol, MVP core.

Pipeline: extract functions -> judge claim vs reality -> classify (CVSS 3.1 severity,
EPSS where a CVE exists, priority, OWASP, reachability) -> attack in the sandbox -> patch -> attack again -> Verified.

The judge here is a deterministic AST judge so the demo runs offline. It returns the
same {claim, reality, mismatch, lie_score, reason} shape an LLM judge would, so an LLM
call can replace judge() later without touching anything else.
"""
import ast
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "sample_app" / "vulnerable.py"
RUNNER = ROOT / "sandbox_runner.py"
TARGET_LABEL = "sample_app/vulnerable.py"

USERS = [
    {"id": 1, "username": "alice", "email": "alice@example.test"},
    {"id": 2, "username": "bob", "email": "bob@example.test"},
    {"id": 3, "username": "carol", "email": "carol@example.test"},
    {"id": 4, "username": "dave", "email": "dave@example.test"},
    {"id": 5, "username": "erin", "email": "erin@example.test"},
]

KEYWORDS = ("sanitize", "clean", "escape", "validate", "verify", "auth", "hash", "encrypt")
LEVELS = ["Low", "Medium", "High", "Critical"]

ATTACKS = {
    "sqli_sanitizer": {
        "label": "SQL injection", "payload": "' OR '1'='1", "owasp": "A03:2021 Injection",
        "fix": "Allow-list the input (or use parameterised queries) instead of passing it through unchanged.",
    },
    "sqli_validator": {
        "label": "SQL injection through a validator that accepts everything", "payload": "' OR '1'='1",
        "owasp": "A03:2021 Injection",
        "fix": "Validate against a strict allow-list pattern and reject anything else.",
    },
    "fake_auth": {
        "label": "Forged session token", "payload": "forged-token-xyz", "owasp": "A07:2021 Identification and Authentication Failures",
        "fix": "Compare the token against stored sessions or a signature, using a constant-time comparison.",
    },
    "weak_hash": {
        "label": "Rainbow-table lookup", "payload": "hunter2", "owasp": "A02:2021 Cryptographic Failures",
        "fix": "Use a salted, slow password hash such as PBKDF2, scrypt, bcrypt or Argon2.",
    },
}
KIND_OF = {"sanitizer": "sqli_sanitizer", "validator": "sqli_validator", "auth": "fake_auth", "crypto": "weak_hash"}

# Prewritten patches (also the offline fallback if a live LLM patch fails).
PATCHES = {
    "sanitizer": r'''def __NAME__(__ARGS__):
    """Allow-list sanitizer: keeps letters, digits, whitespace and @ . _ - only."""
    return re.sub(r"[^\w\s@.\-]", "", str(__P__))
''',
    "validator": r'''def __NAME__(__ARGS__):
    """Accepts only 1-32 letters, digits, dots, dashes and underscores."""
    return isinstance(__P__, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", __P__) is not None
''',
    "auth": r'''def __NAME__(__ARGS__):
    """Accepts the token only if it matches an active session (constant-time compare)."""
    return isinstance(__P__, str) and any(hmac.compare_digest(__P__, t) for t in SESSIONS)
''',
    "crypto": r'''def __NAME__(__ARGS__):
    """Salted PBKDF2-HMAC-SHA256 password hash (200k iterations)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", str(__P__).encode(), salt, 200_000)
    return salt.hex() + "$" + dk.hex()
''',
}


# ------------------------------------------------------------------ extraction

def extract_functions(source):
    tree = ast.parse(source)
    lines = source.splitlines()
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            comment, i = [], node.lineno - 2
            while i >= 0 and lines[i].strip().startswith("#"):
                comment.insert(0, lines[i].strip().lstrip("#").strip())
                i -= 1
            out.append({
                "name": node.name, "line": node.lineno, "end": node.end_lineno,
                "params": [a.arg for a in node.args.args],
                "doc": ast.get_docstring(node) or "", "comment": " ".join(comment), "node": node,
            })
    return sorted(out, key=lambda f: f["line"])


def claiming(funcs):
    return [f for f in funcs
            if not f["name"].startswith("handle_") and any(k in f["name"].lower() for k in KEYWORDS)]


def category(name):
    n = name.lower()
    if "hash" in n or "encrypt" in n:
        return "crypto"
    if "sanitize" in n or "clean" in n or "escape" in n:
        return "sanitizer"
    if "validate" in n:
        return "validator"
    return "auth"


# ----------------------------------------------------------------------- judge

SANITIZING = {"replace", "sub", "escape", "quote", "quote_plus", "translate", "basename", "fullmatch", "match"}
SLOW_KDF = {"pbkdf2_hmac", "scrypt", "hashpw", "argon2", "bcrypt", "argon2id"}
WEAK_HASH = {"md5", "sha1"}
B64 = {"b64encode", "encodebytes", "urlsafe_b64encode"}


def judge(fn):
    """Does this function do what its name and comment claim?"""
    node, cat, params = fn["node"], category(fn["name"]), set(fn["params"])
    calls = {ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
    tails = {c.split(".")[-1] for c in calls}
    rets = [n.value for n in ast.walk(node) if isinstance(n, ast.Return) and n.value is not None]
    has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(node))
    compares = [n for n in ast.walk(node) if isinstance(n, ast.Compare)]
    claim = fn["doc"] or fn["comment"] or f"{fn['name']}() implies a security {cat} step"

    def verdict(score, reality):
        mismatch = score >= 50
        return {
            "claim": claim, "reality": reality, "mismatch": mismatch, "lie_score": score,
            "reason": f"Claims: {claim} Reality: {reality}" if mismatch else "Behaviour matches the claim.",
        }

    if cat == "sanitizer":
        if rets and all(isinstance(r, ast.Name) and r.id in params for r in rets):
            return verdict(95, "Returns its input unchanged. Nothing is removed or escaped.")
        if not (tails & SANITIZING) and not has_raise:
            return verdict(80, "Only makes cosmetic changes (" + ", ".join(sorted(tails)) +
                           "). Quotes and other dangerous characters survive.")
        return verdict(5, "Transforms or escapes the input (" + ", ".join(sorted(tails & SANITIZING)) + ").")

    if cat == "validator":
        all_true = bool(rets) and all(isinstance(r, ast.Constant) and r.value is True for r in rets)
        if all_true and not has_raise:
            return verdict(92, "Always returns True. It never checks the input.")
        if not (has_raise or compares or tails & {"fullmatch", "match", "isinstance", "isalnum", "isdigit"}):
            return verdict(75, "Returns without checking the input against any rule.")
        return verdict(8, "Checks the input against explicit rules.")

    if cat == "auth":
        strong = bool(tails & {"compare_digest", "decode", "verify", "checkpw", "check_password_hash"})
        for c in compares:
            for op, cmp in zip(c.ops, c.comparators):
                if isinstance(op, ast.In):
                    strong = True
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(cmp, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                    strong = True
        if not strong:
            return verdict(90, "Accepts any non-empty token. It is never compared with a stored session or signature.")
        return verdict(6, "Compares the credential against a trusted value.")

    # crypto
    if tails & SLOW_KDF:
        return verdict(4, "Uses a slow, salted key-derivation function.")
    if tails & WEAK_HASH:
        return verdict(80, "Uses MD5/SHA-1, a fast unsalted hash that precomputed tables crack instantly.")
    if tails & B64:
        return verdict(90, "Base64 is encoding, not encryption. Anyone can reverse it.")
    if rets and all(isinstance(r, ast.Name) and r.id in params for r in rets):
        return verdict(98, "Returns its input unchanged.")
    if "password" in fn["name"].lower() and tails & {"sha256", "sha512"}:
        return verdict(60, "Uses a fast unsalted hash for passwords.")
    return verdict(8, "No weakness found by the rules.")


def reachability(source, target):
    """Does request data (handle_* parameters) flow into a call of target?"""
    hits = []
    for h in ast.walk(ast.parse(source)):
        if isinstance(h, ast.FunctionDef) and h.name.startswith("handle_"):
            tainted = {a.arg for a in h.args.args}
            for _ in range(3):
                for n in ast.walk(h):
                    if isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id in tainted for x in ast.walk(n.value)):
                        tainted.update(t.id for t in n.targets if isinstance(t, ast.Name))
            for n in ast.walk(h):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == target:
                    used = [x.id for a in n.args for x in ast.walk(a) if isinstance(x, ast.Name) and x.id in tainted]
                    if used:
                        hits.append(f"user input '{used[0]}' enters {h.name}() and reaches {target}()")
    return hits


# CVSS v3.1 base metrics per vulnerability type (scope unchanged). The attack vector comes from the
# reachability check: user input reaches the flaw -> Network, otherwise -> Local.
CVSS_METRICS = {
    "sqli_sanitizer": dict(ac="L", pr="N", ui="N", c="H", i="H", a="N"),
    "sqli_validator": dict(ac="L", pr="N", ui="N", c="H", i="H", a="N"),
    "fake_auth": dict(ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "weak_hash": dict(ac="H", pr="N", ui="N", c="H", i="N", a="N"),
}
_W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_W_AC = {"L": 0.77, "H": 0.44}
_W_PR = {"N": 0.85, "L": 0.62, "H": 0.27}
_W_UI = {"N": 0.85, "R": 0.62}
_W_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Function name -> CVE id. Empty for new findings (they have no CVE). Fill it for known issues
# such as a vulnerable dependency, and the dashboard fetches the real EPSS from FIRST.
CVE_MAP = {}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss31(av, ac, pr, ui, c, i, a):
    """CVSS v3.1 base score, scope unchanged."""
    iss = 1 - (1 - _W_CIA[c]) * (1 - _W_CIA[i]) * (1 - _W_CIA[a])
    impact = 6.42 * iss
    expl = 8.22 * _W_AV[av] * _W_AC[ac] * _W_PR[pr] * _W_UI[ui]
    return 0.0 if impact <= 0 else _roundup(min(impact + expl, 10))


def cvss_band(score):
    return "None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


def cvss_for(kind, reachable):
    m, av = CVSS_METRICS[kind], ("N" if reachable else "L")
    score = cvss31(av, m["ac"], m["pr"], m["ui"], m["c"], m["i"], m["a"])
    vector = (f"CVSS:3.1/AV:{av}/AC:{m['ac']}/PR:{m['pr']}/UI:{m['ui']}/S:U/"
              f"C:{m['c']}/I:{m['i']}/A:{m['a']}")
    return {"score": score, "band": cvss_band(score), "vector": vector}


def epss_lookup(cve, timeout=5):
    """Real EPSS from FIRST's public API. Only defined for published CVEs."""
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.first.org/data/v1/epss?cve=" + cve, timeout=timeout) as r:
            d = json.load(r)["data"]
        if d:
            return {"cve": cve, "epss": float(d[0]["epss"]), "percentile": float(d[0]["percentile"]), "date": d[0]["date"]}
    except Exception:
        return None
    return None


def likelihood_text(epss, exploit, status):
    if epss:
        return f"EPSS {epss['epss'] * 100:.1f}% ({epss['cve']})"
    if exploit == "confirmed":
        return "Exploit proven in sandbox" + (" (now blocked)" if status == "Verified" else "")
    if exploit.startswith("unconfirmed"):
        return "Not reproduced (AI-suspected)"
    return "Not tested. No CVE, so no EPSS."


def priority(band, epss, exploit, status):
    """Triage rule: CVSS says how bad, exploit likelihood says how soon.
    Likely = EPSS >= 10% when a CVE exists, otherwise exploit proven in the sandbox."""
    if status == "Verified":
        return "Closed"
    likely = bool(epss and epss["epss"] >= 0.10) or exploit == "confirmed"
    severe = band in ("Critical", "High")
    if severe and likely:
        return "P1"
    if severe or (band == "Medium" and likely):
        return "P2"
    return "P3"


# --------------------------------------------------------------------- sandbox

def _sandbox_error(msg):
    return {"mode": "Real execution", "vulnerable": False, "banner": "SANDBOX ERROR: " + msg,
            "steps": [{"kind": "bad", "msg": msg}], "users": USERS, "leaked_ids": [], "response": ""}


SANDBOX_IMAGE = os.environ.get("LD_SANDBOX_IMAGE", "zday-protocol-sandbox:latest")
DOCKER_STARTUP_GRACE = 7  # seconds allowed on top of the run timeout for the container to start
DOCKER_LIMITS = [  # every run: no network, read-only root, no capabilities, no root user, hard resource caps
    "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "64", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
    "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--env", "PYTHONDONTWRITEBYTECODE=1",
]


def sandbox_backend():
    """'process' (default, local subprocess) or 'docker' (one throwaway container per run). Set LD_SANDBOX."""
    b = os.environ.get("LD_SANDBOX", "process").strip().lower()
    if b not in ("process", "docker"):
        raise SystemExit(f"LD_SANDBOX must be 'process' or 'docker', got {b!r}")
    return b


def check_docker():
    """Return None if the Docker backend is usable, else a message saying what to fix. Used to fail fast at startup."""
    docker = shutil.which("docker")
    if not docker:
        return "docker CLI not found on PATH"
    try:
        p = subprocess.run([docker, "image", "inspect", SANDBOX_IMAGE], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"cannot talk to the docker daemon: {e}"
    if p.returncode:
        return (f"sandbox image {SANDBOX_IMAGE!r} not found (or daemon unreachable). "
                f"Build it with: docker build -f Dockerfile.sandbox -t {SANDBOX_IMAGE} .")
    return None


def _parse_result(p, payload, label):
    for line in reversed(p.stdout.splitlines()):
        if line.startswith("@@RESULT@@"):
            res = json.loads(line[len("@@RESULT@@"):])
            res["payload"] = payload
            res["mode"] = label
            return res
    return _sandbox_error("sandbox produced no result: " + (p.stderr.strip().splitlines() or ["no output"])[-1])


def _run_process(req, payload, timeout):
    with tempfile.TemporaryDirectory() as tmp:
        try:
            p = subprocess.run([sys.executable, "-I", str(RUNNER)], input=req, capture_output=True,
                               text=True, timeout=timeout, cwd=tmp, env={"PATH": "/usr/bin:/bin"})
        except subprocess.TimeoutExpired:
            return _sandbox_error("target exceeded the time limit")
    return _parse_result(p, payload, "Real execution")


def _run_docker(req, payload, timeout):
    docker = shutil.which("docker")
    if not docker:
        return _sandbox_error("docker CLI not found on PATH")
    name = "ld-sbx-" + uuid.uuid4().hex[:12]
    cmd = [docker, "run", "--rm", "-i", "--pull", "never", "--name", name, *DOCKER_LIMITS, SANDBOX_IMAGE]
    try:
        p = subprocess.run(cmd, input=req, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout + DOCKER_STARTUP_GRACE)  # utf-8 explicitly: Windows defaults to cp1252
    except subprocess.TimeoutExpired:
        subprocess.run([docker, "kill", name], capture_output=True, timeout=15)  # killing the CLI would leave it running
        return _sandbox_error("target exceeded the time limit (container killed)")
    except OSError as e:
        return _sandbox_error(f"could not start docker: {e}")
    return _parse_result(p, payload, "Real execution (Docker container: no network, read-only filesystem)")


def run_in_sandbox(code, function, attack, payload, timeout=8):
    """The single execution seam: local subprocess, or a throwaway Docker container when LD_SANDBOX=docker.
    Both run the same sandbox_runner.py and return the same result shape, so callers don't change."""
    req = json.dumps({"code": code, "function": function, "attack": attack, "payload": payload, "users": USERS})
    if sandbox_backend() == "docker":
        return _run_docker(req, payload, timeout)
    return _run_process(req, payload, timeout)


# --------------------------------------------------------------------- session

def replace_function(source, fn, new_src):
    lines = source.splitlines()
    return "\n".join(lines[: fn["line"] - 1] + new_src.rstrip("\n").splitlines() + lines[fn["end"]:]) + "\n"


class Session:
    def __init__(self):
        self.reset()

    def reset(self):
        self.source = SAMPLE.read_text()
        self.patched, self.status, self.exploit, self.patches = set(), {}, {}, {}
        self.cve_map, self._epss_cache = dict(CVE_MAP), {}
        self.base = {}
        for f in claiming(extract_functions(self.source)):
            j, cat = judge(f), category(f["name"])
            self.base[f["name"]] = {
                "line": f["line"], "judge": j, "cat": cat, "kind": KIND_OF[cat],
                "reach": reachability(self.source, f["name"]),
            }
        self.trust_before = self._trust_pct(self._current())

    def _current(self):
        return {f["name"]: judge(f) for f in claiming(extract_functions(self.source))}

    def _epss(self, name):
        cve = self.cve_map.get(name)
        if not cve:
            return None
        if cve not in self._epss_cache:
            self._epss_cache[cve] = epss_lookup(cve)
        return self._epss_cache[cve]

    @staticmethod
    def _trust_pct(cur):
        honest = sum(1 for j in cur.values() if not j["mismatch"])
        return round(100.0 * honest / len(cur), 1) if cur else 100.0

    def scan(self):
        cur = self._current()
        findings, honest = [], []
        for name, b in self.base.items():
            if not b["judge"]["mismatch"]:
                honest.append({"name": name, "line": b["line"], "claim": cur[name]["claim"],
                               "reality": cur[name]["reality"], "lie_score": cur[name]["lie_score"]})
                continue
            kind, atk = b["kind"], ATTACKS[b["kind"]]
            cv = cvss_for(kind, bool(b["reach"]))
            ep = self._epss(name)
            exploit, status = self.exploit.get(name, "not tested"), self.status.get(name, "Open")
            findings.append({
                "id": name, "file": TARGET_LABEL, "function": name, "line": b["line"],
                "claim": b["judge"]["claim"], "reality": b["judge"]["reality"], "mismatch": True,
                "lie_score": b["judge"]["lie_score"], "current_lie_score": cur[name]["lie_score"],
                "reason": b["judge"]["reason"], "severity": cv["band"],
                "cvss_score": cv["score"], "cvss_vector": cv["vector"], "epss": ep,
                "owasp": atk["owasp"], "attack": atk["label"],
                "payload": atk["payload"], "reachable": bool(b["reach"]),
                "evidence": b["reach"] or ["No request handler passes user input to this function."],
                "exploit": exploit, "status": status,
                "exploit_likelihood": likelihood_text(ep, exploit, status),
                "priority": priority(cv["band"], ep, exploit, status),
                "mode": "Real execution (Python" + (", in Docker)" if sandbox_backend() == "docker" else ")"), "recommended_fix": atk["fix"],
                "patch": self.patches.get(name),
            })
        findings.sort(key=lambda f: (-f["cvss_score"], -f["lie_score"]))
        counts = {s: sum(1 for f in findings if f["status"] == s) for s in ("Open", "Fixed", "Verified")}
        return {
            "target": TARGET_LABEL, "findings": findings, "honest": honest, "counts": counts, "users": USERS,
            "trust": {"before": self.trust_before, "after": self._trust_pct(cur),
                      "honest": sum(1 for j in cur.values() if not j["mismatch"]), "total": len(cur)},
        }

    def simulate(self, name):
        b = self.base.get(name)
        if not b or not b["judge"]["mismatch"]:
            return {"error": "unknown finding"}
        atk = ATTACKS[b["kind"]]
        res = run_in_sandbox(self.source, name, b["kind"], atk["payload"])
        if name not in self.patched:
            self.exploit[name] = "confirmed" if res["vulnerable"] else "unconfirmed (AI-suspected)"
        return res

    def apply_fix(self, name):
        b = self.base.get(name)
        if not b or not b["judge"]["mismatch"]:
            return {"error": "unknown finding"}
        if self.exploit.get(name) != "confirmed":
            return {"error": "Run Simulate Attack first: a fix is only applied to a confirmed exploit."}
        if name in self.patched:
            return {"error": "Already patched."}
        fn = next(f for f in extract_functions(self.source) if f["name"] == name)
        patch = (PATCHES[b["cat"]].replace("__NAME__", name)
                 .replace("__ARGS__", ast.unparse(fn["node"].args)).replace("__P__", fn["params"][0]))
        self.source = replace_function(self.source, fn, patch)
        self.patched.add(name)
        self.patches[name] = patch
        self.status[name] = "Fixed"
        res = run_in_sandbox(self.source, name, b["kind"], ATTACKS[b["kind"]]["payload"])
        if not res["vulnerable"]:
            self.status[name] = "Verified"
        return {"result": res, "status": self.status[name], "patch": patch, "needs_review": res["vulnerable"]}

    def report(self):
        s = self.scan()
        return {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "target": s["target"],
            "repo_trust_score": s["trust"], "status_counts": s["counts"],
            "findings": [{k: f[k] for k in ("id", "file", "function", "line", "claim", "reality", "lie_score",
                                             "severity", "cvss_score", "cvss_vector", "epss", "exploit_likelihood", "priority", "owasp", "evidence", "exploit", "status", "mode",
                                             "recommended_fix")} for f in s["findings"]],
        }


def report_html(session):
    r, e = session.report(), html.escape
    rows = "".join(
        f"<tr><td><b>{e(f['function'])}</b><br><small>{e(f['file'])}:{f['line']}</small></td>"
        f"<td>{e(f['claim'])}</td><td>{e(f['reality'])}</td><td>{f['lie_score']}</td>"
        f"<td>{f['cvss_score']} {e(f['severity'])}<br><small>{e(f['cvss_vector'])}</small></td><td>{e(f['owasp'])}</td><td>{e(f['exploit_likelihood'])}</td><td>{e(f['priority'])}</td>"
        f"<td>{e(f['status'])}</td><td>{e(f['recommended_fix'])}</td></tr>" for f in r["findings"])
    t = r["repo_trust_score"]
    return f"""<!doctype html><meta charset=utf-8><title>Zday Protocol report</title>
<style>body{{font:14px system-ui;margin:2rem;color:#111}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}}th{{background:#f3f3f3}}</style>
<h1>Zday Protocol: report</h1><p>{e(r['target'])} &middot; {e(r['generated'])}</p>
<p><b>Repo Trust Score:</b> {t['before']}% before fixes, {t['after']}% now
({t['honest']} of {t['total']} security-claiming functions do what they claim).</p>
<p>Open: {r['status_counts']['Open']} &middot; Fixed: {r['status_counts']['Fixed']} &middot; Verified: {r['status_counts']['Verified']}</p>
<table><tr><th>Function</th><th>Claim</th><th>Reality</th><th>Lie Score</th><th>CVSS 3.1</th><th>OWASP</th><th>Exploit likelihood</th><th>Priority</th><th>Status</th><th>Recommended fix</th></tr>{rows}</table>"""
