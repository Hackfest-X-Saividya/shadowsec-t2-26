"""Process sandbox: runs ONE sample-app function against ONE prewritten attack.

Fake in-memory data only, no network. Invoked by engine.run_in_sandbox() as
`python -I sandbox_runner.py` with a JSON request on stdin. Never point this at
uploaded code: the engine only passes it the project's own sample app.
"""
import hashlib
import json
import resource
import socket
import sqlite3
import sys


def _deny(*args, **kwargs):
    raise OSError("network disabled in sandbox")


socket.socket = _deny
socket.create_connection = _deny
socket.getaddrinfo = _deny
for _lim, _val in ((resource.RLIMIT_CPU, 4), (resource.RLIMIT_AS, 1 << 30)):
    try:
        resource.setrlimit(_lim, (_val, _val))
    except Exception:
        pass

req = json.loads(sys.stdin.read())
USERS = req["users"]
FLAG = "FLAG{demo}"
KIND = req["attack"]
PAYLOAD = req["payload"]
NAME = req["function"]
steps = []


def log(kind, msg):
    steps.append({"kind": kind, "msg": msg})


def finish(vulnerable, banner, leaked_ids=(), response=""):
    out = {
        "mode": "Real execution",
        "vulnerable": vulnerable,
        "banner": banner,
        "steps": steps,
        "users": USERS,
        "leaked_ids": list(leaked_ids),
        "response": response,
    }
    print("@@RESULT@@" + json.dumps(out))
    sys.exit(0)


db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
db.executemany("INSERT INTO users VALUES (?,?,?)", [(u["id"], u["username"], u["email"]) for u in USERS])

log("info", "Sandbox ready: in-memory SQLite, 5 fake users, planted secret FLAG{demo}, no network")

ns = {"__name__": "target"}
try:
    exec(compile(req["code"], "<target>", "exec"), ns)
    fn = ns[NAME]
except Exception as e:
    log("bad", f"could not load target function: {e!r}")
    finish(False, "SANDBOX ERROR: target could not be loaded")
ns["SESSIONS"] = {"tok-valid-123": "admin"}
log("info", f"Loaded {NAME}() from the app into the mock app")

try:
    if KIND in ("sqli_sanitizer", "sqli_validator"):
        def search(term):
            if KIND == "sqli_validator":
                ok = fn(term)
                log("app", f"{NAME}({term!r}) -> {ok!r}")
                if not ok:
                    return 400, []
                clean = term
            else:
                clean = fn(term)
                log("app", f"{NAME}({term!r}) -> {clean!r}")
            sql = f"SELECT id, username, email FROM users WHERE username = '{clean}'"
            log("app", "SQL: " + sql)
            try:
                rows = db.execute(sql).fetchall()
            except sqlite3.Error as e:
                log("app", f"database error: {e}")
                return 500, []
            return 200, rows

        log("attacker", "Baseline request: GET /search?user=alice")
        status, rows = search("alice")
        log("app", f"HTTP {status}, {len(rows)} row(s)")
        log("attacker", f"Attack request: GET /search?user={PAYLOAD}")
        status, rows = search(PAYLOAD)
        leaked = [r for r in rows if r[1] != PAYLOAD]
        log("app", f"HTTP {status}, {len(rows)} row(s) returned")
        if leaked:
            log("bad", f"{len(leaked)} rows came back that do not match the search")
            finish(True, f"VULNERABLE: {len(leaked)} fake user records exposed",
                   [r[0] for r in leaked], f"HTTP {status}, {len(leaked)} leaked rows")
        log("ok", "No rows leaked: input was rejected or neutralised")
        finish(False, "BLOCKED: the same attack leaked 0 records", [], f"HTTP {status}, 0 leaked rows")

    elif KIND == "fake_auth":
        def admin(token):
            ok = fn(token)
            log("app", f"{NAME}({token!r}) -> {ok!r}")
            return (200, {"secret": FLAG}) if ok else (401, {"error": "unauthorized"})

        log("attacker", "Baseline request: GET /admin with the real session token")
        status, _ = admin("tok-valid-123")
        log("app", f"HTTP {status}")
        log("attacker", f"Attack request: GET /admin with forged token {PAYLOAD!r}")
        status, body = admin(PAYLOAD)
        log("app", f"HTTP {status} {json.dumps(body)}")
        if status == 200:
            log("bad", "Forged token accepted, secret returned")
            finish(True, "VULNERABLE: admin endpoint opened with a forged token, FLAG{demo} exposed",
                   [], f"HTTP 200 {json.dumps(body)}")
        log("ok", "Forged token rejected")
        finish(False, "BLOCKED: forged token rejected", [], "HTTP 401")

    elif KIND == "weak_hash":
        log("attacker", f"Hash {PAYLOAD!r} twice and compare against a rainbow table")
        h1, h2 = str(fn(PAYLOAD)), str(fn(PAYLOAD))
        b = PAYLOAD.encode()
        table = {"md5": hashlib.md5(b).hexdigest(), "sha1": hashlib.sha1(b).hexdigest(),
                 "sha256": hashlib.sha256(b).hexdigest()}
        match = [k for k, v in table.items() if v == h1]
        log("app", f"{NAME}() -> {h1[:32]}...")
        log("app", "second call: " + ("identical hash, so no salt" if h1 == h2 else "different hash, so it is salted"))
        log("attacker", "rainbow-table lookup: " + (("match on " + ", ".join(match)) if match else "no match"))
        if match or h1 == h2:
            log("bad", "Hash is fast and unsalted: precomputed tables crack it instantly")
            finish(True, "VULNERABLE: password hash is unsalted and matches a rainbow table",
                   [], f"{h1[:24]}... matches {match or 'repeat-hash check'}")
        log("ok", "Salted, slow hash: lookup fails")
        finish(False, "BLOCKED: salted slow hash defeats the rainbow table", [], f"{h1[:24]}...")

    else:
        log("bad", f"unknown attack {KIND}")
        finish(False, "SANDBOX ERROR: unknown attack")
except SystemExit:
    raise
except Exception as e:
    log("bad", f"target raised {e!r}")
    finish(False, "SANDBOX ERROR: target crashed during the attack")
