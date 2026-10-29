"""End-to-end check: scan, attack, fix, re-attack, trust score."""
from engine import Session

s = Session()
scan = s.scan()
names = {f["function"]: f for f in scan["findings"]}
print("findings:", {n: (f["severity"], f["lie_score"]) for n, f in names.items()})
print("honest:", [h["name"] for h in scan["honest"]])
print("trust before:", scan["trust"])

assert set(names) == {"sanitize_input", "clean_query", "validate_username", "verify_token", "hash_password"}
assert {h["name"] for h in scan["honest"]} == {"escape_html", "sanitize_filename", "validate_age", "verify_signature"}
from engine import cvss31
assert cvss31("N", "L", "N", "N", "H", "H", "H") == 9.8       # known CVSS 3.1 reference vectors
assert cvss31("N", "L", "N", "N", "H", "N", "N") == 7.5
got = {n: (f["cvss_score"], f["severity"], f["priority"]) for n, f in names.items()}
assert got["sanitize_input"][:2] == (9.1, "Critical")         # SQLi, input reaches it: AV:N
assert got["validate_username"][:2] == (9.1, "Critical")
assert got["verify_token"][:2] == (9.8, "Critical")           # auth bypass
assert got["clean_query"][:2] == (7.7, "High")                # not reachable: AV:L
assert got["hash_password"][:2] == (5.9, "Medium")            # AC:H, confidentiality only
assert all(f["epss"] is None and f["priority"] in ("P2", "P3") for f in names.values())  # not yet attacked

for name in names:
    res = s.simulate(name)
    assert res["vulnerable"], (name, res["steps"])
    pr = next(f for f in s.scan()["findings"] if f["id"] == name)["priority"]
    assert pr == ("P2" if name == "hash_password" else "P1"), (name, pr)   # proven exploit raises priority
    print(f"[attack ] {name}: {res['banner']}")
    fix = s.apply_fix(name)
    assert fix["status"] == "Verified", (name, fix)
    assert next(f for f in s.scan()["findings"] if f["id"] == name)["priority"] == "Closed"
    print(f"[re-run ] {name}: {fix['result']['banner']}")

final = s.scan()
print("trust after:", final["trust"], "counts:", final["counts"])
assert final["trust"]["after"] == 100.0 and final["counts"]["Verified"] == 5
assert s.apply_fix("clean_query")["error"]
print("ALL CHECKS PASSED")
