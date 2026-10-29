"""Tests the Docker sandbox backend WITHOUT needing Docker: a stand-in `docker` command on PATH checks that every
hardening flag is passed, then runs the same sandbox_runner.py locally. Real Docker is covered by `make docker-test`."""
import os, stat, sys, tempfile, textwrap, time
from pathlib import Path

tmp = Path(tempfile.mkdtemp())
LOG = tmp / "calls.log"
RUNNER = Path(__file__).resolve().parent / "sandbox_runner.py"
shim = tmp / "docker"
shim.write_text(textwrap.dedent(f"""\
    #!{sys.executable}
    import os, subprocess, sys, time
    a = sys.argv[1:]
    open({str(LOG)!r}, "a").write(" ".join(a) + "\\n")
    if a[:2] == ["image", "inspect"]:
        sys.exit(1 if os.environ.get("FAKE_NO_IMAGE") else 0)
    if a[0] == "kill":
        sys.exit(0)
    assert a[0] == "run", a
    need = ["--rm", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
            "--user 65534:65534", "--pids-limit 64", "--memory 256m", "--pull never"]
    line = " ".join(a)
    missing = [n for n in need if n not in line]
    assert not missing, ("missing hardening flags", missing)
    assert a[-1] == "zday-protocol-sandbox:latest", a
    if os.environ.get("FAKE_HANG"):
        time.sleep(30)
    sys.exit(subprocess.run([{sys.executable!r}, "-I", {str(RUNNER)!r}]).returncode)
"""))
shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
os.environ["PATH"] = f"{tmp}:{os.environ['PATH']}"
os.environ["LD_SANDBOX"] = "docker"

import engine
from engine import Session

assert engine.check_docker() is None
os.environ["FAKE_NO_IMAGE"] = "1"
assert "docker build" in engine.check_docker()
del os.environ["FAKE_NO_IMAGE"]

s = Session()
names = [f["id"] for f in s.scan()["findings"]]
for n in names:
    r = s.simulate(n)
    assert r["vulnerable"] and "Docker" in r["mode"], (n, r["mode"], r["steps"][-1])
    fx = s.apply_fix(n)
    assert fx["status"] == "Verified" and "Docker" in fx["result"]["mode"], (n, fx)
assert s.scan()["trust"]["after"] == 100.0
print("docker backend: 5 attacks + 5 fixes ran through the container command, all hardening flags present")

# a hung container must be killed by name, not just abandoned
engine.DOCKER_STARTUP_GRACE = 0
os.environ["FAKE_HANG"] = "1"
t = time.time()
res = engine.run_in_sandbox(Path(engine.SAMPLE).read_text(), names[0], "fake_auth", "x", timeout=1)
assert "time limit" in res["banner"] and time.time() - t < 10, res["banner"]
assert any(l.startswith("kill ld-sbx-") for l in LOG.read_text().splitlines()), "container was not killed"
print("timeout: container killed by name")
print("DOCKER BACKEND CHECKS PASSED")
