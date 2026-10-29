<<<<<<< HEAD
# shadowsec-t2-26
Official HackFest 2026 repository for team Shadowsec (T2-26).
=======
# Zday Protocol: MVP

Finds security functions that don't do what they claim, proves the flaw by attacking it in a
sandbox, patches it, and attacks again. Python 3.9+, no dependencies.

```
python3 server.py          # (no Docker) then open http://127.0.0.1:8000
python3 selftest.py        # headless check of scan -> attack -> fix -> re-attack
```

Demo: Claims vs Reality tab (flagged `sanitize_input`, Lie Score 95) -> Open in Lab -> Simulate Attack
(VULNERABLE, red rows) -> Apply Fix (same attack, BLOCKED, green) -> Trust Score rises. "Reset demo" starts over.

## Run it all in Docker (simplest)

```
docker compose up --build        # then open http://127.0.0.1:8000   (stop: docker compose down)
```
The dashboard and the attack sandbox both run inside one hardened container (read-only root, all capabilities
dropped, non-root user, 512 MB / 1 CPU / 128 pids), published on your machine's 127.0.0.1 only. Nothing needs
installing besides Docker. After changing code, rerun with `--build` so the image is rebuilt, otherwise you keep
seeing the old version.

## Run it (host dashboard + Docker sandbox per attack)

Needs Docker and Python 3.9+. No pip packages.
```
make                      # same as ./scripts/run-docker-sandbox.sh, then open http://127.0.0.1:8000
```
The dashboard runs on your machine. Each Simulate Attack and Apply Fix replay runs `sandbox_runner.py` in a fresh
container built from `Dockerfile.sandbox`, with `--network none --read-only --cap-drop ALL
--security-opt no-new-privileges --user 65534 --pids-limit 64 --memory 256m --cpus 1`. The image holds only the
runner: no app source, no secrets, no pip packages. A run that hangs has its container killed by name. At startup
the server checks that the image exists and refuses to start otherwise. The UI labels these runs
"Real execution (Docker container ...)".

The app is deliberately not run inside a container: launching sandboxes from there would need the Docker socket
mounted into it, which is root-equivalent on the host.

Without Docker, `python3 server.py` uses the older subprocess sandbox (`LD_SANDBOX=process`). That one is Linux and Mac only; on Windows, Docker is required.

**Windows (PowerShell):** `.\scripts\run-docker-sandbox.ps1` starts the dashboard; add `-Test` for the full check through real containers.

| Variable | Default | Meaning |
|---|---|---|
| `LD_SANDBOX` | `process` (the script sets `docker`) | `process` or `docker` |
| `LD_SANDBOX_IMAGE` | `zday-protocol-sandbox:latest` | image used when `LD_SANDBOX=docker` |
| `LD_BIND` / `LD_PORT` | `127.0.0.1` / `8000` | bind address and port |

`make test` runs every check without Docker. `make docker-test` runs the full flow through real containers.

## How it works (refined, safe-by-design)
- **Analyze any code:** paste it, drop a file, or load an example. Python, JavaScript/TypeScript, Java, PHP, Go, C#, Ruby.
  Analysis runs in the browser (`static/analyzer.js`). The code is read as text: never uploaded, never executed.
- **Real attacks only on the bundled sample app** (`sample_app/vulnerable.py`), inside the throwaway subprocess sandbox.
  Everything else gets a prediction, labelled "Simulated (predicted from static analysis, not executed)".
- **Fixes on your own code** are reference patches (Python, JavaScript), marked Fixed but **not verified**, and they do
  not raise the Trust Score. Only a real replayed attack (sample app) can mark a finding Verified.
- **Server hardening:** localhost only, Host and Origin checks, strict CSP, 4 KB request limit, no code accepted.
  Unit and browser tests: `node test_analyzer.js`, `python3 selftest.py`.

## Files
- `static/index.html`, `static/app.js`, `static/analyzer.js`: dashboard and the language-neutral analyzer
- `engine.py`, `sandbox_runner.py`, `server.py`: Python engine, sandbox and hardened server (sample app only)
- `Dockerfile.sandbox`, `docker-compose.yml`, `Makefile`, `scripts/run-docker-sandbox.sh`: Docker sandbox setup
- `test_docker_backend.py`: Docker backend check using a stand-in `docker` command
- `build_demo.py`: bakes recorded sandbox runs and the analyzer into one static HTML page

## Severity: CVSS and EPSS
- **CVSS 3.1** base score is computed per finding from a vector for its vulnerability type. Reachability sets the
  attack vector: user input reaches the flaw -> Network, otherwise Local. Severity is the CVSS band.
- **EPSS** is only defined for published CVEs, so new findings have none. If a finding has a CVE (add it to `CVE_MAP`
  in `engine.py`), the real EPSS is fetched from FIRST's public API (needs internet; not tested in the build sandbox).
- **Priority** combines both: P1 = Critical/High and likely exploited (EPSS >= 10%, or exploit proven in the sandbox
  when there is no CVE); P2 = Critical/High, or Medium and likely; P3 = the rest; Closed = Verified fix.
  This triage rule is our own, not part of either standard.

## Honest limits of this MVP
- The judge is rule-based (regex and AST), not an LLM. It uses one `{claim, reality, mismatch, lie_score, reason}` shape,
  so an LLM judge can replace `judge()` later. Non-Python languages use text patterns and will miss unusual code styles.
- Predictions for non-sample code are rule-based, not proof. Reachability is a simple handler-to-call trace.
- The process sandbox is a guard rail for the bundled sample only. Do not extend it to run untrusted code. The Docker backend above is that
  per-run container, but it is still only pointed at the bundled sample. Do not feed it uploaded code without a security review.
- Not built: log rules, LLM audit mode, fuzzing, and the Semgrep/Bandit comparison numbers (run both on
  `sample_app/` and record real counts first).
>>>>>>> 4949d00 (Successfully commited)
