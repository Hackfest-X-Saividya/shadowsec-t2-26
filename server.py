"""Dashboard server (stdlib only).

Security design:
- Binds to 127.0.0.1 only; rejects other Host headers (DNS rebinding) and cross-origin POSTs.
- Never accepts code, files or URLs from the client. Pasted/uploaded code is analysed in the
  browser (static/analyzer.js) as text and is never sent here or executed.
- The only code that ever runs is the bundled sample app, in the throwaway subprocess sandbox.
- Strict Content-Security-Policy: only this server's own scripts, no inline script, no network except self.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from engine import SAMPLE, Session, check_docker, report_html, sandbox_backend

STATIC = Path(__file__).resolve().parent / "static"
FILES = {"/": ("index.html", "text/html"), "/index.html": ("index.html", "text/html"),
         "/app.js": ("app.js", "text/javascript"), "/analyzer.js": ("analyzer.js", "text/javascript")}
SESSION = Session()
LOCK = threading.Lock()
LOCAL_HOSTS = ("127.0.0.1", "localhost")
MAX_BODY = 4096
CSP = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else str(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host in LOCAL_HOSTS

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "forbidden host"})
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self._send(200, {"ok": True, "sandbox": sandbox_backend()})
        if path in FILES:
            name, ctype = FILES[path]
            return self._send(200, (STATIC / name).read_bytes(), ctype)
        with LOCK:
            if path == "/api/sample":
                self._send(200, {"source": SAMPLE.read_text(), "label": "sample_app/vulnerable.py"})
            elif path == "/api/scan":
                self._send(200, SESSION.scan())
            elif path == "/api/report.json":
                self._send(200, SESSION.report(), extra={"Content-Disposition": "attachment; filename=zday-protocol-report.json"})
            elif path == "/report":
                self._send(200, report_html(SESSION), "text/html")
            else:
                self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "forbidden host"})
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + (self.headers.get("Host") or ""):
            return self._send(403, {"error": "cross-origin request refused"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"error": "bad length"})
        if n > MAX_BODY:
            return self._send(413, {"error": "request too large: this server never accepts code"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        with LOCK:
            if self.path == "/api/simulate":
                out = SESSION.simulate(str(body.get("id", "")))
            elif self.path == "/api/fix":
                out = SESSION.apply_fix(str(body.get("id", "")))
            elif self.path == "/api/reset":
                SESSION.reset()
                out = {"ok": True}
            else:
                return self._send(404, {"error": "not found"})
        self._send(400 if "error" in out else 200, out)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("LD_PORT", "8000"))
    # 127.0.0.1 unless LD_BIND says otherwise. Inside Docker it is 0.0.0.0, and compose publishes the port on the
    # host's 127.0.0.1 only. The Host-header check above still refuses anything that is not localhost.
    bind = os.environ.get("LD_BIND", "127.0.0.1")
    backend = sandbox_backend()
    if backend == "docker":
        problem = check_docker()
        if problem:
            sys.exit("LD_SANDBOX=docker but " + problem)
    print(f"Zday Protocol -> http://127.0.0.1:{port}  sandbox={backend}  (Ctrl+C to stop)", flush=True)
    ThreadingHTTPServer((bind, port), Handler).serve_forever()
