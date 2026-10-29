"""Builds the static demo page: one HTML file with the analyzer, the app and recorded sandbox runs of the
bundled sample baked in. Usage: python3 build_demo.py out.html"""
import json, re, sys
from engine import Session, SAMPLE

out_path = sys.argv[1] if len(sys.argv) > 1 else "zday-protocol-demo.html"
s = Session()
rec = {"simulate": {}, "fix": {}, "fix_state": {}}
for f in list(s.scan()["findings"]):
    n = f["id"]
    rec["simulate"][n] = s.simulate(n)
    rec["fix"][n] = s.apply_fix(n)
    rec["fix_state"][n] = {"current_lie_score": next(x for x in s.scan()["findings"] if x["id"] == n)["current_lie_score"]}
assert all(v["vulnerable"] for v in rec["simulate"].values())
assert all(v["status"] == "Verified" for v in rec["fix"].values())

h = open("static/index.html").read()
style = re.search(r"<style>(.*?)</style>", h, re.S).group(1)
body = re.search(r"<body>(.*?)<script src=", h, re.S).group(1)
demo = json.dumps({"sample": SAMPLE.read_text(), "recorded": rec}).replace("<", "\\u003c")
page = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        '<title>Zday Protocol</title>\n<style>' + style + '</style>\n</head>\n<body>' + body +
        '<script>window.__DEMO__=' + demo + ';</script>\n<script>' + open("static/analyzer.js").read() + '</script>\n<script>' +
        open("static/app.js").read() + '</script>\n</body>\n</html>\n')
open(out_path, "w").write(page)
print("wrote", out_path, len(page), "bytes")
