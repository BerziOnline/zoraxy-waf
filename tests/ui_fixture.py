"""Loopback-only browser fixture; never runs Zoraxy or connects to an origin.
Usage: python3 tests/ui_fixture.py (build the plugin first).
The proxy simulates only Zoraxy's path/header contract, not real authentication.
"""
import http.client
import http.server
import os
import json
from datetime import datetime, timezone
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "local-ui-fixture-session"
API_KEY = "local-ui-fixture-key"
# Fake Zoraxy plugin API (route list + plugin groups), same shapes as Zoraxy.
ROUTES = b'[{"ProxyType":1,"RootOrMatchingDomain":"shop.example","MatchingDomainAlias":[],"Tags":["waf"],"Disabled":false},' \
         b'{"ProxyType":1,"RootOrMatchingDomain":"api.example","MatchingDomainAlias":["www.api.example"],"Tags":["waf"],"Disabled":false},' \
         b'{"ProxyType":1,"RootOrMatchingDomain":"chat.example.test","MatchingDomainAlias":[],"Tags":["waf"],"Disabled":false,"ActiveOrigins":[{"OriginIpOrDomain":"chat-backend.example.test:8065"}]},' \
         b'{"ProxyType":1,"RootOrMatchingDomain":"static.example","MatchingDomainAlias":null,"Tags":["cdn"],"Disabled":false}]'
GROUPS = b'{"waf":["org.zoraxy.waf"],"cdn":["org.example.cache"]}'
# Zoraxy shows plugin UIs in this frame (src/web/components/plugincontext.html):
# sandboxed without allow-forms/allow-modals/allow-popups/allow-downloads.
ZORAXY_FRAME = b'<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">' \
    b'<style>html,body{margin:0}iframe{display:block;width:100%;height:100vh;border:none}</style></head><body>' \
    b'<iframe id="pluginContextLoader" src="/plugin.ui/org.zoraxy.waf/" allow="scripts" sandbox="allow-scripts allow-same-origin"></iframe>' \
    b'<script>window.openTabById=function(id){window.lastTab=id;};</script></body></html>'

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        api = {"/plugin/api/proxy/list?type=host": ROUTES, "/plugin/api/plugins/groups/list": GROUPS}
        if self.path == "/zoraxy.html":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(ZORAXY_FRAME))); self.end_headers()
            self.wfile.write(ZORAXY_FRAME); return
        if self.path in api:
            if self.headers.get("Authorization") != "Bearer " + API_KEY:
                self.send_error(401); return
            body = api[self.path]
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body); return
        self.forward()
    def do_PUT(self):
        self.forward()
    def do_POST(self):
        if self.path == "/hook":  # alert receiver for the UI test: accept anything
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200); self.end_headers(); return
        self.forward()
    def forward(self):
        prefix = "/plugin.ui/org.zoraxy.waf"
        if not self.path.startswith(prefix + "/"):
            self.send_error(404)
            return
        path = "/ui" + self.path[len(prefix):]
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "connection", "x-zoraxy-csrf")}
        headers["X-Zoraxy-Csrf"] = TOKEN
        headers["Host"] = "admin.example:18483"
        n = int(self.headers.get("Content-Length", "0"))
        conn = http.client.HTTPConnection("127.0.0.1", 18482, timeout=30)
        try:
            conn.request(self.command, path, self.rfile.read(n) if n else None, headers)
            response = conn.getresponse()
            body = response.read()
            self.send_response(response.status)
            for k, v in response.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            conn.close()
    def log_message(self, format, *args):
        pass

def main():
    scratch = os.environ.get("TMPDIR", tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="waf-ui-", dir=scratch) as data:
        if os.environ.get("WAF_PROFILE_FIXTURE"):
            now = datetime.now(timezone.utc).isoformat()
            Path(data, "config.json").write_text(json.dumps({"mode": "learn", "learning": {"days": 7, "activated_at": now}}))
            findings = {}
            for path, arg, rules in [("/api/v4/posts", "json.message", [932125, 932380]), ("/plugins/playbooks/api/v0/query", "json.query", [932235]), ("/unrelated", "json.title", [941100])]:
                findings["POST " + path] = {"method": "POST", "path": path, "example": path, "rules": [{"id": r, "argument": arg} for r in rules], "count": 8, "with_login": 8, "clients": [1, 2], "first_seen": now, "last_seen": now}
            Path(data, "learning.json").write_text(json.dumps({"chat.example.test": {"since": now, "requests": 32, "paths": {"/api/v4/posts": 12, "/plugins/playbooks/api/v0/query": 8}, "findings": findings}}))
        plugin = subprocess.Popen([str(ROOT / "zoraxy-waf-plugin"), "-configure", '{"port":18482,"zoraxy_port":18483,"api_key":"%s"}' % API_KEY],
                                  env={**os.environ, "ZORAXY_WAF_DATA_DIR": data})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 18483), Proxy)
        def stop(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        try:
            for _ in range(100):
                conn = http.client.HTTPConnection("127.0.0.1", 18482, timeout=.2)
                try:
                    conn.request("GET", "/sniff/")
                    if conn.getresponse().status == 405:  # mounted; sniff is POST-only
                        break
                except OSError:
                    if plugin.poll() is not None:
                        raise RuntimeError("Plugin exited during startup")
                    time.sleep(.05)
                finally:
                    conn.close()
            else:
                raise RuntimeError("Plugin startup timed out")
            print("UI fixture ready: http://127.0.0.1:18483/plugin.ui/org.zoraxy.waf/", flush=True)
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            plugin.terminate()
            try:
                plugin.wait(timeout=6)
            except subprocess.TimeoutExpired:
                plugin.kill()
                plugin.wait()

if __name__ == "__main__":
    main()
