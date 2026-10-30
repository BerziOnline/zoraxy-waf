"""Loopback-only browser fixture; never runs Zoraxy or connects to an origin.
Usage: python3 tests/ui_fixture.py (build the plugin first).
The proxy simulates only Zoraxy's path/header contract, not real authentication.
"""
import http.client
import http.server
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "local-ui-fixture-session"

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
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
        plugin = subprocess.Popen([str(ROOT / "zoraxy-waf-plugin"), "-configure", '{"port":18482}'],
                                  env={**os.environ, "ZORAXY_WAF_DATA_DIR": data})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 18483), Proxy)
        def stop(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        try:
            for _ in range(100):
                conn = http.client.HTTPConnection("127.0.0.1", 18482, timeout=.2)
                try:
                    conn.request("GET", "/policy")
                    if conn.getresponse().status == 200:
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
