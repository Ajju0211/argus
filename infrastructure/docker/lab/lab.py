"""Authorized mock target lab for the ARGUS docker compose demo.

This is intentionally tiny and safe: it only serves a banner and a fake
``/etc/passwd``-looking response on the Apache 2.4.49 traversal path so that the
end-to-end test and a live demo have a deterministic target. It must never be
exposed outside the compose network.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = 8080
FAKE_PASSWD = b"root:x:0:0:root:/root:/bin/bash\nlab:x:1000:1000:ARGUS Lab:/home/lab:/bin/sh\n"


class LabHandler(BaseHTTPRequestHandler):
    """Serves an Apache-like banner and a deterministic traversal proof."""

    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"

    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b'{"status":"ok","service":"mock-target-lab"}'
            content_type = "application/json"
        elif self.path.startswith("/icons") or "etc/passwd" in self.path:
            body = FAKE_PASSWD
            content_type = "text/plain"
        else:
            body = (
                b"<html><body><h1>ARGUS authorized lab target</h1>"
                b"<p>Apache/2.4.49 lab fixture. Scope-limited demo only.</p></body></html>"
            )
            content_type = "text/html"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Keeps container logs quiet; healthchecks are frequent."""


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), LabHandler)
    print(f"ARGUS mock target lab listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()
