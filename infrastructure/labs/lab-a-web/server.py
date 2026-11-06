"""ARGUS Lab A: Vulnerable Web App (Apache 2.4.49 CVE-2021-41773).

Safe, isolated evaluation target simulating path traversal vulnerability.
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("LAB_A_HOST", "0.0.0.0")
PORT = int(os.getenv("LAB_A_PORT", "8080"))

FAKE_PASSWD = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    b"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    b"sync:x:4:65534:sync:/bin:/bin/sync\n"
    b"lab:x:1000:1000:ARGUS Lab User:/home/lab:/bin/sh\n"
)


class LabAHandler(BaseHTTPRequestHandler):
    """Simulates Apache 2.4.49 web server and safe path traversal behavior."""

    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"

    def do_GET(self) -> None:
        # 1. Healthcheck endpoint
        if self.path == "/healthz":
            self._send_response(200, b'{"status":"ok","lab":"lab-a-web","cve":"CVE-2021-41773"}', "application/json")
            return

        # 2. Path traversal signature matching (Apache 2.4.49 flaw)
        normalized = self.path.lower()
        if (
            "/icons" in normalized
            or ".%2e" in normalized
            or ".%%32%65" in normalized
            or "etc/passwd" in normalized
        ):
            self._send_response(200, FAKE_PASSWD, "text/plain")
            return

        # 3. Default index page
        body = (
            b"<!DOCTYPE html>\n"
            b"<html>\n"
            b"<head><title>ARGUS Authorized Lab A Target</title></head>\n"
            b"<body>\n"
            b"<h1>Apache 2.4.49 Test Fixture</h1>\n"
            b"<p>Evaluation environment for ARGUS autonomous security assessments.</p>\n"
            b"<p>Authorized scope only. Prohibited for external use.</p>\n"
            b"</body>\n"
            b"</html>\n"
        )
        self._send_response(200, body, "text/html")

    def _send_response(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Suppresses noisy healthcheck access logs."""


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), LabAHandler)
    print(f"ARGUS Lab A (Apache 2.4.49) running on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()

