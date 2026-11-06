"""ARGUS Lab B: Multi-Service Network Host.

Spec 08 Section 3.2: Multi-port enumeration, banner extraction, and service categorization.
Exposes FTP (port 21/2121) simulating vsftpd 2.3.4 and SSH (port 22/2222) simulating OpenSSH 8.4p1,
along with an HTTP healthcheck on port 8080.
"""

import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("LAB_B_HOST", "0.0.0.0")
FTP_PORT = int(os.getenv("LAB_B_FTP_PORT", "21"))
SSH_PORT = int(os.getenv("LAB_B_SSH_PORT", "22"))
HTTP_PORT = int(os.getenv("LAB_B_HTTP_PORT", "8080"))

FTP_BANNER = b"220 (vsFTPd 2.3.4)\r\n"
SSH_BANNER = b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n"


def run_ftp_service() -> None:
    """Simulates an FTP daemon responding to basic commands."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, FTP_PORT))
        sock.listen(10)
        print(f"[Lab B] FTP service listening on {HOST}:{FTP_PORT}", flush=True)

        while True:
            conn, _ = sock.accept()
            try:
                conn.sendall(FTP_BANNER)
                # Read client greeting or QUIT
                conn.settimeout(2.0)
                data = conn.recv(1024)
                if data.startswith(b"USER"):
                    conn.sendall(b"331 Please specify the password.\r\n")
                elif data.startswith(b"QUIT"):
                    conn.sendall(b"221 Goodbye.\r\n")
            except (socket.timeout, OSError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
    except Exception as exc:
        print(f"[Lab B] FTP service error: {exc}", flush=True)


def run_ssh_service() -> None:
    """Simulates an SSH daemon returning OpenSSH version banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, SSH_PORT))
        sock.listen(10)
        print(f"[Lab B] SSH service listening on {HOST}:{SSH_PORT}", flush=True)

        while True:
            conn, _ = sock.accept()
            try:
                conn.sendall(SSH_BANNER)
                conn.settimeout(2.0)
                _ = conn.recv(1024)
            except (socket.timeout, OSError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
    except Exception as exc:
        print(f"[Lab B] SSH service error: {exc}", flush=True)


class LabBHttpHandler(BaseHTTPRequestHandler):
    """Provides healthcheck and discovery endpoint."""

    server_version = "Debian-Linux"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = (
                b'{"status":"ok","lab":"lab-b-network","services":["ftp:21","ssh:22"]}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b"ARGUS Lab B: Multi-Service Host (FTP/SSH)"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Suppresses noisy healthcheck access logs."""


if __name__ == "__main__":
    t_ftp = threading.Thread(target=run_ftp_service, daemon=True)
    t_ssh = threading.Thread(target=run_ssh_service, daemon=True)
    t_ftp.start()
    t_ssh.start()

    print(f"[Lab B] HTTP healthcheck listening on {HOST}:{HTTP_PORT}", flush=True)
    http_server = ThreadingHTTPServer((HOST, HTTP_PORT), LabBHttpHandler)
    http_server.serve_forever()

