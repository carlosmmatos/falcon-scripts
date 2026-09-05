#!/usr/bin/env python3
"""One-shot 307/200 capture server for credential-redirect tests.

Usage: redirect-capture-server.py OUTPUT_PATH [REDIRECT_TO] [CERT KEY]

Binds 127.0.0.1:0, writes OUTPUT_PATH.port and OUTPUT_PATH.ready, serves one
request, then exits. CERT and KEY enable HTTPS. The capture line always
records Authorization and body so (A) hop contact and (B) credential
presence can be asserted separately.
"""
import ssl
import sys

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:  # Python 2
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

output_path = sys.argv[1]
redirect_to = sys.argv[2] if len(sys.argv) > 2 else ""
if redirect_to in ("", "-"):
    redirect_to = ""
cert = sys.argv[3] if len(sys.argv) > 3 else ""
key = sys.argv[4] if len(sys.argv) > 4 else ""


class Handler(BaseHTTPRequestHandler):
    def _capture(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            body_text = body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = repr(body)
        with open(output_path, "w") as handle:
            handle.write(
                "REQUEST_ARRIVED|auth=[%s]|body=[%s]"
                % (self.headers.get("Authorization", ""), body_text)
            )

    def _respond(self):
        if redirect_to:
            self.send_response(307)
            self.send_header("Location", redirect_to)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"access_token":"mock","token":"mock"}')

    def do_GET(self):
        self._capture()
        self._respond()

    def do_POST(self):
        self._capture()
        self._respond()

    def log_message(self, *args):
        pass


HTTPServer.allow_reuse_address = True
server = HTTPServer(("127.0.0.1", 0), Handler)
if cert and key:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
port = server.server_address[1]
with open(output_path + ".port", "w") as handle:
    handle.write(str(port))
with open(output_path + ".ready", "w") as handle:
    handle.write("ready")
server.timeout = 20
server.handle_request()
