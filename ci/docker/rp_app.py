import json
import logging
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

RP_BASE_URL = os.environ.get("RP_BASE_URL", "http://localhost:8080").rstrip("/")
CALLBACK_PATH = "/callback"


class Handler(BaseHTTPRequestHandler):
    server_version = "GreenticRPStub/0.1"

    def _send_json(self, payload, status=HTTPStatus.OK):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html, status=HTTPStatus.OK):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path == "/":
            html = f"""
            <html>
              <head><title>RP Harness Stub</title></head>
              <body>
                <h1>Greentic RP Harness Stub</h1>
                <p>Callback URL: {RP_BASE_URL}{CALLBACK_PATH}</p>
              </body>
            </html>
            """
            self._send_html(html)
            return

        if self.path.startswith(CALLBACK_PATH):
            query = parse_qs(urlparse(self.path).query)
            logging.info("Received callback parameters: %s", query)
            html = """
            <html>
              <head><title>Callback Received</title></head>
              <body>
                <h1>Authorization Response Captured</h1>
                <p>Check container logs for details.</p>
              </body>
            </html>
            """
            self._send_html(html)
            return

        if self.path == "/.well-known/oidf-rp-stub":
            payload = {
                "redirect_uris": [f"{RP_BASE_URL}{CALLBACK_PATH}"],
                "features": {"pkce": True},
            }
            self._send_json(payload)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        logging.info("Received POST %s payload=%s", self.path, body.decode("utf-8", "ignore"))
        self._send_json({"status": "ok"})


def run():
    parsed = urlparse(RP_BASE_URL)
    host = parsed.hostname or "0.0.0.0"
    port = parsed.port or 8080
    server = HTTPServer((host, port), Handler)
    logging.info("Starting RP stub at http://%s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - manual stop
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
