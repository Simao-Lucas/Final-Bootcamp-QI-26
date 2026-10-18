"""Mock HTTP da API de condenacoes — pra testes de freshness.

Sobe um servidor local que a API (no Docker) alcanca via
host.docker.internal quando FRAUD_REGISTRY_API_URL aponta pra ca.
Registra cada GET pra o teste afirmar quente vs frio.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote


class FraudRegistryMock:
    def __init__(self, port: int = 8765) -> None:
        self.port = port
        self.hits: list[str] = []
        self.condemned: set[str] = set()
        self.delay_seconds = 0.0
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def condemn(self, document_number: str) -> None:
        self.condemned.add(document_number)

    def clear_hits(self) -> None:
        self.hits.clear()

    def start(self) -> None:
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                if mock.delay_seconds > 0:
                    time.sleep(mock.delay_seconds)

                prefix = "/fraud/document/"
                if not self.path.startswith(prefix):
                    self.send_response(404)
                    self.end_headers()
                    return

                document_number = unquote(self.path[len(prefix) :])
                mock.hits.append(document_number)
                body = {
                    "condemned": document_number in mock.condemned,
                    "document_number": document_number,
                }
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._server = HTTPServer(("0.0.0.0", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
