from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


CLIENT_ROOT = Path(__file__).with_name("client")


class ClientHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(CLIENT_ROOT), **kwargs)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/", "/callback", "/callback/"}:
            self.path = "/index.html"
        return super().do_GET()

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:  # noqa: A003
        if code == HTTPStatus.NOT_FOUND:
            self.path = "/index.html"
            return super().do_GET()
        return super().send_error(code, message, explain)


def run(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), ClientHandler)
    print(f"Serving Auth0 token helper on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local Auth0 PKCE token helper")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=3000, type=int)
    args = parser.parse_args()
    run(args.host, args.port)


if __name__ == "__main__":
    main()
