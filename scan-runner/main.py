"""scan-runner HTTP service (internal `scan-control` network only).

POST /scan validates the request against images.lock and the fixed templates. Execution is off unless
SP_RUNNER_EXECUTE=1 (needs a container runtime and the Docker socket, which only this service gets: rule R8).
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import runner

MAX_BODY = 16 * 1024


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_GET(self) -> None:
        self._send(200, {"status": "ok"}) if self.path == "/health" else self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/scan":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self._send(413, {"error": "bad body size"})
        try:
            images, registry = runner.load_lock(Path(os.environ.get("SP_IMAGES_LOCK", runner.LOCK_PATH)))
            req = runner.validate(json.loads(self.rfile.read(length)), images)
        except (ValueError, runner.RequestError) as e:
            return self._send(400, {"error": str(e)})
        if os.environ.get("SP_RUNNER_EXECUTE") != "1":
            return self._send(501, {"error": "execution disabled", "argv": runner.docker_argv(req, images, registry)})
        result = runner.run(req, images, registry)
        result.pop("stderr_tail", None)  # untrusted scanner output never leaves scan-runner
        self._send(200, result)

    def log_message(self, fmt: str, *args) -> None:
        print(json.dumps({"msg": fmt % args}))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
