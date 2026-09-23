"""Run a documented CLI consumer against local HTTP/SSE failure fixtures.

No attestation or inference is simulated here: the verifier's own transport tests
cover that boundary. This checks whether the downstream client hides failures.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

command = sys.argv[1:]
if not command:
    raise SystemExit("usage: python check_http_client.py COMMAND [ARGS...]")

for scenario in ("success", "quota", "unavailable", "truncated", "truncated_chunk"):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append((self.path, self.headers["Authorization"], json.loads(body)))
            chunk = json.dumps({"id": "example", "object": "chat.completion.chunk", "created": 1,
                                "model": "example", "choices": [{"index": 0, "delta": {"content": "Hello"}, "finish_reason": None}]})
            prefix = f": STOGAS PROCESSING\n\ndata: {chunk}\n\n".encode()
            if scenario in ("quota", "unavailable"):
                self.send_response(429 if scenario == "quota" else 503)
                data = b'{"error":{"message":"unavailable","type":"provider_unavailable"}}'
                self.send_header("Content-Type", "application/json")
            else:
                self.send_response(200)
                data = prefix + (b"data: [DONE]\n\n" if scenario == "success" else b"")
                self.send_header("Content-Type", "text/event-stream")
            if scenario == "truncated_chunk":
                self.send_header("Transfer-Encoding", "chunked")
                # The local verifier proxy aborts a failed stream without the final HTTP chunk.
                data = f"{len(data):x}\r\n".encode() + data + b"\r\n"
            else:
                self.send_header("Content-Length", str(len(data) + (100 if scenario == "truncated" else 0)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(data)
                self.wfile.flush()
            except BrokenPipeError:
                pass
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        environment = dict(os.environ, STOGAS_BASE_URL=f"http://127.0.0.1:{server.server_port}/cap/v1",
                           STOGAS_API_KEY="test-key", STOGAS_MODEL="example")
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
        assert len(calls) == 1, (scenario, "unexpected dispatch count", len(calls), result.stderr)
        assert calls[0][0] in ("/cap/v1/chat/completions", "/cap/v1/responses"), calls[0][0]
        assert calls[0][1] == "Bearer test-key"
        assert calls[0][2]["model"] == "example"
        assert calls[0][2]["stream"] is True
        if scenario == "success":
            assert result.returncode == 0 and "Hello" in result.stdout, (scenario, result.returncode, result.stderr)
        else:
            assert result.returncode != 0, (scenario, "client reported success", result.stdout)
        print(scenario, "passed")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
