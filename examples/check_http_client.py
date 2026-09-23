"""Run a documented CLI consumer against local HTTP/SSE failure fixtures.

No attestation or inference is simulated here: the verifier's own transport tests
cover that boundary. This checks whether the downstream client hides failures.
"""
import json
import os
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

command = sys.argv[1:]
cancel = command[:1] == ["--cancel"]
if cancel:
    command = command[1:]
unary = command[:1] == ["--unary"]
if unary:
    command = command[1:]
framing = command[:1] == ["--sse-framing"]
if framing:
    command = command[1:]
if not command:
    raise SystemExit("usage: python check_http_client.py [--unary | --sse-framing | --cancel] COMMAND [ARGS...]")

scenarios = ["success", "quota", "unavailable", "disconnected", "stream_error", "truncated", "truncated_chunk"]
if unary:
    scenarios = ["success", "quota", "unavailable", "disconnected", "truncated"]
if framing:
    scenarios += ["success_crlf", "success_cr", "success_multiline", "malformed", "trailing_json", "missing_terminal"]
if cancel:
    scenarios = ["cancelled"]
for scenario in scenarios:
    calls = []
    started, closed = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                body = bytearray()
                while True:
                    size = int(self.rfile.readline().split(b";", 1)[0], 16)
                    assert len(body) + size <= 1024 * 1024
                    if not size:
                        assert self.rfile.readline() == b"\r\n"
                        break
                    body.extend(self.rfile.read(size))
                    assert self.rfile.read(2) == b"\r\n"
            else:
                body = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append((self.path, self.headers["Authorization"], json.loads(body)))
            if scenario == "disconnected":
                # The application request arrived, but no response bytes did. Do not replay it.
                self.close_connection = True
                return
            responses = self.path.endswith("/responses")
            chunk = json.dumps({"type": "response.output_text.delta", "delta": "Hello"} if responses else
                               {"id": "example", "object": "chat.completion.chunk", "created": 1,
                                "model": "example", "choices": [{"index": 0, "delta": {"content": "Hello"}, "finish_reason": None}]})
            prefix = f": STOGAS PROCESSING\n\ndata: {chunk}\n\n".encode()
            if scenario in ("quota", "unavailable"):
                self.send_response(429 if scenario == "quota" else 503)
                self.send_header("Retry-After", "0")
                data = b'{"error":{"message":"unavailable","type":"provider_unavailable"}}'
                self.send_header("Content-Type", "application/json")
            else:
                self.send_response(200)
                if unary:
                    data = json.dumps({"id": "example", "object": "chat.completion", "created": 1,
                                       "model": "example", "choices": [{"index": 0,
                                       "message": {"role": "assistant", "content": "Hello"},
                                       "finish_reason": "stop"}]}).encode()
                elif scenario == "stream_error":
                    data = prefix + b'data: {"error":{"message":"provider disconnected","type":"provider_unavailable","code":"provider_unavailable"},"choices":[{"index":0,"delta":{},"finish_reason":"error"}]}\n\ndata: [DONE]\n\n'
                else:
                    terminal = (b'data: {"type":"response.completed","response":{"id":"example","status":"completed"}}\n\n'
                                if responses else b"data: [DONE]\n\n")
                    data = prefix + (terminal if scenario.startswith("success") else b"")
                    if scenario == "success_crlf":
                        data = data.replace(b"\n", b"\r\n")
                    elif scenario == "success_cr":
                        data = data.replace(b"\n", b"\r")
                    elif scenario == "success_multiline":
                        data = data.replace(b', "', b',\ndata: "')
                    elif scenario == "malformed":
                        data = prefix + b"data: {broken}\n\n" + terminal
                    elif scenario == "trailing_json":
                        data = prefix + b"data: {} unparsed\n\n" + terminal
                self.send_header("Content-Type", "application/json" if unary else "text/event-stream")
            if scenario in ("truncated_chunk", "cancelled"):
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
                if scenario == "cancelled":
                    started.set()
                    self.connection.settimeout(10)
                    if not self.rfile.read(1):
                        closed.set()
            except BrokenPipeError:
                pass
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        environment = dict(os.environ, STOGAS_BASE_URL=f"http://127.0.0.1:{server.server_port}/cap/v1",
                           STOGAS_API_KEY="test-key", STOGAS_MODEL="example")
        if cancel:
            with subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) as process:
                try:
                    assert started.wait(20), "client never started its request"
                    process.send_signal(signal.SIGINT)
                    stdout, stderr = process.communicate(timeout=8)
                    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                    assert closed.wait(2), "cancelled client left its request open"
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
        else:
            result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
        assert len(calls) == 1, (scenario, "unexpected dispatch count", len(calls), result.stderr)
        assert calls[0][0] in ("/cap/v1/chat/completions", "/cap/v1/responses"), calls[0][0]
        assert calls[0][1] == "Bearer test-key"
        assert calls[0][2]["model"] == "example"
        assert calls[0][2].get("stream", False) is (not unary)
        if scenario.startswith("success"):
            assert result.returncode == 0 and "Hello" in result.stdout, (scenario, result.returncode, result.stderr)
        else:
            assert result.returncode != 0, (scenario, "client reported success", result.stdout)
        print(scenario, "passed")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
