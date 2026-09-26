"""The real OpenAI client against a local transport boundary; no inference costs."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from openai import APIStatusError

from main import client


class ClientTests(unittest.TestCase):
    def test_request_objects_errors_and_redirects_never_replay(self):
        for status in (200, 307, 429, 503):
            with self.subTest(status=status):
                calls = []

                class Handler(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass

                    def do_POST(self):
                        calls.append((
                            self.path,
                            self.headers.get("Authorization"),
                            json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                        ))
                        self.send_response(status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Location", "/must-not-follow")
                        self.end_headers()
                        payload = (
                            {"id": "chat-1", "choices": [{"index": 0, "message": {
                                "role": "assistant", "content": "Hello"
                            }, "finish_reason": "stop"}]}
                            if status == 200 else
                            {"error": {"message": "Unavailable", "type": "server_error"}}
                        )
                        self.wfile.write(json.dumps(payload).encode())

                with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                    thread = threading.Thread(target=server.serve_forever)
                    thread.start()
                    try:
                        with client(f"http://127.0.0.1:{server.server_port}/v1", "example-key") as api:
                            request = {"model": "example/model", "messages": [{"role": "user", "content": "hello"}]}
                            if status == 200:
                                result = api.chat.completions.create(**request)
                                self.assertEqual(result.choices[0].message.content, "Hello")
                            else:
                                with self.assertRaises(APIStatusError) as caught:
                                    api.chat.completions.create(**request)
                                self.assertEqual(caught.exception.status_code, status)
                            self.assertEqual(calls, [("/v1/chat/completions", "Bearer example-key", request)])
                    finally:
                        server.shutdown()
                        thread.join()


if __name__ == "__main__":
    unittest.main()
