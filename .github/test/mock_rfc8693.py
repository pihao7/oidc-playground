"""Mock RFC 8693 token-exchange server for lab5 self-tests.

Usage: python3 mock_rfc8693.py PORT MODE
  MODE=ok     asserts the SDD section 3 request shape, returns 200 + canned JWT
  MODE=reject returns 400 invalid_request (error-path test)
"""
import base64
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote_plus

port, mode = int(sys.argv[1]), sys.argv[2]


def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[unquote_plus(k)] = unquote_plus(v)

        if mode == "reject":
            payload = json.dumps({
                "error": "invalid_request",
                "error_description": "A subject constraint is required",
            }).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return

        expected = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "org_id": "org-123",
            "connection_id": "conn-github",
            "audience": "nvcr.io",
            "trust_policy_id": "policy-main",
        }
        wrong = {k: params.get(k) for k, v in expected.items() if params.get(k) != v}
        assert not wrong, f"missing/wrong params: {wrong}; got: {sorted(params)}"
        assert len(params.get("subject_token", "")) > 20, "subject_token missing"

        jwt = ".".join([
            b64u({"alg": "RS256", "typ": "JWT"}),
            b64u({
                "iss": "nvcr-registry-token",
                "aud": "nvcr.io",
                "exp": 9999999999,
                "oidc": {
                    "connection_id": "conn-github",
                    "connection_revision": 7,
                    "trust_policy_ids": ["policy-main"],
                },
            }),
            "mock-signature",
        ])
        payload = json.dumps({
            "access_token": jwt,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 300,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
