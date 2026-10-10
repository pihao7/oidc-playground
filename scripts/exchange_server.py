"""POC exchange server — simulates the SDD's KAS Direct + token service side.

Implements POST /oauth/token per "NGC Registry: OIDC Federation" SDD section 3:
  1. parse the RFC 8693 form (grant_type, subject_token, subject_token_type,
     org_id, connection_id, audience, trust_policy_id)
  2. load the connection (from exchange_config.json — stands in for OMS)
  3. validate the external JWT: signature (GitHub JWKS), issuer, audience, expiry
  4. match enabled trust policies (equals / one_of / contains operators)
  5. sign a short-lived registry login credential (RS256) with the SDD's claims;
     exp = min(now + max_token_ttl_seconds, subject_token.exp)
  6. return the RFC 8693 section 2.2 response

Also serves:
  GET /.well-known/jwks.json  — this server's access-token public key, so clients
                                can validate the returned credential (full crypto loop)
  GET /healthz

Run: .venv/bin/python scripts/exchange_server.py [port]
"""
import base64
import json
import sys
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote_plus

import jwt
from jwt import PyJWKClient

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
CONFIG = Path(__file__).parent / "exchange_config.json"
AUDIT_LOG = Path(__file__).parent / "exchange_audit.log"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
CREDENTIAL_ISSUER = "https://nvcr-exchange-poc.local"

# --- audit logging: every exchange outcome, file-backed, timestamps, no raw tokens ---
import logging  # noqa: E402

AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(AUDIT_LOG), logging.StreamHandler(sys.stdout)],
)
audit = logging.getLogger("exchange-audit")


OUTCOME_EMOJI = {"OK": "✅", "DENIED": "❌"}


def audit_exchange(outcome: str, *, conn_id: str = "-", rev: int = -1, principal: str = "-",
                   subject: str = "-", policies: list | None = None, ttl: int = -1,
                   error: str = "-", audience: str = "-", token_type: str = "-"):
    """SDD section 5 'fail closed and audit': connection/revision/principal/policies/outcome.
    Never logs token material — only the verified subject claim and metadata."""
    audit.info("%s [audit] outcome=%s conn=%s rev=%s principal=%s subject=%s policies=%s "
               "ttl=%ss audience=%s subject_token_type=%s error=%s",
               OUTCOME_EMOJI.get(outcome, "⚠️"), outcome, conn_id, rev, principal, subject,
               policies, ttl, audience, token_type, error)

# --- access-token signing key (fresh per process; served via JWKS) ---
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "exchange-poc-key-1"

CONNECTIONS = {c["connection_id"]: c for c in json.loads(CONFIG.read_text())["connections"]}
GITHUB_JWKS = PyJWKClient(f"{GITHUB_ISSUER}/.well-known/jwks")


def b64u_int(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()


def jwks_document() -> dict:
    nums = SIGNING_KEY.public_key().public_numbers()
    def n_int(x: int) -> str:
        return base64.urlsafe_b64encode(x.to_bytes((x.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                      "n": n_int(nums.n), "e": n_int(nums.e)}]}


def match_policy(policy: dict, claims: dict) -> bool:
    """SDD section 2 operators: equals / one_of / contains, on top-level claims."""
    cond = policy.get("subject_claims", {})
    for claim, expected in cond.get("equals", {}).items():
        if claims.get(claim) != expected:
            return False
    for claim, allowed in cond.get("one_of", {}).items():
        if claims.get(claim) not in allowed:
            return False
    for claim, required in cond.get("contains", {}).items():
        value = claims.get(claim)
        if not isinstance(value, list) or not set(required).issubset(value):
            return False
    return True


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path == "/.well-known/jwks.json":
            self._json(200, jwks_document())
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/oauth/token":
            self._json(404, {"error": "not_found"})
            return
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            params = {}
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[unquote_plus(k)] = unquote_plus(v)
            self._exchange(params)
        except ExchangeError as e:
            self._json(e.status, {"error": e.code, "error_description": e.desc})
        except Exception:  # never leak internals; fail closed
            audit_exchange("DENIED", error="malformed request")
            self._json(400, {"error": "invalid_request", "error_description": "malformed request"})

    def log_message(self, fmt, *args):  # route HTTP access lines into the audit log
        audit.info("http %s", fmt % args)

    def _exchange(self, p: dict):
        if p.get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange":
            audit_exchange("DENIED", error="unsupported_grant_type",
                           audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
            raise ExchangeError(400, "unsupported_grant_type", "unsupported grant")
        subject_token = p.get("subject_token", "")
        conn = CONNECTIONS.get(p.get("connection_id", ""))
        if not conn or not conn.get("enabled"):
            audit_exchange("DENIED", conn_id=p.get("connection_id", "-"), error="unknown or disabled connection",
                           audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
            raise ExchangeError(400, "invalid_request", "unknown or disabled connection")
        if p.get("subject_token_type") != "urn:ietf:params:oauth:token-type:id_token":
            audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                           error="unsupported subject_token_type",
                           audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
            raise ExchangeError(400, "invalid_request", "unsupported subject_token_type")

        # 2.5 the request's audience must be one the CONNECTION accepts (SDD: input-token
        # validation is against connection configuration — the caller cannot widen it)
        if p.get("audience") not in conn.get("subject_audiences", []):
            audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                           error=f"invalid_target (audience {p.get('audience')} not in connection subject_audiences)",
                           audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
            raise ExchangeError(400, "invalid_target", "audience not accepted by this connection")

        # 3. validate the external JWT — signature via GitHub JWKS, issuer, audience, expiry
        try:
            claims = jwt.decode(
                subject_token,
                GITHUB_JWKS.get_signing_key_from_jwt(subject_token).key,
                algorithms=["RS256"],
                audience=p.get("audience"),
                issuer=conn["issuer"],
                leeway=5,
            )
        except jwt.InvalidAudienceError:
            audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                           error="invalid_target (audience not accepted)",
                           audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
            raise ExchangeError(400, "invalid_target", "audience not accepted by this connection")
        except jwt.PyJWTError as e:
            audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                           error=f"subject token rejected: {type(e).__name__}",
                           audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
            raise ExchangeError(400, "invalid_request", f"subject token rejected: {type(e).__name__}")

        # 4. trust policy selection — named policy or all enabled matching policies
        selector = p.get("trust_policy_id")
        policies = conn.get("trust_policies", [])
        if selector:
            selected = [q for q in policies if q["id"] == selector and q.get("enabled")]
            if not selected:
                audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                               principal=conn["principal"]["id"], subject=claims.get("sub", "-"),
                               error=f"invalid/foreign/disabled trust_policy_id={selector}")
                raise ExchangeError(400, "invalid_request", "invalid/foreign/disabled trust_policy_id")
            if not match_policy(selected[0], claims):
                audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                               principal=conn["principal"]["id"], subject=claims.get("sub", "-"),
                               policies=[selector], error="no matching policy (claims did not match)")
                raise ExchangeError(400, "invalid_request", "no matching policy")
        else:
            selected = [q for q in policies if q.get("enabled") and match_policy(q, claims)]
            if not selected:
                audit_exchange("DENIED", conn_id=conn["connection_id"], rev=conn["revision"],
                               principal=conn["principal"]["id"], subject=claims.get("sub", "-"),
                               error="no matching policy")
                raise ExchangeError(400, "invalid_request", "no matching policy")

        # 5. sign the login credential — TTL coupled to the subject token (SDD section 3)
        now = int(time.time())
        exp = min(now + conn["max_token_ttl_seconds"], claims["exp"])
        cred_claims = {
            "iss": CREDENTIAL_ISSUER,
            "aud": p.get("audience"),
            "sub": f"nca:{conn['principal']['id']}",
            "org_id": p.get("org_id", "org-123"),
            "principal_type": conn["principal"]["type"],
            "iat": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "oidc": {
                "connection_id": conn["connection_id"],
                "connection_revision": conn["revision"],
                "trust_policy_ids": [q["id"] for q in selected],
                "issuer": conn["issuer"],
                "subject": claims.get("sub"),
                "subject_token_type": p.get("subject_token_type"),
                "verified_claims": {"sub": claims.get("sub")},
            },
        }
        access_token = jwt.encode(cred_claims, SIGNING_KEY, algorithm="RS256", headers={"kid": KID})
        audit_exchange("OK", conn_id=conn["connection_id"], rev=conn["revision"],
                       principal=conn["principal"]["id"], subject=claims.get("sub", "-"),
                       policies=[q["id"] for q in selected], ttl=exp - now,
                       audience=p.get("audience", "-"), token_type=p.get("subject_token_type", "-"))
        self._json(200, {
            "access_token": access_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": exp - now,
        })

    def _json(self, status: int, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class ExchangeError(Exception):
    def __init__(self, status, code, desc):
        self.status, self.code, self.desc = status, code, desc


if __name__ == "__main__":
    print(f"exchange server on :{PORT} — connections: {list(CONNECTIONS)}", flush=True)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
