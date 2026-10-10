"""RFC 8693 token-exchange client for the NGC registry OIDC federation (SDD §3).

Stdlib only. Two calls:
  mint_id_token()  — GitHub Actions: fetch the OIDC ID token (needs id-token: write)
  exchange()       — POST /oauth/token: swap the ID token for a registry access token
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # RFC 8693 §2.1
TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"


def mint_id_token(audience: str) -> str:
    """Fetch a GitHub OIDC ID token for this job, with the requested audience."""
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote(audience)
    req = urllib.request.Request(url, headers={
        "Authorization": f"bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}",
    })
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)["value"]


def exchange(subject_token: str, *, endpoint: str, org_id: str, connection_id: str,
             audience: str = "nvcr.io", trust_policy_id: str | None = None,
             subject_token_type: str = TYPE_ID_TOKEN, timeout: float = 10.0) -> dict:
    """RFC 8693 §2.1 request → §2.2 response ({access_token, issued_token_type, token_type, expires_in})."""
    form = {
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": subject_token_type,
        "org_id": org_id,              # NGC extension (SDD §3)
        "connection_id": connection_id,  # NGC extension (SDD §3)
        "audience": audience,          # RFC 8693 §2.1 — target of the output token
    }
    if trust_policy_id:
        form["trust_policy_id"] = trust_policy_id
    req = urllib.request.Request(
        endpoint,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"exchange failed: HTTP {e.code}: {detail}") from e


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", default="https://nvcr.io/oauth/token")
    p.add_argument("--org-id", required=True)
    p.add_argument("--connection-id", required=True)
    p.add_argument("--trust-policy-id", default=None)
    p.add_argument("--audience", default="nvcr.io")
    args = p.parse_args()
    token = mint_id_token(args.audience)
    result = exchange(token, endpoint=args.endpoint, org_id=args.org_id,
                      connection_id=args.connection_id,
                      trust_policy_id=args.trust_policy_id, audience=args.audience)
    print(f"expires_in={result.get('expires_in')}s, token_type={result.get('token_type')}")
    print(f"access_token: {len(result['access_token'])} chars (masked)")
