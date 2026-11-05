#!/usr/bin/env python3
"""LAB10: decode an exchanged NTS JWT and verify its ES256 signature against the
service's published JWKS. No third-party deps: P-256 JWK -> SPKI PEM by hand,
raw r||s signature -> DER by hand, openssl does the verification.

Usage: lab10_verify_jwt.py <jwt> <jwks-url>
Prints one JSON object: {alg, kid, claims..., signature: "verified"|"FAILED"}.
Exit 0 only when the signature verifies and the required claims are present.
"""
import base64
import json
import ssl
import subprocess
import sys
import tempfile
import urllib.request

SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def b64u(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def der_sig(raw):
    def integer(n):
        n = n.lstrip(b"\x00") or b"\x00"
        if n[0] & 0x80:
            n = b"\x00" + n
        return bytes([0x02, len(n)]) + n
    half = len(raw) // 2
    body = integer(raw[:half]) + integer(raw[half:])
    return bytes([0x30, len(body)]) + body


def main():
    jwt, jwks_url = sys.argv[1], sys.argv[2]
    try:
        head_b64, payload_b64, sig_b64 = jwt.split(".")
        header = json.loads(b64u(head_b64))
        claims = json.loads(b64u(payload_b64))
        raw_sig = b64u(sig_b64)
    except Exception as e:
        print(json.dumps({"error": "unparseable JWT: %s" % e}))
        return 1

    with urllib.request.urlopen(urllib.request.Request(jwks_url), timeout=20,
                                context=ssl.create_default_context()) as resp:
        jwks = json.load(resp)
    jwk = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
    if jwk is None:
        print(json.dumps({"error": "kid not in JWKS", "kid": header.get("kid"),
                          "jwks_kids": [k.get("kid") for k in jwks["keys"]]}))
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        pem = ("-----BEGIN PUBLIC KEY-----\n"
               + base64.encodebytes(SPKI_P256_PREFIX + b"\x04" + b64u(jwk["x"]) + b64u(jwk["y"])).decode()
               + "-----END PUBLIC KEY-----\n")
        pubkey = tmp + "/pub.pem"
        sig = tmp + "/sig.der"
        open(pubkey, "w").write(pem)
        open(sig, "wb").write(der_sig(raw_sig))
        ok = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pubkey, "-signature", sig],
            input=f"{head_b64}.{payload_b64}".encode(),
            capture_output=True).returncode == 0

    out = {
        "alg": header.get("alg"),
        "kid": header.get("kid"),
        "typ": header.get("typ"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "sub": claims.get("sub"),
        "exp": claims.get("exp"),
        "nbf": claims.get("nbf"),
        "iat": claims.get("iat"),
        "assertion": claims.get("assertion"),
        "signature": "verified" if ok else "FAILED",
    }
    print(json.dumps(out))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
