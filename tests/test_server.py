from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
import unittest
from http import HTTPStatus
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from server import build_config, create_server


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def is_probable_prime(candidate: int, rounds: int = 12) -> bool:
    if candidate < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if candidate == p:
            return True
        if candidate % p == 0:
            return False

    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 512) -> dict[str, int]:
    e = 65537
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(e, -1, phi)
        return {"n": n, "e": e, "d": d}


def sign_rs256(signing_input: str, private_key: dict[str, int]) -> bytes:
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + __import__("hashlib").sha256(signing_input.encode("ascii")).digest()
    modulus_len = (private_key["n"].bit_length() + 7) // 8
    padding_len = modulus_len - len(digest_info) - 3
    if padding_len < 8:
        raise ValueError("rsa key too small for rs256")
    em = b"\x00\x01" + (b"\xff" * padding_len) + b"\x00" + digest_info
    sig_int = pow(int.from_bytes(em, "big"), private_key["d"], private_key["n"])
    return sig_int.to_bytes(modulus_len, "big")


def make_jwt(private_key: dict[str, int], kid: str, claims: dict[str, object]) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature_b64 = b64url(sign_rs256(signing_input, private_key))
    return f"{signing_input}.{signature_b64}"


def read_json(url: str, method: str = "GET", token: str | None = None, body: object | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request) as response:
            payload = response.read().decode("utf-8")
            return response.status, json.loads(payload), dict(response.headers.items())
    except HTTPError as exc:
        body_text = exc.read().decode("utf-8")
        return exc.code, json.loads(body_text), dict(exc.headers.items())


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = generate_rsa_keypair()
        cls.kid = "test-key"
        jwk = {
            "kty": "RSA",
            "kid": cls.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url(cls.private_key["n"].to_bytes((cls.private_key["n"].bit_length() + 7) // 8, "big")),
            "e": b64url(cls.private_key["e"].to_bytes((cls.private_key["e"].bit_length() + 7) // 8, "big")),
        }
        cls.old_env = os.environ.copy()
        os.environ["AUTH0_DOMAIN"] = "example.eu.auth0.com"
        os.environ["AUTH0_AUDIENCE"] = "memoire-classification-api"
        os.environ["AUTH0_ISSUER"] = "https://example.eu.auth0.com/"
        os.environ["AUTH0_JWKS_JSON"] = json.dumps({"keys": [jwk]})
        os.environ["DEFAULT_CABINET_ID"] = "cabinet-a"
        os.environ["PUBLIC_BASE_URL"] = "http://127.0.0.1:9999"
        os.environ.pop("CABINET_ID_BY_ORG_JSON", None)
        config = build_config()
        cls.server = create_server("127.0.0.1", 0, config)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        os.environ.clear()
        os.environ.update(cls.old_env)

    def make_token(self) -> str:
        now = int(time.time())
        claims = {
            "sub": "auth0|user-123",
            "aud": "memoire-classification-api",
            "iss": "https://example.eu.auth0.com/",
            "iat": now,
            "exp": now + 300,
            "org_id": "org_123",
            "org_name": "cabinet-a",
        }
        return make_jwt(self.private_key, self.kid, claims)

    def test_health_is_public(self) -> None:
        status, payload, _ = read_json(f"{self.base_url}/health")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(payload, {"ok": True})

    def test_oauth_discovery_metadata_is_exposed(self) -> None:
        status, payload, _ = read_json(f"{self.base_url}/.well-known/oauth-protected-resource")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(payload["resource"], "http://127.0.0.1:9999")
        self.assertEqual(payload["authorization_servers"], ["http://127.0.0.1:9999/"])

        status, payload, _ = read_json(f"{self.base_url}/.well-known/oauth-authorization-server")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(payload["issuer"], "http://127.0.0.1:9999/")
        self.assertEqual(payload["token_endpoint"], "https://example.eu.auth0.com/oauth/token")

    def test_whoami_requires_token(self) -> None:
        status, payload, headers = read_json(f"{self.base_url}/whoami")
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(payload["error"], "invalid_token")
        self.assertIn("WWW-Authenticate", headers)
        self.assertIn("resource_metadata", headers["WWW-Authenticate"])

    def test_mcp_requires_token_exposes_resource_metadata(self) -> None:
        status, payload, headers = read_json(
            f"{self.base_url}/mcp",
            method="POST",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(payload["error"], "invalid_token")
        self.assertIn("WWW-Authenticate", headers)
        self.assertIn("resource_metadata", headers["WWW-Authenticate"])
        self.assertIn("/.well-known/oauth-protected-resource", headers["WWW-Authenticate"])

    def test_whoami_accepts_valid_auth0_token(self) -> None:
        token = self.make_token()
        status, payload, _ = read_json(f"{self.base_url}/whoami", token=token)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(
            payload,
            {"sub": "auth0|user-123", "org_id": "org_123", "cabinet_id": "cabinet-a"},
        )

    def test_mcp_tool_returns_same_identity(self) -> None:
        token = self.make_token()
        status, payload, _ = read_json(
            f"{self.base_url}/mcp",
            method="POST",
            token=token,
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}},
        )
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(payload["result"]["structuredContent"]["cabinet_id"], "cabinet-a")
        self.assertEqual(payload["result"]["structuredContent"]["org_id"], "org_123")

    def test_mcp_initialized_notification_is_accepted(self) -> None:
        token = self.make_token()
        request = Request(
            f"{self.base_url}/mcp",
            data=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}).encode("utf-8"),
            method="POST",
        )
        request.add_header("Accept", "application/json")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", f"Bearer {token}")
        with urlopen(request) as response:
            self.assertEqual(response.status, HTTPStatus.NO_CONTENT)
            self.assertEqual(response.read(), b"")


if __name__ == "__main__":
    unittest.main()
