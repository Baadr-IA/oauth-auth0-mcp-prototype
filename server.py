from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.error import URLError
from urllib.request import Request, urlopen


SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000
DEFAULT_SERVER_NAME = "memoire-classification-api"
DEFAULT_SERVER_VERSION = "0.1.0"


class AuthError(Exception):
    def __init__(self, status: int, message: str, error: str = "invalid_token") -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.error = error


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def parse_bearer_token(header_value: str | None) -> str:
    if not header_value:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "missing bearer token")
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError(HTTPStatus.UNAUTHORIZED, "missing bearer token")
    return token.strip()


def normalize_audience(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "malformed jwt") from exc

    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(signature_b64)
    except Exception as exc:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "invalid jwt encoding") from exc

    signing_input = f"{header_b64}.{payload_b64}"
    return header, payload, signature, signing_input


def rsa_verify_rs256(signing_input: str, signature: bytes, jwk: dict[str, Any]) -> None:
    if jwk.get("kty") != "RSA":
        raise AuthError(HTTPStatus.UNAUTHORIZED, "unsupported jwk type")

    try:
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    except Exception as exc:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "invalid jwk") from exc

    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "invalid signature length")

    sig_int = int.from_bytes(signature, "big")
    em_int = pow(sig_int, e, n)
    em = em_int.to_bytes(k, "big")

    digest = hashlib.sha256(signing_input.encode("ascii")).digest()
    expected = b"\x00\x01" + (b"\xff" * (k - len(SHA256_DER_PREFIX) - len(digest) - 3)) + b"\x00" + SHA256_DER_PREFIX + digest
    if em != expected:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "signature verification failed")


def fetch_jwks(config: "AppConfig", opener: Callable[[Request], Any] = urlopen) -> dict[str, Any]:
    if config.auth0_jwks_json:
        return json.loads(config.auth0_jwks_json)

    cache_key = (config.auth0_domain, config.auth0_jwks_url)
    now = time.time()
    if config._jwks_cache and config._jwks_cache[0] == cache_key and config._jwks_cache[2] > now:
        return config._jwks_cache[1]

    if config.auth0_jwks_url:
        jwks_url = config.auth0_jwks_url
    else:
        if not config.auth0_domain:
            raise AuthError(HTTPStatus.INTERNAL_SERVER_ERROR, "AUTH0_DOMAIN is required for token validation", error="server_misconfigured")
        jwks_url = f"https://{config.auth0_domain}/.well-known/jwks.json"

    request = Request(jwks_url, headers={"Accept": "application/json"})
    try:
        with opener(request) as response:
            jwks = json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise AuthError(HTTPStatus.INTERNAL_SERVER_ERROR, "unable to fetch jwks", error="jwks_unavailable") from exc

    config._jwks_cache = (cache_key, jwks, now + config.jwks_cache_ttl)
    return jwks


def find_jwk(jwks: dict[str, Any], kid: str | None) -> dict[str, Any]:
    keys = jwks.get("keys", [])
    if not isinstance(keys, list):
        raise AuthError(HTTPStatus.UNAUTHORIZED, "invalid jwks")

    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return key
        raise AuthError(HTTPStatus.UNAUTHORIZED, f"unknown kid: {kid}")

    if len(keys) == 1:
        return keys[0]

    raise AuthError(HTTPStatus.UNAUTHORIZED, "missing kid")


def verify_auth0_jwt(config: "AppConfig", token: str) -> dict[str, Any]:
    header, payload, signature, signing_input = parse_jwt(token)

    if header.get("alg") != "RS256":
        raise AuthError(HTTPStatus.UNAUTHORIZED, "unexpected jwt algorithm")

    jwks = fetch_jwks(config)
    jwk = find_jwk(jwks, header.get("kid"))
    rsa_verify_rs256(signing_input, signature, jwk)

    expected_issuer = config.auth0_issuer
    actual_issuer = payload.get("iss")
    if actual_issuer != expected_issuer:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "invalid issuer")

    audience_claim = normalize_audience(payload.get("aud"))
    if config.auth0_audience not in audience_claim:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "invalid audience")

    now = int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= now - config.clock_skew_seconds:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "token expired")

    nbf = payload.get("nbf")
    if isinstance(nbf, int) and nbf > now + config.clock_skew_seconds:
        raise AuthError(HTTPStatus.UNAUTHORIZED, "token not yet valid")

    return payload


def resolve_cabinet_id(config: "AppConfig", claims: dict[str, Any]) -> str:
    for key in ("cabinet_id", "org_name", "organization_name", "organization"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    org_id = claims.get("org_id")
    if isinstance(org_id, str):
        mapped = config.cabinet_id_by_org.get(org_id)
        if mapped:
            return mapped

    if config.default_cabinet_id:
        return config.default_cabinet_id

    raise AuthError(HTTPStatus.INTERNAL_SERVER_ERROR, "unable to resolve cabinet_id", error="missing_tenant_mapping")


def whoami_payload(config: "AppConfig", claims: dict[str, Any]) -> dict[str, Any]:
    cabinet_id = resolve_cabinet_id(config, claims)
    org_id = claims.get("org_id")
    if not isinstance(org_id, str) or not org_id.strip():
        raise AuthError(HTTPStatus.UNAUTHORIZED, "missing org_id")

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise AuthError(HTTPStatus.UNAUTHORIZED, "missing subject")

    return {"sub": sub, "org_id": org_id, "cabinet_id": cabinet_id}


@dataclass
class AppConfig:
    auth0_domain: str | None
    auth0_audience: str
    auth0_issuer: str
    auth0_jwks_url: str | None
    auth0_jwks_json: str | None
    public_base_url: str | None
    cabinet_id_by_org: dict[str, str]
    default_cabinet_id: str | None
    cors_allowed_origins: set[str]
    clock_skew_seconds: int = 60
    jwks_cache_ttl: int = 300
    _jwks_cache: tuple[tuple[str | None, str | None], dict[str, Any], float] | None = None


def build_config() -> AppConfig:
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    auth0_audience = os.environ.get("AUTH0_AUDIENCE", "")
    if not auth0_audience:
        raise SystemExit("AUTH0_AUDIENCE is required")

    auth0_issuer = os.environ.get("AUTH0_ISSUER")
    if not auth0_issuer:
        if auth0_domain:
            auth0_issuer = f"https://{auth0_domain}/"
        else:
            auth0_issuer = ""

    cabinet_id_by_org = {}
    raw_mapping = os.environ.get("CABINET_ID_BY_ORG_JSON")
    if raw_mapping:
        loaded = json.loads(raw_mapping)
        if not isinstance(loaded, dict):
            raise SystemExit("CABINET_ID_BY_ORG_JSON must be a JSON object")
        cabinet_id_by_org = {str(key): str(value) for key, value in loaded.items()}

    default_cabinet_id = os.environ.get("DEFAULT_CABINET_ID")
    cors_allowed_origins = {
        origin.strip()
        for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    }
    return AppConfig(
        auth0_domain=auth0_domain,
        auth0_audience=auth0_audience,
        auth0_issuer=auth0_issuer,
        auth0_jwks_url=os.environ.get("AUTH0_JWKS_URL"),
        auth0_jwks_json=os.environ.get("AUTH0_JWKS_JSON"),
        public_base_url=os.environ.get("PUBLIC_BASE_URL"),
        cabinet_id_by_org=cabinet_id_by_org,
        default_cabinet_id=default_cabinet_id,
        cors_allowed_origins=cors_allowed_origins,
    )


def request_to_json(handler: BaseHTTPRequestHandler) -> Any:
    content_length = int(handler.headers.get("Content-Length", "0"))
    if content_length <= 0:
        return None
    raw = handler.rfile.read(content_length)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise AuthError(HTTPStatus.BAD_REQUEST, "invalid json body", error="invalid_request") from exc


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    if headers:
        for key, value in headers.items():
            handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def bearer_challenge(message: str) -> str:
    safe = message.replace('"', "'")
    return f'Bearer realm="{DEFAULT_SERVER_NAME}", error="invalid_token", error_description="{safe}"'


def normalize_base_url(value: str | None) -> str | None:
    if not value:
        return None
    return value.rstrip("/")


def current_base_url(handler: BaseHTTPRequestHandler) -> str:
    configured = normalize_base_url(handler.config.public_base_url)
    if configured:
        return configured

    forwarded_proto = handler.headers.get("X-Forwarded-Proto")
    scheme = forwarded_proto.split(",")[0].strip() if forwarded_proto else "http"

    forwarded_host = handler.headers.get("X-Forwarded-Host")
    host = forwarded_host.split(",")[0].strip() if forwarded_host else handler.headers.get("Host")
    if not host:
        host = f"{handler.server.server_address[0]}:{handler.server.server_address[1]}"

    return f"{scheme}://{host}"


def authorization_server_metadata(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    config = handler.config
    auth0_issuer = config.auth0_issuer.rstrip("/") + "/"
    issuer = current_base_url(handler).rstrip("/") + "/"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{auth0_issuer}authorize",
        "token_endpoint": f"{auth0_issuer}oauth/token",
        "jwks_uri": config.auth0_jwks_url or f"{auth0_issuer}.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ],
    }


def protected_resource_metadata(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    issuer = current_base_url(handler).rstrip("/") + "/"
    return {
        "resource": current_base_url(handler),
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f"{DEFAULT_SERVER_NAME}/{DEFAULT_SERVER_VERSION}"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    @property
    def config(self) -> AppConfig:
        return self.server.config  # type: ignore[attr-defined]

    def cors_headers(self, preflight: bool = False) -> dict[str, str]:
        origin = self.headers.get("Origin")
        if not origin or origin not in self.config.cors_allowed_origins:
            return {}

        headers = {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
        }
        if preflight:
            headers.update(
                {
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Authorization, Content-Type",
                    "Access-Control-Max-Age": "600",
                }
            )
        return headers

    def _authenticate(self) -> dict[str, Any]:
        token = parse_bearer_token(self.headers.get("Authorization"))
        return verify_auth0_jwt(self.config, token)

    def _send_auth_error(self, error: AuthError) -> None:
        headers = {"WWW-Authenticate": bearer_challenge(error.message)}
        headers.update(self.cors_headers())
        json_response(
            self,
            error.status,
            {"error": error.error, "error_description": error.message},
            headers=headers,
        )

    def do_OPTIONS(self) -> None:  # noqa: N802
        headers = self.cors_headers(preflight=True)
        self.send_response(HTTPStatus.NO_CONTENT)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path

        if path == "/.well-known/oauth-authorization-server":
            json_response(self, HTTPStatus.OK, authorization_server_metadata(self), headers=self.cors_headers())
            return

        if path == "/.well-known/oauth-protected-resource":
            json_response(self, HTTPStatus.OK, protected_resource_metadata(self), headers=self.cors_headers())
            return

        if path == "/health":
            json_response(self, HTTPStatus.OK, {"ok": True}, headers=self.cors_headers())
            return

        if path == "/whoami":
            try:
                claims = self._authenticate()
                json_response(self, HTTPStatus.OK, whoami_payload(self.config, claims), headers=self.cors_headers())
            except AuthError as error:
                self._send_auth_error(error)
            return

        json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"}, headers=self.cors_headers())

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/mcp":
            json_response(self, HTTPStatus.NOT_FOUND, {"error": "not_found"}, headers=self.cors_headers())
            return

        try:
            claims = self._authenticate()
            request = request_to_json(self)
            response = self.handle_mcp_request(request, claims)
            if response is None:
                self.send_response(HTTPStatus.NO_CONTENT)
                for key, value in self.cors_headers().items():
                    self.send_header(key, value)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            json_response(self, HTTPStatus.OK, response, headers=self.cors_headers())
        except AuthError as error:
            self._send_auth_error(error)

    def handle_mcp_request(self, request: Any, claims: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise AuthError(HTTPStatus.BAD_REQUEST, "json-rpc request must be an object", error="invalid_request")

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if request.get("jsonrpc") != "2.0" or not isinstance(method, str):
            raise AuthError(HTTPStatus.BAD_REQUEST, "invalid json-rpc envelope", error="invalid_request")

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": DEFAULT_SERVER_NAME, "version": DEFAULT_SERVER_VERSION},
                "capabilities": {"tools": {}},
            }
            return {"jsonrpc": "2.0", "id": request_id, "result": result}

        if method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "whoami",
                        "description": "Return the authenticated user, org_id, and resolved cabinet_id.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
            return {"jsonrpc": "2.0", "id": request_id, "result": result}

        if method == "notifications/initialized":
            # The MCP client sends this standard notification after initialize.
            # Treat it as a no-op instead of failing the session handshake.
            return None

        if method == "tools/call":
            if not isinstance(params, dict):
                raise AuthError(HTTPStatus.BAD_REQUEST, "invalid tools/call params", error="invalid_request")
            if params.get("name") != "whoami":
                raise AuthError(HTTPStatus.BAD_REQUEST, "unknown tool", error="invalid_request")

            result = whoami_payload(self.config, claims)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                    "structuredContent": result,
                },
            }

        raise AuthError(HTTPStatus.NOT_FOUND, f"unknown method: {method}", error="method_not_found")

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:  # noqa: A003
        payload = {"error": message or HTTPStatus(code).phrase.lower()}
        json_response(self, code, payload, headers=self.cors_headers())


class AppServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], config: AppConfig):
        super().__init__(server_address, RequestHandlerClass)
        self.config = config


def create_server(host: str, port: int, config: AppConfig) -> AppServer:
    return AppServer((host, port), Handler, config)


def run(host: str, port: int) -> None:
    config = build_config()
    server = create_server(host, port, config)
    print(f"Serving on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal Auth0-protected MCP prototype")
    parser.add_argument("--host", default=os.environ.get("HOST", DEFAULT_HOST))
    parser.add_argument("--port", default=int(os.environ.get("PORT", DEFAULT_PORT)), type=int)
    args = parser.parse_args()
    run(args.host, args.port)


if __name__ == "__main__":
    main()
