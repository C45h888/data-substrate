"""Project-scoped credential exchange and Hasura Community Edition auth hook."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

HASURA_CLAIMS = "https://hasura.io/jwt/claims"
PUBLIC_ROLE = "client_public"
SERVICE_ROLE = "service_reader"


class Unauthorized(Exception):
    pass


class Unavailable(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str
    auth_url: str
    issuer: str
    audience: str
    private_key_file: str
    public_key_file: str
    token_ttl_seconds: int = 600

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_url=os.environ["BROKER_DATABASE_URL"],
            auth_url=os.getenv("BROKER_AUTH_URL", "http://auth:4000/v1").rstrip("/"),
            issuer=os.getenv("BROKER_TOKEN_ISSUER", "https://api.888intelligence.org/broker"),
            audience=os.getenv("BROKER_TOKEN_AUDIENCE", "hasura"),
            private_key_file=os.getenv("BROKER_PRIVATE_KEY_FILE", "/run/broker-keys/private.pem"),
            public_key_file=os.getenv("BROKER_PUBLIC_KEY_FILE", "/run/broker-keys/public.pem"),
            token_ttl_seconds=int(os.getenv("BROKER_TOKEN_TTL_SECONDS", "600")),
        )


class CredentialRepository(Protocol):
    def get(self, credential_id: str) -> dict[str, Any] | None: ...


class PostgresCredentialRepository:
    """Read-only runtime access to the credential registry."""

    def __init__(self, dsn: str):
        self.dsn = dsn

    def get(self, credential_id: str) -> dict[str, Any] | None:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(self.dsn, row_factory=dict_row, connect_timeout=2) as conn:
            return conn.execute(
                """
                SELECT credential_id, project_id, credential_kind, secret_hash,
                       status, revoked_at
                FROM platform.api_credentials
                WHERE credential_id = %s
                """,
                (credential_id,),
            ).fetchone()


class ExchangeBody(BaseModel):
    key_id: str = Field(min_length=12, max_length=80, pattern=r"^(pub|svc)_[A-Za-z0-9_-]+$")
    key_secret: str | None = Field(default=None, min_length=32, max_length=160)


class IpRateLimit:
    """Single-process guardrail; Nginx remains the perimeter rate limiter."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.hits: dict[tuple[str, int], int] = {}
        self.lock = threading.Lock()

    def allow(self, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        bucket = int(now // self.window_seconds)
        key = (ip, bucket)
        with self.lock:
            count = self.hits.get(key, 0) + 1
            self.hits[key] = count
            # Bound memory while removing expired windows.
            for old in [item for item in self.hits if item[1] < bucket - 1]:
                self.hits.pop(old, None)
            return count <= self.limit


def create_app(
    settings: Settings | None = None,
    repository: CredentialRepository | None = None,
    auth_verify: Callable[[str], bool] | None = None,
    private_key: str | None = None,
    public_key: str | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    repository = repository or PostgresCredentialRepository(settings.database_url)
    private_key = private_key or Path(settings.private_key_file).read_text()
    public_key = public_key or Path(settings.public_key_file).read_text()

    def verify_nhost_token(token: str) -> bool:
        try:
            response = httpx.post(
                settings.auth_url + "/token/verify",
                headers={"Authorization": f"Bearer {token}"},
                timeout=3.0,
            )
        except httpx.HTTPError as exc:
            raise Unavailable from exc
        if response.status_code == 200:
            return True
        if response.status_code in (400, 401, 403):
            return False
        raise Unavailable

    auth_verify = auth_verify or verify_nhost_token
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    public_limiter = IpRateLimit(60)
    service_limiter = IpRateLimit(10)

    @app.exception_handler(Unauthorized)
    async def unauthorized_handler(_request: Request, _exc: Unauthorized):
        return JSONResponse(status_code=401, content={"message": "unauthorized"})

    @app.exception_handler(Unavailable)
    async def unavailable_handler(_request: Request, _exc: Unavailable):
        return JSONResponse(status_code=503, content={"message": "authentication unavailable"})

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/v1/token")
    def exchange_token(body: ExchangeBody, request: Request):
        ip = request.client.host if request.client else "unknown"
        kind = "public" if body.key_id.startswith("pub_") else "service"
        limiter = public_limiter if kind == "public" else service_limiter
        if not limiter.allow(ip):
            return JSONResponse(status_code=429, content={"message": "rate limit exceeded"})

        row = repository.get(body.key_id)
        if not row or row["status"] != "active" or row["revoked_at"] is not None:
            raise Unauthorized
        if row["credential_kind"] != kind:
            raise Unauthorized

        if kind == "public":
            if body.key_secret is not None or row["secret_hash"] is not None:
                raise Unauthorized
            role = PUBLIC_ROLE
        else:
            if not body.key_secret or row["secret_hash"] is None:
                raise Unauthorized
            presented_hash = hashlib.sha256(body.key_secret.encode()).digest()
            stored_hash = bytes(row["secret_hash"])
            if not hmac.compare_digest(presented_hash, stored_hash):
                raise Unauthorized
            role = SERVICE_ROLE

        now = int(time.time())
        claims = {
            "iss": settings.issuer,
            "aud": settings.audience,
            "sub": body.key_id,
            "iat": now,
            "nbf": now,
            "exp": now + settings.token_ttl_seconds,
            "credential_kind": kind,
            "project_id": row["project_id"],
            HASURA_CLAIMS: {
                "x-hasura-allowed-roles": [role],
                "x-hasura-default-role": role,
                "x-hasura-project-id": str(row["project_id"]),
            },
        }
        token = jwt.encode(claims, private_key, algorithm="RS256")
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": settings.token_ttl_seconds,
            "role": role,
        }

    @app.post("/internal/hasura-auth")
    def hasura_auth(payload: dict[str, Any]):
        raw_headers = payload.get("headers", {})
        headers = {str(key).lower(): value for key, value in raw_headers.items()}
        authorization = headers.get("authorization")
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise Unauthorized
        token = authorization[7:].strip()
        if not token:
            raise Unauthorized

        unverified = _decode_unverified(token)
        if unverified.get("iss") == settings.issuer:
            return _authorize_broker_token(
                token, headers, settings, public_key, repository
            )

        # Existing Nhost user JWTs are verified by Nhost Auth itself. The hook
        # only reads their claims after the Auth service returns success.
        try:
            valid = auth_verify(token)
        except Unavailable:
            raise
        except Exception as exc:
            raise Unavailable from exc
        if not valid:
            raise Unauthorized
        claims = _decode_unverified(token)
        hasura = claims.get(HASURA_CLAIMS, {})
        if isinstance(hasura, str):
            try:
                hasura = json.loads(hasura)
            except json.JSONDecodeError:
                raise Unauthorized
        if not isinstance(hasura, dict):
            raise Unauthorized
        user_id = hasura.get("x-hasura-user-id") or claims.get("sub")
        allowed = hasura.get("x-hasura-allowed-roles", [])
        default = hasura.get("x-hasura-default-role")
        if (
            not isinstance(user_id, str)
            or not isinstance(allowed, list)
            or "user" not in allowed
            or default != "user"
        ):
            raise Unauthorized
        requested_role = headers.get("x-hasura-role")
        if requested_role not in (None, "user"):
            raise Unauthorized
        return {
            "x-hasura-user-id": user_id,
            "x-hasura-role": "user",
            "x-hasura-allowed-roles": ["user"],
        }

    return app


def _decode_unverified(token: str) -> dict[str, Any]:
    try:
        value = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise Unauthorized from exc
    return value if isinstance(value, dict) else {}


def _authorize_broker_token(
    token: str,
    headers: dict[str, Any],
    settings: Settings,
    public_key: str,
    repository: CredentialRepository,
) -> dict[str, str | list[str]]:
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=settings.issuer,
            audience=settings.audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise Unauthorized from exc

    credential_id = claims["sub"]
    row = repository.get(credential_id)
    if not row or row["status"] != "active" or row["revoked_at"] is not None:
        raise Unauthorized
    role = PUBLIC_ROLE if row["credential_kind"] == "public" else SERVICE_ROLE
    expected_kind = "public" if role == PUBLIC_ROLE else "service"
    if (
        claims.get("credential_kind") != expected_kind
        or str(claims.get("project_id")) != str(row["project_id"])
    ):
        raise Unauthorized
    namespace = claims.get(HASURA_CLAIMS)
    if not isinstance(namespace, dict):
        raise Unauthorized
    if (
        namespace.get("x-hasura-default-role") != role
        or namespace.get("x-hasura-allowed-roles") != [role]
        or str(namespace.get("x-hasura-project-id")) != str(row["project_id"])
    ):
        raise Unauthorized
    requested_role = headers.get("x-hasura-role")
    if requested_role not in (None, role):
        raise Unauthorized
    return {
        "x-hasura-role": role,
        "x-hasura-allowed-roles": [role],
        "x-hasura-project-id": str(row["project_id"]),
    }
