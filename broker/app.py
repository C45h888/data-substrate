"""Project-scoped credential exchange and Hasura Community Edition auth hook.

Thin transport layer: HTTP parsing, status mapping, and audit recording.
Lifecycle logic lives in tokens.py, key management in keys.py, and rate
limiting in ratelimit.py.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from keys import LEGACY_KID, KeyStore, key_dir_configured
from ratelimit import ExchangeLimiters
from tokens import (
    HASURA_CLAIMS,
    PUBLIC_ROLE,
    SERVICE_ROLE,
    WRITER_ROLE,
    TokenDenied,
    TokenUnavailable,
    authorize_hook_token,
    check_credential_active,
    mint_with_secret,
    verify_broker_token,
)

AUDIT_LOGGER = logging.getLogger("broker.audit")


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
    key_dir: str = "/run/broker-keys"
    key_poll_seconds: int = 15
    token_ttl_seconds: int = 600

    @classmethod
    def from_env(cls) -> "Settings":
        import os

        return cls(
            database_url=os.environ["BROKER_DATABASE_URL"],
            auth_url=os.getenv("BROKER_AUTH_URL", "http://auth:4000/v1").rstrip("/"),
            issuer=os.getenv("BROKER_TOKEN_ISSUER", "https://api.888intelligence.org/broker"),
            audience=os.getenv("BROKER_TOKEN_AUDIENCE", "hasura"),
            private_key_file=os.getenv("BROKER_PRIVATE_KEY_FILE", "/run/broker-keys/private.pem"),
            public_key_file=os.getenv("BROKER_PUBLIC_KEY_FILE", "/run/broker-keys/public.pem"),
            key_dir=os.getenv("BROKER_KEY_DIR", "/run/broker-keys"),
            key_poll_seconds=int(os.getenv("BROKER_KEY_POLL_SECONDS", "15")),
            token_ttl_seconds=int(os.getenv("BROKER_TOKEN_TTL_SECONDS", "600")),
        )


class CredentialRepository(Protocol):
    def get(self, credential_id: str) -> dict[str, Any] | None: ...


class DecisionAudit(Protocol):
    """Decision-only audit sink. Never receives tokens or request bodies."""

    def record(
        self,
        decision: str,
        credential_id: str | None = None,
        role: str | None = None,
        jti: str | None = None,
        detail: str | None = None,
    ) -> None: ...


class PostgresDecisionAudit:
    """Write-only INSERTs into platform.credential_decisions.

    Best-effort: a failed audit write is logged but never blocks or alters an
    auth decision (availability is chosen over audit completeness; documented
    in docs/api-gateway/project-isolation/BROKER.md).
    """

    def __init__(self, dsn: str):
        self.dsn = dsn

    def record(
        self,
        decision: str,
        credential_id: str | None = None,
        role: str | None = None,
        jti: str | None = None,
        detail: str | None = None,
    ) -> None:
        try:
            import psycopg

            with psycopg.connect(self.dsn, connect_timeout=2) as conn:
                conn.execute(
                    """
                    INSERT INTO platform.credential_decisions
                        (decision, credential_id, role, jti, detail)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (decision, credential_id, role, jti, detail),
                )
                conn.commit()
        except Exception:
            AUDIT_LOGGER.warning("credential decision audit write failed", exc_info=True)


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
                       status, revoked_at, scopes
                FROM platform.api_credentials
                WHERE credential_id = %s
                """,
                (credential_id,),
            ).fetchone()


class ExchangeBody(BaseModel):
    key_id: str = Field(min_length=12, max_length=80, pattern=r"^(pub|svc)_[A-Za-z0-9_-]+$")
    key_secret: str | None = Field(default=None, min_length=32, max_length=160)
    scope: str | None = Field(default=None, min_length=3, max_length=32, pattern=r"^[a-z_]+$")


class _Signer(Protocol):
    def sign(self, claims: dict[str, Any]) -> str: ...
    def key_for_kid(self, kid: str | None) -> str: ...
    def all_keys(self) -> dict[str, str]: ...
    def jwks(self) -> dict: ...


class _LegacySigner:
    """Single keypair passed explicitly (tests and pre-rotation deployments)."""

    def __init__(self, private_key: str, public_key: str):
        self._private = private_key
        self._public = public_key

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self._private, algorithm="RS256")

    def key_for_kid(self, kid: str | None) -> str:
        if kid in (None, LEGACY_KID):
            return self._public
        raise KeyError(f"unknown kid: {kid}")

    def all_keys(self) -> dict[str, str]:
        return {LEGACY_KID: self._public}

    def jwks(self) -> dict:
        from keys import _public_to_jwk

        return {"keys": [_public_to_jwk(self._public, LEGACY_KID)]}


class _StoreSigner:
    """KeyStore-backed signer: newest kid signs, every kid verifies."""

    def __init__(self, store: KeyStore):
        self._store = store

    def sign(self, claims: dict[str, Any]) -> str:
        self._store.maybe_refresh()
        kid, private = self._store.signing_key()
        return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid})

    def key_for_kid(self, kid: str | None) -> str:
        self._store.maybe_refresh()
        return self._store.verification_key(kid)

    def all_keys(self) -> dict[str, str]:
        self._store.maybe_refresh()
        return self._store.verification_keys()

    def jwks(self) -> dict:
        self._store.maybe_refresh()
        return self._store.jwks()


def create_app(
    settings: Settings | None = None,
    repository: CredentialRepository | None = None,
    auth_verify: Callable[[str], bool] | None = None,
    private_key: str | None = None,
    public_key: str | None = None,
    audit: DecisionAudit | None = None,
    key_store: KeyStore | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    repository = repository or PostgresCredentialRepository(settings.database_url)
    audit = audit or PostgresDecisionAudit(settings.database_url)
    if key_store is not None:
        signer: _Signer = _StoreSigner(key_store)
    elif private_key is not None or public_key is not None:
        signer = _LegacySigner(private_key or "", public_key or "")
    elif key_dir_configured() or Path(settings.key_dir).is_dir():
        signer = _StoreSigner(KeyStore(settings.key_dir, settings.key_poll_seconds))
    else:
        signer = _LegacySigner(
            Path(settings.private_key_file).read_text(),
            Path(settings.public_key_file).read_text(),
        )

    def verify_nhost_token(token: str) -> bool:
        # Fail fast: no broker-internal retry. Retry lives caller-side.
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
    limiters = ExchangeLimiters()

    def denied(detail: str, **context: Any) -> Unauthorized:
        audit.record("denied", detail=detail, **context)
        return Unauthorized(detail)

    @app.exception_handler(Unauthorized)
    async def unauthorized_handler(_request: Request, _exc: Unauthorized):
        return JSONResponse(status_code=401, content={"message": "unauthorized"})

    @app.exception_handler(Unavailable)
    async def unavailable_handler(_request: Request, _exc: Unavailable):
        return JSONResponse(status_code=503, content={"message": "authentication unavailable"})

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    def jwks():
        return JSONResponse(signer.jwks())

    @app.post("/v1/token")
    def exchange_token(body: ExchangeBody, request: Request):
        ip = request.client.host if request.client else "unknown"
        kind = "public" if body.key_id.startswith("pub_") else "service"
        cap = limiters.check(kind, ip, body.key_id)
        if cap is not None:
            total = limiters.deny_counter.inc(cap)
            AUDIT_LOGGER.warning("exchange %s count=%d", cap, total)
            audit.record("denied", credential_id=body.key_id, detail=cap)
            return JSONResponse(status_code=429, content={"message": "rate limit exceeded"})

        row = repository.get(body.key_id)
        try:
            check_credential_active(row)
            assert row is not None
            if row["credential_kind"] != kind:
                raise TokenDenied("kind_mismatch")
            token, token_jti, role, _scope = mint_with_secret(
                row,
                kind,
                body.key_secret,
                body.scope,
                issuer=settings.issuer,
                audience=settings.audience,
                ttl_seconds=settings.token_ttl_seconds,
                sign=signer.sign,
            )
        except TokenDenied as exc:
            raise denied(
                exc.detail,
                credential_id=body.key_id,
                jti=exc.context.get("jti"),
            ) from exc
        audit.record("issued", credential_id=body.key_id, role=role, jti=token_jti, detail="exchange")
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
            return _authorize_broker_token(token, headers)

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
        audit.record("allowed", role="user", detail="nhost_user")
        return {
            "x-hasura-user-id": user_id,
            "x-hasura-role": "user",
            "x-hasura-allowed-roles": ["user"],
        }

    def _authorize_broker_token(token: str, headers: dict[str, Any]) -> dict[str, str | list[str]]:
        try:
            claims = verify_broker_token(
                token,
                issuer=settings.issuer,
                key_for_kid=signer.key_for_kid,
                try_all_keys=signer.all_keys,
            )
        except TokenDenied as exc:
            raise denied("invalid_token", jti=_safe_jti(token)) from exc

        credential_id = claims["sub"]
        row = repository.get(credential_id)
        try:
            check_credential_active(row)
            assert row is not None
            session = authorize_hook_token(claims, row, headers, audience=settings.audience)
        except TokenDenied as exc:
            raise denied(
                exc.detail,
                credential_id=exc.context.get("credential_id", credential_id),
                jti=exc.context.get("jti"),
            ) from exc
        audit.record(
            "allowed",
            credential_id=credential_id,
            role=str(session["x-hasura-role"]),
            jti=claims.get("jti"),
            detail="hook",
        )
        return session

    return app


def _safe_jti(token: str) -> str | None:
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
        )
    except jwt.PyJWTError:
        return None
    jti = claims.get("jti") if isinstance(claims, dict) else None
    return str(jti) if jti else None


def _decode_unverified(token: str) -> dict[str, Any]:
    try:
        value = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise Unauthorized from exc
    return value if isinstance(value, dict) else {}
