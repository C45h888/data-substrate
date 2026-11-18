"""Token lifecycle: mint, verify, and scope->role authorization.

Pure lifecycle logic lives here; transport (FastAPI) stays in app.py.
Errors are module-local so the transport layer can map them to status
codes without importing transport concerns.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable, Protocol

import jwt

HASURA_CLAIMS = "https://hasura.io/jwt/claims"
PUBLIC_ROLE = "client_public"
SERVICE_ROLE = "service_reader"
WRITER_ROLE = "service_writer"

# Scope vocabulary, mapped 1:1 to Hasura roles. scopes live on the
# credential row; credential_kind is the family guardrail (public creds may
# only hold public_read, service creds must hold service_read).
ALLOWED_SCOPES = ("public_read", "service_read", "service_write")
SCOPE_ROLE_MAP = {
    "public_read": PUBLIC_ROLE,
    "service_read": SERVICE_ROLE,
    "service_write": WRITER_ROLE,
}
KIND_DEFAULT_SCOPE = {"public": "public_read", "service": "service_read"}

# Strict families: public creds can only ever yield client_public, service
# creds can only ever yield service_reader/service_writer. No cross-family
# minting, so a token can never escalate mid-flow. Downgrade within the
# service family (write holder requesting read) is allowed.
KIND_ALLOWED_SCOPES = {
    "public": {"public_read"},
    "service": {"service_read", "service_write"},
}

# Clock-skew tolerance applied to exp/nbf/iAT validation (seconds).
CLOCK_SKEW_LEEWAY_SECONDS = 60


class TokenDenied(Exception):
    def __init__(self, detail: str, **context: Any):
        super().__init__(detail)
        self.detail = detail
        self.context = context


class TokenUnavailable(Exception):
    pass


class CredentialRepository(Protocol):
    def get(self, credential_id: str) -> dict[str, Any] | None: ...


def _credential_scopes(row: dict[str, Any]) -> list[str]:
    scopes = row.get("scopes")
    if isinstance(scopes, (list, tuple)):
        return [str(s) for s in scopes]
    # Rows predating migration 005 fall back to the kind default.
    kind = row.get("credential_kind")
    return [KIND_DEFAULT_SCOPE.get(kind, "public_read")]


def check_credential_active(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row or row.get("status") != "active" or row.get("revoked_at") is not None:
        raise TokenDenied("unknown_or_revoked_credential")
    return row


def check_secret(row: dict[str, Any], kind: str, presented: str | None) -> None:
    import hashlib
    import hmac

    if kind == "public":
        if presented is not None or row.get("secret_hash") is not None:
            raise TokenDenied("public_key_with_secret")
        return
    if not presented or row.get("secret_hash") is None:
        raise TokenDenied("service_key_without_secret")
    digest = hashlib.sha256(presented.encode()).digest()
    if not hmac.compare_digest(digest, bytes(row["secret_hash"])):
        raise TokenDenied("bad_secret")


def resolve_scope(row: dict[str, Any], kind: str, requested: str | None) -> tuple[str, str]:
    """Return (role, scope) or raise TokenDenied. Downgrade-only in family."""
    cred_scopes = _credential_scopes(row)
    scope = requested or KIND_DEFAULT_SCOPE[kind]
    if scope not in KIND_ALLOWED_SCOPES[kind]:
        raise TokenDenied("scope_kind_mismatch")
    if scope not in cred_scopes:
        raise TokenDenied("scope_not_granted")
    return SCOPE_ROLE_MAP[scope], scope


def build_claims(
    *,
    credential_id: str,
    kind: str,
    project_id: str,
    scope: str,
    cred_scopes: list[str],
    role: str,
    issuer: str,
    audience: str,
    ttl_seconds: int,
    now: int | None = None,
) -> tuple[dict[str, Any], str]:
    at = now if now is not None else int(time.time())
    token_jti = str(uuid.uuid4())
    claims = {
        "iss": issuer,
        # Audience is bound to the credential's project so a token can never
        # be replayed against another project even if other checks regressed.
        "aud": f"{audience}:{project_id}",
        "sub": credential_id,
        "jti": token_jti,
        "iat": at,
        "nbf": at,
        "exp": at + ttl_seconds,
        "credential_kind": kind,
        "project_id": project_id,
        "scope": scope,
        "scopes": sorted(cred_scopes),
        HASURA_CLAIMS: {
            "x-hasura-allowed-roles": [role],
            "x-hasura-default-role": role,
            "x-hasura-project-id": str(project_id),
        },
    }
    return claims, token_jti


def mint_with_secret(
    row: dict[str, Any],
    kind: str,
    presented_secret: str | None,
    requested_scope: str | None,
    *,
    issuer: str,
    audience: str,
    ttl_seconds: int,
    sign: Callable[[dict[str, Any]], str],
) -> tuple[str, str, str, str]:
    """Authorize secret + scope, build claims, sign. Returns (token, jti, role, scope)."""
    if row.get("credential_kind") != kind:
        raise TokenDenied("kind_mismatch")
    check_secret(row, kind, presented_secret)
    cred_scopes = _credential_scopes(row)
    role, scope = resolve_scope(row, kind, requested_scope)
    claims, token_jti = build_claims(
        credential_id=row["credential_id"],
        kind=kind,
        project_id=row["project_id"],
        scope=scope,
        cred_scopes=cred_scopes,
        role=role,
        issuer=issuer,
        audience=audience,
        ttl_seconds=ttl_seconds,
    )
    return sign(claims), token_jti, role, scope


def verify_broker_token(
    token: str,
    *,
    issuer: str,
    key_for_kid: Callable[[str | None], str],
    try_all_keys: Callable[[], dict[str, str]] | None = None,
    leeway: int = CLOCK_SKEW_LEEWAY_SECONDS,
) -> dict[str, Any]:
    """Verify signature/issuer/expiry with skew leeway. Returns claims."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenDenied("invalid_token") from exc
    if header.get("alg") != "RS256":
        raise TokenDenied("invalid_token")
    kid = header.get("kid")
    candidates: list[str] = []
    try:
        candidates.append(key_for_kid(kid))
    except KeyError:
        pass
    if not candidates and kid is None and try_all_keys is not None:
        # Kidless legacy tokens verify against every loaded key (overlap-safe).
        candidates.extend(try_all_keys().values())
    last: Exception | None = None
    for candidate in candidates:
        try:
            return jwt.decode(
                token,
                candidate,
                algorithms=["RS256"],
                issuer=issuer,
                leeway=leeway,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub", "jti"],
                    "verify_aud": False,
                },
            )
        except jwt.PyJWTError as exc:
            last = exc
            continue
    raise TokenDenied("invalid_token") from last


def authorize_hook_token(
    claims: dict[str, Any],
    row: dict[str, Any],
    headers: dict[str, Any],
    *,
    audience: str,
) -> dict[str, str | list[str]]:
    """Enforce project binding + scope->role from the registry row only."""
    credential_id = claims.get("sub")

    def deny(detail: str) -> TokenDenied:
        return TokenDenied(detail, credential_id=credential_id, jti=claims.get("jti"))

    # The audience is pinned to the credential's registered project; a token
    # minted for (or replayed against) any other project is rejected here.
    if claims.get("aud") != f"{audience}:{row['project_id']}":
        raise deny("audience_mismatch")
    cred_scopes = _credential_scopes(row)
    allowed_roles = [SCOPE_ROLE_MAP[s] for s in cred_scopes if s in SCOPE_ROLE_MAP]
    token_scope = claims.get("scope")
    namespace = claims.get(HASURA_CLAIMS)
    if not isinstance(namespace, dict):
        raise deny("claim_mismatch")
    role = namespace.get("x-hasura-default-role")
    if role not in allowed_roles:
        raise deny("scope_not_granted")
    if token_scope is not None and SCOPE_ROLE_MAP.get(token_scope) != role:
        raise deny("scope_mismatch")
    expected_kind = "public" if role == PUBLIC_ROLE else "service"
    if (
        claims.get("credential_kind") != expected_kind
        or str(claims.get("project_id")) != str(row["project_id"])
    ):
        raise deny("claim_mismatch")
    if (
        namespace.get("x-hasura-allowed-roles") != [role]
        or str(namespace.get("x-hasura-project-id")) != str(row["project_id"])
    ):
        raise deny("claim_mismatch")
    requested_role = headers.get("x-hasura-role")
    if requested_role not in (None, role):
        raise deny("role_mismatch")
    return {
        "x-hasura-role": role,
        "x-hasura-allowed-roles": [role],
        "x-hasura-project-id": str(row["project_id"]),
    }
