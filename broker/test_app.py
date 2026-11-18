import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import HASURA_CLAIMS, PUBLIC_ROLE, Settings, create_app


class FakeRepository:
    def __init__(self):
        self.rows = {}

    def get(self, credential_id):
        return self.rows.get(credential_id)


class RecordingAudit:
    def __init__(self):
        self.events = []

    def record(self, decision, credential_id=None, role=None, jti=None, detail=None):
        self.events.append(
            {
                "decision": decision,
                "credential_id": credential_id,
                "role": role,
                "jti": jti,
                "detail": detail,
            }
        )


PROJECT_A = "01M71YVC337C0NQQ9FY8B3NH2H"
PROJECT_B = "01M71YVC337C0NQQ9FY8B3NH2K"


def setup_client():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    settings = Settings(
        database_url="unused",
        auth_url="http://auth:4000/v1",
        issuer="https://api.888intelligence.org/broker",
        audience="hasura",
        private_key_file="unused",
        public_key_file="unused",
    )
    repo = FakeRepository()
    audit = RecordingAudit()
    app = create_app(
        settings,
        repo,
        auth_verify=lambda _token: True,
        private_key=private,
        public_key=public,
        audit=audit,
    )
    return TestClient(app), repo, public, private, audit


def active_row(credential_id, kind, secret_hash=None, project=PROJECT_A, scopes=None):
    if scopes is None:
        scopes = ["public_read"] if kind == "public" else ["service_read"]
    return {
        "credential_id": credential_id,
        "project_id": project,
        "credential_kind": kind,
        "secret_hash": secret_hash,
        "status": "active",
        "revoked_at": None,
        "scopes": scopes,
    }


def test_public_key_issues_only_project_public_token_and_hook_claims():
    client, repo, public_key, _private, audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")

    response = client.post("/v1/token", json={"key_id": key_id})
    assert response.status_code == 200
    token = response.json()["access_token"]
    claims = jwt.decode(
        token, public_key, algorithms=["RS256"], audience=f"hasura:{repo.rows[key_id]['project_id']}"
    )
    assert claims[HASURA_CLAIMS]["x-hasura-default-role"] == PUBLIC_ROLE
    assert claims[HASURA_CLAIMS]["x-hasura-project-id"] == repo.rows[key_id]["project_id"]

    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {token}"}})
    assert hook.status_code == 200
    assert hook.json() == {
        "x-hasura-role": "client_public",
        "x-hasura-allowed-roles": ["client_public"],
        "x-hasura-project-id": repo.rows[key_id]["project_id"],
    }
    issued = [e for e in audit.events if e["decision"] == "issued"]
    allowed = [e for e in audit.events if e["decision"] == "allowed"]
    assert len(issued) == 1 and issued[0]["jti"] == claims["jti"]
    assert len(allowed) == 1 and allowed[0]["jti"] == claims["jti"]


def test_token_has_jti_and_project_bound_audience():
    client, repo, public_key, _private, _audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public", project=PROJECT_A)

    token = client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=f"hasura:{PROJECT_A}")
    assert claims["jti"]
    assert claims["aud"] == f"hasura:{PROJECT_A}"


def test_private_key_issues_read_only_service_token_and_wrong_secret_is_denied():
    client, repo, _public, _private, audit = setup_client()
    key_id = "svc_abcdefghijk1234"
    secret = "service-secret-with-at-least-32-bytes"
    repo.rows[key_id] = active_row(key_id, "service", hashlib.sha256(secret.encode()).digest())

    assert client.post("/v1/token", json={"key_id": key_id, "key_secret": "x" * 40}).status_code == 401
    response = client.post("/v1/token", json={"key_id": key_id, "key_secret": secret})
    assert response.status_code == 200
    assert response.json()["role"] == "service_reader"
    assert any(e["detail"] == "bad_secret" for e in audit.events)


def test_revoking_credential_invalidates_already_issued_token_immediately():
    client, repo, _public, _private, _audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    row = active_row(key_id, "public")
    repo.rows[key_id] = row
    token = client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    row["status"] = "revoked"
    row["revoked_at"] = "now"
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {token}"}})
    assert hook.status_code == 401


def test_caller_cannot_select_a_role_outside_credential_scope():
    client, repo, _public, _private, _audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")
    token = client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    hook = client.post(
        "/internal/hasura-auth",
        json={"headers": {"Authorization": f"Bearer {token}", "X-Hasura-Role": "service_reader"}},
    )
    assert hook.status_code == 401


def test_token_for_project_a_is_rejected_for_project_b_credential():
    """Cross-project replay: valid signature, wrong project audience."""
    client, repo, _public, private, audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public", project=PROJECT_A)
    now = int(time.time())
    forged = jwt.encode(
        {
            "iss": "https://api.888intelligence.org/broker",
            "aud": f"hasura:{PROJECT_B}",
            "sub": key_id,
            "jti": "forged-jti",
            "iat": now,
            "exp": now + 60,
            "credential_kind": "public",
            "project_id": PROJECT_B,
            HASURA_CLAIMS: {
                "x-hasura-default-role": "client_public",
                "x-hasura-allowed-roles": ["client_public"],
                "x-hasura-project-id": PROJECT_B,
            },
        },
        private,
        algorithm="RS256",
    )
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {forged}"}})
    assert hook.status_code == 401
    assert any(e["detail"] == "audience_mismatch" for e in audit.events)


def test_tampered_token_is_rejected():
    client, repo, _public, _private, _audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")
    token = client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    header, payload, signature = token.split(".")
    tampered_payload = json.dumps({**jwt.decode(token, options={"verify_signature": False}), "project_id": PROJECT_B}).rstrip("=")
    import base64

    tampered = f"{header}.{base64.urlsafe_b64encode(tampered_payload.encode()).decode().rstrip('=')}.{signature}"
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {tampered}"}})
    assert hook.status_code == 401


def test_expired_token_is_rejected():
    client, repo, _public, private, _audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")
    now = int(time.time())
    expired = jwt.encode(
        {
            "iss": "https://api.888intelligence.org/broker",
            "aud": f"hasura:{PROJECT_A}",
            "sub": key_id,
            "jti": "expired-jti",
            "iat": now - 120,
            "exp": now - 60,
            "credential_kind": "public",
            "project_id": PROJECT_A,
        },
        private,
        algorithm="RS256",
    )
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {expired}"}})
    assert hook.status_code == 401


def test_per_credential_rate_limit_trips_and_audits():
    client, repo, _public, _private, audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")
    statuses = [client.post("/v1/token", json={"key_id": key_id}).status_code for _ in range(35)]
    assert statuses.count(429) >= 1
    assert any(e["detail"] == "rate_limit_credential" for e in audit.events)


def test_exchange_audits_denied_unknown_credential():
    client, _repo, _public, _private, audit = setup_client()
    response = client.post("/v1/token", json={"key_id": "pub_nonexistentkey1"})
    assert response.status_code == 401
    assert any(e["decision"] == "denied" and e["detail"] == "unknown_or_revoked_credential" for e in audit.events)


def test_service_credential_with_write_scope_mints_writer_token():
    client, repo, public_key, _private, _audit = setup_client()
    key_id = "svc_abcdefghijk1234"
    secret = "service-secret-with-at-least-32-bytes"
    repo.rows[key_id] = active_row(
        key_id, "service", hashlib.sha256(secret.encode()).digest(),
        scopes=["service_read", "service_write"],
    )
    response = client.post("/v1/token", json={"key_id": key_id, "key_secret": secret, "scope": "service_write"})
    assert response.status_code == 200
    assert response.json()["role"] == "service_writer"
    token = response.json()["access_token"]
    claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=f"hasura:{PROJECT_A}")
    assert claims["scope"] == "service_write"
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {token}"}})
    assert hook.status_code == 200
    assert hook.json()["x-hasura-role"] == "service_writer"


def test_scope_not_granted_is_denied_at_exchange_and_hook():
    client, repo, _public, _private, audit = setup_client()
    key_id = "svc_abcdefghijk1234"
    secret = "service-secret-with-at-least-32-bytes"
    repo.rows[key_id] = active_row(
        key_id, "service", hashlib.sha256(secret.encode()).digest(), scopes=["service_read"]
    )
    denied = client.post("/v1/token", json={"key_id": key_id, "key_secret": secret, "scope": "service_write"})
    assert denied.status_code == 401
    assert any(e["detail"] == "scope_not_granted" for e in audit.events)

    pub_id = "pub_abcdefghijk1234"
    repo.rows[pub_id] = active_row(pub_id, "public")
    pub_denied = client.post("/v1/token", json={"key_id": pub_id, "scope": "service_read"})
    assert pub_denied.status_code == 401


def test_strict_families_no_cross_family_minting():
    client, repo, _public, _private, audit = setup_client()
    svc_id = "svc_abcdefghijk1234"
    secret = "service-secret-with-at-least-32-bytes"
    repo.rows[svc_id] = active_row(
        svc_id, "service", hashlib.sha256(secret.encode()).digest(),
        scopes=["service_read", "service_write"],
    )
    # Service credential can never mint a public token, even downgraded.
    cross = client.post("/v1/token", json={"key_id": svc_id, "key_secret": secret, "scope": "public_read"})
    assert cross.status_code == 401
    assert any(e["detail"] == "scope_kind_mismatch" for e in audit.events)
    # Within-family downgrade is allowed: write holder requesting read.
    downgrade = client.post("/v1/token", json={"key_id": svc_id, "key_secret": secret, "scope": "service_read"})
    assert downgrade.status_code == 200
    assert downgrade.json()["role"] == "service_reader"
    # Public credential can never mint a service token.
    pub_id = "pub_abcdefghijk1234"
    repo.rows[pub_id] = active_row(pub_id, "public")
    esc = client.post("/v1/token", json={"key_id": pub_id, "scope": "service_write"})
    assert esc.status_code == 401


def test_hook_rejects_forged_cross_family_role():
    import time as _time
    client, repo, _public, private, audit = setup_client()
    key_id = "svc_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "service", scopes=["service_read"])
    forged = jwt.encode(
        {
            "iss": "https://api.888intelligence.org/broker",
            "aud": f"hasura:{PROJECT_A}",
            "sub": key_id,
            "jti": "forged-family-jti",
            "iat": int(_time.time()),
            "exp": int(_time.time()) + 60,
            "credential_kind": "public",
            "project_id": PROJECT_A,
            "scope": "public_read",
            HASURA_CLAIMS: {
                "x-hasura-default-role": "client_public",
                "x-hasura-allowed-roles": ["client_public"],
                "x-hasura-project-id": PROJECT_A,
            },
        },
        private,
        algorithm="RS256",
    )
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {forged}"}})
    assert hook.status_code == 401


def test_nhost_user_token_can_never_yield_service_roles_and_missing_token_denied():
    client, _repo, _public, _private, _audit = setup_client()
    service_claim_token = jwt.encode(
        {
            "sub": "user-uuid",
            "exp": int(time.time()) + 60,
            HASURA_CLAIMS: {
                "x-hasura-user-id": "user-uuid",
                "x-hasura-default-role": "service_reader",
                "x-hasura-allowed-roles": ["service_reader"],
            },
        },
        "test-key-with-at-least-thirty-two-bytes",
        algorithm="HS256",
    )
    hook = client.post(
        "/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {service_claim_token}"}}
    )
    assert hook.status_code == 401
    assert client.post("/internal/hasura-auth", json={"headers": {}}).status_code == 401


def _write_kid_pair(tmpdir, kid, private_pem, public_pem):
    priv = tmpdir / f"{kid}.private.pem"
    pub = tmpdir / f"{kid}.public.pem"
    priv.write_text(private_pem)
    pub.write_text(public_pem)
    return priv, pub


def _gen_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, public


def _mint_claims(key_id, project, role, scope, skew_exp=None):
    now = int(time.time())
    exp = skew_exp if skew_exp is not None else now + 60
    return {
        "iss": "https://api.888intelligence.org/broker",
        "aud": f"hasura:{project}",
        "sub": key_id,
        "jti": "leeway-jti",
        "iat": now - 120,
        "nbf": now - 120,
        "exp": exp,
        "credential_kind": "public",
        "project_id": project,
        "scope": scope,
        HASURA_CLAIMS: {
            "x-hasura-default-role": role,
            "x-hasura-allowed-roles": [role],
            "x-hasura-project-id": project,
        },
    }


def test_clock_skew_leeway_accepts_slightly_stale_token_and_rejects_old():
    client, repo, _public, private, _audit = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")
    now = int(time.time())
    freshish = client.post(
        "/internal/hasura-auth",
        json={"headers": {"Authorization": "Bearer " + jwt.encode(
            _mint_claims(key_id, PROJECT_A, "client_public", "public_read", skew_exp=now - 30),
            private, algorithm="RS256")}},
    )
    assert freshish.status_code == 200
    stale = client.post(
        "/internal/hasura-auth",
        json={"headers": {"Authorization": "Bearer " + jwt.encode(
            _mint_claims(key_id, PROJECT_A, "client_public", "public_read", skew_exp=now - 120),
            private, algorithm="RS256")}},
    )
    assert stale.status_code == 401


def test_kid_overlap_old_and_new_kids_verify_and_jwks_publishes_both(tmp_path):
    import os

    from keys import KeyStore

    from app import create_app, Settings

    priv1, pub1 = _gen_keypair()
    priv2, pub2 = _gen_keypair()
    _write_kid_pair(tmp_path, "kid-2026a", priv1, pub1)
    _write_kid_pair(tmp_path, "kid-2026b", priv2, pub2)
    # Force kid-2026b to be the newest for deterministic minting.
    future = time.time() + 100
    for name in ("kid-2026b.private.pem", "kid-2026b.public.pem"):
        os.utime(tmp_path / name, (future, future))
    store = KeyStore(str(tmp_path), poll_seconds=0)
    assert store.current_kid == "kid-2026b"

    settings = Settings(
        database_url="unused", auth_url="http://auth:4000/v1",
        issuer="https://api.888intelligence.org/broker", audience="hasura",
        private_key_file="unused", public_key_file="unused",
    )
    from test_app import FakeRepository, RecordingAudit  # noqa: F401  (same module)

    repo = FakeRepository()
    audit = RecordingAudit()
    app_client = TestClient(
        create_app(settings, repo, auth_verify=lambda _t: True,
                   audit=audit, key_store=store)
    )
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")

    old_token = jwt.encode(
        _mint_claims(key_id, PROJECT_A, "client_public", "public_read"),
        priv1, algorithm="RS256", headers={"kid": "kid-2026a"},
    )
    assert app_client.post(
        "/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {old_token}"}}
    ).status_code == 200

    new_token = app_client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    assert jwt.get_unverified_header(new_token)["kid"] == "kid-2026b"
    assert app_client.post(
        "/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {new_token}"}}
    ).status_code == 200

    jwks = app_client.get("/.well-known/jwks.json").json()
    assert {k["kid"] for k in jwks["keys"]} == {"kid-2026a", "kid-2026b"}
    assert all(k["use"] == "sig" and k["kty"] == "RSA" for k in jwks["keys"])


def test_hot_reload_picks_up_new_kid_without_restart(tmp_path):
    import os

    from keys import KeyStore

    from app import create_app, Settings

    priv1, pub1 = _gen_keypair()
    _write_kid_pair(tmp_path, "kid-2026a", priv1, pub1)
    store = KeyStore(str(tmp_path), poll_seconds=0)
    assert store.current_kid == "kid-2026a"

    priv2, pub2 = _gen_keypair()
    _write_kid_pair(tmp_path, "kid-2026b", priv2, pub2)
    future = time.time() + 100
    for name in ("kid-2026b.private.pem", "kid-2026b.public.pem"):
        os.utime(tmp_path / name, (future, future))
    store.maybe_refresh()
    assert store.current_kid == "kid-2026b"
    assert store.verification_key("kid-2026a") == pub1


def test_existing_nhost_user_token_is_verified_and_mapped_to_user_role():
    client, _repo, _public, _private, audit = setup_client()
    token = jwt.encode(
        {
            "sub": "user-uuid",
            "exp": int(time.time()) + 60,
            HASURA_CLAIMS: {
                "x-hasura-user-id": "user-uuid",
                "x-hasura-default-role": "user",
                "x-hasura-allowed-roles": ["user", "me"],
            },
        },
        "test-key-with-at-least-thirty-two-bytes",
        algorithm="HS256",
    )
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {token}"}})
    assert hook.status_code == 200
    assert hook.json() == {
        "x-hasura-user-id": "user-uuid",
        "x-hasura-role": "user",
        "x-hasura-allowed-roles": ["user"],
    }
    assert any(e["decision"] == "allowed" and e["role"] == "user" and e["detail"] == "nhost_user" for e in audit.events)
