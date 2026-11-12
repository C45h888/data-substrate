import hashlib
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import HASURA_CLAIMS, Settings, create_app


class FakeRepository:
    def __init__(self):
        self.rows = {}

    def get(self, credential_id):
        return self.rows.get(credential_id)


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
    app = create_app(settings, repo, auth_verify=lambda _token: True, private_key=private, public_key=public)
    return TestClient(app), repo, public


def active_row(credential_id, kind, secret_hash=None, project="01M71YVC337C0NQQ9FY8B3NH2H"):
    return {
        "credential_id": credential_id,
        "project_id": project,
        "credential_kind": kind,
        "secret_hash": secret_hash,
        "status": "active",
        "revoked_at": None,
    }


def test_public_key_issues_only_project_public_token_and_hook_claims():
    client, repo, public_key = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")

    response = client.post("/v1/token", json={"key_id": key_id})
    assert response.status_code == 200
    token = response.json()["access_token"]
    claims = jwt.decode(token, public_key, algorithms=["RS256"], audience="hasura")
    assert claims[HASURA_CLAIMS]["x-hasura-default-role"] == "client_public"
    assert claims[HASURA_CLAIMS]["x-hasura-project-id"] == repo.rows[key_id]["project_id"]

    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {token}"}})
    assert hook.status_code == 200
    assert hook.json() == {
        "x-hasura-role": "client_public",
        "x-hasura-allowed-roles": ["client_public"],
        "x-hasura-project-id": repo.rows[key_id]["project_id"],
    }


def test_private_key_issues_read_only_service_token_and_wrong_secret_is_denied():
    client, repo, _public = setup_client()
    key_id = "svc_abcdefghijk1234"
    secret = "service-secret-with-at-least-32-bytes"
    repo.rows[key_id] = active_row(key_id, "service", hashlib.sha256(secret.encode()).digest())

    assert client.post("/v1/token", json={"key_id": key_id, "key_secret": "x" * 40}).status_code == 401
    response = client.post("/v1/token", json={"key_id": key_id, "key_secret": secret})
    assert response.status_code == 200
    assert response.json()["role"] == "service_reader"


def test_revoking_credential_invalidates_already_issued_token_immediately():
    client, repo, _public = setup_client()
    key_id = "pub_abcdefghijk1234"
    row = active_row(key_id, "public")
    repo.rows[key_id] = row
    token = client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    row["status"] = "revoked"
    row["revoked_at"] = "now"
    hook = client.post("/internal/hasura-auth", json={"headers": {"Authorization": f"Bearer {token}"}})
    assert hook.status_code == 401


def test_caller_cannot_select_a_role_outside_credential_scope():
    client, repo, _public = setup_client()
    key_id = "pub_abcdefghijk1234"
    repo.rows[key_id] = active_row(key_id, "public")
    token = client.post("/v1/token", json={"key_id": key_id}).json()["access_token"]
    hook = client.post(
        "/internal/hasura-auth",
        json={"headers": {"Authorization": f"Bearer {token}", "X-Hasura-Role": "service_reader"}},
    )
    assert hook.status_code == 401


def test_existing_nhost_user_token_is_verified_and_mapped_to_user_role():
    client, _repo, _public = setup_client()
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
