BEGIN;

-- Key identifiers are public identifiers; only high-entropy service secrets
-- are stored as SHA-256 hashes. Runtime access is read-only.
CREATE TABLE platform.api_credentials (
    credential_id text PRIMARY KEY
        CHECK (credential_id ~ '^(pub|svc)_[A-Za-z0-9_-]{12,}$'),
    project_id char(26) NOT NULL
        REFERENCES platform.projects(id) ON DELETE RESTRICT,
    credential_kind text NOT NULL
        CHECK (credential_kind IN ('public', 'service')),
    secret_hash bytea,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK (
        (credential_kind = 'public' AND secret_hash IS NULL)
        OR
        (credential_kind = 'service' AND secret_hash IS NOT NULL AND octet_length(secret_hash) = 32)
    ),
    CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR
        (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX api_credentials_project_status_idx
    ON platform.api_credentials(project_id, status);
REVOKE ALL ON platform.api_credentials FROM PUBLIC;
GRANT USAGE ON SCHEMA platform TO nhost_broker;
GRANT SELECT ON platform.api_credentials TO nhost_broker;

COMMIT;
