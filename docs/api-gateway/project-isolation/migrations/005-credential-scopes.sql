BEGIN;

-- Scope vocabulary for project credentials, mapped 1:1 to Hasura roles:
--   public_read  -> client_public  (curated selects)
--   service_read -> service_reader (curated selects)
--   service_write -> service_writer (curated inserts/updates; permissions
--     are added in the Hasura metadata step, not here)
-- credential_kind is the family guardrail (strict, no cross-family scopes):
--   public credentials hold exactly {public_read}
--   service credentials hold service_read and may additionally hold
--   service_write. A service credential can never mint a public token and
--   a public credential can never mint a service token, so there is no
--   mid-flow escalation or cross-family replay. Least-privilege downgrade
--   within a family (service_write holder requesting service_read) is
--   allowed; anything outside the granted scopes is denied.

ALTER TABLE platform.api_credentials
    ADD COLUMN scopes text[] NOT NULL DEFAULT '{public_read}';

-- Backfill rows created before scopes existed.
UPDATE platform.api_credentials
    SET scopes = CASE
        WHEN credential_kind = 'public' THEN '{public_read}'::text[]
        ELSE '{service_read}'::text[]
    END
    WHERE scopes = '{public_read}' AND credential_kind = 'service';

ALTER TABLE platform.api_credentials
    ADD CONSTRAINT api_credentials_scopes_nonempty CHECK (scopes <> '{}'),
    ADD CONSTRAINT api_credentials_scopes_vocabulary
        CHECK (scopes <@ ARRAY['public_read', 'service_read', 'service_write']),
    ADD CONSTRAINT api_credentials_kind_scopes
        CHECK (
            (credential_kind = 'public' AND scopes = '{public_read}'::text[])
            OR
            (credential_kind = 'service'
                AND scopes <@ ARRAY['service_read', 'service_write']
                AND 'service_read' = ANY (scopes))
        );

CREATE INDEX IF NOT EXISTS api_credentials_scopes_idx
    ON platform.api_credentials USING GIN (scopes);

COMMENT ON COLUMN platform.api_credentials.scopes IS
    'Granted scopes; 1:1 to Hasura roles: public_read->client_public, service_read->service_reader, service_write->service_writer';

COMMIT;
