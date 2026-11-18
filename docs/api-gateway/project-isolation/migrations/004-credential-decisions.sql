BEGIN;

-- Tier 1 decision audit log. One row per broker decision:
--   issued  — an exchange endpoint minted a token
--   allowed — the auth hook admitted a request
--   denied  — exchange or hook refused (reason in detail)
-- Never stores tokens, request bodies, or secrets. jti correlates a decision
-- with a specific issued token; credential_id may be NULL for user-JWT
-- decisions and unparseable tokens.
CREATE TABLE platform.credential_decisions (
    decision_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    decision text NOT NULL CHECK (decision IN ('issued', 'allowed', 'denied')),
    credential_id text,
    role text,
    jti text,
    detail text
);

CREATE INDEX credential_decisions_credential_time_idx
    ON platform.credential_decisions(credential_id, occurred_at DESC);
CREATE INDEX credential_decisions_decision_time_idx
    ON platform.credential_decisions(decision, occurred_at DESC);

REVOKE ALL ON platform.credential_decisions FROM PUBLIC;
-- The broker may append decisions but never read or modify them: the audit
-- trail is tamper-evident against the broker's own runtime role.
GRANT INSERT ON platform.credential_decisions TO nhost_broker;

COMMIT;
