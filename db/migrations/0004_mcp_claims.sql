BEGIN;

SET LOCAL ROLE sentinel_owner;

DO $precondition$
DECLARE
    v_version integer;
BEGIN
    SELECT version INTO v_version
    FROM sentinel.schema_version
    WHERE id = 1
    FOR UPDATE;

    IF v_version <> 3 THEN
        RAISE EXCEPTION '0004 requires schema version 3, found %', v_version;
    END IF;
END
$precondition$;

CREATE TABLE sentinel.mcp_claims (
    id                      text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    code_hash               bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    purpose                 text NOT NULL CHECK (octet_length(purpose) BETWEEN 1 AND 2048),
    agent                   text NOT NULL CHECK (length(agent) BETWEEN 1 AND 128),
    permission_exec         boolean NOT NULL DEFAULT true CHECK (permission_exec),
    permission_shell        boolean NOT NULL DEFAULT false,
    permission_upload       boolean NOT NULL DEFAULT false,
    permission_download     boolean NOT NULL DEFAULT false,
    permission_history_read boolean NOT NULL DEFAULT false,
    permission_notes_read   boolean NOT NULL DEFAULT false,
    permission_notes_write  boolean NOT NULL DEFAULT false,
    history_current_session boolean NOT NULL DEFAULT false,
    history_previous        boolean NOT NULL DEFAULT false,
    history_other_agents    boolean NOT NULL DEFAULT false,
    history_include_output  boolean NOT NULL DEFAULT false,
    grant_ttl_seconds       integer NOT NULL CHECK (grant_ttl_seconds BETWEEN 30 AND 28800),
    security_epoch          bigint NOT NULL CHECK (security_epoch >= 0),
    issued_at               timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    used_at                 timestamptz,
    CHECK (expires_at >= issued_at + interval '30 seconds'),
    CHECK (expires_at <= issued_at + interval '5 minutes'),
    CHECK (used_at IS NULL OR used_at >= issued_at)
);

CREATE TABLE sentinel.mcp_claim_targets (
    claim_id    text NOT NULL REFERENCES sentinel.mcp_claims(id) ON DELETE RESTRICT,
    target      text NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
    PRIMARY KEY (claim_id, target)
);

CREATE INDEX mcp_claims_redeem_idx
    ON sentinel.mcp_claims (code_hash, expires_at)
    WHERE used_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON sentinel.mcp_claims TO sentinel_control;
GRANT SELECT, INSERT ON sentinel.mcp_claim_targets TO sentinel_control;

UPDATE sentinel.schema_version
SET version = 4, updated_at = clock_timestamp()
WHERE id = 1;

COMMIT;
