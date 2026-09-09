BEGIN;

SET LOCAL ROLE sentinel_owner;

CREATE SCHEMA IF NOT EXISTS sentinel AUTHORIZATION sentinel_owner;
REVOKE ALL ON SCHEMA sentinel FROM PUBLIC;

CREATE TABLE sentinel.schema_version (
    id          smallint PRIMARY KEY CHECK (id = 1),
    version     integer NOT NULL CHECK (version > 0),
    updated_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO sentinel.schema_version (id, version)
VALUES (1, 1);

CREATE TABLE sentinel.authority_state (
    id          smallint PRIMARY KEY CHECK (id = 1),
    epoch       bigint NOT NULL CHECK (epoch >= 0),
    disabled    boolean NOT NULL,
    updated_at  timestamptz NOT NULL,
    reason      text NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 512)
);

-- New PostgreSQL-backed deployments start fail-closed. The operator must
-- explicitly enable autonomous access after migration/config validation.
INSERT INTO sentinel.authority_state (id, epoch, disabled, updated_at, reason)
VALUES (1, 0, true, clock_timestamp(), 'initial PostgreSQL bootstrap');

CREATE TABLE sentinel.grants (
    id                      text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    token_hash              bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    purpose                 text NOT NULL DEFAULT '' CHECK (octet_length(purpose) <= 2048),
    agent                   text NOT NULL CHECK (length(agent) BETWEEN 1 AND 128),
    permission_exec         boolean NOT NULL DEFAULT false,
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
    security_epoch          bigint NOT NULL CHECK (security_epoch >= 0),
    issued_at               timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    revoked_at              timestamptz,
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE INDEX grants_active_epoch_idx
    ON sentinel.grants (security_epoch, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE sentinel.grant_targets (
    grant_id    text NOT NULL REFERENCES sentinel.grants(id) ON DELETE RESTRICT,
    target      text NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
    PRIMARY KEY (grant_id, target)
);

CREATE INDEX grant_targets_target_idx
    ON sentinel.grant_targets (target, grant_id);

CREATE TABLE sentinel.approvals (
    id                       text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    grant_id                 text NOT NULL REFERENCES sentinel.grants(id) ON DELETE RESTRICT,
    agent                    text NOT NULL CHECK (length(agent) BETWEEN 1 AND 128),
    target                   text NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
    argv                     text[] NOT NULL CHECK (cardinality(argv) >= 1 AND length(argv[1]) >= 1),
    category                 text NOT NULL CHECK (length(category) BETWEEN 1 AND 128),
    risk_level               text NOT NULL DEFAULT '' CHECK (length(risk_level) <= 64),
    scope_key                text NOT NULL CHECK (length(scope_key) BETWEEN 1 AND 2048),
    risk_reason              text NOT NULL DEFAULT '' CHECK (octet_length(risk_reason) <= 8192),
    agent_reason             text NOT NULL DEFAULT '' CHECK (octet_length(agent_reason) <= 8192),
    session_approval_allowed boolean NOT NULL DEFAULT false,
    status                   text NOT NULL CHECK (status IN ('pending', 'decided', 'consumed')),
    decision                 text CHECK (decision IN ('deny', 'allow_once', 'allow_session')),
    created_at               timestamptz NOT NULL,
    decided_at               timestamptz,
    decision_actor           text NOT NULL DEFAULT '' CHECK (length(decision_actor) <= 128),
    CHECK (
        (status = 'pending' AND decision IS NULL AND decided_at IS NULL)
        OR
        (status IN ('decided', 'consumed') AND decision IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CHECK (status <> 'consumed' OR decision = 'allow_once')
);

CREATE UNIQUE INDEX approvals_one_pending_scope_idx
    ON sentinel.approvals (grant_id, target, category, scope_key)
    WHERE status = 'pending';

CREATE INDEX approvals_match_idx
    ON sentinel.approvals (grant_id, target, category, scope_key, created_at DESC)
    WHERE status = 'decided';

CREATE TABLE sentinel.execution_jobs (
    id                 text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    request_id         text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9._:-]{8,128}$'),
    grant_id           text NOT NULL REFERENCES sentinel.grants(id) ON DELETE RESTRICT,
    agent              text NOT NULL CHECK (length(agent) BETWEEN 1 AND 128),
    target             text NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
    argv               text[] NOT NULL CHECK (cardinality(argv) >= 1 AND length(argv[1]) >= 1),
    command_sha256     bytea NOT NULL CHECK (octet_length(command_sha256) = 32),
    approval_id        text REFERENCES sentinel.approvals(id) ON DELETE RESTRICT,
    risk_category      text NOT NULL DEFAULT '' CHECK (length(risk_category) <= 128),
    scope_key          text NOT NULL DEFAULT '' CHECK (length(scope_key) <= 2048),
    created_at         timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    status             text NOT NULL CHECK (status IN (
                           'staged', 'pending', 'claimed', 'running',
                           'succeeded', 'failed', 'canceled', 'expired'
                       )),
    claim_token_hash   bytea CHECK (claim_token_hash IS NULL OR octet_length(claim_token_hash) = 32),
    claimed_at         timestamptz,
    started_at         timestamptz,
    completed_at       timestamptz,
    result_success     boolean,
    result_exit_code   integer,
    output_sha256      bytea CHECK (output_sha256 IS NULL OR octet_length(output_sha256) = 32),
    error_kind         text NOT NULL DEFAULT '' CHECK (length(error_kind) <= 128),
    UNIQUE (grant_id, request_id),
    CHECK (expires_at > created_at),
    CHECK (
        (status IN ('claimed', 'running') AND claim_token_hash IS NOT NULL)
        OR
        (status NOT IN ('claimed', 'running') AND claim_token_hash IS NULL)
    ),
    CHECK (
        status NOT IN ('succeeded', 'failed', 'canceled', 'expired')
        OR completed_at IS NOT NULL
    ),
    CHECK (
        status <> 'succeeded'
        OR (result_success = true AND result_exit_code IS NOT NULL)
    ),
    CHECK (
        status <> 'failed'
        OR (result_success = false AND result_exit_code IS NOT NULL)
    )
);

CREATE INDEX execution_jobs_claim_idx
    ON sentinel.execution_jobs (created_at, id)
    WHERE status = 'pending';

CREATE INDEX execution_jobs_grant_status_idx
    ON sentinel.execution_jobs (grant_id, status, created_at);

CREATE TABLE sentinel.audit_head (
    id            smallint PRIMARY KEY CHECK (id = 1),
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    last_hash     bytea CHECK (last_hash IS NULL OR octet_length(last_hash) = 32),
    CHECK ((last_sequence = 0 AND last_hash IS NULL) OR (last_sequence > 0 AND last_hash IS NOT NULL))
);

INSERT INTO sentinel.audit_head (id, last_sequence, last_hash)
VALUES (1, 0, NULL);

CREATE TABLE sentinel.audit_events (
    sequence      bigint PRIMARY KEY CHECK (sequence > 0),
    id            text NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 128),
    event_time    timestamptz NOT NULL,
    kind          text NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    actor         text NOT NULL DEFAULT '' CHECK (length(actor) <= 128),
    grant_id      text CHECK (grant_id IS NULL OR length(grant_id) BETWEEN 1 AND 128),
    target        text NOT NULL DEFAULT '' CHECK (length(target) <= 128),
    argv          text[] NOT NULL DEFAULT '{}'::text[],
    decision      text NOT NULL DEFAULT '' CHECK (length(decision) <= 128),
    category      text NOT NULL DEFAULT '' CHECK (length(category) <= 128),
    scope_key     text NOT NULL DEFAULT '' CHECK (length(scope_key) <= 2048),
    approval_id   text CHECK (approval_id IS NULL OR length(approval_id) BETWEEN 1 AND 128),
    reason        text NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 8192),
    metadata      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    event_hash    bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32)
);

CREATE INDEX audit_events_grant_time_idx
    ON sentinel.audit_events (grant_id, event_time DESC, sequence DESC);
CREATE INDEX audit_events_target_time_idx
    ON sentinel.audit_events (target, event_time DESC, sequence DESC)
    WHERE target <> '';

CREATE TABLE sentinel.agent_notes (
    id           text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    note_time    timestamptz NOT NULL,
    grant_id     text NOT NULL REFERENCES sentinel.grants(id) ON DELETE RESTRICT,
    agent        text NOT NULL CHECK (length(agent) BETWEEN 1 AND 128),
    target       text NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
    trust_level  text NOT NULL CHECK (trust_level = 'TRUST_2'),
    content      text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 16384),
    content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32)
);

CREATE INDEX agent_notes_target_time_idx
    ON sentinel.agent_notes (target, note_time DESC, id DESC);
CREATE INDEX agent_notes_grant_time_idx
    ON sentinel.agent_notes (grant_id, note_time DESC, id DESC);

-- Runtime owns no schema objects and receives no DELETE/DDL privileges.
GRANT USAGE ON SCHEMA sentinel TO sentinel_control;
GRANT SELECT ON sentinel.schema_version TO sentinel_control;
GRANT SELECT, INSERT, UPDATE ON sentinel.authority_state TO sentinel_control;
GRANT SELECT, INSERT, UPDATE ON sentinel.grants TO sentinel_control;
GRANT SELECT, INSERT ON sentinel.grant_targets TO sentinel_control;
GRANT SELECT, INSERT, UPDATE ON sentinel.approvals TO sentinel_control;
GRANT SELECT, INSERT, UPDATE ON sentinel.execution_jobs TO sentinel_control;
GRANT SELECT, UPDATE ON sentinel.audit_head TO sentinel_control;
GRANT SELECT, INSERT ON sentinel.audit_events TO sentinel_control;
GRANT SELECT, INSERT ON sentinel.agent_notes TO sentinel_control;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA sentinel
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA sentinel
    REVOKE ALL ON SEQUENCES FROM PUBLIC;

COMMIT;
