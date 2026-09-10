\set ON_ERROR_STOP on

DO $assertions$
DECLARE
    v_disabled boolean;
    v_epoch bigint;
    v_version integer;
BEGIN
    SELECT disabled, epoch INTO v_disabled, v_epoch
    FROM sentinel.authority_state WHERE id = 1;
    IF v_disabled IS DISTINCT FROM true OR v_epoch <> 0 THEN
        RAISE EXCEPTION 'authority_state must bootstrap disabled at epoch 0';
    END IF;

    SELECT version INTO v_version
    FROM sentinel.schema_version WHERE id = 1;
    IF v_version <> 2 THEN
        RAISE EXCEPTION 'unexpected schema version: %', v_version;
    END IF;

    IF has_schema_privilege('sentinel_control', 'sentinel', 'CREATE') THEN
        RAISE EXCEPTION 'sentinel_control unexpectedly has CREATE on sentinel schema';
    END IF;
    IF NOT has_schema_privilege('sentinel_control', 'sentinel', 'USAGE') THEN
        RAISE EXCEPTION 'sentinel_control lacks USAGE on sentinel schema';
    END IF;
    IF has_table_privilege('sentinel_control', 'sentinel.grants', 'DELETE') THEN
        RAISE EXCEPTION 'sentinel_control unexpectedly has DELETE on grants';
    END IF;
    IF NOT has_table_privilege('sentinel_control', 'sentinel.grants', 'SELECT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.grants', 'INSERT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.grants', 'UPDATE') THEN
        RAISE EXCEPTION 'sentinel_control grant DML privileges are incomplete';
    END IF;
    IF has_table_privilege('sentinel_control', 'sentinel.audit_events', 'UPDATE')
       OR has_table_privilege('sentinel_control', 'sentinel.audit_events', 'DELETE') THEN
        RAISE EXCEPTION 'audit_events must be append-only to sentinel_control';
    END IF;
    IF NOT has_table_privilege('sentinel_control', 'sentinel.audit_events', 'INSERT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.audit_events', 'SELECT') THEN
        RAISE EXCEPTION 'sentinel_control lacks required audit event privileges';
    END IF;
    IF pg_has_role('sentinel_control', 'sentinel_owner', 'MEMBER') THEN
        RAISE EXCEPTION 'runtime control role must not inherit/SET ROLE to owner';
    END IF;
END
$assertions$;

-- Hash length constraints.
DO $hash_constraint$
BEGIN
    BEGIN
        INSERT INTO sentinel.grants (
            id, token_hash, agent, security_epoch, issued_at, expires_at
        ) VALUES (
            'bad-hash', decode('aa', 'hex'), 'agent-a', 0,
            clock_timestamp(), clock_timestamp() + interval '1 hour'
        );
        RAISE EXCEPTION 'invalid token hash was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$hash_constraint$;

-- Seed one valid grant for relational/uniqueness checks.
INSERT INTO sentinel.grants (
    id, token_hash, purpose, agent,
    permission_exec, security_epoch, issued_at, expires_at
) VALUES (
    'grant-ci-00000001', decode(repeat('11', 32), 'hex'), 'ci', 'agent-a',
    true, 0, clock_timestamp(), clock_timestamp() + interval '1 hour'
);
INSERT INTO sentinel.grant_targets (grant_id, target)
VALUES ('grant-ci-00000001', 'dns01');

-- Only one pending approval may exist for the same narrow scope.
INSERT INTO sentinel.approvals (
    id, grant_id, agent, target, argv, category, scope_key,
    status, created_at
) VALUES (
    'approval-ci-0001', 'grant-ci-00000001', 'agent-a', 'dns01',
    ARRAY['systemctl', 'restart', 'pdns'], 'SERVICE_RESTART', 'systemctl:restart:pdns',
    'pending', clock_timestamp()
);

DO $approval_unique$
BEGIN
    BEGIN
        INSERT INTO sentinel.approvals (
            id, grant_id, agent, target, argv, category, scope_key,
            status, created_at
        ) VALUES (
            'approval-ci-0002', 'grant-ci-00000001', 'agent-a', 'dns01',
            ARRAY['systemctl', 'restart', 'pdns'], 'SERVICE_RESTART', 'systemctl:restart:pdns',
            'pending', clock_timestamp()
        );
        RAISE EXCEPTION 'duplicate pending approval scope was accepted';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;
END
$approval_unique$;

-- Request IDs are unique within a grant and cannot be rebound.
INSERT INTO sentinel.execution_jobs (
    id, request_id, grant_id, agent, target, argv, command_sha256,
    risk_category, scope_key, created_at, expires_at, status
) VALUES (
    'job-ci-00000001', 'request-ci-0001', 'grant-ci-00000001', 'agent-a', 'dns01',
    ARRAY['true'], decode(repeat('22', 32), 'hex'), '', '',
    clock_timestamp(), clock_timestamp() + interval '10 minutes', 'staged'
);

DO $request_unique$
BEGIN
    BEGIN
        INSERT INTO sentinel.execution_jobs (
            id, request_id, grant_id, agent, target, argv, command_sha256,
            risk_category, scope_key, created_at, expires_at, status
        ) VALUES (
            'job-ci-00000002', 'request-ci-0001', 'grant-ci-00000001', 'agent-a', 'dns01',
            ARRAY['false'], decode(repeat('33', 32), 'hex'), '', '',
            clock_timestamp(), clock_timestamp() + interval '10 minutes', 'staged'
        );
        RAISE EXCEPTION 'duplicate grant/request_id was accepted';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;
END
$request_unique$;

-- A consumed-by-job binding is valid only for an allow-once consumption.
DO $approval_consumption_binding$
BEGIN
    BEGIN
        UPDATE sentinel.approvals
        SET consumed_by_job_id = 'job-ci-00000001'
        WHERE id = 'approval-ci-0001';
        RAISE EXCEPTION 'job binding on pending approval was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$approval_consumption_binding$;

-- Claim material is present only in claimed/running states.
DO $claim_state_constraint$
BEGIN
    BEGIN
        UPDATE sentinel.execution_jobs
        SET status = 'claimed'
        WHERE id = 'job-ci-00000001';
        RAISE EXCEPTION 'claimed state without claim hash was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$claim_state_constraint$;

-- Audit head cannot claim a sequence without a matching hash.
DO $audit_head_constraint$
BEGIN
    BEGIN
        UPDATE sentinel.audit_head SET last_sequence = 1 WHERE id = 1;
        RAISE EXCEPTION 'audit head accepted nonzero sequence without hash';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$audit_head_constraint$;
