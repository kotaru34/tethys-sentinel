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
    IF v_version <> 5 THEN
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
    IF has_table_privilege('sentinel_control', 'sentinel.mcp_claims', 'DELETE') THEN
        RAISE EXCEPTION 'sentinel_control unexpectedly has DELETE on mcp_claims';
    END IF;
    IF NOT has_table_privilege('sentinel_control', 'sentinel.mcp_claims', 'SELECT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.mcp_claims', 'INSERT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.mcp_claims', 'UPDATE') THEN
        RAISE EXCEPTION 'sentinel_control MCP claim DML privileges are incomplete';
    END IF;
    IF has_table_privilege('sentinel_control', 'sentinel.mcp_claim_targets', 'UPDATE')
       OR has_table_privilege('sentinel_control', 'sentinel.mcp_claim_targets', 'DELETE') THEN
        RAISE EXCEPTION 'sentinel_control MCP claim targets must be append-only';
    END IF;
    IF NOT has_table_privilege('sentinel_control', 'sentinel.mcp_claim_targets', 'SELECT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.mcp_claim_targets', 'INSERT') THEN
        RAISE EXCEPTION 'sentinel_control MCP claim target privileges are incomplete';
    END IF;
    IF has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'DELETE') THEN
        RAISE EXCEPTION 'sentinel_control unexpectedly has DELETE on execution_job_output';
    END IF;
    IF NOT has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'SELECT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'INSERT')
       OR NOT has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'UPDATE') THEN
        RAISE EXCEPTION 'sentinel_control execution output privileges are incomplete';
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

    BEGIN
        INSERT INTO sentinel.mcp_claims (
            id, code_hash, purpose, agent, grant_ttl_seconds,
            security_epoch, issued_at, expires_at
        ) VALUES (
            'mcpclaim-bad-hash', decode('aa', 'hex'), 'ci claim', 'agent-a', 3600,
            0, clock_timestamp(), clock_timestamp() + interval '1 minute'
        );
        RAISE EXCEPTION 'invalid MCP claim hash was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$hash_constraint$;

-- MCP claim validity is tightly bounded before redemption.
DO $mcp_claim_constraints$
BEGIN
    BEGIN
        INSERT INTO sentinel.mcp_claims (
            id, code_hash, purpose, agent, grant_ttl_seconds,
            security_epoch, issued_at, expires_at
        ) VALUES (
            'mcpclaim-too-long', decode(repeat('44', 32), 'hex'), 'ci claim', 'agent-a', 3600,
            0, clock_timestamp(), clock_timestamp() + interval '6 minutes'
        );
        RAISE EXCEPTION 'oversized MCP claim TTL was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$mcp_claim_constraints$;

-- Unrestricted shell is an explicit stronger authority and cannot exist
-- without both normal execution and shell permissions.
DO $unrestricted_shell_constraints$
BEGIN
    BEGIN
        INSERT INTO sentinel.grants (
            id, token_hash, agent,
            permission_exec, permission_shell, permission_unrestricted_shell,
            security_epoch, issued_at, expires_at
        ) VALUES (
            'grant-bad-unrestricted', decode(repeat('66', 32), 'hex'), 'agent-a',
            true, false, true,
            0, clock_timestamp(), clock_timestamp() + interval '1 hour'
        );
        RAISE EXCEPTION 'unrestricted shell grant without shell permission was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO sentinel.mcp_claims (
            id, code_hash, purpose, agent,
            permission_exec, permission_shell, permission_unrestricted_shell,
            grant_ttl_seconds, security_epoch, issued_at, expires_at
        ) VALUES (
            'mcpclaim-bad-unrestricted', decode(repeat('77', 32), 'hex'), 'ci claim', 'agent-a',
            true, false, true,
            3600, 0, clock_timestamp(), clock_timestamp() + interval '1 minute'
        );
        RAISE EXCEPTION 'unrestricted shell MCP claim without shell permission was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$unrestricted_shell_constraints$;

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

-- Seed one valid MCP claim and target for relational checks.
INSERT INTO sentinel.mcp_claims (
    id, code_hash, purpose, agent, permission_exec, grant_ttl_seconds,
    security_epoch, issued_at, expires_at
) VALUES (
    'mcpclaim-ci-00000001', decode(repeat('55', 32), 'hex'), 'ci claim', 'agent-a', true, 3600,
    0, clock_timestamp(), clock_timestamp() + interval '1 minute'
);
INSERT INTO sentinel.mcp_claim_targets (claim_id, target)
VALUES ('mcpclaim-ci-00000001', 'dns01');

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

-- Raw execution output is bounded independently from job metadata.
INSERT INTO sentinel.execution_job_output (job_id, stdout, stderr)
VALUES ('job-ci-00000001', convert_to('ok', 'UTF8'), ''::bytea);

DO $output_limit$
BEGIN
    BEGIN
        UPDATE sentinel.execution_job_output
        SET stdout = decode(repeat('aa', 262145), 'hex')
        WHERE job_id = 'job-ci-00000001';
        RAISE EXCEPTION 'oversized execution output was accepted';
    EXCEPTION
        WHEN check_violation THEN NULL;
    END;
END
$output_limit$;

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
