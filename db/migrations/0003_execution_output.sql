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

    IF v_version <> 2 THEN
        RAISE EXCEPTION '0003 requires schema version 2, found %', v_version;
    END IF;
END
$precondition$;

CREATE TABLE sentinel.execution_job_output (
    job_id            text PRIMARY KEY REFERENCES sentinel.execution_jobs(id) ON DELETE RESTRICT,
    stdout            bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(stdout) <= 262144),
    stderr            bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(stderr) <= 262144),
    stdout_truncated  boolean NOT NULL DEFAULT false,
    stderr_truncated  boolean NOT NULL DEFAULT false
);

GRANT SELECT, INSERT, UPDATE ON sentinel.execution_job_output TO sentinel_control;

UPDATE sentinel.schema_version
SET version = 3, updated_at = clock_timestamp()
WHERE id = 1;

COMMIT;
