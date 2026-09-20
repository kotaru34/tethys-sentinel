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

    IF v_version <> 1 THEN
        RAISE EXCEPTION '0002 requires schema version 1, found %', v_version;
    END IF;
END
$precondition$;

ALTER TABLE sentinel.approvals
    ADD COLUMN consumed_by_job_id text;

ALTER TABLE sentinel.approvals
    ADD CONSTRAINT approvals_consumed_by_job_fk
    FOREIGN KEY (consumed_by_job_id)
    REFERENCES sentinel.execution_jobs(id)
    ON DELETE RESTRICT;

ALTER TABLE sentinel.approvals
    ADD CONSTRAINT approvals_consumed_binding_chk
    CHECK (
        consumed_by_job_id IS NULL
        OR (status = 'consumed' AND decision = 'allow_once')
    );

CREATE UNIQUE INDEX approvals_consumed_job_uidx
    ON sentinel.approvals (consumed_by_job_id)
    WHERE consumed_by_job_id IS NOT NULL;

UPDATE sentinel.schema_version
SET version = 2, updated_at = clock_timestamp()
WHERE id = 1;

COMMIT;
