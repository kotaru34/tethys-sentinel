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

    IF v_version <> 4 THEN
        RAISE EXCEPTION '0005 requires schema version 4, found %', v_version;
    END IF;
END
$precondition$;

ALTER TABLE sentinel.grants
    ADD COLUMN permission_unrestricted_shell boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT grants_unrestricted_shell_requires_exec_shell
        CHECK (
            NOT permission_unrestricted_shell
            OR (permission_exec AND permission_shell)
        );

ALTER TABLE sentinel.mcp_claims
    ADD COLUMN permission_unrestricted_shell boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT mcp_claims_unrestricted_shell_requires_exec_shell
        CHECK (
            NOT permission_unrestricted_shell
            OR (permission_exec AND permission_shell)
        );

UPDATE sentinel.schema_version
SET version = 5, updated_at = clock_timestamp()
WHERE id = 1;

COMMIT;
