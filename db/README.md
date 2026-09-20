# Tethys Sentinel PostgreSQL files

This directory contains the reviewed database bootstrap/migration material for the PostgreSQL persistence boundary.

## Layout

```text
db/
├── bootstrap/
│   └── roles.sql
├── migrations/
│   ├── 0001_core.sql
│   ├── 0002_allow_once_job_binding.sql
│   ├── 0003_execution_output.sql
│   └── 0004_mcp_claims.sql
└── ci/
    └── assertions.sql
```

Current accepted schema version: **4**.

`0002_allow_once_job_binding.sql` adds the durable approval-to-job binding used to prove that a consumed `allow_once` authorization belongs to exactly one execution job. This prevents a consumed one-shot approval from being reused by another staged job in the same risk scope.

`0003_execution_output.sql` adds the separate one-to-one `sentinel.execution_job_output` table used for bounded command-output readback. Raw output is deliberately not added to the general execution-job read model. PostgreSQL enforces a 256 KiB limit independently for stdout and stderr, while Control runtime receives only `SELECT`, `INSERT` and `UPDATE` on the table.

`0004_mcp_claims.sql` adds short-lived one-time MCP bootstrap claims. PostgreSQL stores only the claim-code SHA-256 plus the fixed grant scope/targets, grant TTL, security epoch, expiry and single-use state. Claim issuance and redemption serialize with `authority_state`; redemption atomically creates the normal hashed-capability grant and consumes the claim.

## Bootstrap order

1. As a PostgreSQL administrator, run `db/bootstrap/roles.sql`.
2. Create a deployment LOGIN and grant it `sentinel_migrator`.
3. Create the Sentinel database owned by `sentinel_owner`.
4. Connect as the deployment LOGIN and apply **all** reviewed migrations in numeric order.
5. Create a separate runtime LOGIN and grant it `sentinel_control`.
6. Configure Control Plane with the runtime credential only.

The running Sentinel service must never use the deployment/migrator credential.

Example skeleton (replace LOGIN names/password handling locally):

```sql
-- administrator
\i db/bootstrap/roles.sql
CREATE ROLE sentinel_deploy LOGIN PASSWORD 'managed-outside-git';
GRANT sentinel_migrator TO sentinel_deploy;
CREATE DATABASE tethys_sentinel OWNER sentinel_owner;

CREATE ROLE sentinel_control_login LOGIN PASSWORD 'managed-outside-git';
GRANT sentinel_control TO sentinel_control_login;
```

Then apply every migration while connected to `tethys_sentinel` as the deployment LOGIN:

```sh
for migration in db/migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -d tethys_sentinel -f "$migration"
done
```

Migration filenames use zero-padded numeric prefixes, so lexical order is migration order. Each migration checks the schema version it expects before changing it: `0002` requires version 1 and advances to 2; `0003` requires version 2 and advances to 3; `0004` requires version 3 and advances to 4.

The migrations use `SET LOCAL ROLE sentinel_owner`, so the migration session must have the reviewed owner membership path. Runtime `sentinel_control` has no such membership.

## Initial state

The PostgreSQL schema intentionally initializes:

```text
epoch=0
disabled=true
```

Fresh database creation therefore does not automatically enable AI authority. Enable only after schema/configuration validation.

## Runtime privileges

`sentinel_control` receives only the table DML required by Control Plane. It receives no schema `CREATE`, table `DELETE`, ownership, role administration, database creation, replication, superuser or bypass-RLS authority.

For `sentinel.execution_job_output`, runtime access is limited to `SELECT`, `INSERT` and `UPDATE`. Output rows are job-bound and cannot be used to create or widen execution authority.

Gateway, Worker, SSH Signer, `sentinel-operator`, `sentinel-mcp`, and `sentinelctl` do not receive PostgreSQL credentials.

## Runtime selection

Persistence selection is explicit:

```text
SENTINEL_PERSISTENCE_BACKEND=postgres
SENTINEL_POSTGRES_DSN=postgres://...
```

Production PostgreSQL connections require verified TLS unless the explicit development-only insecure switch is set. If PostgreSQL is selected and the connection, role checks, or schema-version validation fails, Control Plane exits. It never falls back to the local file stores.

The development compatibility backend remains explicit:

```text
SENTINEL_PERSISTENCE_BACKEND=file
```

## Migration policy

- Migrations are reviewed source files, not generated at service startup.
- Apply all migrations in numeric order; never skip a version precondition.
- Production startup validates the exact supported schema version and fails if incompatible.
- Production startup fails if PostgreSQL is unavailable; there is no automatic file-store fallback.
- Future migrations must explicitly grant any new runtime privileges rather than relying on broad default grants.
- Destructive/down migrations are not automatic. Authority/audit rollback requires an explicit operator recovery procedure.
- Apply every reviewed migration through schema v4 before starting the current Control binary; Control must fail closed against an incompatible schema rather than silently running with missing persistence semantics.

See `docs/POSTGRESQL_PERSISTENCE.md` for transaction, output-persistence and cutover semantics.
