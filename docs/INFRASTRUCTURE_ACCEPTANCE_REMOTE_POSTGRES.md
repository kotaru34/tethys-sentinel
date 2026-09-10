# Remote PostgreSQL acceptance profile

This profile modifies `docs/INFRASTRUCTURE_ACCEPTANCE.md` for deployments that already have a trusted remote PostgreSQL service. It does not change Sentinel runtime semantics or versioning.

## Topology

Use five disposable/constrained guests:

```text
sentinel-control      Control Plane
sentinel-gateway      AI Gateway
sentinel-worker       Execution Worker
sentinel-signer       isolated SSH CA/Signer
sentinel-target-test  disposable SSH execution target
```

Do not provision a dedicated Sentinel database guest when an existing PostgreSQL service can provide an isolated Sentinel database, isolated LOGINs, verified TLS, and source-restricted `pg_hba.conf` rules.

Gateway, Worker and Signer still receive no PostgreSQL credentials. Only Control Plane receives the runtime database credential.

## Existing PostgreSQL requirements

The existing cluster must satisfy all of the following before acceptance:

- PostgreSQL major supported by the current CI matrix (15 or 18 for `0.1.0-dev.11`);
- TLS enabled and verifiable from the Control VM;
- a dedicated `tethys_sentinel` database;
- repository bootstrap roles `sentinel_owner`, `sentinel_migrator`, and `sentinel_control`;
- a deployment LOGIN granted only `sentinel_migrator` for migrations;
- a separate runtime LOGIN granted only `sentinel_control`;
- runtime `hostssl` access limited to the Control VM source address;
- schema migrations applied in numeric order through schema version 2;
- fresh Sentinel authority state verified as `epoch=0, disabled=true`;
- no automatic fallback to the file backend.

Do not reuse an application superuser, database owner, or another service's LOGIN for Sentinel runtime.

## Bootstrap on an existing cluster

Run `db/bootstrap/roles.sql` once as a PostgreSQL administrator, then create the dedicated LOGINs and database as described in `db/README.md`.

A representative HBA rule is:

```text
hostssl tethys_sentinel sentinel_control_login <CONTROL_IP>/32 scram-sha-256
```

The deployment LOGIN does not need network access from Sentinel runtime guests; run migrations locally on the database host or through a separate operator-only administration path.

Apply all migrations:

```sh
for migration in db/migrations/*.sql; do
    PGPASSWORD="$DB_DEPLOY_PASS" \
      psql -X -v ON_ERROR_STOP=1 \
      -h <DB_ADMIN_ENDPOINT> -U sentinel_deploy -d tethys_sentinel \
      -f "$migration"
done
```

Verify from the Control VM using the runtime LOGIN and the database CA:

```sh
PGPASSWORD="$DB_RUNTIME_PASS" \
psql 'host=<DB_IP_OR_VERIFIED_NAME> port=5432 dbname=tethys_sentinel user=sentinel_control_login sslmode=verify-full sslrootcert=/etc/tethys-sentinel/postgres-ca.crt' \
  -X -Atc 'select version from sentinel.schema_version where id=1; select epoch,disabled from sentinel.authority_state where id=1;'
```

Expected fresh state:

```text
2
0|t
```

## Egress implications

The remote database endpoint is **not** part of Worker egress. Worker continues to receive only:

```text
Control Plane HTTPS
registered target SSH endpoints
```

Only the Control VM needs PostgreSQL network reachability. Do not add PostgreSQL, DNS, generic LAN, or Internet access to the Worker PVE firewall because the database is remote.

## Acceptance evidence

Replace the dedicated-DB-VM evidence item from the main runbook with:

```text
remote PostgreSQL host/verified identity
PostgreSQL server major
Sentinel database name
schema version
runtime LOGIN role-membership/privilege checks
TLS verification result from Control
source-restricted HBA rule
PostgreSQL-unavailable Control startup fail-closed result
```

All remaining tests from `docs/INFRASTRUCTURE_ACCEPTANCE.md` remain mandatory: TLS/mTLS boundaries, PVE Worker egress, real SSH execution, one-shot approval non-reuse, individual revoke, global revoke/epoch non-revival, persistence across Control restart, and audit consistency.
