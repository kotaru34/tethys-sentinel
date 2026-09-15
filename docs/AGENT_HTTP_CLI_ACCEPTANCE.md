# dev.16 Agent HTTP API + `sentinelctl` infrastructure acceptance

This runbook is the constrained real-infrastructure acceptance delta for `0.1.0-dev.16`.

It supplements the already accepted `docs/INFRASTRUCTURE_ACCEPTANCE.md` and `docs/INFRASTRUCTURE_ACCEPTANCE_REMOTE_POSTGRES.md`. Do not repeat unrelated dev.13 provisioning when the accepted topology is unchanged.

The dev.16 runtime candidate is frozen at:

```text
d9f688f5cd97bd932a4b9b99c243f0fb11361137
```

CI Actions run `34920564170` passed on that exact source checkpoint: Go tidy/format/vet/race tests, PostgreSQL 15, PostgreSQL 18, frontend dependency verification/build and embedded archive parity.

The canonical deployment bundle is produced by Actions run `34922039158`, artifact `tethys-sentinel-dev16-linux-amd64-d9f688f5`. The workflow checks out the frozen runtime SHA, uses Go 1.27.1, builds all four Linux/amd64 binaries twice outside the source tree and requires byte-for-byte equality before packaging. The bundle also contains the exact schema-v3 migration from the frozen source.

Do not merge dev.16 before this runbook passes.

## Accepted starting state

Intended existing topology:

```text
Control       10.169.2.210
Gateway       10.169.2.211
Worker        10.169.2.212
Signer        10.169.2.213
Target-test   10.169.2.214
PostgreSQL    10.169.2.6:5432
```

Expected starting authority:

```text
epoch=5
disabled=true
reason=dev.15 approval workflow acceptance complete
```

Expected starting PostgreSQL schema:

```text
2
```

The accepted deployed binaries before this upgrade are recorded in `HANDOFF.md`. In particular, verify their hashes before overwriting anything.

Do not enable authority during artifact verification, backup, schema migration or service deployment.

## 1. Obtain and verify the exact dev.16 bundle

No separate build host is required for this acceptance. Download artifact `tethys-sentinel-dev16-linux-amd64-d9f688f5` from Actions run `34922039158`.

The artifact ZIP contains:

```text
tethys-sentinel-0.1.0-dev.16-linux-amd64-d9f688f5.tar.gz
tethys-sentinel-0.1.0-dev.16-linux-amd64-d9f688f5.tar.gz.sha256
```

Verify and unpack it on an operator-controlled machine:

```sh
sha256sum -c tethys-sentinel-0.1.0-dev.16-linux-amd64-d9f688f5.tar.gz.sha256

rm -rf dev16-bundle
mkdir dev16-bundle
tar -xzf tethys-sentinel-0.1.0-dev.16-linux-amd64-d9f688f5.tar.gz \
  -C dev16-bundle

(
  cd dev16-bundle
  sha256sum -c SHA256SUMS
  cat BUILDINFO
)
```

Expected outer tar SHA-256:

```text
4336026365683215191520650157d4480f23d36d7ba6f2caa685b772e83424a6
```

Expected manifest:

```text
d9708e74b9e05124d2bd1304ee1736faf1e58b0e72fe8b0d1956337697ab1db2  sentinel-control
a1971546ebe36ddfa07f88c07d48139f013fdc749a931e52547cc3ab37aa5fcb  sentinel-gateway
014f0f22be23724cbd3de5a534323831acb5abfcfcd3a55749b42a31101ea9dd  sentinel-worker
a2c67c056f5801f9719ead0d22d354f7bc5fc15ee860d0e452fdfe4c9a28d28f  sentinelctl
813668ee447ba0c9767c6cab22535b28be6fbd8fa2e7062ffa9dc0d9650dbb99  db/migrations/0003_execution_output.sql
```

`BUILDINFO` must contain:

```text
version=0.1.0-dev.16
source_sha=d9f688f5cd97bd932a4b9b99c243f0fb11361137
go_version=go version go1.27.1 linux/amd64
goos=linux
goarch=amd64
cgo=disabled
build_flags=-trimpath -buildvcs=true
```

Do not rebuild from a later moving branch during this acceptance. `sentinel-signer`, target wrappers and `sentinel-egress-policy` are not changed by dev.16 and must remain at their already accepted versions unless an acceptance failure proves otherwise.

## 2. Fail-closed preflight

Before stopping anything, verify in Operator UI/API:

```text
AI AUTHORITY DISABLED
epoch 5
active grants 0
active jobs 0
```

If active grants are not zero, revoke them before proceeding. The rollback database snapshot must not contain an epoch-5 capability that could later become usable after an operator re-enable.

Also verify there are no non-terminal execution jobs that matter to the operator. Do not snapshot during a running acceptance or production execution.

On each runtime host record the current binary hash:

```sh
sha256sum /usr/local/bin/sentinel-control   # Control
sha256sum /usr/local/bin/sentinel-gateway   # Gateway
sha256sum /usr/local/bin/sentinel-worker    # Worker
```

Compare them with `HANDOFF.md` before continuing.

## 3. Stop capability-bearing runtime paths

Keep Signer and target unchanged. Stop components in this order:

```text
Worker -> Gateway -> Operator -> Control
```

Commands on the respective VMs:

```sh
sudo systemctl stop sentinel-worker.service
sudo systemctl stop sentinel-gateway.service
sudo systemctl stop sentinel-operator.service
sudo systemctl stop sentinel-control.service
```

Confirm no Control database session remains before taking the database rollback clone.

Authority is already disabled; stopping Gateway/Worker additionally removes the agent execution path while the database is being migrated.

## 4. Create two rollback artifacts before schema v3

The remote PostgreSQL service is shared infrastructure, so dev.16 acceptance uses both an immediate same-cluster database clone and an offline logical dump.

Run as PostgreSQL administrator on the database host. First terminate any remaining sessions to the Sentinel database:

```sh
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d postgres <<'SQL'
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'tethys_sentinel'
  AND pid <> pg_backend_pid();
SQL
```

Create an exact v2 rollback database from the now-quiescent original:

```sh
ROLLBACK_DB="tethys_sentinel_dev15_rollback_20260915"

sudo -u postgres createdb \
  --template=tethys_sentinel \
  --owner=sentinel_owner \
  "$ROLLBACK_DB"

sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d postgres \
  -c "ALTER DATABASE ${ROLLBACK_DB} WITH ALLOW_CONNECTIONS false;"
```

Then create an independent custom-format dump:

```sh
sudo install -d -o postgres -g postgres -m 0700 /var/backups/tethys-sentinel
sudo -u postgres pg_dump -Fc tethys_sentinel \
  > /var/backups/tethys-sentinel/pre-dev16-schema-v2.dump
sudo sha256sum /var/backups/tethys-sentinel/pre-dev16-schema-v2.dump
```

Record the dump hash. Keep both rollback artifacts until dev.16 is accepted and stable.

Verify the rollback clone itself is schema v2 and epoch 5 disabled without enabling normal connections. A PostgreSQL administrator can temporarily connect despite the runtime HBA path as appropriate for the local host; do not expose the clone to Sentinel services.

## 5. Save accepted rollback binaries

Before installing dev.16, save the exact existing binaries on each VM:

Control:

```sh
sudo cp -a /usr/local/bin/sentinel-control /usr/local/bin/sentinel-control.dev15.rollback
sudo sha256sum /usr/local/bin/sentinel-control.dev15.rollback
```

Gateway:

```sh
sudo cp -a /usr/local/bin/sentinel-gateway /usr/local/bin/sentinel-gateway.dev13.rollback
sudo sha256sum /usr/local/bin/sentinel-gateway.dev13.rollback
```

Worker:

```sh
sudo cp -a /usr/local/bin/sentinel-worker /usr/local/bin/sentinel-worker.dev13.rollback
sudo sha256sum /usr/local/bin/sentinel-worker.dev13.rollback
```

Do not overwrite existing rollback files unless their hashes match the accepted values recorded in `HANDOFF.md`.

## 6. Apply only migration 0003 to the original database

Use the exact bundled migration:

```text
dev16-bundle/db/migrations/0003_execution_output.sql
```

Its SHA-256 must already have passed the bundle manifest check above.

Copy it to the database administration path and apply it with the deployment/migrator identity exactly once:

```sh
PGPASSWORD="$DB_DEPLOY_PASS" \
psql -X -v ON_ERROR_STOP=1 \
  -h <DB_ADMIN_ENDPOINT> -U sentinel_deploy -d tethys_sentinel \
  -f dev16-bundle/db/migrations/0003_execution_output.sql
```

Do not loop over all migrations against the already initialized database.

Verify as PostgreSQL administrator:

```sql
SELECT version
FROM sentinel.schema_version
WHERE id = 1;

SELECT epoch, disabled, reason
FROM sentinel.authority_state
WHERE id = 1;

SELECT to_regclass('sentinel.execution_job_output');

SELECT
  has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'SELECT') AS can_select,
  has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'INSERT') AS can_insert,
  has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'UPDATE') AS can_update,
  has_table_privilege('sentinel_control', 'sentinel.execution_job_output', 'DELETE') AS can_delete;
```

Expected:

```text
version = 3
epoch = 5
disabled = true
execution_job_output exists
SELECT/INSERT/UPDATE = true
DELETE = false
```

If migration or these checks fail, do not start dev.16. Use the rollback procedure below.

## 7. Install exact dev.16 binaries while authority remains disabled

Copy the verified bundle files to the appropriate hosts through the normal operator path.

Control:

```sh
sudo install -o root -g root -m 0755 dev16-bundle/sentinel-control \
  /usr/local/bin/sentinel-control
sha256sum /usr/local/bin/sentinel-control
```

Gateway:

```sh
sudo install -o root -g root -m 0755 dev16-bundle/sentinel-gateway \
  /usr/local/bin/sentinel-gateway
sha256sum /usr/local/bin/sentinel-gateway
```

Worker:

```sh
sudo install -o root -g root -m 0755 dev16-bundle/sentinel-worker \
  /usr/local/bin/sentinel-worker
sha256sum /usr/local/bin/sentinel-worker
```

Install the client on a trusted Linux machine that can reach Gateway. Installing it on Gateway for the constrained acceptance is acceptable:

```sh
sudo install -o root -g root -m 0755 dev16-bundle/sentinelctl \
  /usr/local/bin/sentinelctl
sentinelctl --version
```

The installed hashes must exactly match the bundled `SHA256SUMS` listed in section 1.

No Signer, target wrapper, SSH host-key pin or PVE Worker firewall change is expected.

## 8. Start disabled control path and verify before Worker

Start in this order:

```text
Control -> Operator -> Gateway
```

Do **not** start Worker yet.

```sh
sudo systemctl start sentinel-control.service
sudo systemctl start sentinel-operator.service
sudo systemctl start sentinel-gateway.service
```

Verify:

- Control service active;
- internal listener remains `10.169.2.210:9091`;
- admin listener remains loopback `127.0.0.1:8081`;
- Operator UI still loads over its dedicated mTLS listener;
- Operator Overview still shows epoch 5 disabled;
- Gateway `/healthz` is healthy over verified Gateway TLS;
- no service is using a development plaintext switch;
- no raw output field has appeared in the Operator Jobs read model.

A dev.16 Control startup failure here is an acceptance blocker. Do not enable authority.

## 9. Start Worker and recheck hard egress boundary

Start Worker:

```sh
sudo systemctl start sentinel-worker.service
```

The existing PVE policy must still be unchanged:

```text
policy_in: ACCEPT
policy_out: DROP
allowed outbound only:
  10.169.2.210:9091/tcp
  10.169.2.214:22/tcp
```

Repeat the two positive connectivity checks and at least one Internet + one unrelated-LAN negative check from the accepted runbook. Dev.16 does not justify broader Worker egress.

## 10. Prepare `curl` / `sentinelctl` client without leaking capability

Use Gateway public CA verification. Never use `-k`.

For `sentinelctl`, prefer a private capability file:

```sh
STATE="$HOME/.cache/tethys-sentinel/dev16-acceptance"
mkdir -p "$STATE"
chmod 0700 "$STATE"

install -m 0600 /path/to/gateway-public-ca.crt "$STATE/gateway-public-ca.crt"
read -rsp 'Paste capability: ' CAP
echo
printf '%s\n' "$CAP" > "$STATE/cap"
chmod 0600 "$STATE/cap"
unset CAP

export SENTINEL_URL='https://10.169.2.211:8443'
export SENTINEL_CA_FILE="$STATE/gateway-public-ca.crt"
export SENTINEL_CAP_FILE="$STATE/cap"
```

For raw `curl`, construct the Authorization header in a private temporary file rather than putting the bearer in argv/history:

```sh
printf 'Authorization: Bearer %s\n' "$(cat "$STATE/cap")" > "$STATE/auth.hdr"
chmod 0600 "$STATE/auth.hdr"
```

Delete the entire state directory after each grant is revoked.

## 11. Acceptance grant A — output must remain hidden

Enable authority only now, deliberately, through Operator Security. Epoch remains 5 on enable.

Issue a narrow grant:

```text
agent: dev16-curl-no-output
purpose: dev.16 curl/job/request acceptance without raw output
target: sentinel-target-test
TTL: 10 minutes
exec: true
shell: false
history.include_output: false
all unrelated permissions: false
```

Capture the one-time capability only into the private client file above.

First prove bootstrap through raw curl:

```sh
curl --fail-with-body --silent --show-error \
  --cacert "$STATE/gateway-public-ca.crt" \
  --header @"$STATE/auth.hdr" \
  "$SENTINEL_URL/v1/bootstrap"
```

Submit a harmless direct argv command that produces known output and should not require shell authority:

```sh
REQ_A="dev16-no-output-$(openssl rand -hex 8)"
cat > "$STATE/a.json" <<EOF
{
  "request_id": "$REQ_A",
  "target": "sentinel-target-test",
  "argv": ["printf", "dev16-no-output\\n"],
  "agent_reason": "dev.16 raw curl job/request acceptance",
  "timeout_seconds": 60
}
EOF

curl --fail-with-body --silent --show-error \
  --cacert "$STATE/gateway-public-ca.crt" \
  --header @"$STATE/auth.hdr" \
  --header 'Content-Type: application/json' \
  --data-binary @"$STATE/a.json" \
  "$SENTINEL_URL/v1/commands/submit"
```

Record the returned job ID, then poll:

```sh
curl --fail-with-body --silent --show-error \
  --cacert "$STATE/gateway-public-ca.crt" \
  --header @"$STATE/auth.hdr" \
  "$SENTINEL_URL/v1/jobs/JOB_ID"
```

And recover through request ID:

```sh
curl --fail-with-body --silent --show-error \
  --cacert "$STATE/gateway-public-ca.crt" \
  --header @"$STATE/auth.hdr" \
  "$SENTINEL_URL/v1/requests/$REQ_A"
```

Both reads must identify the same terminal job/result. Neither JSON response may contain `output`, `stdout_b64` or `stderr_b64` because this grant does not include output.

Revoke grant A and remove its local capability material.

## 12. Acceptance grant B — `sentinelctl`, output and sanitization

Issue a fresh narrow grant:

```text
agent: dev16-sentinelctl-output
purpose: dev.16 sentinelctl bounded output acceptance
target: sentinel-target-test
TTL: 15 minutes
exec: true
shell: false
history.include_output: true
all unrelated permissions: false
```

Capture its capability into a new private `STATE/cap` file and rebuild `auth.hdr` if raw curl will also be used.

Prove bootstrap:

```sh
sentinelctl bootstrap
```

Then prove ordinary output readback:

```sh
sentinelctl exec --wait \
  --target sentinel-target-test \
  --timeout 60 \
  -- printf 'dev16-sentinelctl-output\n'
```

Expected human output includes the terminal job, exit 0 and a stdout section containing the expected text.

Prove machine JSON/base64 using the returned job ID:

```sh
sentinelctl --json job get JOB_ID
```

The response must expose `stdout_b64`, not an ambiguous plaintext `stdout` field.

### Terminal sanitization check

Use a direct program that can emit an ESC byte without invoking a shell. Python/interpreter commands are classified as arbitrary-code and would intentionally require `shell=true`, so do not use them for this narrow grant. A suitable acceptance command is `printf` with a literal argument containing an ESC byte supplied by the client process.

From bash:

```sh
sentinelctl exec --wait \
  --target sentinel-target-test \
  --timeout 60 \
  -- printf '%s\n' $'safe\033[31mNOT-RED\033[0m'
```

The remote argv remains structured; the local shell only constructs one argument byte string. Human `sentinelctl` output must show visible `\x1b` escapes and must **not** cause terminal color/state changes.

The same job through `sentinelctl --json job get JOB_ID` must preserve the captured bytes in base64.

## 13. Optional approval-aware `exec --wait` proof

To prove the new CLI's approval waiting behavior end to end, create a controlled risky request whose grant contains the necessary capability and whose side effect is harmless. Do not reuse the terminal-sanitization grant if that would require widening it unnecessarily.

A recommended acceptance-only command is a `FILESYSTEM_DELETE` operation against a known nonexistent path:

```text
rm -f /tmp/tethys-sentinel-dev16-acceptance-does-not-exist
```

Run `sentinelctl exec --wait` with a fixed/generated request ID. It should print one approval-required notice, continue waiting, and after Operator chooses **Allow once**, retry the exact same request ID, receive the job and wait to terminal success.

Then submit the same scope with a **new** request ID and prove a new approval is required; deny it. This rechecks that CLI approval handling did not weaken existing allow-once semantics.

## 14. Operator UI non-leak regression

After at least one include-output job completes, open the Operator Jobs page and inspect the matching job.

Pass criteria:

- normal status/result metadata remains visible;
- raw stdout/stderr are **not** displayed or present in the Operator job API response;
- no browser storage rule regressed;
- Security still shows the current authority epoch/state correctly.

The separate agent output store must not silently become an Operator read-model expansion.

## 15. Close the acceptance window

Revoke every dev.16 acceptance grant.

Then run global `REVOKE ALL` with reason:

```text
dev.16 Agent HTTP CLI acceptance complete
```

Because acceptance began by enabling epoch 5, expected final state is:

```text
epoch=6
disabled=true
```

Delete all temporary capability/header files:

```sh
rm -rf "$HOME/.cache/tethys-sentinel/dev16-acceptance"
```

Verify no acceptance capability remains in environment variables or shell history.

Record audit evidence for grant issue/revoke, approvals if used, job authorization/claim/start/certificate/completion and final emergency revoke.

## 16. Success criteria

Dev.16 passes only if all of the following are true:

- schema v3 applied cleanly with authority unchanged/disabled during migration;
- exact dev.16 Control/Gateway/Worker binaries run on the accepted topology;
- Signer, target wrapper and PVE Worker boundary remain unchanged;
- raw curl bootstrap/submit/job/request-recovery works with verified TLS;
- cross-grant isolation remains enforced;
- no-output grant receives no raw output;
- include-output grant receives bounded output;
- `sentinelctl exec --wait` reaches terminal status and returns correct CLI status;
- human output escapes terminal control data;
- `--json` returns explicit base64 byte fields;
- approval-aware wait, if exercised, preserves one-shot approval semantics;
- Operator UI remains functional and does not gain raw output;
- final authority is epoch 6 disabled;
- audit chain/actors remain valid;
- temporary capability material is removed.

Any functional or security blocker requires a branch fix and version bump to dev.17 before another acceptance attempt. Do not merge dev.16 with a known blocker.

## Emergency rollback to accepted dev.15

Rollback is operator-only and is valid only with all Sentinel agent execution paths stopped.

Immediately stop:

```text
Worker -> Gateway -> Operator -> Control
```

Keep them stopped throughout database swap.

Terminate remaining connections to the failed/migrated database:

```sh
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d postgres <<'SQL'
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'tethys_sentinel'
  AND pid <> pg_backend_pid();
SQL
```

Rename the failed dev.16 database out of the production name and restore the exact pre-dev16 clone:

```sh
FAILED_DB="tethys_sentinel_dev16_failed_$(date +%Y%m%d%H%M%S)"
ROLLBACK_DB="tethys_sentinel_dev15_rollback_20260915"

sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d postgres <<SQL
ALTER DATABASE tethys_sentinel WITH ALLOW_CONNECTIONS false;
ALTER DATABASE tethys_sentinel RENAME TO ${FAILED_DB};
ALTER DATABASE ${ROLLBACK_DB} RENAME TO tethys_sentinel;
ALTER DATABASE tethys_sentinel WITH ALLOW_CONNECTIONS true;
SQL
```

Verify restored database before any service start:

```text
schema version 2
epoch 5
disabled true
```

Then atomically restore the saved accepted binaries on Control/Gateway/Worker and verify their hashes against `HANDOFF.md` before restart.

Start accepted services in normal order:

```text
Control -> Operator -> Gateway -> Worker
```

Recheck Operator Security state and keep authority disabled. Do not delete the failed dev.16 database or pre-dev16 dump until root cause is understood.

Because the rollback snapshot was taken at epoch 5 while disabled and before any dev.16 acceptance capability was issued, capabilities created after the snapshot do not exist in the restored database. The preflight requirement of zero active epoch-5 grants prevents rollback from reviving an earlier usable grant.

If the database clone is unavailable or damaged, restore from the recorded custom-format `pg_dump` into a clean database under operator control, verify schema v2/epoch 5 disabled, and only then restore accepted dev.15 services.
