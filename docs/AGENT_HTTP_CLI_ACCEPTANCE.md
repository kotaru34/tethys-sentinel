# Agent HTTP API + `sentinelctl` acceptance

This runbook validates the public Agent HTTP and first-party CLI surface without depending on any site-specific topology.

Use documentation-only names and addresses in records committed to this repository. Real hostnames, IP addresses, VM identifiers, fingerprints, credentials, capability material, and operator evidence belong in private deployment records.

## Preconditions

Before beginning:

- current source has passed CI;
- PostgreSQL is at the schema version required by the candidate;
- autonomous authority is disabled;
- no active grants or jobs are required by another operator;
- Gateway, Control, Worker and target trust roots are already provisioned through the normal deployment procedure;
- the client uses verified TLS and never disables certificate validation.

Example documentation-only topology:

```text
Control       192.0.2.10
Gateway       192.0.2.11
Worker        192.0.2.12
Signer        192.0.2.13
Target        192.0.2.14
PostgreSQL    192.0.2.20:5432
```

Replace these addresses with the actual private deployment values only in operator-local notes/configuration.

## 1. Verify fail-closed starting state

Confirm:

- AI authority is disabled;
- active grants are zero;
- active jobs are zero or otherwise explicitly accounted for;
- runtime services use verified TLS/mTLS as designed;
- Worker external egress policy is already deny-by-default;
- no capability is present in shell history, process arguments, browser storage, or world-readable files.

Do not enable authority while performing backups, schema migration, binary replacement, or configuration verification.

## 2. Verify the candidate binaries

Build or obtain the exact candidate through the project release process and verify its checksums before installation.

Record the candidate version and SHA-256 values in private operator notes. Do not commit site-specific installed-binary paths, hostnames, or deployment hashes back into this public runbook.

Install only the components changed by the candidate unless the release procedure explicitly requires a synchronized full-runtime rollout.

## 3. Database safety

When a schema migration is required:

1. stop capability-bearing execution paths;
2. take an operator-approved rollback snapshot/dump;
3. apply only the migration(s) required for the current schema transition;
4. verify schema version and least-privilege role behavior;
5. confirm authority remains disabled;
6. only then restart the normal runtime path.

Production PostgreSQL must use verified TLS and the intended least-privilege runtime role. A database failure must never cause silent fallback to a weaker persistence backend.

## 4. Start services while authority remains disabled

Start the candidate services in dependency order appropriate to the deployment.

Before enabling AI authority, verify:

- Control is healthy;
- Operator UI loads over its dedicated HTTPS+mTLS boundary;
- Gateway health is good over verified TLS;
- Worker cannot reach unapproved destinations;
- no development plaintext or insecure TLS switch is enabled;
- Operator job reads do not expose raw stdout/stderr.

## 5. Prepare a protected client state directory

Use a private directory and capability file:

```sh
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/tethys-sentinel/acceptance"
mkdir -p "$STATE"
chmod 0700 "$STATE"

install -m 0600 /path/to/gateway-public-ca.crt "$STATE/gateway-public-ca.crt"

export SENTINEL_URL='https://192.0.2.11:8443'
export SENTINEL_CA_FILE="$STATE/gateway-public-ca.crt"
export SENTINEL_CAP_FILE="$STATE/cap"
```

The URL above is a documentation example only.

Never pass a capability as a normal command-line argument. If a capability must be installed manually, use protected stdin/prompt handling and mode 0600 storage.

For current MCP-capable builds, prefer the one-time operator claim flow:

```sh
sentinelctl mcp claim
```

## 6. Narrow structured-exec acceptance

Enable AI authority deliberately through the Operator UI, then issue a short-lived grant with:

```text
target: target-test
exec: true
shell: false
history.include_output: true
all unrelated permissions: false
```

Bootstrap:

```sh
sentinelctl bootstrap
```

Run a harmless structured command:

```sh
sentinelctl exec --wait \
  --target target-test \
  --timeout 60 \
  -- printf 'SENTINEL_ACCEPTANCE_OK\n'
```

Pass criteria:

- command reaches a terminal success state;
- exit status is zero;
- stdout is exactly the expected line;
- the immutable request/job relationship is preserved;
- no shell authority was required.

## 7. Request recovery and output permissions

For a completed operation, verify:

```sh
sentinelctl job get JOB_ID
sentinelctl request get REQUEST_ID
```

Both lookups must identify the same job when scoped to the same capability session.

With `history.include_output=false`, lifecycle/result metadata may be visible but raw stdout/stderr must not be returned.

With `history.include_output=true`, bounded raw output may be returned to that exact grant. Machine JSON must keep byte-exact output in explicit base64 fields.

## 8. Terminal/output sanitization

Exercise output containing ANSI/control bytes without invoking a shell:

```sh
sentinelctl exec --wait \
  --target target-test \
  --timeout 60 \
  -- printf '%s\n' $'safe\033[31mNOT-RED\033[0m'
```

Human-readable output must render control bytes visibly instead of changing terminal state.

The machine-readable form must preserve the captured bytes unambiguously.

## 9. Approval recovery

Create one harmless operation that the semantic risk classifier intentionally places behind approval.

The client must:

- surface the approval-required state once;
- wait without inventing a new request ID;
- after **Allow once**, retry/recover the exact immutable request;
- complete successfully only after approval;
- require a new approval for a new request ID when policy says approval is one-shot.

Do not widen the acceptance grant merely to make the test easier.

## 10. Capability revocation behavior

After at least one successful structured operation:

1. invoke `REVOKE ALL`;
2. retry the same harmless command through the client/model;
3. verify the request fails with capability-invalid semantics;
4. verify the client/model does not loop through repeated execution or `sentinel_check` attempts;
5. verify it reports that operator action/a fresh capability is required.

For native MCP, the server process and health endpoint must remain alive after capability invalidation.

## 11. Capability rotation without MCP restart

Issue a fresh one-time claim for the same constrained target/scope and redeem it with:

```sh
sentinelctl mcp claim
```

Do not restart `sentinel-mcp`.

Repeat the harmless structured command and verify it succeeds under the new capability while the MCP process identity remains unchanged. This proves per-call capability reload.

## 12. Operator UI non-leak regression

After an include-output job completes, inspect the corresponding Operator job view.

Pass criteria:

- normal lifecycle/result metadata is visible;
- raw stdout/stderr are not present in the normal Operator job read model;
- browser persistent storage contains no capability/authority secret;
- Security shows the factual current authority state;
- multi-tab session/CSRF handling remains stable.

## 13. Worker hard-boundary checks

From inside Worker, verify only the approved runtime transport set is reachable:

```text
Worker -> Control internal HTTPS
Worker -> registered target SSH endpoints
```

And verify representative disallowed destinations fail:

```text
Worker -> public Internet HTTPS
Worker -> unrelated LAN host
Worker -> registered target on an unlisted port
Worker -> DNS resolver
```

Exact deployment addresses belong in private operator records.

## 14. Close the acceptance window

After all checks:

- revoke every acceptance grant;
- run `REVOKE ALL`;
- remove temporary capability/header files;
- verify the MCP capability file is absent;
- verify MCP remains healthy without authority;
- record the resulting evidence privately.

Example cleanup:

```sh
rm -rf "$STATE"
```

## Success criteria

Acceptance passes only if:

- verified TLS/mTLS boundaries remain intact;
- schema and runtime role checks pass;
- structured execution works end-to-end;
- output permission/sanitization boundaries hold;
- approval recovery preserves immutable request identity;
- capability revoke fails closed without retry loops;
- capability rotation resumes execution without restarting MCP;
- Operator UI does not gain raw output or persistent browser authority;
- Worker deny-by-default egress still holds;
- final authority is disabled and capability material is removed.

Any functional or security blocker requires a fix and a new development version before merge/release.
