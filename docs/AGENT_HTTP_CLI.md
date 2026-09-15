# Agent HTTP API and `sentinelctl`

This document defines the agent-facing execution surface introduced in `0.1.0-dev.16`.

The design has two supported clients:

1. the HTTPS Agent API itself, usable with `curl` as the reference/raw interface;
2. `sentinelctl`, a small first-party client over exactly the same API.

MCP is intentionally not part of this milestone. A future MCP adapter must remain a thin client over the accepted Agent HTTP API rather than becoming a second authority model.

## Security model

The agent presents one opaque Sentinel capability as an HTTP bearer token. The capability is still constrained by its grant, target scope, permissions, expiry and security epoch. The Agent API cannot issue grants, decide approvals, edit targets, change `TRUST_0`, call the Signer directly, change Worker egress, or invoke emergency/operator authority.

Command submission is structured argv. Sentinel never reconstructs agent commands through a shell. Existing risk classification and approval policy apply unchanged.

Command output is `TRUST_2` data. It can never alter capability scope, approval policy, target inventory or any other authority-bearing state.

Raw execution output is returned only when the authenticating grant has:

```json
{
  "history": {
    "include_output": true
  }
}
```

Without that flag, job status and result metadata remain readable but the output store is not consulted and no raw stdout/stderr is returned.

## Public endpoints

The Gateway exposes these execution endpoints:

```text
GET  /v1/bootstrap
POST /v1/commands/submit
GET  /v1/jobs/{id}
GET  /v1/requests/{request_id}
```

All require:

```text
Authorization: Bearer <capability>
```

`/v1/jobs/{id}` and `/v1/requests/{request_id}` are capability-scoped. A grant cannot read jobs belonging to another grant, even when it knows the job ID or request ID.

### Bootstrap

`GET /v1/bootstrap` returns the grant scope and advertises the job/request resource templates.

Example:

```bash
curl --fail-with-body \
  --cacert sentinel-gateway-ca.crt \
  -H "Authorization: Bearer $SENTINEL_CAP" \
  https://sentinel-gateway.example/v1/bootstrap
```

### Submit a command

```bash
curl --fail-with-body \
  --cacert sentinel-gateway-ca.crt \
  -H "Authorization: Bearer $SENTINEL_CAP" \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "deploy-example-0001",
    "target": "example-prod",
    "argv": ["git", "-C", "/opt/example", "fetch", "--all"],
    "agent_reason": "deploy accepted project version",
    "timeout_seconds": 300
  }' \
  https://sentinel-gateway.example/v1/commands/submit
```

`timeout_seconds` is optional. `0` uses the default execution TTL. Explicit values are limited to 1..900 seconds and are also bounded by the grant expiry.

The response decision is one of the existing submission outcomes:

```text
accepted
approval_required
deny
```

An accepted response includes a job receipt. An approval-required response includes the approval ID but does not create a runnable authorization bypass: the caller retries the exact same immutable request after the operator decision.

The same `request_id` is an idempotency key. It cannot later be rebound to a different target/argv command.

### Read a job

```bash
curl --fail-with-body \
  --cacert sentinel-gateway-ca.crt \
  -H "Authorization: Bearer $SENTINEL_CAP" \
  https://sentinel-gateway.example/v1/jobs/JOB_ID
```

Terminal jobs expose result metadata such as success, exit code, error kind and output digest.

When `history.include_output=true`, a bounded captured prefix can additionally appear as:

```json
{
  "output": {
    "stdout_b64": "aGVsbG8K",
    "stderr_b64": "",
    "stdout_truncated": false,
    "stderr_truncated": false
  }
}
```

`stdout_b64` and `stderr_b64` are base64 because execution output is arbitrary bytes, not guaranteed UTF-8 text. Each stream is independently bounded to 256 KiB. The Worker also retains the pre-existing larger accounting limit used to abort pathological output volume; capture truncation and execution-output accounting are separate concepts.

The raw output object is stored separately from the execution job read model. Operator UI job views therefore do not gain raw command output merely because agent output capture exists.

### Recover by request ID

If a client loses the original submission response, it can recover the job associated with the same capability and request ID:

```bash
curl --fail-with-body \
  --cacert sentinel-gateway-ca.crt \
  -H "Authorization: Bearer $SENTINEL_CAP" \
  https://sentinel-gateway.example/v1/requests/deploy-example-0001
```

This is intended for disconnect/retry recovery. It does not make request IDs globally readable.

## `sentinelctl`

`sentinelctl` is the normal first-party CLI for agents and humans. It uses the same HTTPS API and does not contain a second execution protocol.

Global configuration:

```text
--url URL          or SENTINEL_URL
--ca-file PATH     or SENTINEL_CA_FILE
--cap-file PATH    or SENTINEL_CAP_FILE
--json
```

The capability can also come from `SENTINEL_CAP`.

There is deliberately no `--token` option. Passing a bearer capability in argv would expose it through process listings and shell history. On Unix, `--cap-file` must reference a regular non-symlink file that is not group/world accessible.

`sentinelctl` requires HTTPS, does not provide an insecure TLS mode, does not use proxy environment variables for the Sentinel connection, and does not follow HTTP redirects. These defaults prevent bearer forwarding to an unexpected origin.

### Bootstrap

```bash
sentinelctl bootstrap
```

### Submit without waiting

```bash
sentinelctl exec \
  --target example-prod \
  --reason 'deploy accepted project version' \
  --timeout 300 \
  -- git -C /opt/example fetch --all
```

When `--request-id` is omitted, `sentinelctl` generates one and prints it in the response.

### Submit and wait

```bash
sentinelctl exec --wait \
  --target example-prod \
  --timeout 300 \
  -- systemctl restart example.service
```

With `--wait`, the client:

1. submits the request;
2. if approval is required, keeps the same request ID and polls by retrying that immutable submission;
3. after acceptance, polls the job until a terminal state;
4. prints result/output;
5. returns the remote exit code when it is representable safely as a CLI exit status.

An approval-required command therefore does not need a new request ID after the operator clicks Allow.

### Job and request recovery

```bash
sentinelctl job get JOB_ID
sentinelctl job wait JOB_ID
sentinelctl request get REQUEST_ID
```

`job wait` polls until `succeeded`, `failed`, `canceled` or `expired`.

### Human output versus `--json`

Human-readable mode decodes captured bytes for display, but it does not send arbitrary remote control characters directly to the terminal. Escape/control and Unicode format characters are rendered visibly, while normal text, newlines and tabs remain readable. This protects the terminal from output such as ANSI escape injection.

For machine processing use:

```bash
sentinelctl --json job get JOB_ID
```

JSON mode preserves the byte-exact base64 fields `stdout_b64` and `stderr_b64` rather than applying terminal rendering.

## Output persistence

PostgreSQL schema version 3 adds `sentinel.execution_job_output`, keyed one-to-one by execution job ID. The runtime Control role has only SELECT/INSERT/UPDATE on this table. Per-stream database constraints enforce the same 256 KiB capture bound.

PostgreSQL terminal job completion, bounded output persistence and the required completion audit event occur in one transaction.

File-mode development compatibility uses a separate private execution-output store. Existing stores must be regular non-symlink files and, on Unix, must not be accessible by group/other users. New stores are written as mode `0600`.

## Intended remote-agent workflow

A deployment/testing agent should normally receive a grant scoped to one logical target and only the capabilities it needs. A typical workflow is:

```text
bootstrap
  -> inspect allowed target/scope
  -> submit structured argv
  -> wait for approval when required
  -> poll terminal job
  -> inspect bounded output
  -> run health/smoke checks
  -> operator revokes grant or grant expires
```

The client never receives Worker credentials, SSH CA material, Control admin authority, PostgreSQL credentials, target host-key override ability or PVE firewall authority.
