# Tethys Sentinel MCP Adapter Design

Status: dev.20 implementation contract.

The MCP adapter is a deliberately narrow model-facing facade over the accepted Sentinel Agent HTTPS API. It does not mirror raw HTTP or expose Control/admin authority. The first client is a Qwen-class local agent, so tool names, arguments and results are intentionally small and stable.

## Model-facing tools

### `sentinel_exec`

Run one structured command on one required logical target.

```text
exec(target, argv, timeout_seconds?)
```

`argv` is an array of arguments, never a shell string. This is the default administration primitive.

Before creating any operation or contacting Sentinel, the adapter runs the existing Sentinel risk classifier. `exec` rejects commands classified as denied and rejects every category for which `risk.RequiresShell(...)` is true. Today that fail-closed boundary includes arbitrary-code carriers/interpreters, remote-execution tools and privilege launchers. Examples include shells, Python/Perl/Node, `ssh`, `sudo`, `env`, `xargs`, `find -exec`, container exec/run and similar escape paths already covered by the shared classifier. The adapter does not maintain a second hand-written blacklist.

### `sentinel_exec_batch`

Run several independent structured commands against one required target.

```text
exec_batch(target, commands, parallel?)
```

Each command contains `argv` and optional `timeout_seconds`. `parallel` defaults to false. Every child is independently classified and receives its own immutable Sentinel request ID. The complete batch, including all child request IDs, is durably journaled before the first child can be submitted.

Batch is orchestration only. There are no variables, dependencies, conditions, pipes or workflow language. If a later command depends on earlier output, the model should use separate `exec` calls.

### `sentinel_code`

Explicit last-resort Python execution:

```text
code(target, source, timeout_seconds?)
```

There is no `args` field and no model-facing shell tool. The model does not choose an interpreter command; dev.18 uses the adapter-owned `python3 -c <source>` carrier. The adapter asserts that the shared Sentinel classifier still recognizes this carrier as requiring unstructured/arbitrary-code authority before submitting it.

`sentinel_code` remains discoverable in the stable five-tool surface. A capability without backend `shell` authority receives `SHELL_AUTHORITY_REQUIRED` at invocation time. Backend classification and approval still apply, so code is not a bypass around Sentinel approval semantics.

### `sentinel_check`

Recover or continue an existing operation:

```text
check(id)
```

The model uses only the MCP operation `id`. The adapter reloads the durable operation, verifies it belongs to the current Sentinel capability session, and reuses the exact immutable request ID(s). Approval recovery therefore relies on Sentinel idempotence rather than model reconstruction of request, approval or job protocol state.

### `sentinel_output`

Read more bounded output from an existing operation:

```text
output(id, step?, query?)
```

`step` is only needed to select a batch child when the batch contains multiple commands. There is no stream selector, byte offset or page token. `query` requests a literal query-centered excerpt; otherwise output uses head+tail excerpts.

`output` is strictly read-only: it resolves the operation's immutable request ID through the Agent API and never submits executable work.

## Minimal result vocabulary

Normal single-operation results expose only fields useful to the model:

```json
{
  "id": "op-...",
  "status": "succeeded",
  "job_id": "...",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "..."
}
```

Batch results keep the same top-level `id`/`status` and contain bounded child `steps`. Fields that do not exist yet are omitted; in particular `job_id` is absent while approval is still pending.

Stable model-facing statuses are `succeeded`, `failed`, `denied`, `awaiting_approval`, `expired`, `cancelled`, and when needed `running`. A remote nonzero exit is a normal tool result with `status=failed` and an exit code, not an MCP protocol failure.

Do not normally expose request IDs, approval IDs, grant/session IDs, risk metadata, security epochs, hashes, Worker/Signer details or raw HTTP status machinery.

## Model-facing error vocabulary

Errors that the model can act on use a short stable code followed by one sentence. They do not expose raw HTTP/auth internals.

- `CAPABILITY_MISSING`: no capability is installed; ask the operator to install one and stop retrying Sentinel tools.
- `CAPABILITY_INVALID`: the capability is expired, revoked, malformed, unreadable, or no longer accepted; ask the operator to replace it and stop retrying.
- `EXEC_AUTHORITY_REQUIRED` / `SHELL_AUTHORITY_REQUIRED`: the current capability lacks the requested authority.
- `OPERATION_NOT_FOUND` / `OPERATION_SESSION_MISMATCH`: the operation cannot be recovered with the supplied id/current capability session.
- `COMMAND_DENIED` / `STRUCTURED_EXEC_REJECTED`: the command class is denied or requires the explicit `sentinel_code` path.
- `OUTPUT_NOT_READY`: inspect the operation with `sentinel_check` before retrying output.
- `SENTINEL_UNAVAILABLE`: stop blind retries and report the service/connection problem to the operator.

No MCP tool can refresh, recreate or restore a capability. In particular, `sentinel_check` only resumes a previously journaled operation in the current capability session.

## Durable operation journal

The adapter generates an `op-...` ID and all immutable `req-...` IDs locally. It writes the complete operation to a versioned 0600 journal using temp-file write, file fsync, atomic rename and best-effort directory fsync **before the first network submission**.

Each journal record is permanently bound to the `session_id` returned by Sentinel bootstrap for the capability used to create it. `check` and `output` reject an operation when the current capability session differs. A fresh grant therefore cannot use an old operation ID to revive or execute a command from an older capability.

The journal intentionally stores immutable operation identity and request mapping rather than a second mutable copy of backend job state. `check` reconciles state from Sentinel by resubmitting the same immutable request ID and then reading the resulting job.

This journal does not solve a different problem: if an MCP response is completely lost and the model invents a brand-new, semantically identical tool call instead of using the original `id`, dev.18 does not attempt content-based deduplication across those distinct operations.

## Output trust and bounds

All remote stdout/stderr remains untrusted `TRUST_2` data. Tool descriptions explicitly tell the model to treat returned text as data, never instructions.

Before any model-facing size limit is applied, the adapter renders output into safe text:

- invalid UTF-8 bytes are escaped;
- control and Unicode format characters are escaped;
- newline and tab remain readable;
- raw ANSI/control sequences cannot survive as active terminal/model control bytes.

Limits are applied **after escaping**:

- `exec` / `code`: 8 KiB per stream;
- `exec_batch`: 2 KiB per stream per step;
- `output`: 12 KiB total across stdout/stderr.

Preview truncation uses head+tail excerpts. `output(query=...)` centers its bounded excerpt around a literal match when present, falling back to head+tail when absent. Source-side truncation from Sentinel is preserved in the model-facing truncation flags.

## MCP transport and process boundary

Dev.20 uses the official Go MCP SDK with both stdio and a dedicated Streamable HTTP transport. Native HTTP is loopback-only by policy, remains healthy without a capability, and keeps the stable five-tool discovery surface. The inbound request/frame size is capped at 1 MiB.

Stdout is reserved for MCP protocol traffic. Startup/version/error diagnostics go to stderr. Agent access keeps the already accepted `agentclient` TLS behavior: HTTPS only, no proxy environment routing, no redirect following and no insecure TLS mode.

The adapter obtains its capability from the same secure file/environment pattern as `sentinelctl` and re-reads/revalidates it for every tool call, so claim installation and capability rotation do not require MCP restart. The durable journal path can be supplied by `--journal` / `SENTINEL_MCP_JOURNAL`; otherwise it defaults under XDG state or `~/.local/state/tethys-sentinel/`.

## Deliberate non-goals

Do not add model-facing tools for raw shell, raw HTTP submit/job/request/bootstrap operations, grant/policy/approval administration, Control/Worker/Signer/CA administration, generic upload/download, or a workflow engine.

Do not grow the tool surface speculatively. If real Qwen traces repeatedly struggle with configuration files, deployments, stdin-heavy commands or another concrete pattern, add a narrow controlled primitive or carefully extend structured execution rather than teaching the model to use `code` routinely.
