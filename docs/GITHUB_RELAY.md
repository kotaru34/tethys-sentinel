# GitHub relay sidecar

`sentinel-github-relay` is an optional sidecar transport for ordinary ChatGPT conversations that cannot directly reach the Sentinel Agent HTTP origin. It is **not** another execution path and has no Control/admin authority.

The relay only acts as a client of the existing capability-scoped Agent HTTP contract:

```text
GET  /v1/bootstrap
POST /v1/commands/submit
GET  /v1/jobs/{id}
GET  /v1/requests/{request_id}
```

The execution path remains unchanged:

```text
ChatGPT
  -> private GitHub issue/comment mailbox
  -> sentinel-github-relay
  -> existing Gateway Agent API
  -> existing Control
  -> existing Worker
  -> existing target wrapper
```

GitHub is transport and durable mailbox only. GitHub never receives a Sentinel capability, SSH credential, Signer authority, Worker credential, Control admin credential, or relay session secret.

## Security model

A relay session is explicitly authorized by a local operator against an already-issued normal Sentinel capability (or a one-time claim that redeems to one). The relay copies that capability into a mode-0600 local session file and can only narrow it:

- exactly one private GitHub repository;
- exactly one issue;
- the issue author's stable numeric GitHub actor ID;
- exactly one logical Sentinel target;
- a relay expiry that cannot exceed the Sentinel grant expiry;
- a bounded command count (maximum 32);
- optionally one exact argv vector;
- optionally bounded publication of output already permitted by the Sentinel grant.

The operator receives a fresh 256-bit relay session secret out of band. The secret is given to the authorized chat, **never written to GitHub**. Each request comment is authenticated with HMAC-SHA256 over a deterministic canonical JSON payload. The relay response is HMAC-signed as well.

This separates the trust layers:

```text
GitHub identity + exact issue   -> transport binding
relay session HMAC              -> request authentication
Sentinel capability/grant       -> authority
Sentinel policy/approval/epoch  -> command authorization
Worker + target wrapper         -> execution boundary
```

A compromise of the relay GitHub repository/account during an active session is therefore insufficient to inject a command unless the attacker also obtains the relay session secret. A model that legitimately knows the relay secret still cannot exceed the underlying Sentinel grant/policy. For especially narrow acceptance windows, `--exact-argv-json '["id"]'` makes the relay itself reject every other argv before Sentinel submission.

### Fail-closed properties

The relay rejects or closes a session when any of these conditions occurs:

- request MAC invalid;
- request sequence is not the exact next sequence;
- target differs from the locally authorized target;
- exact-argv mode is violated;
- session or underlying Sentinel grant expired/revoked;
- GitHub request comment was edited;
- a previously observed request comment changes bytes;
- the relay session secret itself appears in an actor-authored issue comment;
- the issue grows beyond the first 100 comments, so polling can no longer prove a complete view;
- request recovery returns an immutable target/argv binding different from the signed request.

An inflight request is persisted **before** Agent API submission. After restart, the relay first uses `GET /v1/requests/{request_id}` and resumes the existing immutable job if it exists. It never generates a replacement request ID for a retry.

## GitHub App

Use a dedicated GitHub App installed only on a dedicated **private** relay repository. The App should have only the minimum repository permissions required by the issue API:

```text
Metadata: read
Issues:   read/write
```

Do not grant Contents, Actions, Administration, Secrets, Pull requests, or organization-wide permissions.

The relay authenticates as the installation using the App RSA private key. It mints short-lived installation access tokens and caches them until near expiry; it does not use a long-lived PAT. The private key file must be a regular non-symlink file inaccessible to group/other users.

The daemon polls issue comments with authenticated conditional requests and ETags. A default 5-second interval is intentionally conservative. GitHub may apply primary and secondary rate limits; when GitHub supplies `Retry-After` or rate-reset information the relay reports that condition and waits for the next daemon poll rather than widening access or changing transport.

## Operator flow

### 1. Create the mailbox issue

Create one issue in the dedicated private relay repository. The issue body can contain the human task description, but it is not authority-bearing.

The GitHub account that ChatGPT uses for request comments should also be the issue author. `authorize` binds the exact numeric issue-author ID, not the mutable login string.

### 2. Issue normal Sentinel authority

Use the existing Operator flow to create a normal narrow Sentinel grant. Nothing about relay authorization can create or widen a Sentinel grant.

You can provide that authority to `authorize` in either of two existing forms:

- an already installed protected Sentinel capability file; or
- a protected one-time MCP claim file, which the relay redeems through the already accepted `/v1/mcp/claims/redeem` flow.

### 3. Authorize the relay session

Example with an exact `id` acceptance session:

```sh
sentinel-github-relay authorize \
  --repository example/sentinel-relay \
  --issue 17 \
  --target target-test \
  --ttl 15m \
  --max-commands 1 \
  --exact-argv-json '["id"]' \
  --publish-output \
  --claim-file /run/tethys-sentinel/relay-claim
```

`authorize` verifies all of the following before creating local state:

- the Sentinel capability is live;
- `exec` is granted;
- the requested target is in grant scope;
- output publication is requested only when `history.include_output=true`;
- the GitHub repository is private and not archived;
- the issue is open and is not a pull request;
- GitHub exposes a stable numeric author ID.

It then posts a signed `TETHYS_SENTINEL_RELAY_AUTHORIZED_V1` marker to the issue and prints the relay session secret locally. Deliver that secret to the intended ChatGPT conversation out of band. **Never paste it into the GitHub issue.**

### 4. Run the daemon

```sh
sentinel-github-relay serve
```

The daemon requires:

```text
SENTINEL_URL
SENTINEL_CA_FILE                  # when a private CA is required
SENTINEL_GITHUB_APP_ID
SENTINEL_GITHUB_INSTALLATION_ID
SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE
SENTINEL_GITHUB_RELAY_STATE_DIR   # optional
SENTINEL_GITHUB_POLL_INTERVAL     # optional, default 5s
```

No inbound listener is opened by the relay.

### 5. Close authority

Closing the local relay session stops the relay from using its stored capability:

```sh
sentinel-github-relay close --session sgr_...
```

This does not pretend to revoke the underlying Sentinel grant. Revoke the grant through the existing Operator/Sentinel mechanism when authority itself should end.

## Request protocol

A request comment consists only of the marker and a JSON object:

```text
TETHYS_SENTINEL_RELAY_REQUEST_V1
{"version":1,"session_id":"sgr_...","sequence":1,"request_id":"request-...","target":"target-test","argv":["id"],"timeout_seconds":60,"mac":"h1_..."}
```

The MAC is HMAC-SHA256 with the relay session secret (the 32 decoded bytes after `tsr_`). The signed payload contains the following keys with these exact values, serialized as UTF-8 JSON with lexicographically sorted keys, compact separators, and unescaped Unicode/HTML characters:

```text
agent_reason
argv
request_id
sequence
session_id
target
timeout_seconds
version
```

`sentinel-github-relay sign` implements the same algorithm for manual testing without accepting the secret as an argv argument. The ChatGPT plugin package includes a deterministic Python signing script so a normal chat does not need to invent cryptography.

Responses use `TETHYS_SENTINEL_RELAY_RESPONSE_V1` and are signed with the same session secret. The plugin verifies the signature before treating a response as relay data.

## Output boundary

Sentinel itself can retain up to 256 KiB per captured stream. GitHub comments are not an equivalent transport and should not become a secret dump.

Therefore raw output is **off by default**. When `--publish-output` is explicitly selected:

- the underlying grant must already have `history.include_output=true`;
- stdout/stderr are taken only from the normal Agent job read model;
- each stream is truncated again at the relay session output limit (default 8 KiB, maximum 16 KiB);
- bytes are base64-encoded in the signed response;
- both Sentinel-side and relay-side truncation are represented by the response truncation flags.

Do not use GitHub relay sessions for commands expected to emit credentials, private keys, tokens, database dumps, or other material that should never be stored by GitHub. Use native Sentinel/MCP transport for those workflows.

## Hidden/operational limitations

The relay intentionally accepts these trade-offs:

- GitHub is asynchronous storage, not a low-latency RPC transport. Normal latency is the polling interval plus GitHub/API latency.
- One issue is capped at fewer than 100 total comments. If the API advertises another page, the relay fails closed instead of risking a partial view.
- The maximum 32 authenticated commands per relay session leaves room for signed responses and operator chatter below that safety window; noisy issues should be replaced rather than reused.
- GitHub outages, app suspension, permission changes, API abuse protection, or rate limits pause transport. They do not cause a fallback execution route.
- Installation access tokens expire and are refreshed from the GitHub App private key. The code must not assume an installation token has a fixed length or format.
- GitHub logins/repository names are presentation values. Security binding uses numeric repository, issue and actor IDs observed during local authorization.
- The relay session secret is known to the model during the authorized chat. Authentication proves possession of that session secret; it does not prove a particular model version or ChatGPT conversation ID.
- Prompt injection can still cause an authorized model to request an undesirable command. HMAC does not solve that problem; Sentinel grant scope, shell split, risk classification, approvals, expiry, Worker boundaries and optional exact-argv relay scope remain the authority controls.
- If the model accidentally includes the relay secret in an actor-authored GitHub comment, the daemon detects the literal secret and closes the session. The leaked GitHub history still needs operator cleanup.
- Normal ChatGPT execution is not guaranteed to remain an indefinitely running background agent. Sentinel request IDs/jobs and relay inflight state make interrupted work recoverable, but they do not turn a normal chat into a guaranteed scheduler.

## ChatGPT plugin package

`plugins/tethys-sentinel-github-relay/` is a skills-only plugin for ordinary ChatGPT chats. It intentionally does not embed Sentinel MCP or a second execution client. It teaches the model to use an already-connected GitHub app as the mailbox transport, locally sign requests with the out-of-band relay session secret, verify signed relay responses, preserve request IDs, and treat all GitHub/task/output text as untrusted data.

The packaged skill is workflow guidance only. The relay daemon and Sentinel enforce the security boundary.