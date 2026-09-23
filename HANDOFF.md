# Tethys Sentinel — Handoff

Updated: 2026-09-22  
Current accepted development version: `0.1.0-dev.22`  
Current candidate version: `0.1.0-dev.24`  
Branch: `wip/dev24-github-relay`

## Status

`0.1.0-dev.22` is the accepted development baseline.

The current development milestone is reproducible Ansible onboarding for Debian/Ubuntu VM and unprivileged-LXC execution targets. The separate repository-history/public-release cleanup gate remains outstanding and is not coupled to this runtime-tooling milestone.

The public repository must not contain site-specific deployment data. Real addresses, hostnames, VM identifiers, local usernames or home paths, certificate/SSH fingerprints, acceptance-only topology, capability material, tokens, or other operator-specific evidence belong in private operator records.

## dev.22 acceptance status

A live external-Agent-HTTP acceptance run against the accepted dev.20 deployment exercised the path through the public reverse-proxy boundary, Gateway, Control, Worker, short-lived SSH certificate issuance, pinned target execution, and bounded output retrieval.

The run found two hardening gaps:

- Worker deny-by-default egress did not model a trusted time source. With no permitted NTP path, Worker clock skew exceeded the Signer backdate tolerance and locally rejected a newly issued short-lived SSH certificate as not currently valid.
- AI-facing `/v1/context` included configured host network addresses from the operator-owned context inventory even though agents only require logical target IDs.

Operator-side temporary remediation proved both diagnoses: a narrowly allowed trusted NTP source restored clock synchronization and end-to-end execution, and removing addresses from the deployment context removed them from the AI bundle.

The accepted dev.22 release carries the following structural fixes:

- `sentinel-egress-policy` requires one or more operator-supplied literal-IP `-ntp` sources, includes exact UDP/123 rules in the canonical policy/hash/drift check, and still denies DNS/general Internet egress;
- Agent `INFRASTRUCTURE.json` automatically omits host `addresses`, while the privileged Operator context snapshot retains the configured inventory;
- tests and infrastructure/egress/API documentation cover both boundaries.

The frontend reproducibility gate also detected a post-baseline registry drift. Reconstructing npm resolution with the timestamp of the last accepted CI run reproduced the previous lockfile hash exactly. The only current-registry difference was `electron-to-chromium` moving from `1.5.433` to `1.5.434`; it is a zero-runtime-dependency browser-version mapping package used through Browserslist. After review, the pinned graph hash was advanced. The full frontend typecheck/build, CSP/storage checks and embedded-distribution byte comparison then passed unchanged.

CI for commit `4c403d64c671b6b153d7f283e6045cac36d69833` passed the Go privacy/tidy/format/vet/race suite, PostgreSQL 15/18 integration, and the complete operator-frontend reproducibility/security job.

Gateway ingress firewall acceptance is now complete on the intended deployment: only the intended reverse-proxy source and the intended direct MCP client can reach the Gateway listener, an unrelated internal source times out at TCP connect, and the public reverse-proxy path still reaches Gateway and returns the expected unauthenticated capability error rather than a proxy failure. The VM-interface firewall is active and the Proxmox firewall compiler accepted the configuration.

The first live deployment attempt of dev.21 exposed a release-version consistency blocker: `VERSION` said `0.1.0-dev.21`, but `internal/buildinfo.Version` was still `0.1.0-dev.20`, so the installed candidate logged itself as dev.20. Per the acceptance rule, dev.21 is blocked and must not be merged or accepted.

dev.22 fixes that blocker by synchronizing the embedded runtime version and adds a CI version-consistency gate so `VERSION` and `internal/buildinfo.Version` cannot drift again. The functional NTP/context changes are unchanged from the blocked dev.21 candidate.

CI for exact deployed dev.22 artifact commit `5389e429f2abbd9f22162d13dbde3ce1e8daf581` is green across the version-consistency gate, Go privacy/tidy/format/vet/race suite, PostgreSQL 15/18 integration, operator-frontend reproducibility/security checks, and the linux/amd64 deployment-artifact build. The deployed binaries are built with Go 1.27.1, CGO disabled, and carry `version=0.1.0-dev.22` in build metadata.

Live dev.22 Control deployment is now accepted for the context-privacy fix. The installed binary hash matches the published dev.22 artifact and the service reports `0.1.0-dev.22` at startup. With the operator-owned context restored to include the target address, the privileged Operator `/admin/v1/context` view retains that address while the public capability-scoped Agent `/v1/context` `INFRASTRUCTURE.json` view omits the `addresses` field; a machine assertion confirmed no scoped host exposes it.

Live dev.22 Worker egress acceptance is now complete. The generated policy was installed byte-for-byte into the Proxmox VM-interface firewall and the dev.22 verifier returned rc=0 against the installed policy, Datacenter firewall and Worker NIC activation. The compiled rules contain only the Control HTTPS destination, the registered target SSH destination and the trusted NTP UDP/123 destination before the outbound drop. After restarting the Worker time client, it synchronized to the trusted time source with sub-millisecond offset; Control and target TCP probes succeeded while generic Internet TCP egress remained blocked. The temporary manual dev.20 NTP rule/drift is therefore replaced by canonical dev.22 policy.

Final external Agent HTTP acceptance is complete. A restricted public capability submitted a harmless structured `id` command through the public edge, Gateway, Control, Worker, short-lived SSH certificate path and target wrapper; the job succeeded with the expected unprivileged target identity. `GET /v1/requests/{request_id}` resolved to the same completed job, proving request-ID recovery. The acceptance grant was then revoked through the protected Control admin surface, and the same bearer immediately received HTTP 401 with `valid capability required` on bootstrap. No acceptance capability remains active.

`0.1.0-dev.22` is accepted on the intended infrastructure and may be merged. This acceptance is independent of the separate public-release historical-ref/cache purge still awaiting GitHub Support.

## dev.24 candidate status

dev.24 adds a **sidecar GitHub transport relay for ordinary ChatGPT chats**. It must not add, bypass or duplicate a Sentinel execution path. The relay is a client of the already accepted capability-scoped Agent HTTP contract only:

- `GET /v1/bootstrap`
- `POST /v1/commands/submit`
- `GET /v1/jobs/{id}`
- `GET /v1/requests/{request_id}`

The intended path is `ChatGPT -> dedicated private GitHub issue/comment mailbox -> sentinel-github-relay -> existing Gateway/Agent API -> existing Control/Worker/target path`. GitHub transports requests and results only; it never receives the Sentinel capability.

Security requirements for this milestone:

- a relay session is created only by an explicit local operator action against an already-issued normal Sentinel capability;
- session lifetime and target scope can only narrow the underlying Sentinel grant and can never outlive it;
- each session binds one repository ID, one issue number, the exact GitHub numeric actor ID and the GitHub App attribution observed on the approved issue;
- command comments must be newly created, unedited, sequential, uniquely identified and authenticated with a short-lived per-session HMAC key delivered out of band to the chat/operator, so GitHub is not the sole request-authentication root;
- replay, edit, reorder, duplicate request IDs, stale/closed sessions and invalid MACs fail closed before any Agent API submission;
- optional exact-argv mode provides an acceptance profile in which the relay can physically forward only one explicitly approved argv such as `["id"]`;
- the relay uses a dedicated GitHub App installation identity with only repository metadata plus Issues read/write permissions; installation access tokens are minted on demand and expire/rotate rather than using a long-lived PAT;
- polling uses authenticated conditional requests/ETags and serial processing with backoff; no new inbound listener is required on the Sentinel side;
- request/result bodies, logs and public repository material must never contain Sentinel capabilities, GitHub App private keys, relay session keys or deployment-specific secrets;
- GitHub/App identity is an additional transport binding, not Sentinel authority. Every forwarded command still passes the normal immutable request-ID, grant, policy, approval, epoch, Worker and target-wrapper checks.

This branch starts from the exact dev.23 candidate head `275e75b871ccb012d01209c0c33f31ef4285f276`. dev.23 remains independently testable on its original branch; the relay work is a new feature and therefore bumps the candidate to dev.24.

## dev.23 candidate status

dev.23 introduces operator-side target onboarding automation while preserving the accepted dev.22 trust boundaries. One top-level Ansible playbook composes three roles:

- `sentinel_target` configures Debian/Ubuntu VMs or unprivileged LXC guests with the locked `sentinel-ai` account, root-owned execution/replay helpers, local target identity, SSH user-CA public trust, authorized principal, narrow replay-helper sudo rule, hardened sshd policy and local host-key discovery;
- `sentinel_control_targets` treats the Ansible target inventory as the declarative SSH-target source of truth, obtains each pinned host key locally from that target, reconciles the complete Control `ssh-targets.json`, preserves non-managed context-only hosts, updates managed authoritative context, blocks removals unless explicitly authorized, and rolls back if Control does not return active;
- `sentinel_worker_egress` consumes the actual installed Control registry, generates the canonical Worker PVE policy with the accepted egress tool, writes changed bytes through pmxcfs, compiles and verifies activation, and removes temporary protected registry/policy material.

The linux/amd64 CI artifact now includes `tethys-sentinel-exec` and `tethys-sentinel-consume` in addition to Control/egress binaries. CI also syntax-checks the top-level playbook with pinned Ansible Core. Artifact consumers verify the published `SHA256SUMS` before installing target or egress binaries.

CI for implementation commit `0f98d44bebc13b63fdcedfe162854c37e36928cc` is green across the Go/privacy/version suite, PostgreSQL 15/18 integration, operator frontend, linux/amd64 artifact build, and the pinned Ansible syntax-check job.

A subsequent registry-only frontend reproducibility drift moved `electron-to-chromium` from `1.5.434` to `1.5.435`. The previous successful lock artifact confirms the prior version, the new graph dump shows the single mapping-package advance, and the package remains a zero-runtime-dependency Browserslist mapping dataset. The reviewed graph hash was advanced without changing Sentinel frontend source.

Live dev.23 onboarding acceptance is now complete through the infrastructure/idempotency boundary. The staged target, Control and Worker-egress plays all passed; two subsequent complete top-level playbook runs reported `changed=0` and `failed=0` for the target, Control and PVE operator host. Worker trusted-time remained synchronized to the configured operator NTP source, Control HTTPS and registered-target SSH remained reachable, and representative public HTTPS egress remained blocked.

The only remaining dev.23 acceptance item is the final harmless constrained Sentinel `id` execution through the newly playbook-managed target. A direct attempt from the current ChatGPT execution sandbox could not reach the operator's public Sentinel origin because that sandbox has no usable generic outbound HTTP/DNS path; this is a client-environment limitation, not a Sentinel failure. dev.23 remains unmerged until that last end-to-end check is completed.

## Operator-mandated development rules

1. Keep task reports short; explain what needs to be done and why.
2. Every newly implemented feature released as a new version must bump the project version.
3. Update this handoff when a new version is released/applied, a notably large step completes, or discussion changes the agreed next step.
4. Once a functioning version has been tested and accepted on the intended infrastructure, merge the WIP branch.
5. On merge, review/update README and project documentation.
6. Acceptance blocker => fix the branch and bump the next development version; do not merge the blocked version.
7. Keep the model-facing MCP surface deliberately narrow; never expose generic Control/admin APIs to the model.

## Accepted security architecture

- Agent capabilities are high-entropy opaque bearers; only token hashes persist server-side.
- Agent-facing APIs cannot widen grants, policy, targets, audit scope, Worker authority, signer authority, or emergency authority.
- `TRUST_0` is the only authority-bearing context. Files, logs, command output, web content, history, and model text are data only.
- Execution jobs bind grant + immutable request ID + logical target + argv + expiry and pass through staged/pending/claimed/running/terminal lifecycle states.
- `exec` and `shell` are separate permissions. Unbounded execution classes require explicit shell authority and operator approval.
- Control reclassifies immutable argv before signing.
- Worker uses fresh per-job SSH key material and does not receive plaintext agent capabilities.
- Targets are resolved only from operator-owned inventory to pinned endpoints/host keys.
- Structured remote execution transports argv directly; Sentinel does not reconstruct structured agent commands through a shell.
- Target-side replay protection enforces at-most-once execution.
- Worker egress is externally constrained and cannot be widened by the agent or Worker itself.
- `REVOKE ALL` advances a monotonic security epoch and disables authority; stale capabilities cannot revive.
- PostgreSQL is authoritative for mutable production security state; production failures are fail-closed.
- Browser operator access is isolated behind the dedicated Operator BFF with certificate-derived identity and strict browser security boundaries.
- Raw execution output is bounded, permission-gated, treated as untrusted data, and kept out of the normal Operator job read model.

## Accepted runtime baseline

The accepted runtime is `0.1.0-dev.22` with PostgreSQL schema v4.

The Agent HTTP contract remains the canonical authority boundary beneath MCP:

- `GET /v1/bootstrap`
- `POST /v1/commands/submit`
- `GET /v1/jobs/{id}`
- `GET /v1/requests/{request_id}`

The native MCP endpoint is loopback-only and exposes exactly five stable tools:

- `sentinel_exec`
- `sentinel_exec_batch`
- `sentinel_code`
- `sentinel_check`
- `sentinel_output`

Capabilities can be installed through a short-lived, one-time operator-issued claim. The MCP process reloads capability state per call, so grant rotation does not require restarting the MCP service.

Model-facing failures use compact `CODE: sentence` errors. Capability invalidation explicitly tells the model to stop retrying Sentinel tools and request operator action.

## dev.20 acceptance summary

The accepted intended-infrastructure run proved:

- Operator multi-tab CSRF state remains stable across concurrent tabs without weakening Origin, SameSite, Secure, HttpOnly, or `__Host-` cookie protections;
- the real AI client discovered exactly the five underscore-named MCP tools;
- structured execution completed end-to-end under a constrained `shell=false` capability;
- after `REVOKE ALL`, the model received `CAPABILITY_INVALID`, stopped retrying, and correctly requested a fresh operator-installed capability;
- a fresh one-time claim restored execution without restarting the MCP process;
- final cleanup revoked authority, removed installed capability material, and left the MCP health endpoint/process alive.

No dev.20 runtime acceptance blocker remains.

## Public-release cleanup status

Completed on the public repository:

- current source/docs/config examples were sanitized to documentation-only addresses and names;
- public documentation is normalized to the accepted `0.1.0-dev.22` / PostgreSQL schema v4 baseline, including the current Agent API, Operator, bounded-output, MCP, one-time claim, trusted-time egress and Agent-context privacy contracts;
- database/runbook documentation now includes migration `0004_mcp_claims.sql` and schema v4 rather than presenting dev.13-dev.16 checkpoints as the current deployment state;
- development-only frozen artifact workflows were removed;
- a permanent tracked-tree privacy/secret guard was added to CI;
- Go tidy/format/vet/race tests, PostgreSQL 15/18 integration, Operator frontend reproducibility/security, and the privacy scan passed on the sanitized snapshot;
- documentation-baseline commit `f0137bb4fb531650badf3690613aa6ee1704dbdf` passed the complete CI matrix, including the tracked-tree public privacy scan;
- every remaining public branch ref was moved onto the sanitized history; at the post-docs audit checkpoint all branch names pointed to `f0137bb4fb531650badf3690613aa6ee1704dbdf`;
- `main` contains only the original safe initialization commit plus sanitized public commits;
- repository metadata currently has no release/tag publication path carrying the removed deployment evidence, and no forks were present when checked.

Remaining server-side cleanup before the first public release:

- historical merged pull-request refs/cached diff views still retain the pre-sanitization object graph even though normal branch history no longer does;
- the first known changed/sensitive-history commit `43a42cd0bca025f8e1ac9bf30a6e048495e26ffe` remains directly addressable by SHA on GitHub after the rewrite;
- cached diffs for historical PRs #1-#4 still visibly contain deployment-specific evidence; PR #5 is also part of the affected pre-rewrite pull-request graph and should be included in the Support purge request;
- legacy Actions runs/artifacts that point at pre-rewrite development SHAs must be deleted rather than retained as a second publication path for historical data;
- GitHub Support must be asked to dereference/delete affected PR refs, run server-side garbage collection, and remove cached views after the history rewrite;
- obsolete branch names may now be deleted: they have already been verified on sanitized history;
- collaborators/local clones made before the rewrite must be discarded/re-cloned or carefully cleaned so an old merge/push cannot reintroduce the tainted graph.

Do not call the repository public-release-ready until the GitHub-hosted historical references above are gone and a final negative scan is repeated.

## Public-release cleanup gate

Before the first public release:

- replace every deployment-specific example with RFC documentation addresses/names;
- remove or rewrite historical acceptance documents that expose a concrete operator deployment;
- remove obsolete development-only artifact workflows and stale branch references;
- scan the current tree for private IPs, hostnames, usernames, paths, fingerprints, secrets, and acceptance-only topology;
- scan reachable Git history and every public branch, not only `main`;
- rewrite public history if old reachable commits contain deployment-specific data;
- move all obsolete WIP branch refs to the sanitized history or delete them;
- review GitHub Actions artifacts/releases and remove any publication path that unnecessarily retains old source-history pointers;
- run CI and a final negative privacy scan against the sanitized public history;
- keep real deployment evidence only in private operator records.

Do not call the repository public-release-ready until the current tree and reachable public history both pass the negative scan.
