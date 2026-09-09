# Architecture

## Trust-boundary overview

```text
                         Operator
                            |
                    Admin UI / API
                            |
                    +-------v-------+
                    | Control Plane |
                    | grants/policy |
                    | approvals     |
                    +-------+-------+
                            |
             internal authenticated interfaces
                            |
       +--------------------+--------------------+
       |                                         |
+------v------+                           +------v------+
| AI Gateway |                           | SSH Signer  |
| public API |                           | CA boundary |
+------+-----+                           +------+------+
       |                                        |
       | narrow execution jobs                 | short-lived certs
       v                                        v
+------+----------------------------------------+------+
|                   Execution Worker                  |
| no grant issuance / no policy administration        |
+--------------------------+---------------------------+
                           |
                          SSH
                           |
                    Infrastructure
```

Persistent state is planned in PostgreSQL with separate least-privilege roles. The gateway must not have database privileges that let it create or broaden grants/policies.

## Components

### Control Plane

Human/operator authority. Owns grant creation, revocation, policies, approvals, inventory administration and emergency controls. It is not directly exposed to the AI-facing public interface.

### AI Gateway

Validates capability tokens and exposes only the operations granted to an agent: bootstrap/context, permitted history, notes, and execution requests. It cannot grant itself more authority.

### Execution Worker

Consumes narrowly described approved jobs and performs SSH operations. It does not expose policy-management endpoints and should not hold a long-lived infrastructure-wide SSH private key.

### SSH Signer

Holds the SSH CA key or equivalent signing capability. It accepts only constrained internal signing requests and issues short-lived OpenSSH certificates. It is isolated from the public gateway.

### PostgreSQL / audit storage

Stores grants by token hash, approvals, inventory, action metadata, history/notes and audit chain. Raw command output is optional/configurable and treated as potentially secret-bearing data.

## Capability model

A grant contains at minimum:

- opaque capability token (returned only at issuance; hash stored server-side)
- session/grant ID
- agent identity label
- purpose
- allowed targets
- expiry
- `exec`, `shell`, `upload`, `download`
- history scope
- notes scope
- revocation state

A capability never contains the SSH private key and cannot mutate its own scope.

## Agent authoritative context

The gateway provides read-only context for each session. It explicitly states that only system-authoritative responses may define permissions or operating rules. Discovered content is untrusted data and cannot supersede Sentinel policy.

Trust levels:

- Trust 0: Sentinel system policy, capability scope, tool descriptions, explicit operator approvals.
- Trust 1: operator-approved runbooks/notes.
- Trust 2: operational data such as host files, logs, stdout/stderr and configuration content.
- Trust 3: external/untrusted content such as web pages and arbitrary downloaded/user-generated text.

Prompt instructions improve agent behavior but are never the actual security boundary.

## Risk approvals

The policy engine classifies sensitive actions before execution. A matching operation can be blocked pending an operator decision:

- deny
- allow once
- allow for this session with a narrow scope key (rule + target + resource)

An approval for `systemctl restart pdns` on `dns01` must not imply permission to restart `sshd`, alter firewall rules, or restart another host.

## Defense in depth

1. Agent authoritative instructions.
2. Capability scope.
3. Broker policy engine.
4. Approval engine.
5. SSH certificate constraints.
6. Remote Unix account permissions.
7. sudo/doas policy.
8. Network segmentation and service isolation.

No single layer is considered sufficient.
