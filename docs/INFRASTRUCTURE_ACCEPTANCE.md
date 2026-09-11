# Constrained infrastructure acceptance

This runbook is the repeatable real-infrastructure acceptance procedure for `0.1.0-dev.13`. It is deliberately conservative: use disposable/constrained guests, keep the Gateway non-public during acceptance, and do not merge to `main` until every required positive and negative check passes.

The first dev.13 run on the intended PVE topology passed the hard-boundary checks described here. `HANDOFF.md` is the evidence record for that run; this document remains the reproducible procedure.

The purpose is to prove the boundaries together, not merely prove that each binary starts.

## Acceptance topology

Recommended PVE guest labels:

```text
sentinel-db           PostgreSQL 18
sentinel-control      Control Plane
sentinel-gateway      AI Gateway
sentinel-worker       Execution Worker
sentinel-signer       isolated SSH CA/Signer
sentinel-target-test  disposable SSH execution target
```

Use separate VMs for Gateway, Worker and Signer. Keep PostgreSQL separate from Control Plane for the acceptance run so database host/admin state is not colocated with the runtime Control Plane credential. The disposable target may be a fresh VM or another host whose loss is acceptable.

All guests may initially share one private PVE/LAN segment. The Worker VM-interface firewall is still mandatory and becomes the hard egress boundary before executable authority is enabled.

Suggested minimum sizing for the acceptance environment:

```text
sentinel-db           2 vCPU / 2 GiB RAM
sentinel-control      2 vCPU / 1 GiB RAM
sentinel-gateway      1 vCPU / 512 MiB RAM
sentinel-worker       1 vCPU / 512 MiB RAM
sentinel-signer       1 vCPU / 512 MiB RAM
sentinel-target-test  1 vCPU / 512 MiB RAM
```

Debian 13 minimal is suitable for the application guests. Use PostgreSQL 18 for this first acceptance because it is directly covered by the CI matrix. PostgreSQL 15 is also covered by CI.

Do not publish the Gateway to the Internet yet. Reach it from an operator workstation/LAN only.

## Site variables

Choose addresses/VMIDs that are unused in the local environment and keep them in an operator-only shell file that is **not committed**.

```sh
export DB_IP='10.169.0.X'
export CONTROL_IP='10.169.0.X'
export GATEWAY_IP='10.169.0.X'
export WORKER_IP='10.169.0.X'
export SIGNER_IP='10.169.0.X'
export TARGET_IP='10.169.0.X'

export WORKER_VMID='XXXX'
export WORKER_NET='net0'

# Pick an unrelated existing/non-sensitive LAN address for the negative test.
export UNLISTED_LAN_IP='10.169.0.X'
```

Before using the rest of this runbook:

```sh
: "${DB_IP:?set DB_IP}"
: "${CONTROL_IP:?set CONTROL_IP}"
: "${GATEWAY_IP:?set GATEWAY_IP}"
: "${WORKER_IP:?set WORKER_IP}"
: "${SIGNER_IP:?set SIGNER_IP}"
: "${TARGET_IP:?set TARGET_IP}"
: "${WORKER_VMID:?set WORKER_VMID}"
: "${WORKER_NET:?set WORKER_NET}"
: "${UNLISTED_LAN_IP:?set UNLISTED_LAN_IP}"
```

Never use production infrastructure as `sentinel-target-test` for this acceptance.

## Build the accepted source

Build from the accepted `0.1.0-dev.13` release state, not an arbitrary moving branch checkout:

```sh
git clone https://github.com/kotaru34/tethys-sentinel.git
cd tethys-sentinel
git checkout bd6796aae2ee192fd9d007bab39a40ab6870dbcc
cat VERSION
# expected: 0.1.0-dev.13
```

Use Go 1.27.1, matching CI. Build static binaries on a trusted build host before the Worker firewall is locked down:

```sh
mkdir -p out
for name in \
    sentinel-control \
    sentinel-gateway \
    sentinel-worker \
    sentinel-signer \
    sentinel-egress-policy \
    tethys-sentinel-exec \
    tethys-sentinel-consume
do
    CGO_ENABLED=0 go build -trimpath -o "out/$name" "./cmd/$name"
done
sha256sum out/* > out/SHA256SUMS
```

Copy only the binaries required by each VM. Do not clone GitHub from the runtime Worker after its egress policy is active.

## Generate operator secrets

Generate these once on an operator-controlled system:

```sh
ADMIN_TOKEN="$(openssl rand -hex 32)"
WORKER_TOKEN="$(openssl rand -hex 32)"
SIGNER_API_TOKEN="$(openssl rand -hex 32)"
DB_DEPLOY_PASS="$(openssl rand -hex 32)"
DB_RUNTIME_PASS="$(openssl rand -hex 32)"

printf '%s\n' \
  "ADMIN_TOKEN=$ADMIN_TOKEN" \
  "WORKER_TOKEN=$WORKER_TOKEN" \
  "SIGNER_API_TOKEN=$SIGNER_API_TOKEN" \
  "DB_DEPLOY_PASS=$DB_DEPLOY_PASS" \
  "DB_RUNTIME_PASS=$DB_RUNTIME_PASS" \
  > acceptance-secrets.env
chmod 600 acceptance-secrets.env
```

Do not commit this file. `ADMIN_TOKEN` stays operator/Control-only. `WORKER_TOKEN` is shared only by Control and Worker. `SIGNER_API_TOKEN` is shared only by Control and Signer.

## TLS trust domains

Use distinct X.509 CA trust domains for:

1. Gateway/Worker -> Control mTLS;
2. Control -> Signer mTLS;
3. Gateway public TLS;
4. PostgreSQL server TLS.

Keep all X.509 CA private keys on the operator-controlled PKI host; services receive only the leaf private key they need and CA public certificates.

For the acceptance environment, create leaf certificates with these identities:

```text
control-mtls CA:
  server: sentinel-control, SAN DNS:sentinel-control + IP:$CONTROL_IP, EKU serverAuth
  client: sentinel-gateway, EKU clientAuth
  client: sentinel-worker, EKU clientAuth

signer-mtls CA:
  server: sentinel-signer, SAN DNS:sentinel-signer + IP:$SIGNER_IP, EKU serverAuth
  client: sentinel-control-signer, EKU clientAuth

gateway-public CA:
  server: sentinel-gateway, SAN DNS:sentinel-gateway + IP:$GATEWAY_IP, EKU serverAuth

postgres CA:
  server: sentinel-db, SAN DNS:sentinel-db + IP:$DB_IP, EKU serverAuth
```

Tethys Sentinel requires TLS 1.3 and normal X.509 validation; do not use `InsecureSkipVerify`, `curl -k`, unverified self-signed leaf certificates, or plaintext non-loopback development switches for this acceptance.

A minimal OpenSSL pattern for each CA/leaf is:

```sh
# CA example
openssl genrsa -out control-mtls-ca.key 3072
openssl req -x509 -new -sha256 -days 3650 \
  -key control-mtls-ca.key \
  -out control-mtls-ca.crt \
  -subj '/CN=Tethys Sentinel Control mTLS CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

# Control server leaf example
openssl req -new -newkey rsa:3072 -nodes \
  -keyout control-server.key \
  -out control-server.csr \
  -subj '/CN=sentinel-control' \
  -addext "subjectAltName=DNS:sentinel-control,IP:${CONTROL_IP}" \
  -addext 'extendedKeyUsage=serverAuth'
openssl x509 -req -sha256 -days 365 \
  -in control-server.csr \
  -CA control-mtls-ca.crt -CAkey control-mtls-ca.key -CAcreateserial \
  -copy_extensions copy \
  -out control-server.crt
```

Use the same pattern for the other leaves/CAs with the identities above. Client leaf CSRs use `extendedKeyUsage=clientAuth`; server leaves use `serverAuth`.

## PostgreSQL 18

Install PostgreSQL 18 on `sentinel-db`. Copy the accepted repository `db/` directory to an operator-readable location on that VM.

Copy only these TLS files to the DB VM:

```text
postgres-server.crt
postgres-server.key
```

Install them root/postgres-owned; the private key must not be readable by other users.

Configure PostgreSQL to listen only on localhost plus `$DB_IP`, enable TLS, and use SCRAM. Equivalent `ALTER SYSTEM` settings are:

```sql
ALTER SYSTEM SET listen_addresses = '127.0.0.1,<DB_IP>';
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '/etc/tethys-sentinel/postgres-server.crt';
ALTER SYSTEM SET ssl_key_file = '/etc/tethys-sentinel/postgres-server.key';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
```

Replace `<DB_IP>` with the literal chosen address and restart PostgreSQL.

Run the repository role bootstrap as PostgreSQL administrator:

```sh
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -f db/bootstrap/roles.sql
```

Create the two LOGIN identities using the generated hex passwords:

```sh
sudo -u postgres psql -X -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE sentinel_deploy LOGIN PASSWORD '$DB_DEPLOY_PASS';
GRANT sentinel_migrator TO sentinel_deploy;
CREATE ROLE sentinel_control_login LOGIN PASSWORD '$DB_RUNTIME_PASS';
GRANT sentinel_control TO sentinel_control_login;
CREATE DATABASE tethys_sentinel OWNER sentinel_owner;
SQL
```

Add narrow HBA rules. Deployment login is local-only; runtime login is TLS-only from the Control VM:

```text
host    tethys_sentinel  sentinel_deploy         127.0.0.1/32       scram-sha-256
hostssl tethys_sentinel  sentinel_control_login  <CONTROL_IP>/32    scram-sha-256
```

Reload PostgreSQL, then apply **all** migrations in order through the deployment login:

```sh
for migration in db/migrations/*.sql; do
    PGPASSWORD="$DB_DEPLOY_PASS" \
      psql -X -v ON_ERROR_STOP=1 \
      -h 127.0.0.1 -U sentinel_deploy -d tethys_sentinel \
      -f "$migration"
done
```

Verify schema version and fail-closed initial authority:

```sh
PGPASSWORD="$DB_RUNTIME_PASS" \
psql 'host=<DB_IP> port=5432 dbname=tethys_sentinel user=sentinel_control_login sslmode=verify-full sslrootcert=/path/to/postgres-ca.crt' \
  -X -Atc 'select version from sentinel.schema_version where id=1; select epoch,disabled from sentinel.authority_state where id=1;'
```

Expected:

```text
2
0|t
```

The runtime role must not receive `sentinel_owner`, `sentinel_migrator`, schema `CREATE`, or table `DELETE` privileges.

## SSH Signer VM

Create a dedicated system account and directories:

```sh
useradd --system --home /nonexistent --shell /usr/sbin/nologin sentinel-signer
install -d -o root -g sentinel-signer -m 0750 /etc/tethys-sentinel
install -o root -g root -m 0755 sentinel-signer /usr/local/bin/sentinel-signer
```

Generate the **SSH user CA private key directly on the Signer VM** so it never has to leave that VM:

```sh
ssh-keygen -t ed25519 -N '' -f /etc/tethys-sentinel/ssh-user-ca
chown root:sentinel-signer /etc/tethys-sentinel/ssh-user-ca
chmod 0640 /etc/tethys-sentinel/ssh-user-ca
ssh-keygen -y -f /etc/tethys-sentinel/ssh-user-ca > /etc/tethys-sentinel/ssh-user-ca.pub
chmod 0644 /etc/tethys-sentinel/ssh-user-ca.pub
```

Install the Signer TLS server key/cert and signer-mTLS client CA public certificate. Keep private key permissions restricted to the Signer service account.

Signer environment:

```text
SENTINEL_SIGNER_API_TOKEN=<SIGNER_API_TOKEN>
SENTINEL_SIGNER_CA_KEY=/etc/tethys-sentinel/ssh-user-ca
SENTINEL_SIGNER_PRINCIPAL=sentinel-ai
SENTINEL_SIGNER_WRAPPER=/usr/local/libexec/tethys-sentinel-exec
SENTINEL_SIGNER_SOURCE_ADDRESSES=<WORKER_IP>/32
SENTINEL_SIGNER_CERT_TTL_SECONDS=45
SENTINEL_SIGNER_BACKDATE_SECONDS=5
SENTINEL_SIGNER_LISTEN=<SIGNER_IP>:9443
SENTINEL_SIGNER_TLS_CERT=/etc/tethys-sentinel/signer-server.crt
SENTINEL_SIGNER_TLS_KEY=/etc/tethys-sentinel/signer-server.key
SENTINEL_SIGNER_CLIENT_CA=/etc/tethys-sentinel/signer-mtls-ca.crt
```

Do not put the SSH CA key on Control, Gateway or Worker.

## Disposable target VM

Build/copy `tethys-sentinel-exec` and `tethys-sentinel-consume` to the target and install them root-owned:

```sh
install -o root -g root -m 0755 tethys-sentinel-exec /usr/local/libexec/tethys-sentinel-exec
install -o root -g root -m 0755 tethys-sentinel-consume /usr/local/libexec/tethys-sentinel-consume
```

Create the dedicated account with a real executable shell because sshd uses the account shell to launch the certificate forced command:

```sh
useradd --create-home --shell /bin/sh sentinel-ai
passwd -l sentinel-ai
```

Install the Signer's SSH CA **public** key:

```sh
install -d -o root -g root -m 0755 /etc/tethys-sentinel
install -o root -g root -m 0644 ssh-user-ca.pub /etc/ssh/tethys-sentinel-user-ca.pub
printf '%s\n' 'sentinel-target-test' > /etc/tethys-sentinel/target-id
chown root:root /etc/tethys-sentinel/target-id
chmod 0644 /etc/tethys-sentinel/target-id
```

Create root-only replay state:

```sh
install -d -o root -g root -m 0700 /var/lib/tethys-sentinel
install -d -o root -g root -m 0700 /var/lib/tethys-sentinel/executed
```

Create authorized principals:

```sh
install -d -o root -g root -m 0755 /etc/ssh/auth_principals
printf '%s\n' 'sentinel-ai' > /etc/ssh/auth_principals/sentinel-ai
chown root:root /etc/ssh/auth_principals/sentinel-ai
chmod 0644 /etc/ssh/auth_principals/sentinel-ai
```

Install only the narrow replay helper sudo permission:

```text
# /etc/sudoers.d/tethys-sentinel-consume
sentinel-ai ALL=(root) NOPASSWD: /usr/local/libexec/tethys-sentinel-consume *
```

Validate with `visudo -cf /etc/sudoers.d/tethys-sentinel-consume`. The helper itself is narrow and validates its job/binding arguments; do not grant any generic root shell or unrelated command.

Add an sshd drop-in equivalent to the following. `PermitUserEnvironment no` is a **global** directive and must remain outside the `Match` block:

```text
TrustedUserCAKeys /etc/ssh/tethys-sentinel-user-ca.pub
PermitUserEnvironment no

Match User sentinel-ai
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile none
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
```

Run `sshd -t` before reload/restart. Do not proceed on configuration warnings/errors.

Obtain the target host key **locally on the target**, not through TOFU:

```sh
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Copy that exact raw public key into Control's target registry. Sentinel must both verify the pinned raw key and constrain SSH host-key negotiation to algorithms compatible with that pin. For RSA pins, only RSA-SHA2 host-key algorithms are allowed; do not re-enable SHA-1 `ssh-rsa` fallback.

Create one harmless user-owned file for the one-shot approval test:

```sh
install -o sentinel-ai -g sentinel-ai -m 0600 /dev/null /tmp/sentinel-acceptance-delete-me
```

## Control Plane VM

Create a dedicated service account and install `sentinel-control`:

```sh
useradd --system --home /nonexistent --shell /usr/sbin/nologin sentinel-control
install -d -o root -g sentinel-control -m 0750 /etc/tethys-sentinel
install -o root -g root -m 0755 sentinel-control /usr/local/bin/sentinel-control
```

Install:

```text
control-server.crt/key
control-mtls-ca.crt
gateway/worker client CA public material as the same control-mTLS CA
control-signer-client.crt/key
signer-mtls-ca.crt
postgres-ca.crt
```

Create `/etc/tethys-sentinel/ssh-targets.json`:

```json
{
  "targets": [
    {
      "name": "sentinel-target-test",
      "address": "<TARGET_IP>:22",
      "user": "sentinel-ai",
      "host_key": "ssh-ed25519 AAAA..."
    }
  ]
}
```

The file must be regular and not group/other writable.

Create a minimal authoritative `/etc/tethys-sentinel/context.json` based on `config/context.example.json`, with only `sentinel-target-test` in the acceptance inventory. Treat all output/history/notes as non-authoritative.

Control environment:

```text
SENTINEL_ADMIN_TOKEN=<ADMIN_TOKEN>
SENTINEL_WORKER_TOKEN=<WORKER_TOKEN>
SENTINEL_PERSISTENCE_BACKEND=postgres
SENTINEL_POSTGRES_DSN=postgres://sentinel_control_login:<DB_RUNTIME_PASS>@<DB_IP>:5432/tethys_sentinel?sslmode=verify-full&sslrootcert=/etc/tethys-sentinel/postgres-ca.crt
SENTINEL_CONTEXT_FILE=/etc/tethys-sentinel/context.json
SENTINEL_SSH_TARGETS_FILE=/etc/tethys-sentinel/ssh-targets.json
SENTINEL_ADMIN_LISTEN=127.0.0.1:8081
SENTINEL_INTERNAL_LISTEN=<CONTROL_IP>:9091
SENTINEL_INTERNAL_TLS_CERT=/etc/tethys-sentinel/control-server.crt
SENTINEL_INTERNAL_TLS_KEY=/etc/tethys-sentinel/control-server.key
SENTINEL_INTERNAL_CLIENT_CA=/etc/tethys-sentinel/control-mtls-ca.crt
SENTINEL_SIGNER_URL=https://<SIGNER_IP>:9443
SENTINEL_SIGNER_API_TOKEN=<SIGNER_API_TOKEN>
SENTINEL_SIGNER_CLIENT_TLS_CERT=/etc/tethys-sentinel/control-signer-client.crt
SENTINEL_SIGNER_CLIENT_TLS_KEY=/etc/tethys-sentinel/control-signer-client.key
SENTINEL_SIGNER_SERVER_CA=/etc/tethys-sentinel/signer-mtls-ca.crt
SENTINEL_SIGNER_SERVER_NAME=sentinel-signer
```

Because `DB_RUNTIME_PASS` is generated as hex, it is safe to embed in the URI without extra URL escaping for this acceptance.

Do **not** `source /etc/tethys-sentinel/service.env` to recover the live PostgreSQL DSN for acceptance queries. A systemd EnvironmentFile is not a shell script and the DSN contains `&`. For post-start inspection, retrieve `SENTINEL_POSTGRES_DSN` silently from `/proc/<Control MainPID>/environ` or parse the EnvironmentFile with a non-shell parser; never print the DSN.

## Gateway VM

Create `sentinel-gateway`, install the binary, the Gateway public server certificate/key, its Control mTLS client certificate/key and the Control mTLS CA certificate.

Gateway environment:

```text
SENTINEL_CONTROL_URL=https://<CONTROL_IP>:9091
SENTINEL_INTERNAL_TLS_CERT=/etc/tethys-sentinel/gateway-client.crt
SENTINEL_INTERNAL_TLS_KEY=/etc/tethys-sentinel/gateway-client.key
SENTINEL_INTERNAL_SERVER_CA=/etc/tethys-sentinel/control-mtls-ca.crt
SENTINEL_INTERNAL_SERVER_NAME=sentinel-control
SENTINEL_GATEWAY_LISTEN=<GATEWAY_IP>:8443
SENTINEL_GATEWAY_TLS_CERT=/etc/tethys-sentinel/gateway-server.crt
SENTINEL_GATEWAY_TLS_KEY=/etc/tethys-sentinel/gateway-server.key
```

Do not install admin token, worker token, PostgreSQL credentials, SSH target registry or signer credentials on Gateway.

## Worker VM

Before enabling the runtime PVE egress policy, install `netcat-openbsd` or equivalent operator diagnostic tooling. Then create `sentinel-worker`, install only the worker binary, its Control mTLS client certificate/key and Control mTLS CA certificate.

Worker environment:

```text
SENTINEL_WORKER_ID=worker-acceptance-01
SENTINEL_WORKER_TOKEN=<WORKER_TOKEN>
SENTINEL_CONTROL_URL=https://<CONTROL_IP>:9091
SENTINEL_WORKER_TLS_CERT=/etc/tethys-sentinel/worker-client.crt
SENTINEL_WORKER_TLS_KEY=/etc/tethys-sentinel/worker-client.key
SENTINEL_INTERNAL_SERVER_CA=/etc/tethys-sentinel/control-mtls-ca.crt
SENTINEL_INTERNAL_SERVER_NAME=sentinel-control
SENTINEL_WORKER_POLL_MS=1000
SENTINEL_WORKER_AUTHORITY_POLL_MS=250
SENTINEL_WORKER_SSH_DIAL_TIMEOUT_SECONDS=5
SENTINEL_WORKER_OUTPUT_LIMIT_BYTES=4194304
```

Do not install agent capabilities, admin token, PostgreSQL credentials, SSH CA/signing material, signer credentials, target inventory, or PVE credentials on Worker.

## Minimal systemd service policy

For each Sentinel application VM, use a static service user and a root-owned `0600` EnvironmentFile. A minimal unit pattern is:

```ini
[Unit]
Description=Tethys Sentinel component
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=COMPONENT_USER
Group=COMPONENT_USER
EnvironmentFile=/etc/tethys-sentinel/service.env
ExecStart=/usr/local/bin/COMPONENT_BINARY
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

Use the actual component user/binary per VM. Ports 8443/9091/9443 do not require privileged bind capabilities. Keep secrets/config readable by the matching service account but not writable by it unless a specific future feature requires that.

Start order for the acceptance environment:

```text
PostgreSQL -> Signer -> Control Plane -> Gateway -> Worker
```

Inspect `journalctl -u ...` after every start. Stop immediately if any component uses a development plaintext switch or cannot verify its peer.

## Apply the external Worker egress boundary

Run `sentinel-egress-policy` only from the operator/PVE side, never on behalf of the autonomous Worker.

Using the final Control target registry and literal Control endpoint:

```sh
sentinel-egress-policy \
  -targets /path/to/ssh-targets.json \
  -control "https://${CONTROL_IP}:9091" \
  -format pve \
  > "${WORKER_VMID}.fw"
```

Review the output. It must contain **both** `policy_in: ACCEPT` and `policy_out: DROP`, plus exactly the required outbound destinations:

```text
CONTROL_IP:9091/tcp
TARGET_IP:22/tcp
```

There must be no generic LAN, Internet, DNS or broad HTTPS allow. `policy_in: ACCEPT` preserves unspecified inbound behavior while this file enforces outbound containment; it is not permission to broaden autonomous Worker egress.

Install it on the PVE node:

```sh
install -m 0640 "${WORKER_VMID}.fw" "/etc/pve/firewall/${WORKER_VMID}.fw"
```

Ensure:

1. Datacenter firewall is enabled;
2. the VM firewall file has `enable: 1`;
3. the Worker NIC selected by `$WORKER_NET` has `firewall=1`.

Then verify generated policy + PVE activation:

```sh
sentinel-egress-policy \
  -targets /path/to/ssh-targets.json \
  -control "https://${CONTROL_IP}:9091" \
  -format pve \
  -check "/etc/pve/firewall/${WORKER_VMID}.fw" \
  -pve-cluster-fw /etc/pve/firewall/cluster.fw \
  -pve-vm-config "/etc/pve/qemu-server/${WORKER_VMID}.conf" \
  -pve-net "$WORKER_NET"
```

Do not enable Sentinel authority before the packet-level tests below pass.

## Packet-level acceptance from inside Worker

Expected successes:

```sh
nc -vz -w 3 "$CONTROL_IP" 9091
nc -vz -w 3 "$TARGET_IP" 22
```

Expected failures:

```sh
! nc -vz -w 3 1.1.1.1 443
! nc -vz -w 3 "$UNLISTED_LAN_IP" 22
! nc -vz -w 3 "$TARGET_IP" 80
! nc -vz -w 3 10.169.0.1 53
```

Replace the last address with the actual local resolver if necessary. DNS/53 must still fail under the autonomous runtime policy.

Record the commands and exit status. A configuration diff alone is not acceptance.

Also inspect IPv6 on Worker:

```sh
ip -6 addr show
ip -6 route show
```

Acceptance requires no global/ULA IPv6 address and no IPv6 default route unless an equally strict external IPv6 egress policy has been deliberately configured and tested. Link-local-only IPv6 is acceptable.

## Initial authority state

On the Control VM, query the loopback-only admin API:

```sh
curl -fsS \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:8081/admin/v1/emergency/state
```

A fresh PostgreSQL deployment must report `disabled:true`.

Only after the egress and TLS boundaries pass, enable authority:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"dev.13 constrained infrastructure acceptance"}' \
  http://127.0.0.1:8081/admin/v1/emergency/enable
```

## Test 1: autonomous non-destructive execution

Issue a short grant from the Control VM:

```sh
GRANT_JSON="$({ curl -fsS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "agent":"acceptance-agent",
    "purpose":"dev.13 constrained infrastructure acceptance",
    "targets":["sentinel-target-test"],
    "permissions":{"exec":true,"shell":false,"history_read":true,"notes_read":true,"notes_write":true},
    "history":{"current_session":true,"previous_sessions":false,"other_agents":false,"include_output":false},
    "ttl_seconds":600
  }' \
  http://127.0.0.1:8081/admin/v1/grants; } )"
CAPABILITY="$(printf '%s' "$GRANT_JSON" | jq -r .token)"
GRANT_ID="$(printf '%s' "$GRANT_JSON" | jq -r .grant.id)"
test -n "$CAPABILITY" && test "$CAPABILITY" != null
test -n "$GRANT_ID" && test "$GRANT_ID" != null
```

From the operator workstation, use Gateway TLS and the capability. If the Gateway certificate is DNS-only, connect using that DNS identity plus an explicit address mapping rather than disabling verification.

Submit a harmless command:

```sh
curl --fail --silent --show-error \
  --cacert gateway-public-ca.crt \
  -H "Authorization: Bearer $CAPABILITY" \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id":"acceptance-true-dev13-0001",
    "target":"sentinel-target-test",
    "argv":["true"],
    "agent_reason":"non-destructive dev.13 infrastructure acceptance"
  }' \
  "https://${GATEWAY_IP}:8443/v1/commands/submit"
```

Expected: `decision:"accepted"`. Worker should claim/start/sign/connect/complete it without operator approval. Verify in Control audit/history that the job reached a successful terminal state and produced exactly one authorization/claim/start/certificate/completion chain. Independently verify target sshd accepted the short-lived CA-signed certificate and the root replay marker exists.

## Test 2: one-shot approval path

Confirm `/tmp/sentinel-acceptance-delete-me` exists on the disposable target, then submit `rm /tmp/sentinel-acceptance-delete-me` with a unique request ID.

Expected: `approval_required` and an approval ID. Approve **once** through the loopback Control admin endpoint:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"allow_once"}' \
  "http://127.0.0.1:8081/admin/v1/approvals/<APPROVAL_ID>/decision"
```

Resubmit the **same** request ID and command. Expected: accepted and executed once. Confirm the marker is gone and the replay marker exists.

Then submit the same command with a **new** request ID. It must not reuse the consumed one-shot approval; a new operator decision must be required. This is the real-infrastructure proof of the schema-v2 `consumed_by_job_id` invariant.

## Test 3: individual revoke during execution

Issue a fresh grant and submit a bounded foreground command such as:

```json
{
  "request_id":"acceptance-active-revoke-dev13-0001",
  "target":"sentinel-target-test",
  "argv":["sleep","20"],
  "agent_reason":"individual active revoke acceptance"
}
```

Avoid human/chat latency between observing `running` and issuing revoke. A single operator-side script should poll until the job is exactly `running` and immediately revoke the grant:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:8081/admin/v1/grants/<GRANT_ID>/revoke"
```

Expected:

- grant `revoked_at` is after `started_at` but well before job expiry;
- Worker authority lease turns false;
- Worker cancels the execution context/SSH transport;
- job becomes terminal and does not remain stuck `running`;
- factual terminal error is `execution_authority_lost` for the accepted dev.13 path;
- target sshd closes the session and the foreground `sleep` process disappears;
- the revoked capability cannot submit new work.

A target process that deliberately daemonizes/detaches is outside this generic guarantee; foreground `sleep` is intentionally chosen because it remains tied to the SSH session.

## Test 4: global revoke-all and epoch non-revival

Enable authority if required, issue another short grant, and run another bounded foreground `sleep`. Once running, immediately perform:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"dev.13 active global revoke acceptance"}' \
  http://127.0.0.1:8081/admin/v1/emergency/revoke-all
```

Expected:

- global `disabled:true`;
- epoch increments exactly once;
- staged/pending/claimed jobs are canceled;
- running worker execution loses its authority lease and transport is canceled;
- active foreground target process disappears;
- old capability is invalid immediately.

Then re-enable:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"stale epoch capability non-revival acceptance"}' \
  http://127.0.0.1:8081/admin/v1/emergency/enable
```

Re-enable must **not** increment the epoch. While the pre-revoke grant is still unexpired, present its bearer to the real Gateway. It must receive HTTP 401. Then issue a fresh grant in the new epoch and prove the same Gateway endpoint accepts it. This distinguishes permanent stale-epoch invalidation from ordinary TTL expiry or temporary global disable.

## Test 5: PostgreSQL persistence and fail-closed startup

Finish/cancel active work, then perform a controlled Control Plane restart while PostgreSQL remains running.

Verify after restart:

- schema version is still 2;
- current epoch/disabled state is unchanged;
- revoked/stale grants do not revive;
- audit history verifies;
- previous terminal job/history state remains readable within granted scope.

For database inspection of the running Control service, do not shell-source its systemd EnvironmentFile. Derive the DSN silently from the process environment, for example:

```sh
PID="$(systemctl show -p MainPID --value sentinel-control.service)"
DSN="$(tr '\0' '\n' < "/proc/$PID/environ" | sed -n 's/^SENTINEL_POSTGRES_DSN=//p')"
test -n "$DSN"
```

Never print the DSN.

To prove startup fail-closed without unnecessarily taking down the accepted live Control instance, launch a **second copy of the exact deployed Control binary** with the live environment cloned from `/proc/<MainPID>/environ`, substitute only the PostgreSQL endpoint with a known-unreachable local endpoint, and use unused test admin/internal listen ports.

Also redirect all file-backend paths into a disposable trap directory and provide any prerequisite dummy key needed by the file backend. Expected:

- test Control exits nonzero during PostgreSQL initialization (`ping PostgreSQL` failure);
- it does not open either test API listener;
- no file-backed grant/approval/audit/job/emergency/note state appears in the trap directory;
- production Control remains active with the same PID.

This proves PostgreSQL loss fails closed before APIs are served and cannot silently fall back to local file authority.

## Test 6: Worker sensitive-material, service-account, mTLS and IPv6 boundary

Inspect the running Worker without printing secret values. The Worker process environment may contain only Worker-owned runtime material and ordinary tuning/configuration such as:

```text
SENTINEL_WORKER_ID
SENTINEL_WORKER_TOKEN
SENTINEL_CONTROL_URL
SENTINEL_WORKER_TLS_CERT
SENTINEL_WORKER_TLS_KEY
SENTINEL_INTERNAL_SERVER_CA
SENTINEL_INTERNAL_SERVER_NAME
SENTINEL_WORKER_POLL_MS
SENTINEL_WORKER_AUTHORITY_POLL_MS
SENTINEL_WORKER_SSH_DIAL_TIMEOUT_SECONDS
SENTINEL_WORKER_OUTPUT_LIMIT_BYTES
```

It must not contain agent capabilities, `SENTINEL_ADMIN_TOKEN`, PostgreSQL credentials/backend authority, Signer API/client credentials or SSH CA signing key, Control target inventory, PVE credentials, or local mutable authority stores.

Verify filesystem permissions by file name/mode only. The Worker service account may read its client mTLS key/cert and Control CA, but must not be able to read the root-only EnvironmentFile directly. The Worker account must use a non-login shell, have no sudo/wheel membership, and the running process must have zero effective and ambient Linux capabilities.

Prove the Control mTLS boundary both ways:

1. as the Worker service account, use the configured Worker client cert/key and Control CA to request a nonexistent internal path; a normal HTTP-layer 4xx proves the authenticated TLS connection reached Control;
2. repeat without a client certificate; TLS must fail before a normal HTTP response is accepted.

Finally verify Worker IPv6 has no autonomous bypass: no global/ULA address and no IPv6 default route unless a separately reviewed/tested IPv6 PVE policy exists. Link-local IPv6 alone is acceptable.

## Required evidence

Keep a short acceptance record containing:

```text
Tethys Sentinel version/commit
PVE node + Worker VMID/NIC
Control/Gateway/Worker/Signer/DB/target addresses
PostgreSQL version + schema version
SHA256SUMS of deployed binaries
PVE generated-policy SHA256/drift verification result
packet-level positive/negative results
non-destructive execution job ID/result
allow_once approval ID + bound job ID + non-reuse result
individual revoke grant/job/timing + target session-close result
revoke-all epoch before/after + running-job result
stale old-epoch bearer 401 + fresh new-epoch bearer success
Control restart persistence result
PostgreSQL-unavailable startup fail-closed result
Worker forbidden-material/env/files result
Worker service UID/GID/capabilities result
Worker authenticated mTLS + no-client-cert negative result
Worker IPv6 address/default-route result
relevant audit sequence range/hash head
```

Do **not** store bearer tokens, worker claim tokens, DB passwords, TLS private keys or SSH CA private key in the acceptance record.

## Pass/fail rule

The first WIP merge is allowed only when all of these are true:

- all components use authenticated TLS/mTLS as designed;
- PostgreSQL schema/runtime role checks pass;
- Worker external PVE egress policy is installed and verified with `policy_in: ACCEPT`, `policy_out: DROP`;
- positive Worker Control/SSH paths work;
- Internet, unrelated LAN, DNS and unlisted target ports fail from Worker;
- Worker has no uncontained IPv6 egress path;
- autonomous non-destructive command completes through the real target wrapper;
- one-shot approval executes once and cannot authorize a second job;
- individual revoke terminates active bounded execution authority and target SSH transport;
- `REVOKE ALL` increments epoch, stops active authority, and old capabilities never revive after enable;
- Control restart preserves PostgreSQL state;
- PostgreSQL loss makes Control Plane fail closed with no file fallback or API listener;
- Worker holds only its own runtime token/mTLS material and no Control/DB/Signer/PVE/agent authority secrets;
- Worker service account is unprivileged and the no-client-cert mTLS negative test fails as expected;
- audit/history remains internally consistent.

Any failed hard-boundary check blocks the merge. Fix the implementation/configuration, repeat the affected tests, update `HANDOFF.md`, and bump the project version if code/functionality changes are required.
