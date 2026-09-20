# Operator UI deployment

This guide deploys the `sentinel-operator` BFF/web service without weakening the accepted Sentinel security boundaries.

The intended production topology is:

```text
operator browser
    |
    | HTTPS + dedicated operator client certificate
    v
sentinel-operator :8444
    |
    | HTTP over loopback only + Control admin credential
    v
sentinel-control 127.0.0.1:8081
```

`sentinel-operator` runs on the Control host as a separate unprivileged systemd service. The public AI Gateway does not receive operator routes.

The recommended deployment keeps operator configuration under a separate `/etc/tethys-sentinel-operator` root. Do **not** grant the operator service traversal of `/etc/tethys-sentinel`; that directory belongs to the `sentinel-control` security boundary.

## Credential boundary

The operator service may receive only:

- its HTTPS server private key and certificate;
- the dedicated operator-client CA certificate (public trust root only);
- a Control admin bearer credential stored in a mode `0400` file readable only by the operator service account.

It must not receive:

- PostgreSQL credentials or DSNs;
- Worker credentials or claim material;
- SSH Signer bearer credentials;
- SSH user-CA private material;
- target SSH private keys;
- PVE credentials;
- agent capabilities except the newly issued capability returned once through an intentional grant-issue request.

The browser never receives the Control admin credential. Browser mutations use an mTLS-derived operator identity plus same-origin CSRF protection at the BFF.

## Build

The deployed host does not need Node.js.

The browser source lives in `web/operator` and is built with TypeScript, Preact and Vite. CI verifies that generated files match the frontend archive embedded into the Go binary.

Build from the exact source commit you intend to deploy and record that commit plus the resulting binary hash in private operator records:

```bash
git rev-parse HEAD
cat VERSION
# current accepted baseline: 0.1.0-dev.20

go test ./internal/operatorweb ./internal/operatorproxy ./cmd/sentinel-operator
CGO_ENABLED=0 go build -trimpath -o sentinel-operator ./cmd/sentinel-operator
sha256sum sentinel-operator
```

`sentinel-operator` intentionally has no runtime dependency on a checkout, `node_modules`, npm or Vite.

## Service account and isolated configuration root

On the Control host:

```bash
sudo useradd \
  --system \
  --no-create-home \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  tethys-operator 2>/dev/null || true

sudo install -o root -g root -m 0755 \
  ./sentinel-operator \
  /usr/local/sbin/sentinel-operator

sudo install -d \
  -o root \
  -g tethys-operator \
  -m 0750 \
  /etc/tethys-sentinel-operator
```

Install `config/systemd/sentinel-operator.service` as `/etc/systemd/system/sentinel-operator.service`.

The Control directory remains separately protected, for example:

```text
/etc/tethys-sentinel          0750 root:sentinel-control
/etc/tethys-sentinel-operator 0750 root:tethys-operator
```

Do not add `tethys-operator` to the `sentinel-control` group and do not weaken `/etc/tethys-sentinel` permissions.

## Control admin token file

Do not print the token and do not place it in the browser-facing environment.

If Control already has the token in its process environment, copy it directly into the isolated operator-only file on the same host:

```bash
sudo bash <<'EOF'
set -euo pipefail
umask 077

PID="$(systemctl show -p MainPID --value sentinel-control.service)"
ADMIN_TOKEN="$(
  tr '\0' '\n' < "/proc/$PID/environ" |
  sed -n 's/^SENTINEL_ADMIN_TOKEN=//p'
)"

test -n "$ADMIN_TOKEN"
printf '%s\n' "$ADMIN_TOKEN" > /etc/tethys-sentinel-operator/operator-admin.token
chown tethys-operator:tethys-operator /etc/tethys-sentinel-operator/operator-admin.token
chmod 0400 /etc/tethys-sentinel-operator/operator-admin.token
unset ADMIN_TOKEN
EOF
```

Do not use `cat`, `set -x`, shell tracing, or command-line arguments that expose this token.

## Dedicated operator TLS trust root

Do not reuse the Sentinel SSH user CA or another infrastructure CA.

Create a dedicated TLS CA for operator browser authentication. Keep its private key off the Sentinel runtime hosts after certificates are issued. Only the CA certificate belongs on the Control host.

The server certificate must contain the exact DNS name or IP address used by the browser in `SENTINEL_OPERATOR_PUBLIC_ORIGIN`.

For example, when the browser reaches Operator at documentation address `192.0.2.10`, the server certificate needs IP SAN `192.0.2.10` for:

```text
https://192.0.2.10:8444
```

The operator client certificate must have client-auth EKU. Export the client key/certificate as a password-protected PKCS#12/PFX for import into the Windows certificate store/browser.

After verified workstation import, remove temporary client private-key material and the operator CA private key from the Control host.

Install only these TLS files for the service:

```text
/etc/tethys-sentinel-operator/operator-server.crt
/etc/tethys-sentinel-operator/operator-server.key
/etc/tethys-sentinel-operator/operator-client-ca.crt
```

Accepted permissions:

```bash
sudo chown tethys-operator:tethys-operator \
  /etc/tethys-sentinel-operator/operator-server.key
sudo chmod 0400 \
  /etc/tethys-sentinel-operator/operator-server.key

sudo chown root:tethys-operator \
  /etc/tethys-sentinel-operator/operator-server.crt \
  /etc/tethys-sentinel-operator/operator-client-ca.crt
sudo chmod 0440 \
  /etc/tethys-sentinel-operator/operator-server.crt \
  /etc/tethys-sentinel-operator/operator-client-ca.crt
```

Record deployment-specific Operator PKI fingerprints only in private operator records; do not commit real fingerprints to the public repository.

## Runtime configuration

Copy `config/operator.env.example` to `/etc/tethys-sentinel-operator/operator.env` and set the exact management address/origin. Public documentation uses RFC 5737 example addresses:

```ini
SENTINEL_OPERATOR_PUBLIC_ORIGIN=https://192.0.2.10:8444
SENTINEL_OPERATOR_LISTEN=192.0.2.10:8444
SENTINEL_OPERATOR_CONTROL_URL=http://127.0.0.1:8081
SENTINEL_OPERATOR_ADMIN_TOKEN_FILE=/etc/tethys-sentinel-operator/operator-admin.token
SENTINEL_OPERATOR_TLS_CERT=/etc/tethys-sentinel-operator/operator-server.crt
SENTINEL_OPERATOR_TLS_KEY=/etc/tethys-sentinel-operator/operator-server.key
SENTINEL_OPERATOR_CLIENT_CA=/etc/tethys-sentinel-operator/operator-client-ca.crt
```

The public origin must be an HTTPS origin with no path/query/fragment and must exactly match the browser Origin header. The binary rejects a non-loopback Control URL.

The environment file contains no secret but is still kept within the operator-only boundary:

```bash
sudo chown root:tethys-operator /etc/tethys-sentinel-operator/operator.env
sudo chmod 0440 /etc/tethys-sentinel-operator/operator.env
```

## Start

For staged acceptance, start the service without enabling it at boot:

```bash
sudo systemctl daemon-reload
sudo systemctl start sentinel-operator.service
sudo systemctl status --no-pager sentinel-operator.service
```

After acceptance and an explicit deployment decision, enabling at boot may be done separately:

```bash
sudo systemctl enable sentinel-operator.service
```

Do not dump the full process environment while troubleshooting. Logs must never include the admin token or issued capabilities.

## Network policy

Allow TCP/8444 only from the intended operator/management network where practical.

The service itself is fail-closed by mTLS even when the TCP listener is reachable. No HTTP listener is provided. The only upstream destination permitted by application validation is a loopback HTTP Control URL.

No new route from the Worker, Gateway or target networks to operator authority is required.

## Windows browser client certificate

Import the password-protected operator PFX into the current user's Personal certificate store. Import the dedicated operator CA certificate into the trusted root store only through the intended administrator workflow.

Navigate to the exact HTTPS origin configured in `SENTINEL_OPERATOR_PUBLIC_ORIGIN`. The browser should prompt for/select the operator client certificate when necessary.

Do not import or distribute the operator CA private key.

## Acceptance checklist

Run acceptance against the exact release candidate binary and record the source commit SHA and binary hashes.

### TLS / browser boundary

- Connecting without a trusted client certificate fails at TLS authentication.
- A trusted operator client certificate reaches the UI.
- The server certificate validates normally; no `-k`/insecure browser bypass is used.
- The UI response has strict CSP, HSTS, `nosniff`, no-referrer and restrictive Permissions-Policy headers.
- Generated HTML contains no inline script/style and loads no third-party runtime content.

### Credential boundary

- Browser requests never contain the Control admin bearer token.
- `sentinel-operator` process environment contains no PostgreSQL DSN/password, Worker secret, Signer token, PVE credential or SSH CA private material.
- The operator admin token and server private key are mode `0400` and readable only by `tethys-operator`/root.
- `/etc/tethys-sentinel` remains inaccessible to `tethys-operator`.
- The Control URL is exactly loopback.

### CSRF/origin

- Normal same-origin UI mutation succeeds with the BFF-issued CSRF session.
- Missing/mismatched CSRF token is rejected.
- Cross-origin mutation is rejected.
- A spoofed browser `Authorization` or forwarded operator identity cannot replace server-side authority/identity.
- Unknown browser API routes return 404; there is no generic admin proxy.

### Functional

- Overview reflects current authority state/counts.
- A pending approval can be denied and allowed once; reusable session approval appears only when policy permits it.
- Powerful execution categories show one-shot-only policy and cannot receive reusable session approval.
- A consumed `allow_once` cannot authorize a second request ID with the same risk scope.
- A grant can be issued and its plaintext capability appears only in the immediate reveal state.
- Dismissing the reveal removes the token from application state; it is not in localStorage/sessionStorage.
- A one-time MCP claim can be issued from the UI, appears only in the immediate reveal state, expires within its configured 30..300 second TTL, and cannot be redeemed twice.
- Redeeming a claim with `sentinelctl mcp claim` installs a normal scoped capability without exposing the Control admin credential to the MCP host.
- A claim issued before `REVOKE ALL` cannot be redeemed after the epoch changes, even after authority is re-enabled.
- A grant can be revoked.
- Jobs expose immutable command binding, timestamps and terminal result without inventing raw stdout/stderr.
- Audit, Targets and Trust-0 Context are readable and remain non-mutable in the browser.
- Mutation audit actor is derived from the verified client certificate.

### Emergency semantics

- `REVOKE ALL` is reachable globally and, after confirmation, advances the epoch and disables AI authority.
- A running execution loses authority promptly, preserving the accepted active-revoke semantics.
- `Enable AI access` requires an explicit human reason/confirmation.
- Re-enable preserves the current epoch and does not revive an older capability.

Leave authority in the intended fail-closed state after acceptance and never reuse an expired, revoked, stale, or already-consumed acceptance credential. Record deployment-specific epochs, reasons, source commits, binary hashes and PKI fingerprints only in private operator records; do not commit them to this public guide.
