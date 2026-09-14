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

`sentinel-operator` should run on the Control host as a separate unprivileged systemd service. The public AI Gateway does not receive any operator routes.

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

The browser source lives in `web/operator` and is built with TypeScript, Preact and Vite. CI verifies that the generated files match the frontend archive embedded into the Go binary.

Build the release binary from the exact accepted commit:

```bash
go test ./internal/operatorweb ./internal/operatorproxy ./cmd/sentinel-operator
CGO_ENABLED=0 go build -trimpath -o sentinel-operator ./cmd/sentinel-operator
./sentinel-operator --help 2>/dev/null || true
```

`sentinel-operator` intentionally has no runtime dependency on a checkout, `node_modules`, npm or Vite.

## Service account and binary

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

sudo install -d -o root -g root -m 0755 /etc/tethys-sentinel
```

Install `config/systemd/sentinel-operator.service` as `/etc/systemd/system/sentinel-operator.service`.

## Control admin token file

Do not print the token and do not place it in the browser-facing environment.

If Control already has the token in its process environment, copy it directly into the operator-only file on the same host:

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
printf '%s\n' "$ADMIN_TOKEN" > /etc/tethys-sentinel/operator-admin.token
chown tethys-operator:tethys-operator /etc/tethys-sentinel/operator-admin.token
chmod 0400 /etc/tethys-sentinel/operator-admin.token
unset ADMIN_TOKEN
EOF
```

Do not use `cat`, `set -x`, shell tracing, or command-line arguments that expose this token.

## Dedicated operator TLS trust root

Do not reuse the Sentinel SSH user CA or any other infrastructure CA.

Create a dedicated TLS CA for operator browser authentication. Keep its private key offline after certificates are issued. Only the CA certificate belongs on the Control host.

The server certificate must contain the exact DNS name or IP address used by the browser in `SENTINEL_OPERATOR_PUBLIC_ORIGIN`.

For the accepted Control address example `10.169.2.210`, a server certificate therefore needs an IP SAN for `10.169.2.210` if the browser URL is:

```text
https://10.169.2.210:8444
```

The operator client certificate should have client-auth EKU. Export the client key/certificate as a password-protected PKCS#12/PFX for import into the Windows certificate store/browser.

After transfer to the operator workstation, remove any temporary plaintext client private key from the Control host. The dedicated operator CA private key should likewise not remain on the Sentinel host.

Install only these TLS files for the service:

```text
/etc/tethys-sentinel/operator-server.crt
/etc/tethys-sentinel/operator-server.key
/etc/tethys-sentinel/operator-client-ca.crt
```

Recommended permissions:

```bash
sudo chown root:root /etc/tethys-sentinel/operator-server.crt
sudo chmod 0444 /etc/tethys-sentinel/operator-server.crt

sudo chown tethys-operator:tethys-operator /etc/tethys-sentinel/operator-server.key
sudo chmod 0400 /etc/tethys-sentinel/operator-server.key

sudo chown root:root /etc/tethys-sentinel/operator-client-ca.crt
sudo chmod 0444 /etc/tethys-sentinel/operator-client-ca.crt
```

## Runtime configuration

Copy `config/operator.env.example` to `/etc/tethys-sentinel/operator.env` and set the exact management address/origin. For the accepted Control VM example:

```ini
SENTINEL_OPERATOR_PUBLIC_ORIGIN=https://10.169.2.210:8444
SENTINEL_OPERATOR_LISTEN=10.169.2.210:8444
SENTINEL_OPERATOR_CONTROL_URL=http://127.0.0.1:8081
SENTINEL_OPERATOR_ADMIN_TOKEN_FILE=/etc/tethys-sentinel/operator-admin.token
SENTINEL_OPERATOR_TLS_CERT=/etc/tethys-sentinel/operator-server.crt
SENTINEL_OPERATOR_TLS_KEY=/etc/tethys-sentinel/operator-server.key
SENTINEL_OPERATOR_CLIENT_CA=/etc/tethys-sentinel/operator-client-ca.crt
```

The public origin must be an HTTPS origin with no path/query/fragment and must exactly match the browser Origin header. The binary rejects a non-loopback Control URL.

The environment file contains no secret and can remain root-owned/readable:

```bash
sudo chown root:root /etc/tethys-sentinel/operator.env
sudo chmod 0644 /etc/tethys-sentinel/operator.env
```

## Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-operator.service
sudo systemctl status --no-pager sentinel-operator.service
```

Do not dump the full process environment while troubleshooting. Logs must never include the admin token or issued capabilities.

## Network policy

Allow TCP/8444 only from the intended operator/management network where practical.

The service itself is still fail-closed by mTLS even when the TCP listener is reachable. No HTTP listener is provided. The only upstream destination permitted by application validation is a loopback HTTP Control URL.

No new route from the Worker, Gateway or target networks to operator authority is required.

## Windows browser client certificate

Import the password-protected operator PFX into the current user's Personal certificate store. Import the dedicated operator CA certificate into the appropriate trusted root store only if it is not already trusted through another approved mechanism.

Navigate to the exact HTTPS origin configured in `SENTINEL_OPERATOR_PUBLIC_ORIGIN`. The browser should prompt for/select the operator client certificate when necessary.

Do not import or distribute the operator CA private key.

## Acceptance checklist

Run acceptance against the exact release candidate binary and record the commit SHA.

### TLS / browser boundary

- Connecting without a trusted client certificate fails at TLS authentication.
- A trusted operator client certificate reaches the UI.
- The server certificate validates normally; no `-k`/insecure browser bypass is used.
- The UI response has strict CSP, HSTS, `nosniff`, no-referrer and restrictive Permissions-Policy headers.
- Generated HTML contains no inline script/style and loads no third-party runtime content.

### Credential boundary

- Browser requests never contain the Control admin bearer token.
- `sentinel-operator` process environment contains no PostgreSQL DSN/password, Worker secret, Signer token, PVE credential or SSH CA private material.
- The operator admin token file is mode `0400` and readable only by the service account/root.
- The Control URL is loopback.

### CSRF/origin

- Normal same-origin UI mutation succeeds with the BFF-issued CSRF session.
- Missing/mismatched CSRF token is rejected.
- Cross-origin mutation is rejected.
- A spoofed browser `Authorization` or forwarded operator identity cannot replace server-side authority/identity.

### Functional

- Overview reflects current authority state/counts.
- A pending approval can be denied and allowed once; reusable session approval appears only when policy permits it.
- A grant can be issued and its plaintext capability appears only in the immediate reveal state.
- Dismissing the reveal removes the token from application state; it is not in localStorage/sessionStorage.
- A grant can be revoked.
- Jobs expose immutable command binding, timestamps and terminal result without inventing raw stdout/stderr.
- Audit, Targets and Trust-0 Context are readable and remain non-mutable in the browser.

### Emergency semantics

- `REVOKE ALL` is reachable globally and, after confirmation, advances the epoch and disables AI authority.
- A running execution loses authority promptly, preserving the already-accepted active-revoke semantics.
- `Enable AI access` requires an explicit human reason/confirmation.
- Re-enable preserves the current epoch and does not revive an older capability.

Leave production authority in the intended final state after acceptance. Never use an expired/revoked/stale acceptance capability for later operations.
