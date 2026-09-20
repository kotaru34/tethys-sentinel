#!/usr/bin/env bash
set -euo pipefail

# Public-tree privacy/secret guard. The scanner deliberately ignores itself so
# its signatures do not become findings.
pathspec=(':(top)' ':(exclude)scripts/public_privacy_scan.sh')

fail=0

check() {
  local label="$1"
  local pattern="$2"
  local hits

  if hits="$(git grep -nIE "$pattern" -- "${pathspec[@]}" 2>/dev/null)"; then
    printf 'PUBLIC PRIVACY SCAN FAILED: %s\n' "$label" >&2
    printf '%s\n' "$hits" >&2
    printf '\n' >&2
    fail=1
  fi
}

# Site-specific network data must never be committed. Public examples use
# RFC 5737 / RFC 3849 documentation ranges instead.
check 'RFC1918 10/8 IPv4 literal' '(^|[^0-9])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'
check 'RFC1918 172.16/12 IPv4 literal' '(^|[^0-9])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'
check 'RFC1918 192.168/16 IPv4 literal' '(^|[^0-9])192\.168\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'
check 'IPv6 ULA literal' '(^|[^0-9A-Fa-f])f[cd][0-9A-Fa-f]{2}:'

# Known operator-environment identifiers that appeared during private
# acceptance. Keep real topology only in private operator records.
check 'operator home path' '/home/kotaru([^A-Za-z0-9_-]|$)'
check 'operator shell identity' '(^|[^A-Za-z0-9_-])kotaru@'
check 'private MCP host name' '(^|[^A-Za-z0-9_-])bs-tethys-core([^A-Za-z0-9_-]|$)'
check 'private hypervisor name' '(^|[^A-Za-z0-9_-])ai-server([^A-Za-z0-9_-]|$)'
check 'private VLAN identifier' 'VLAN[[:space:]]+1520([^0-9]|$)'
check 'private VM identifier' '(^|[^0-9])(VM|VMID)[[:space:]#:=_-]*(1310|1320|1330|1340|1350)([^0-9]|$)'

# Do not publish concrete certificate/SSH key fingerprints or private keys.
check 'concrete SHA256 fingerprint' 'SHA256:[A-Za-z0-9+/=]{32,}'
check 'private key PEM header' '-----BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----'

# Common high-signal credential formats.
check 'GitHub token literal' 'gh[pousr]_[A-Za-z0-9]{20,}'
check 'AWS access key literal' 'AKIA[0-9A-Z]{16}'
check 'Google API key literal' 'AIza[0-9A-Za-z_-]{30,}'
check 'OpenAI-style secret literal' '(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}'
check 'literal bearer credential' 'Bearer[[:space:]]+[A-Za-z0-9._~+/-]{24,}'
check_url_password() {
  local hits filtered
  if hits="$(git grep -nIE '((https?|postgres(ql)?):)//[^/@[:space:]]+:[^/@[:space:]]+@' -- "${pathspec[@]}" 2>/dev/null)"; then
    # Public runbooks may use an explicit <PLACEHOLDER> in the password slot.
    filtered="$(printf '%s\n' "$hits" | grep -Ev '://[^/@[:space:]]+:<[A-Z0-9_]+>@' || true)"
    if [[ -n "$filtered" ]]; then
      printf 'PUBLIC PRIVACY SCAN FAILED: URL-embedded credential\n' >&2
      printf '%s\n\n' "$filtered" >&2
      fail=1
    fi
  fi
}
check_url_password

if (( fail != 0 )); then
  exit 1
fi

echo 'public privacy scan: PASS'
