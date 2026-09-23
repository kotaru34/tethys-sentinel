#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import sys

AUTH = "TETHYS_SENTINEL_RELAY_AUTHORIZED_V1"
RESPONSE = "TETHYS_SENTINEL_RELAY_RESPONSE_V1"


def b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check(secret: str, payload: dict, mac: str) -> None:
    if not secret.startswith("tsr_"):
        raise SystemExit("invalid relay session secret")
    key = b64url_decode(secret[4:])
    expected = "h1_" + b64url_encode(hmac.new(key, canonical(payload), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, mac):
        raise SystemExit("relay MAC verification failed")


def main() -> None:
    request = json.load(sys.stdin)
    secret = str(request["secret"])
    comment = str(request["comment"]).strip()
    marker, _, json_text = comment.partition("\n")
    if not json_text:
        raise SystemExit("invalid relay comment")
    wire = json.loads(json_text)
    mac = str(wire.pop("mac", ""))

    if marker == AUTH:
        payload = {
            "actor_id": int(wire["actor_id"]),
            "exact_argv": wire.get("exact_argv"),
            "expires_at": str(wire["expires_at"]),
            "issue_number": int(wire["issue_number"]),
            "max_commands": int(wire["max_commands"]),
            "output_limit_bytes": int(wire.get("output_limit_bytes", 0)),
            "publish_output": bool(wire["publish_output"]),
            "repository_id": int(wire["repository_id"]),
            "session_id": str(wire["session_id"]),
            "target": str(wire["target"]),
            "version": int(wire["version"]),
        }
    elif marker == RESPONSE:
        payload = {
            "approval_id": str(wire.get("approval_id", "")),
            "decision": str(wire.get("decision", "")),
            "error": str(wire.get("error", "")),
            "error_kind": str(wire.get("error_kind", "")),
            "exit_code": wire.get("exit_code"),
            "job_id": str(wire.get("job_id", "")),
            "job_status": str(wire.get("job_status", "")),
            "output_sha256": str(wire.get("output_sha256", "")),
            "request_id": str(wire["request_id"]),
            "sequence": int(wire["sequence"]),
            "session_id": str(wire["session_id"]),
            "status": str(wire["status"]),
            "stderr_b64": str(wire.get("stderr_b64", "")),
            "stderr_truncated": bool(wire.get("stderr_truncated", False)),
            "stdout_b64": str(wire.get("stdout_b64", "")),
            "stdout_truncated": bool(wire.get("stdout_truncated", False)),
            "success": wire.get("success"),
            "version": int(wire["version"]),
        }
    else:
        raise SystemExit("unsupported relay marker")

    check(secret, payload, mac)
    result = dict(wire)
    result["mac_verified"] = True
    if marker == RESPONSE:
        if wire.get("stdout_b64"):
            result["stdout_text"] = base64.b64decode(wire["stdout_b64"]).decode("utf-8", errors="backslashreplace")
        if wire.get("stderr_b64"):
            result["stderr_text"] = base64.b64decode(wire["stderr_b64"]).decode("utf-8", errors="backslashreplace")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()