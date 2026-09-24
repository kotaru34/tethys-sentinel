#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import sys

AUTH = "TETHYS_SENTINEL_RELAY_AUTHORIZED_V1"
RESPONSE = "TETHYS_SENTINEL_RELAY_RESPONSE_V1"
MAX_COMMENT_BYTES = 48 << 10

AUTH_REQUIRED = {
    "version", "session_id", "repository_id", "issue_number", "actor_id",
    "target", "expires_at", "max_commands", "publish_output", "mac",
}
AUTH_OPTIONAL = {"exact_argv", "output_limit_bytes"}
RESPONSE_REQUIRED = {"version", "session_id", "sequence", "request_id", "status", "mac"}
RESPONSE_OPTIONAL = {
    "decision", "approval_id", "job_id", "job_status", "success", "exit_code",
    "error_kind", "output_sha256", "stdout_b64", "stderr_b64",
    "stdout_truncated", "stderr_truncated", "error",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + pad)
    except Exception as exc:
        fail(f"invalid base64url value: {exc}")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def strict_object(text: str) -> dict:
    def object_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                fail(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    try:
        value = json.loads(text, object_pairs_hook=object_pairs)
    except (ValueError, TypeError) as exc:
        fail(f"invalid relay JSON: {exc}")
    if type(value) is not dict:
        fail("relay payload must be a JSON object")
    return value


def exact_keys(wire: dict, required: set, optional: set) -> None:
    keys = set(wire)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        fail("missing relay fields: " + ",".join(sorted(missing)))
    if unknown:
        fail("unknown relay fields: " + ",".join(sorted(unknown)))


def require_string(value, name: str) -> str:
    if type(value) is not str:
        fail(f"{name} must be a string")
    return value


def require_int(value, name: str) -> int:
    if type(value) is not int:
        fail(f"{name} must be an integer")
    return value


def require_bool(value, name: str) -> bool:
    if type(value) is not bool:
        fail(f"{name} must be a boolean")
    return value


def require_string_list(value, name: str):
    if value is None:
        return None
    if type(value) is not list or any(type(item) is not str for item in value):
        fail(f"{name} must be an array of strings")
    return value


def check(secret: str, payload: dict, mac: str) -> None:
    if not secret.startswith("tsr_"):
        fail("invalid relay session secret")
    key = b64url_decode(secret[4:])
    if len(key) != 32:
        fail("invalid relay session secret")
    expected = "h1_" + b64url_encode(hmac.new(key, canonical(payload), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, mac):
        fail("relay MAC verification failed")


def decode_output(value: str, name: str) -> str:
    if not value:
        return ""
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        fail(f"invalid {name}: {exc}")
    return raw.decode("utf-8", errors="backslashreplace")


def main() -> None:
    request = json.load(sys.stdin)
    allowed_input = {"secret", "comment", "expected_author_id", "comment_author_id", "comment_author_type"}
    if type(request) is not dict or set(request) - allowed_input:
        fail("invalid verifier input fields")

    secret = require_string(request.get("secret"), "secret")
    comment = require_string(request.get("comment"), "comment").strip()
    if len(comment.encode("utf-8")) > MAX_COMMENT_BYTES:
        fail("relay comment exceeds transport limit")

    expected_author_id = require_int(request.get("expected_author_id"), "expected_author_id")
    comment_author_id = require_int(request.get("comment_author_id"), "comment_author_id")
    comment_author_type = require_string(request.get("comment_author_type"), "comment_author_type")
    if expected_author_id <= 0 or comment_author_id != expected_author_id:
        fail("relay GitHub App actor ID mismatch")
    if comment_author_type != "Bot":
        fail("relay comment author is not a GitHub App bot")

    marker, sep, json_text = comment.partition("\n")
    if not sep or not json_text.strip():
        fail("invalid relay comment")
    wire = strict_object(json_text.strip())

    if marker == AUTH:
        exact_keys(wire, AUTH_REQUIRED, AUTH_OPTIONAL)
        payload = {
            "actor_id": require_int(wire["actor_id"], "actor_id"),
            "exact_argv": require_string_list(wire.get("exact_argv"), "exact_argv"),
            "expires_at": require_string(wire["expires_at"], "expires_at"),
            "issue_number": require_int(wire["issue_number"], "issue_number"),
            "max_commands": require_int(wire["max_commands"], "max_commands"),
            "output_limit_bytes": require_int(wire.get("output_limit_bytes", 0), "output_limit_bytes"),
            "publish_output": require_bool(wire["publish_output"], "publish_output"),
            "repository_id": require_int(wire["repository_id"], "repository_id"),
            "session_id": require_string(wire["session_id"], "session_id"),
            "target": require_string(wire["target"], "target"),
            "version": require_int(wire["version"], "version"),
        }
    elif marker == RESPONSE:
        exact_keys(wire, RESPONSE_REQUIRED, RESPONSE_OPTIONAL)
        success = wire.get("success")
        if success is not None:
            success = require_bool(success, "success")
        exit_code = wire.get("exit_code")
        if exit_code is not None:
            exit_code = require_int(exit_code, "exit_code")
        payload = {
            "approval_id": require_string(wire.get("approval_id", ""), "approval_id"),
            "decision": require_string(wire.get("decision", ""), "decision"),
            "error": require_string(wire.get("error", ""), "error"),
            "error_kind": require_string(wire.get("error_kind", ""), "error_kind"),
            "exit_code": exit_code,
            "job_id": require_string(wire.get("job_id", ""), "job_id"),
            "job_status": require_string(wire.get("job_status", ""), "job_status"),
            "output_sha256": require_string(wire.get("output_sha256", ""), "output_sha256"),
            "request_id": require_string(wire["request_id"], "request_id"),
            "sequence": require_int(wire["sequence"], "sequence"),
            "session_id": require_string(wire["session_id"], "session_id"),
            "status": require_string(wire["status"], "status"),
            "stderr_b64": require_string(wire.get("stderr_b64", ""), "stderr_b64"),
            "stderr_truncated": require_bool(wire.get("stderr_truncated", False), "stderr_truncated"),
            "stdout_b64": require_string(wire.get("stdout_b64", ""), "stdout_b64"),
            "stdout_truncated": require_bool(wire.get("stdout_truncated", False), "stdout_truncated"),
            "success": success,
            "version": require_int(wire["version"], "version"),
        }
    else:
        fail("unsupported relay marker")

    mac = require_string(wire["mac"], "mac")
    check(secret, payload, mac)

    result = dict(wire)
    result["mac_verified"] = True
    result["relay_actor_verified"] = True
    result["relay_actor_id"] = comment_author_id
    if marker == RESPONSE:
        if wire.get("stdout_b64"):
            result["stdout_text"] = decode_output(wire["stdout_b64"], "stdout_b64")
        if wire.get("stderr_b64"):
            result["stderr_text"] = decode_output(wire["stderr_b64"], "stderr_b64")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
