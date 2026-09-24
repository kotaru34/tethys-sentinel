#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import secrets
import sys

MARKER = "TETHYS_SENTINEL_RELAY_REQUEST_V1"


def b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> None:
    data = json.load(sys.stdin)
    secret = str(data.pop("secret"))
    if not secret.startswith("tsr_"):
        raise SystemExit("invalid relay session secret")
    key = b64url_decode(secret[4:])
    if len(key) != 32:
        raise SystemExit("invalid relay session secret")

    request_id = str(data.get("request_id") or ("req-" + secrets.token_hex(12)))
    payload = {
        "agent_reason": str(data.get("agent_reason", "")),
        "argv": list(data["argv"]),
        "request_id": request_id,
        "sequence": int(data["sequence"]),
        "session_id": str(data["session_id"]),
        "target": str(data["target"]),
        "timeout_seconds": int(data.get("timeout_seconds", 0)),
        "version": 1,
    }
    mac = "h1_" + b64url_encode(hmac.new(key, canonical(payload), hashlib.sha256).digest())
    wire = {
        "version": 1,
        "session_id": payload["session_id"],
        "sequence": payload["sequence"],
        "request_id": request_id,
        "target": payload["target"],
        "argv": payload["argv"],
    }
    if payload["agent_reason"]:
        wire["agent_reason"] = payload["agent_reason"]
    if payload["timeout_seconds"]:
        wire["timeout_seconds"] = payload["timeout_seconds"]
    wire["mac"] = mac
    print(MARKER)
    print(json.dumps(wire, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()