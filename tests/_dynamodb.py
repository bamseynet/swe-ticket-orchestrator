"""DynamoDB Local helper shared by the CI-only integration and e2e smoke tests (D0-09)."""

from __future__ import annotations

import json
import os
import socket

from hermetic_guard import allow_loopback_bind

DDB_PORT = int(os.environ.get("STO_DDB_PORT", "8720"))
# DynamoDB Local does not verify signatures, but insists the request looks signed.
FAKE_AUTH = (
    "AWS4-HMAC-SHA256 Credential=fake/20260101/us-east-1/dynamodb/aws4_request, "
    "SignedHeaders=host, Signature=fake"
)


def list_tables() -> dict[str, object]:
    """POST ListTables over a raw loopback socket (name lookups stay blocked by the guard)."""
    payload = b"{}"
    head = (
        f"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
        f"Content-Type: application/x-amz-json-1.0\r\n"
        f"X-Amz-Target: DynamoDB_20120810.ListTables\r\n"
        f"Authorization: {FAKE_AUTH}\r\nContent-Length: {len(payload)}\r\n\r\n"
    ).encode()
    chunks: list[bytes] = []
    with allow_loopback_bind(), socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect(("127.0.0.1", DDB_PORT))
        conn.sendall(head + payload)
        while chunk := conn.recv(65536):
            chunks.append(chunk)
    header, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    assert header.startswith(b"HTTP/1.1 200"), header
    parsed: dict[str, object] = json.loads(body[body.index(b"{") :])
    return parsed
