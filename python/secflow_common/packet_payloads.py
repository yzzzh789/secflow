from __future__ import annotations

from typing import Any

from .protocol_types import PacketPayloadDescription

HTTP_REQUEST_PREFIXES = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")


def payload_size(payload: object) -> int:
    try:
        return len(payload)  # type: ignore[arg-type]
    except Exception:
        return 0


def extract_http_request_line(payload_text: str) -> str | None:
    if not payload_text.startswith(HTTP_REQUEST_PREFIXES):
        return None
    if "\r\n" in payload_text:
        return payload_text.split("\r\n", 1)[0]
    return payload_text.split("\n", 1)[0]


def describe_payload(payload: Any) -> PacketPayloadDescription:
    try:
        if isinstance(payload, str):
            payload_text = payload
        else:
            payload_text = bytes(payload).decode("utf-8", errors="ignore")
    except Exception:
        return {"payload": f"<binary data, {payload_size(payload)} bytes>"}

    details: PacketPayloadDescription = {"payload": payload_text}
    request_line = extract_http_request_line(payload_text)
    if request_line is not None:
        details["http_detected"] = True
        details["http_request_line"] = request_line
    return details
