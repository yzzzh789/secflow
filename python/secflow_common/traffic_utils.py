from __future__ import annotations

from typing import Any, Mapping


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(value: int, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(upper, value))


def event_signature(event: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    return "|".join(str(event.get(key, "")) for key in keys)


def packet_size(packet: Any, ip_layer: Any) -> int:
    ip_length = safe_int(getattr(ip_layer, "len", 0), 0)
    if ip_length > 0:
        return ip_length
    try:
        return len(bytes(packet))
    except Exception:  # pragma: no cover - depends on packet backend
        return 0
