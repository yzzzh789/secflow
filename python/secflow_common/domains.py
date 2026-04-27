from __future__ import annotations

import ipaddress
import re
from typing import Iterable


def normalize_domain(
    domain: str | bytes | None,
    *,
    ignored_suffixes: Iterable[str] = (),
    ignored_patterns: Iterable[str] = (),
    max_length: int | None = None,
) -> str | None:
    if domain is None:
        return None
    if isinstance(domain, bytes):
        try:
            domain = domain.decode("utf-8", errors="ignore")
        except Exception:  # pragma: no cover - defensive
            return None

    value = domain.strip().rstrip(".").lower()
    if not value:
        return None
    if max_length is not None and len(value) > max_length:
        return None
    if any(value.endswith(suffix) for suffix in ignored_suffixes):
        return None
    if any(pattern in value for pattern in ignored_patterns):
        return None
    if not re.fullmatch(r"[a-z0-9._:-]+", value):
        return None
    return value


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def root_domain(domain: str) -> str:
    if is_ip_address(domain):
        return domain
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def extract_host_header(
    payload: bytes,
    *,
    ignored_suffixes: Iterable[str] = (),
    ignored_patterns: Iterable[str] = (),
    max_length: int | None = None,
) -> str | None:
    if not payload or b"host:" not in payload.lower():
        return None
    try:
        text = payload[:4096].decode("latin-1", errors="ignore")
    except Exception:  # pragma: no cover - defensive
        return None

    match = re.search(r"^Host:\s*([^\r\n]+)", text, re.IGNORECASE | re.MULTILINE)
    if not match:
        return None

    host = match.group(1).strip().split(":", 1)[0]
    return normalize_domain(
        host,
        ignored_suffixes=ignored_suffixes,
        ignored_patterns=ignored_patterns,
        max_length=max_length,
    )


def extract_tls_sni(
    payload: bytes,
    *,
    ignored_suffixes: Iterable[str] = (),
    ignored_patterns: Iterable[str] = (),
    max_length: int | None = None,
) -> str | None:
    if len(payload) < 5 or payload[0] != 0x16:
        return None

    try:
        record_length = int.from_bytes(payload[3:5], "big")
        if len(payload) < 5 + min(record_length, 4):
            return None
        if payload[5] != 0x01:
            return None

        cursor = 9
        cursor += 2
        cursor += 32
        if len(payload) <= cursor:
            return None

        session_id_length = payload[cursor]
        cursor += 1 + session_id_length
        if len(payload) < cursor + 2:
            return None

        cipher_suites_length = int.from_bytes(payload[cursor : cursor + 2], "big")
        cursor += 2 + cipher_suites_length
        if len(payload) <= cursor:
            return None

        compression_methods_length = payload[cursor]
        cursor += 1 + compression_methods_length
        if len(payload) < cursor + 2:
            return None

        extensions_length = int.from_bytes(payload[cursor : cursor + 2], "big")
        cursor += 2
        end = min(len(payload), cursor + extensions_length)

        while cursor + 4 <= end:
            extension_type = int.from_bytes(payload[cursor : cursor + 2], "big")
            extension_length = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
            cursor += 4
            extension_end = cursor + extension_length
            if extension_end > end:
                return None

            if extension_type == 0x0000 and extension_length >= 5:
                list_length = int.from_bytes(payload[cursor : cursor + 2], "big")
                name_type = payload[cursor + 2]
                name_length = int.from_bytes(payload[cursor + 3 : cursor + 5], "big")
                if name_type != 0 or list_length < 3 or cursor + 5 + name_length > extension_end:
                    return None

                host = payload[cursor + 5 : cursor + 5 + name_length].decode("utf-8", errors="ignore")
                return normalize_domain(
                    host,
                    ignored_suffixes=ignored_suffixes,
                    ignored_patterns=ignored_patterns,
                    max_length=max_length,
                )

            cursor = extension_end
    except Exception:  # pragma: no cover - parser must fail closed
        return None

    return None


def extract_domain_from_tcp_payload(
    payload: bytes,
    *,
    enable_http: bool = True,
    enable_tls: bool = True,
    ignored_suffixes: Iterable[str] = (),
    ignored_patterns: Iterable[str] = (),
    max_length: int | None = None,
) -> tuple[str | None, str]:
    if not payload:
        return None, ""

    if enable_http:
        host = extract_host_header(
            payload,
            ignored_suffixes=ignored_suffixes,
            ignored_patterns=ignored_patterns,
            max_length=max_length,
        )
        if host:
            return host, "http_host"

    if enable_tls:
        sni = extract_tls_sni(
            payload,
            ignored_suffixes=ignored_suffixes,
            ignored_patterns=ignored_patterns,
            max_length=max_length,
        )
        if sni:
            return sni, "tls_sni"

    return None, ""
