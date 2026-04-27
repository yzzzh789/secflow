from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Mapping

WINDOWS_NOISE_PATTERNS = (
    "npcap packet driver",
    "qos packet scheduler",
    "wfp native",
    "wfp 802.3",
    "virtual filtering platform",
    "hyper-v virtual switch extension",
)

SCAPY_WINDOWS_PROBE_SCRIPT = """
import json
from scapy.arch.windows import get_windows_if_list

items = []
for item in get_windows_if_list():
    items.append({
        "rawName": str(item.get("name", "")).strip(),
        "displayName": str(item.get("description", "")).strip(),
    })
print(json.dumps({"interfaces": items}, ensure_ascii=False))
""".strip()


def should_skip_windows_interface(description: str) -> bool:
    normalized = description.strip().lower()
    if not normalized:
        return True
    return any(pattern in normalized for pattern in WINDOWS_NOISE_PATTERNS)


def unique_name(existing: set[str], preferred: str) -> str:
    candidate = preferred
    suffix = 1
    while candidate in existing:
        suffix += 1
        candidate = f"{preferred} ({suffix})"
    existing.add(candidate)
    return candidate


def normalize_windows_interface_rows(rows: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    seen_raw_names: set[str] = set()
    for row in rows:
        raw_name = str(row.get("rawName", "")).strip()
        display_name = str(row.get("displayName", "")).strip() or raw_name
        if not raw_name or raw_name in seen_raw_names:
            continue
        if should_skip_windows_interface(display_name):
            continue
        seen_raw_names.add(raw_name)
        normalized.append(
            {
                "rawName": raw_name,
                "displayName": display_name or raw_name,
            }
        )
    return normalized


def prepare_scapy_probe_env(base_dir: Path | None = None) -> dict[str, str]:
    runtime_dir = base_dir or (Path(tempfile.gettempdir()) / "secflow-scapy")
    scapy_dir = runtime_dir / "scapy"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    scapy_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.setdefault("XDG_CONFIG_HOME", str(runtime_dir))
    env.setdefault("SCAPY_CONFIG_FOLDER", str(scapy_dir))
    return env


def probe_windows_interfaces(timeout_seconds: float = 3.0) -> list[dict[str, str]]:
    if sys.platform != "win32":
        return []

    try:
        completed = subprocess.run(
            [sys.executable, "-u", "-c", SCAPY_WINDOWS_PROBE_SCRIPT],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=prepare_scapy_probe_env(),
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if completed.returncode != 0:
        return []

    try:
        payload = json.loads((completed.stdout or "").strip() or "{}")
    except json.JSONDecodeError:
        return []

    interfaces = payload.get("interfaces")
    if not isinstance(interfaces, list):
        return []
    return normalize_windows_interface_rows(interfaces)
