from __future__ import annotations

import json
import sys
from pathlib import Path

import psutil

_COMMON_PYTHON_DIR = Path(__file__).resolve().parents[1] / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

from secflow_common.interface_discovery import probe_windows_interfaces, unique_name
from secflow_common.output_messages import build_error_output, build_output_payload

def list_interfaces() -> list[dict[str, str]]:
    interfaces: list[dict[str, str]] = []
    used_names: set[str] = set()
    seen_raw_names: set[str] = set()

    if sys.platform == "win32":
        for item in probe_windows_interfaces():
            raw_name = str(item.get("rawName", "")).strip()
            display_name = str(item.get("displayName", "")).strip() or raw_name
            if not raw_name or raw_name in seen_raw_names:
                continue

            seen_raw_names.add(raw_name)
            interfaces.append(
                {
                    "name": unique_name(used_names, display_name),
                    "rawName": raw_name,
                }
            )
        if interfaces:
            return interfaces

    raw_interfaces = psutil.net_if_addrs().keys()
    for raw_name in raw_interfaces:
        normalized = str(raw_name).strip()
        if not normalized or normalized in seen_raw_names:
            continue
        seen_raw_names.add(normalized)
        interfaces.append(
            {
                "name": unique_name(used_names, normalized),
                "rawName": normalized,
            }
        )

    return interfaces


def main() -> None:
    try:
        print(json.dumps(build_output_payload(nics=list_interfaces()), ensure_ascii=False))
    except Exception as exc:  # pragma: no cover - runtime guard
        print(json.dumps(build_error_output(exc), ensure_ascii=False))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
