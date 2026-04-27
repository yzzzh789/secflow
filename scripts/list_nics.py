from __future__ import annotations

import json
import sys
from pathlib import Path

import psutil

_COMMON_PYTHON_DIR = Path(__file__).resolve().parents[1] / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

from secflow_common.interface_discovery import probe_windows_interfaces
from secflow_common.output_messages import build_error_output, build_output_payload

def load_windows_descriptions() -> dict[str, str]:
    if sys.platform != "win32":
        return {}

    descriptions: dict[str, str] = {}
    for item in probe_windows_interfaces():
        raw_name = str(item.get("rawName", "")).strip()
        description = str(item.get("displayName", "")).strip()
        if not raw_name or not description:
            continue
        descriptions.setdefault(raw_name, description)
    return descriptions


def list_nics() -> list[dict[str, object]]:
    counters = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    descriptions = load_windows_descriptions()

    items: list[dict[str, object]] = []
    for nic_name, nic_counter in counters.items():
        normalized = str(nic_name).strip()
        if not normalized:
            continue

        nic_stats = stats.get(normalized)
        items.append(
            {
                "name": normalized,
                "displayName": descriptions.get(normalized, normalized),
                "rawName": normalized,
                "bytes_sent": nic_counter.bytes_sent,
                "bytes_recv": nic_counter.bytes_recv,
                "packets_sent": nic_counter.packets_sent,
                "packets_recv": nic_counter.packets_recv,
                "isup": bool(nic_stats.isup) if nic_stats else False,
                "speed_mbps": int(nic_stats.speed) if nic_stats else 0,
                "mtu": int(nic_stats.mtu) if nic_stats else 0,
            }
        )

    items.sort(
        key=lambda item: (
            not bool(item["isup"]),
            -(int(item["bytes_sent"]) + int(item["bytes_recv"])),
            str(item["displayName"]).lower(),
        )
    )
    return items


def main() -> None:
    try:
        print(json.dumps(build_output_payload(nics=list_nics()), ensure_ascii=False))
    except Exception as exc:  # pragma: no cover - runtime guard
        print(json.dumps(build_error_output(exc), ensure_ascii=False))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
