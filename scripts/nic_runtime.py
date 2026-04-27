#!/usr/bin/env python3
"""Mainline NIC runtime entrypoint.

The implementation still lives in the compatibility module during this
cleanup phase. Keeping this shim lets the Go service depend on a mainline
path while the legacy path remains executable for existing callers.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from traffic_monitor.nic_monitor_server_enhanced import main


if __name__ == "__main__":
    main()
