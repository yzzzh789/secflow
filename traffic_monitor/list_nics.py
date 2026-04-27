#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""列出所有可用的网卡"""
import json
import sys
import io
from pathlib import Path

import psutil

_COMMON_PYTHON_DIR = Path(__file__).resolve().parents[1] / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

from secflow_common.output_messages import build_error_output, build_output_payload

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

try:
    stats = psutil.net_io_counters(pernic=True)
    nics = []

    for nic_name, nic_stats in stats.items():
        nics.append({
            "name": nic_name,
            "bytes_sent": nic_stats.bytes_sent,
            "bytes_recv": nic_stats.bytes_recv,
            "packets_sent": nic_stats.packets_sent,
            "packets_recv": nic_stats.packets_recv
        })

    print(json.dumps(build_output_payload(nics=nics), ensure_ascii=False))
except Exception as e:
    print(json.dumps(build_error_output(e), ensure_ascii=False))
    sys.exit(1)
