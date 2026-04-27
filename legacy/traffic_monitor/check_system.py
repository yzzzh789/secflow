#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查系统配置"""
import sys

print("=== System Check ===\n")

# 检查Python版本
print(f"Python version: {sys.version}")

# 检查psutil
try:
    import psutil
    print(f"[OK] psutil installed (version: {psutil.__version__})")

    # 列出所有网卡
    print("\nAvailable network interfaces:")
    stats = psutil.net_io_counters(pernic=True)
    for nic_name in stats.keys():
        print(f"  - {nic_name}")

except ImportError:
    print("[ERROR] psutil not installed")
    print("  Run: pip install psutil")
