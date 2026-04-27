#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""查找有流量的网卡"""
import psutil
import time
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("Checking network activity for 3 seconds...\n")

# 第一次采样
stats1 = psutil.net_io_counters(pernic=True)
time.sleep(3)

# 第二次采样
stats2 = psutil.net_io_counters(pernic=True)

print("Network interfaces with traffic:\n")
active_found = False

for nic_name in stats1.keys():
    if nic_name in stats2:
        bytes_recv_diff = stats2[nic_name].bytes_recv - stats1[nic_name].bytes_recv
        bytes_sent_diff = stats2[nic_name].bytes_sent - stats1[nic_name].bytes_sent
        total_diff = bytes_recv_diff + bytes_sent_diff

        if total_diff > 0:
            active_found = True
            mbps = (total_diff * 8) / (3 * 1024 * 1024)
            print(f"  [{nic_name}]")
            print(f"    Received: {bytes_recv_diff / 1024:.2f} KB")
            print(f"    Sent: {bytes_sent_diff / 1024:.2f} KB")
            print(f"    Average speed: {mbps:.2f} Mbps")
            print()

if not active_found:
    print("  No active network interfaces found.")
    print("  Try browsing the web or downloading something to generate traffic.")
