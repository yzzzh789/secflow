from __future__ import annotations

import time


def format_bytes(total_bytes: int) -> str:
    if total_bytes < 1024:
        return f"{total_bytes}B"
    if total_bytes < 1024 * 1024:
        return f"{total_bytes / 1024:.1f}KB"
    if total_bytes < 1024 * 1024 * 1024:
        return f"{total_bytes / (1024 * 1024):.1f}MB"
    return f"{total_bytes / (1024 * 1024 * 1024):.2f}GB"


def format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, remaining = divmod(total, 60)
    if minutes == 0:
        return f"{remaining}s"
    return f"{minutes}m {remaining}s"


def format_capture_time(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
