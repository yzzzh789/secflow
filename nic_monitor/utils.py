from __future__ import annotations

import datetime as _dt
from typing import Optional


TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def utc_now_epoch_s() -> int:
    return int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp())


def epoch_s_to_local_dt(ts: int) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).astimezone()


def format_local_ts(ts: int) -> str:
    return epoch_s_to_local_dt(ts).strftime(TS_FORMAT)


def parse_local_ts(text: str) -> Optional[int]:
    text = (text or "").strip()
    if not text:
        return None
    try:
        local = _dt.datetime.strptime(text, TS_FORMAT)
    except ValueError:
        return None
    local = local.replace(tzinfo=_dt.datetime.now().astimezone().tzinfo)
    return int(local.astimezone(_dt.timezone.utc).timestamp())


def bps_to_mbps(bps: float) -> float:
    return (bps * 8.0) / 1_000_000.0


def clamp_non_negative(value: float) -> float:
    return value if value >= 0 else 0.0

