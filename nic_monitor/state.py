from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, List, Mapping, Sequence, Tuple


@dataclass(frozen=True)
class RatePoint:
    ts: int
    rx_bps: float
    tx_bps: float


class SharedState:
    def __init__(self, *, live_keep_seconds: int = 3600) -> None:
        self._lock = threading.Lock()
        self._current: Dict[str, RatePoint] = {}
        self._series: Dict[str, Deque[RatePoint]] = defaultdict(deque)
        self._live_keep_seconds = int(live_keep_seconds)

    def update(self, nic: str, point: RatePoint) -> None:
        with self._lock:
            self._current[nic] = point
            series = self._series[nic]
            series.append(point)
            cutoff = point.ts - self._live_keep_seconds
            while series and series[0].ts < cutoff:
                series.popleft()

    def get_current(self, nics: Sequence[str]) -> Dict[str, RatePoint]:
        with self._lock:
            return {n: self._current[n] for n in nics if n in self._current}

    def get_live_series(self, nics: Sequence[str], *, last_seconds: int) -> Dict[str, List[RatePoint]]:
        last_seconds = int(last_seconds)
        out: Dict[str, List[RatePoint]] = {}
        with self._lock:
            for nic in nics:
                series = self._series.get(nic)
                if not series:
                    continue
                if series:
                    cutoff = series[-1].ts - last_seconds
                else:
                    cutoff = 0
                out[nic] = [p for p in series if p.ts >= cutoff]
        return out

