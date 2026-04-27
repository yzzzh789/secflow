from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil

from .state import RatePoint, SharedState
from .storage import SQLiteStorage, TrafficRow
from .utils import clamp_non_negative, utc_now_epoch_s


@dataclass(frozen=True)
class CollectorConfig:
    interval_s: float = 1.0


class TrafficCollector:
    def __init__(
        self,
        *,
        storage: SQLiteStorage,
        state: SharedState,
        config: CollectorConfig = CollectorConfig(),
    ) -> None:
        self._storage = storage
        self._state = state
        self._config = config
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_counters: Dict[str, psutil._common.snetio] = {}
        self._last_mono: Optional[float] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="TrafficCollector", daemon=True)
        self._thread.start()

    def stop(self, *, join_timeout_s: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=join_timeout_s)

    def _run(self) -> None:
        interval = float(self._config.interval_s)
        self._last_mono = time.monotonic() - interval
        self._last_counters = psutil.net_io_counters(pernic=True)

        while not self._stop.is_set():
            tick_start = time.monotonic()
            now_mono = tick_start
            last_mono = self._last_mono or (now_mono - interval)
            elapsed = max(0.001, now_mono - last_mono)
            self._last_mono = now_mono

            current = psutil.net_io_counters(pernic=True)
            ts = utc_now_epoch_s()

            rows: List[TrafficRow] = []
            for nic, io in current.items():
                prev = self._last_counters.get(nic)
                if prev is None:
                    continue

                rx_delta = clamp_non_negative(float(io.bytes_recv - prev.bytes_recv))
                tx_delta = clamp_non_negative(float(io.bytes_sent - prev.bytes_sent))
                rx_bps = int(rx_delta / elapsed)
                tx_bps = int(tx_delta / elapsed)

                point = RatePoint(ts=ts, rx_bps=float(rx_bps), tx_bps=float(tx_bps))
                self._state.update(nic, point)
                rows.append(TrafficRow(ts=ts, nic=nic, rx_bps=rx_bps, tx_bps=tx_bps))

            self._last_counters = current
            self._storage.insert_many(rows)

            spent = time.monotonic() - tick_start
            sleep_s = max(0.0, interval - spent)
            self._stop.wait(timeout=sleep_s)

