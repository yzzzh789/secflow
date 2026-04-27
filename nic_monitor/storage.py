from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class TrafficRow:
    ts: int  # epoch seconds (UTC)
    nic: str
    rx_bps: int  # bytes/sec
    tx_bps: int  # bytes/sec


class SQLiteStorage:
    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        self._closed = False
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA busy_timeout=5000;")
        self._init_schema()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._conn.commit()
            self._conn.close()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError(f"SQLiteStorage is closed: {self._db_path}")

    def _init_schema(self) -> None:
        with self._lock:
            self._ensure_open()
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic (
                    ts INTEGER NOT NULL,
                    nic TEXT NOT NULL,
                    rx_bps INTEGER NOT NULL,
                    tx_bps INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_traffic_nic_ts ON traffic(nic, ts)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(ts)"
            )
            self._conn.commit()

    def insert_many(self, rows: Sequence[TrafficRow]) -> None:
        if not rows:
            return
        with self._lock:
            self._ensure_open()
            self._conn.executemany(
                "INSERT INTO traffic(ts, nic, rx_bps, tx_bps) VALUES(?,?,?,?)",
                [(r.ts, r.nic, r.rx_bps, r.tx_bps) for r in rows],
            )
            self._conn.commit()

    def query_range(
        self,
        *,
        nics: Sequence[str],
        ts_start: int,
        ts_end: int,
    ) -> List[TrafficRow]:
        if not nics:
            return []
        placeholders = ",".join(["?"] * len(nics))
        sql = (
            "SELECT ts, nic, rx_bps, tx_bps FROM traffic "
            f"WHERE nic IN ({placeholders}) AND ts BETWEEN ? AND ? "
            "ORDER BY ts ASC"
        )
        params: Tuple[object, ...] = tuple(nics) + (ts_start, ts_end)
        with self._lock:
            self._ensure_open()
            cur = self._conn.execute(sql, params)
            out = [TrafficRow(int(ts), str(nic), int(rx), int(tx)) for ts, nic, rx, tx in cur.fetchall()]
        return out

    def query_latest_ts(self) -> Optional[int]:
        with self._lock:
            self._ensure_open()
            cur = self._conn.execute("SELECT MAX(ts) FROM traffic")
            (v,) = cur.fetchone()
        return int(v) if v is not None else None
