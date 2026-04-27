#!/usr/bin/env python3
"""
NIC traffic monitor service for SecFlow.

Keeps the interactive command protocol used by main.go,
with dynamic-baseline thresholding per NIC.
"""

import argparse
import json
import math
import statistics
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple, cast

import psutil

_COMMON_PYTHON_DIR = Path(__file__).resolve().parents[1] / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

from nic_monitor.collector import CollectorConfig, TrafficCollector
from nic_monitor.state import SharedState
from nic_monitor.storage import SQLiteStorage
from nic_monitor.utils import utc_now_epoch_s
from secflow_common.output_messages import build_timed_output_message
from secflow_common.protocol_types import NICMonitorCommand


def bps_to_mbps(value: float) -> float:
    return value / 1024 / 1024


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0

    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])

    rank = (len(ordered) - 1) * pct / 100.0
    lower = math.floor(rank)
    upper = math.ceil(rank)

    if lower == upper:
        return float(ordered[lower])

    weight = rank - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * weight)


@dataclass
class ThresholdConfig:
    warning_bps: int = 10 * 1024 * 1024
    critical_bps: int = 50 * 1024 * 1024
    per_ip_warning_bps: int = 10 * 1024 * 1024
    per_ip_critical_bps: int = 20 * 1024 * 1024
    warning_pps: int = 500
    critical_pps: int = 1000
    sustained_seconds: int = 5
    interval_seconds: float = 1.0
    baseline_seconds: int = 300
    warmup_seconds: int = 60
    min_baseline_samples: int = 30
    warning_multiplier: float = 1.3
    critical_multiplier: float = 1.8
    warning_mad_factor: float = 3.0
    critical_mad_factor: float = 5.0
    warning_sustain_seconds: int = 10
    critical_sustain_seconds: int = 5
    recovery_seconds: int = 15
    cooldown_seconds: int = 60
    recovery_ratio: float = 0.8


class DynamicNICThresholdState:
    def __init__(self, nic_name: str, config: ThresholdConfig):
        self.nic_name = nic_name
        self.config = config
        self.start_time: Optional[int] = None
        self.total_bps_window = deque(
            maxlen=max(
                config.min_baseline_samples,
                int(config.baseline_seconds / max(config.interval_seconds, 0.1)),
            )
        )
        self.warning_sustain_samples = self.seconds_to_samples(config.warning_sustain_seconds)
        self.critical_sustain_samples = self.seconds_to_samples(config.critical_sustain_seconds)
        self.recovery_samples = self.seconds_to_samples(config.recovery_seconds)

        self.warning_streak = 0
        self.critical_streak = 0
        self.recovery_streak = 0
        self.active_level: Optional[str] = None
        self.last_alert_at = {"warning": 0, "critical": 0}
        self.first_warning_sent = False

    def seconds_to_samples(self, seconds: int) -> int:
        return max(1, int(math.ceil(seconds / max(self.config.interval_seconds, 0.1))))

    def samples_to_seconds(self, samples: int) -> int:
        return int(round(samples * self.config.interval_seconds))

    def build_baseline(self) -> Optional[Dict[str, float]]:
        if len(self.total_bps_window) < self.config.min_baseline_samples:
            return None

        values = list(self.total_bps_window)
        median_bps = float(statistics.median(values))
        deviations = [abs(value - median_bps) for value in values]
        mad_bps = float(statistics.median(deviations)) if deviations else 0.0
        p95_bps = percentile(values, 95)

        warning_dynamic = max(
            self.config.warning_bps,
            p95_bps * self.config.warning_multiplier,
            median_bps + self.config.warning_mad_factor * mad_bps,
        )
        critical_dynamic = max(
            self.config.critical_bps,
            p95_bps * self.config.critical_multiplier,
            median_bps + self.config.critical_mad_factor * mad_bps,
        )
        critical_dynamic = max(critical_dynamic, warning_dynamic)

        return {
            "sample_count": len(values),
            "median_bps": median_bps,
            "median_mbps": bps_to_mbps(median_bps),
            "p95_bps": p95_bps,
            "p95_mbps": bps_to_mbps(p95_bps),
            "mad_bps": mad_bps,
            "mad_mbps": bps_to_mbps(mad_bps),
            "warning_bps": warning_dynamic,
            "warning_mbps": bps_to_mbps(warning_dynamic),
            "critical_bps": critical_dynamic,
            "critical_mbps": bps_to_mbps(critical_dynamic),
        }

    def get_threshold_context(self, timestamp: int) -> Dict[str, object]:
        if self.start_time is None:
            self.start_time = timestamp

        elapsed = max(0, timestamp - self.start_time)
        baseline = self.build_baseline()
        is_warmup = elapsed < self.config.warmup_seconds or baseline is None

        if baseline is None:
            warning_bps = self.config.warning_bps
            critical_bps = self.config.critical_bps
            baseline_payload = {
                "sample_count": len(self.total_bps_window),
                "median_mbps": 0.0,
                "p95_mbps": 0.0,
                "mad_mbps": 0.0,
            }
        else:
            warning_bps = baseline["warning_bps"]
            critical_bps = baseline["critical_bps"]
            baseline_payload = {
                "sample_count": baseline["sample_count"],
                "median_mbps": baseline["median_mbps"],
                "p95_mbps": baseline["p95_mbps"],
                "mad_mbps": baseline["mad_mbps"],
            }

        return {
            "is_warmup": is_warmup,
            "warmup_remaining_s": max(0, int(math.ceil(self.config.warmup_seconds - elapsed))),
            "alerting_mode": "fixed_critical_only" if is_warmup else "dynamic",
            "warning_bps": warning_bps,
            "critical_bps": critical_bps,
            "warning_mbps": bps_to_mbps(warning_bps),
            "critical_mbps": bps_to_mbps(critical_bps),
            "fixed_warning_mbps": bps_to_mbps(self.config.warning_bps),
            "fixed_critical_mbps": bps_to_mbps(self.config.critical_bps),
            "baseline": baseline_payload,
        }

    def should_emit(self, level: str, timestamp: int) -> bool:
        if timestamp - self.last_alert_at[level] < self.config.cooldown_seconds:
            return False

        self.last_alert_at[level] = timestamp
        return True

    def build_trigger_alert(self, level: str, total_bps: float, context: Dict[str, object], duration_s: int, timestamp: int) -> Dict[str, object]:
        current_mbps = bps_to_mbps(total_bps)
        if context["is_warmup"]:
            reason = (
                f"warmup fallback critical threshold {context['fixed_critical_mbps']:.2f} MB/s "
                f"exceeded for {duration_s}s"
            )
        else:
            baseline = context["baseline"]
            threshold_key = f"{level}_mbps"
            reason = (
                f"current {current_mbps:.2f} MB/s > dynamic {level} {context[threshold_key]:.2f} MB/s; "
                f"baseline median {baseline['median_mbps']:.2f} MB/s, "
                f"p95 {baseline['p95_mbps']:.2f} MB/s, mad {baseline['mad_mbps']:.2f} MB/s; "
                f"streak {duration_s}s"
            )

        return {
            "level": level,
            "state": "triggered",
            "message": reason,
            "nic": self.nic_name,
            "current_mbps": current_mbps,
            "duration_s": duration_s,
            "thresholds": {
                "warning_mbps": context["warning_mbps"],
                "critical_mbps": context["critical_mbps"],
                "fixed_warning_mbps": context["fixed_warning_mbps"],
                "fixed_critical_mbps": context["fixed_critical_mbps"],
                "alerting_mode": context["alerting_mode"],
            },
            "baseline": context["baseline"],
            "timestamp": timestamp,
        }

    def build_first_warning_alert(self, total_bps: float, timestamp: int) -> Dict[str, object]:
        current_mbps = bps_to_mbps(total_bps)
        message = (
            f"traffic crossed the initial warning floor of "
            f"{bps_to_mbps(self.config.warning_bps):.2f} MB/s, current {current_mbps:.2f} MB/s"
        )
        return {
            "level": "warning",
            "state": "first_warning",
            "message": message,
            "nic": self.nic_name,
            "current_mbps": current_mbps,
            "threshold_mbps": bps_to_mbps(self.config.warning_bps),
            "timestamp": timestamp,
        }

    def build_recovery_alert(self, context: Dict[str, object], timestamp: int) -> Dict[str, object]:
        recovery_duration_s = self.samples_to_seconds(self.recovery_streak)
        message = (
            f"traffic recovered after {recovery_duration_s}s below "
            f"{context['warning_mbps'] * self.config.recovery_ratio:.2f} MB/s"
        )
        previous_level = self.active_level or "warning"
        return {
            "level": "recovery",
            "state": "recovery",
            "message": message,
            "nic": self.nic_name,
            "previous_level": previous_level,
            "thresholds": {
                "warning_mbps": context["warning_mbps"],
                "critical_mbps": context["critical_mbps"],
                "alerting_mode": context["alerting_mode"],
            },
            "baseline": context["baseline"],
            "timestamp": timestamp,
        }

    def evaluate_alert(self, total_bps: float, timestamp: int, context: Dict[str, object]) -> Optional[Dict[str, object]]:
        if not context["is_warmup"] and not self.first_warning_sent and total_bps >= self.config.warning_bps:
            self.first_warning_sent = True
            return self.build_first_warning_alert(total_bps, timestamp)

        if context["is_warmup"]:
            warning_trigger_bps = float("inf")
            critical_trigger_bps = self.config.critical_bps
        else:
            warning_trigger_bps = context["warning_bps"]
            critical_trigger_bps = context["critical_bps"]

        if total_bps >= critical_trigger_bps:
            self.critical_streak += 1
        else:
            self.critical_streak = 0

        if total_bps >= warning_trigger_bps:
            self.warning_streak += 1
        else:
            self.warning_streak = 0

        recovery_threshold_bps = context["warning_bps"] * self.config.recovery_ratio
        if self.active_level and total_bps < recovery_threshold_bps:
            self.recovery_streak += 1
        else:
            self.recovery_streak = 0

        if self.active_level == "warning" and self.critical_streak >= self.critical_sustain_samples:
            if self.should_emit("critical", timestamp):
                self.active_level = "critical"
                return self.build_trigger_alert(
                    "critical",
                    total_bps,
                    context,
                    self.samples_to_seconds(self.critical_streak),
                    timestamp,
                )

        if self.active_level is None:
            if self.critical_streak >= self.critical_sustain_samples and self.should_emit("critical", timestamp):
                self.active_level = "critical"
                return self.build_trigger_alert(
                    "critical",
                    total_bps,
                    context,
                    self.samples_to_seconds(self.critical_streak),
                    timestamp,
                )

            if self.warning_streak >= self.warning_sustain_samples and self.should_emit("warning", timestamp):
                self.active_level = "warning"
                return self.build_trigger_alert(
                    "warning",
                    total_bps,
                    context,
                    self.samples_to_seconds(self.warning_streak),
                    timestamp,
                )

        if self.active_level and self.recovery_streak >= self.recovery_samples:
            alert = self.build_recovery_alert(context, timestamp)
            self.active_level = None
            self.warning_streak = 0
            self.critical_streak = 0
            self.recovery_streak = 0
            return alert

        return None

    def build_metric(self, rx_bps: float, tx_bps: float, timestamp: int) -> Tuple[Dict[str, object], Optional[Dict[str, object]]]:
        total_bps = max(0.0, rx_bps + tx_bps)
        context = self.get_threshold_context(timestamp)
        alert = self.evaluate_alert(total_bps, timestamp, context)

        metric = {
            "timestamp": timestamp,
            "rx_bps": rx_bps,
            "tx_bps": tx_bps,
            "total_bps": total_bps,
            "rx_mbps": bps_to_mbps(rx_bps),
            "tx_mbps": bps_to_mbps(tx_bps),
            "total_mbps": bps_to_mbps(total_bps),
            "thresholds": {
                "warning_mbps": context["warning_mbps"],
                "critical_mbps": context["critical_mbps"],
                "fixed_warning_mbps": context["fixed_warning_mbps"],
                "fixed_critical_mbps": context["fixed_critical_mbps"],
                "alerting_mode": context["alerting_mode"],
                "warmup_remaining_s": context["warmup_remaining_s"],
            },
            "baseline": context["baseline"],
            "alert_state": {
                "level": self.active_level or "normal",
                "warning_streak_s": self.samples_to_seconds(self.warning_streak),
                "critical_streak_s": self.samples_to_seconds(self.critical_streak),
                "recovery_streak_s": self.samples_to_seconds(self.recovery_streak),
            },
        }

        self.total_bps_window.append(total_bps)
        return metric, alert


class NICMonitorServer:
    def __init__(self, db_path: str = "data/nic_traffic.sqlite", threshold_config: Optional[ThresholdConfig] = None):
        self.db_path = Path(db_path)
        self.storage = SQLiteStorage(self.db_path)
        self.threshold_config = threshold_config or ThresholdConfig()
        self.running = False
        self.trackers: Dict[str, DynamicNICThresholdState] = {}
        self._reset_runtime_state()

    def _reset_runtime_state(self) -> None:
        self.trackers = {}
        self.live_metric_history: Dict[str, Deque[Dict[str, object]]] = defaultdict(
            lambda: deque(maxlen=3600)
        )
        self.history_cache: Dict[Tuple[str, int, int, int, int], List[Dict[str, object]]] = {}
        self.history_cache_order: Deque[Tuple[str, int, int, int, int]] = deque()
        self.history_cache_limit = 128
        self.state = SharedState(live_keep_seconds=3600)
        self.collector = TrafficCollector(
            storage=self.storage,
            state=self.state,
            config=CollectorConfig(interval_s=self.threshold_config.interval_seconds),
        )

    def _store_history_cache(
        self,
        cache_key: Tuple[str, int, int, int, int],
        result: List[Dict[str, object]],
    ) -> None:
        if cache_key in self.history_cache:
            self.history_cache[cache_key] = result
            return

        self.history_cache[cache_key] = result
        self.history_cache_order.append(cache_key)
        while len(self.history_cache_order) > self.history_cache_limit:
            stale_key = self.history_cache_order.popleft()
            self.history_cache.pop(stale_key, None)

    def _bootstrap_tracker(self, nic: str, before_ts: Optional[int] = None) -> DynamicNICThresholdState:
        tracker = DynamicNICThresholdState(nic, self.threshold_config)
        lookback = self.threshold_config.baseline_seconds + self.threshold_config.warmup_seconds
        history = self.state.get_live_series([nic], last_seconds=lookback).get(nic, [])
        for point in history:
            if before_ts is not None and point.ts >= before_ts:
                break
            tracker.build_metric(point.rx_bps, point.tx_bps, point.ts)
        return tracker

    def get_tracker(self, nic: str, before_ts: Optional[int] = None) -> DynamicNICThresholdState:
        if nic not in self.trackers:
            self.trackers[nic] = self._bootstrap_tracker(nic, before_ts=before_ts)
        return self.trackers[nic]

    def start_collector(self) -> None:
        if not self.running:
            self._reset_runtime_state()
            self.collector.start()
            self.running = True
            self._send_message("info", "traffic collection started")

    def stop_collector(self) -> None:
        if self.running:
            self.collector.stop()
            self.running = False
            self._reset_runtime_state()
            self._send_message("info", "traffic collection stopped")

    def get_available_nics(self) -> List[Dict[str, object]]:
        nics = []
        stats = psutil.net_io_counters(pernic=True)
        for name, io in stats.items():
            nics.append(
                {
                    "name": name,
                    "bytes_sent": io.bytes_sent,
                    "bytes_recv": io.bytes_recv,
                    "packets_sent": io.packets_sent,
                    "packets_recv": io.packets_recv,
                }
            )
        return nics

    def get_realtime_data(self, nics: List[str]) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
        current = self.state.get_current(nics)
        data: Dict[str, object] = {}
        alerts: List[Dict[str, object]] = []

        for nic, point in current.items():
            metric, alert = self.get_tracker(nic, before_ts=point.ts).build_metric(point.rx_bps, point.tx_bps, point.ts)
            data[nic] = metric
            history = self.live_metric_history[nic]
            if not history or history[-1]["timestamp"] != metric["timestamp"]:
                history.append(metric)
            if alert:
                alerts.append(alert)

        return data, alerts

    def get_live_series(self, nics: List[str], seconds: int = 600) -> Dict[str, object]:
        data = {}
        replay_lookback = seconds + self.threshold_config.baseline_seconds + self.threshold_config.warmup_seconds
        series = self.state.get_live_series(nics, last_seconds=replay_lookback)
        for nic, points in series.items():
            if not points:
                continue

            requested_cutoff = points[-1].ts - seconds
            recent_points = [point for point in points if point.ts >= requested_cutoff]
            cached = [
                metric
                for metric in self.live_metric_history.get(nic, [])
                if metric["timestamp"] >= requested_cutoff
            ]
            if len(cached) >= len(recent_points):
                data[nic] = [
                    {
                        "ts": metric["timestamp"],
                        "rx_bps": metric["rx_bps"],
                        "tx_bps": metric["tx_bps"],
                        "total_bps": metric["total_bps"],
                        "thresholds": metric["thresholds"],
                        "baseline": metric["baseline"],
                        "alert_state": metric["alert_state"],
                    }
                    for metric in cached
                ]
                continue

            replay_tracker = DynamicNICThresholdState(nic, self.threshold_config)
            data[nic] = []
            for point in points:
                metric, _ = replay_tracker.build_metric(point.rx_bps, point.tx_bps, point.ts)
                if point.ts < requested_cutoff:
                    continue
                data[nic].append(
                    {
                        "ts": point.ts,
                        "rx_bps": point.rx_bps,
                        "tx_bps": point.tx_bps,
                        "total_bps": point.rx_bps + point.tx_bps,
                        "thresholds": metric["thresholds"],
                        "baseline": metric["baseline"],
                        "alert_state": metric["alert_state"],
                    }
                )
        return data

    def get_history_data(self, nics: List[str], start_ts: int, end_ts: int) -> Dict[str, object]:
        replay_lookback = self.threshold_config.baseline_seconds + self.threshold_config.warmup_seconds
        replay_start_ts = max(0, start_ts - replay_lookback)
        rows = self.storage.query_range(nics=nics, ts_start=replay_start_ts, ts_end=end_ts)
        data = {nic: [] for nic in nics}
        rows_by_nic = defaultdict(list)
        for row in rows:
            rows_by_nic[row.nic].append(row)

        for nic in nics:
            replay_tracker = DynamicNICThresholdState(nic, self.threshold_config)
            nic_rows = rows_by_nic.get(nic, [])
            cache_key = (
                nic,
                start_ts,
                end_ts,
                len(nic_rows),
                nic_rows[-1].ts if nic_rows else 0,
            )
            cached = self.history_cache.get(cache_key)
            if cached is not None:
                data[nic] = cached
                continue

            result: List[Dict[str, object]] = []
            for row in nic_rows:
                metric, _ = replay_tracker.build_metric(row.rx_bps, row.tx_bps, row.ts)
                if row.ts < start_ts:
                    continue
                result.append(
                    {
                        "ts": row.ts,
                        "rx_bps": row.rx_bps,
                        "tx_bps": row.tx_bps,
                        "total_bps": row.rx_bps + row.tx_bps,
                        "thresholds": metric["thresholds"],
                        "baseline": metric["baseline"],
                        "alert_state": metric["alert_state"],
                    }
                )
            self._store_history_cache(cache_key, result)
            data[nic] = result
        return data

    def get_statistics(self, nics: List[str], start_ts: int, end_ts: int) -> Dict[str, object]:
        rows = self.storage.query_range(nics=nics, ts_start=start_ts, ts_end=end_ts)
        stats = {}
        rows_by_nic = defaultdict(list)
        current_ts = int(time.time())

        for row in rows:
            rows_by_nic[row.nic].append(row)

        for nic in nics:
            nic_rows = rows_by_nic.get(nic, [])
            if not nic_rows:
                continue

            rx_values = [r.rx_bps for r in nic_rows]
            tx_values = [r.tx_bps for r in nic_rows]
            total_values = [r.rx_bps + r.tx_bps for r in nic_rows]
            tracker = self.get_tracker(nic, before_ts=current_ts)
            threshold_context = tracker.get_threshold_context(current_ts)

            stats[nic] = {
                "rx": {
                    "max": max(rx_values) if rx_values else 0,
                    "min": min(rx_values) if rx_values else 0,
                    "avg": sum(rx_values) / len(rx_values) if rx_values else 0,
                    "max_mbps": bps_to_mbps(max(rx_values)) if rx_values else 0,
                    "avg_mbps": bps_to_mbps(sum(rx_values) / len(rx_values)) if rx_values else 0,
                },
                "tx": {
                    "max": max(tx_values) if tx_values else 0,
                    "min": min(tx_values) if tx_values else 0,
                    "avg": sum(tx_values) / len(tx_values) if tx_values else 0,
                    "max_mbps": bps_to_mbps(max(tx_values)) if tx_values else 0,
                    "avg_mbps": bps_to_mbps(sum(tx_values) / len(tx_values)) if tx_values else 0,
                },
                "total": {
                    "max": max(total_values) if total_values else 0,
                    "min": min(total_values) if total_values else 0,
                    "avg": sum(total_values) / len(total_values) if total_values else 0,
                    "max_mbps": bps_to_mbps(max(total_values)) if total_values else 0,
                    "avg_mbps": bps_to_mbps(sum(total_values) / len(total_values)) if total_values else 0,
                },
                "sample_count": len(nic_rows),
                "thresholds": {
                    "warning_mbps": threshold_context["warning_mbps"],
                    "critical_mbps": threshold_context["critical_mbps"],
                    "fixed_warning_mbps": threshold_context["fixed_warning_mbps"],
                    "fixed_critical_mbps": threshold_context["fixed_critical_mbps"],
                    "alerting_mode": threshold_context["alerting_mode"],
                },
                "baseline": threshold_context["baseline"],
            }

        return stats

    def _send_message(self, msg_type: str, message: str, data: Optional[Dict[str, object]] = None) -> None:
        output = build_timed_output_message(msg_type, message, utc_now_epoch_s(), data)
        print(json.dumps(output, ensure_ascii=False), flush=True)

    def emit_alerts(self, alerts: List[Dict[str, object]]) -> None:
        for alert in alerts:
            self._send_message("alert", alert.get("message", "traffic alert"), alert)

    def run_realtime_mode(self, nics: List[str], interval: float = 1.0) -> None:
        self.start_collector()
        try:
            while True:
                data, alerts = self.get_realtime_data(nics)
                self.emit_alerts(alerts)
                self._send_message("realtime_data", "realtime data", data)
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stop_collector()

    def handle_command(self, command: NICMonitorCommand) -> None:
        action = command.get("action")

        if action == "list_nics":
            self._send_message("nic_list", "NIC list", {"nics": self.get_available_nics()})
            return

        if action == "start":
            self.start_collector()
            return

        if action == "stop":
            self.stop_collector()
            return

        if action == "realtime":
            nics = command.get("nics", [])
            data, alerts = self.get_realtime_data(nics)
            self.emit_alerts(alerts)
            self._send_message("realtime_data", "realtime data", data)
            return

        if action == "live_series":
            nics = command.get("nics", [])
            seconds = int(command.get("seconds", 600))
            self._send_message("live_series", "live series", self.get_live_series(nics, seconds))
            return

        if action == "history":
            nics = command.get("nics", [])
            start_ts = int(command.get("start_ts", 0))
            end_ts = int(command.get("end_ts", utc_now_epoch_s()))
            self._send_message("history_data", "history data", self.get_history_data(nics, start_ts, end_ts))
            return

        if action == "statistics":
            nics = command.get("nics", [])
            start_ts = int(command.get("start_ts", 0))
            end_ts = int(command.get("end_ts", utc_now_epoch_s()))
            self._send_message("statistics", "statistics", self.get_statistics(nics, start_ts, end_ts))
            return

        if action == "get_thresholds":
            thresholds = {
                "warning_mbps": bps_to_mbps(self.threshold_config.warning_bps),
                "critical_mbps": bps_to_mbps(self.threshold_config.critical_bps),
                "per_ip_warning_mbps": bps_to_mbps(self.threshold_config.per_ip_warning_bps),
                "per_ip_critical_mbps": bps_to_mbps(self.threshold_config.per_ip_critical_bps),
                "warning_pps": self.threshold_config.warning_pps,
                "critical_pps": self.threshold_config.critical_pps,
                "sustained_seconds": self.threshold_config.sustained_seconds,
                "baseline_seconds": self.threshold_config.baseline_seconds,
                "warmup_seconds": self.threshold_config.warmup_seconds,
                "min_baseline_samples": self.threshold_config.min_baseline_samples,
            }
            self._send_message("thresholds", "threshold config", thresholds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Enhanced NIC traffic monitor service")
    parser.add_argument("--db", default="data/nic_traffic.sqlite", help="SQLite database path")
    parser.add_argument(
        "--mode",
        choices=["realtime", "interactive"],
        default="interactive",
        help="runtime mode",
    )
    parser.add_argument("--nics", nargs="+", help="NIC names")
    parser.add_argument("--interval", type=float, default=1.0, help="sampling interval in seconds")
    parser.add_argument("--warning-mbps", type=float, default=10, help="fixed warning floor in MB/s")
    parser.add_argument("--critical-mbps", type=float, default=50, help="fixed critical floor in MB/s")
    parser.add_argument("--sustained-seconds", type=int, default=5, help="minimum sustained time before alert")
    parser.add_argument("--baseline-seconds", type=int, default=300, help="rolling baseline window in seconds")
    parser.add_argument("--warmup-seconds", type=int, default=60, help="startup warmup in seconds")
    parser.add_argument("--min-baseline-samples", type=int, default=30, help="minimum samples before dynamic mode")
    parser.add_argument("--warning-multiplier", type=float, default=1.3, help="P95 multiplier for warning")
    parser.add_argument("--critical-multiplier", type=float, default=1.8, help="P95 multiplier for critical")
    parser.add_argument("--warning-mad-factor", type=float, default=3.0, help="MAD factor for warning")
    parser.add_argument("--critical-mad-factor", type=float, default=5.0, help="MAD factor for critical")
    parser.add_argument("--warning-sustain-seconds", type=int, default=10, help="warning hold time in seconds")
    parser.add_argument("--critical-sustain-seconds", type=int, default=5, help="critical hold time in seconds")
    parser.add_argument("--recovery-seconds", type=int, default=15, help="recovery hold time in seconds")
    parser.add_argument("--cooldown-seconds", type=int, default=60, help="minimum seconds between same-level alerts")
    parser.add_argument("--recovery-ratio", type=float, default=0.8, help="recovery threshold ratio")

    args = parser.parse_args()

    threshold_config = ThresholdConfig(
        warning_bps=int(args.warning_mbps * 1024 * 1024),
        critical_bps=int(args.critical_mbps * 1024 * 1024),
        sustained_seconds=args.sustained_seconds,
        interval_seconds=args.interval,
        baseline_seconds=args.baseline_seconds,
        warmup_seconds=args.warmup_seconds,
        min_baseline_samples=args.min_baseline_samples,
        warning_multiplier=args.warning_multiplier,
        critical_multiplier=args.critical_multiplier,
        warning_mad_factor=args.warning_mad_factor,
        critical_mad_factor=args.critical_mad_factor,
        warning_sustain_seconds=args.warning_sustain_seconds,
        critical_sustain_seconds=args.critical_sustain_seconds,
        recovery_seconds=args.recovery_seconds,
        cooldown_seconds=args.cooldown_seconds,
        recovery_ratio=args.recovery_ratio,
    )

    server = NICMonitorServer(db_path=args.db, threshold_config=threshold_config)

    if args.mode == "realtime":
        nics = args.nics or []
        if not nics:
            nics = [n["name"] for n in server.get_available_nics()]
        server.run_realtime_mode(nics, args.interval)
        return

    server.start_collector()
    server._send_message(
        "info",
        (
            f"service started, warning={args.warning_mbps} MB/s, "
            f"critical={args.critical_mbps} MB/s, dynamic baseline enabled"
        ),
    )

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                command = cast(NICMonitorCommand, json.loads(line))
                server.handle_command(command)
            except json.JSONDecodeError as exc:
                server._send_message("error", f"JSON decode error: {exc}")
            except Exception as exc:  # pragma: no cover
                server._send_message("error", f"command handling failed: {exc}")
    except KeyboardInterrupt:
        pass
    finally:
        server.stop_collector()


if __name__ == "__main__":
    main()
