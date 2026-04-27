#!/usr/bin/env python3
"""
Lightweight NIC traffic monitor with dynamic thresholds.
"""
import argparse
import io
import json
import math
import statistics
import sys
import time
from collections import deque

import psutil

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def bps_to_mbps(value):
    return value / 1024 / 1024 / 8


def percentile(values, pct):
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


class SimpleTrafficMonitor:
    def __init__(
        self,
        nic_name,
        warning_mbps=100,
        critical_mbps=200,
        interval=1.0,
        baseline_seconds=300,
        warmup_seconds=60,
        min_baseline_samples=30,
        warning_multiplier=1.3,
        critical_multiplier=1.8,
        warning_mad_factor=3.0,
        critical_mad_factor=5.0,
        warning_sustain_seconds=10,
        critical_sustain_seconds=5,
        recovery_seconds=15,
        cooldown_seconds=60,
        recovery_ratio=0.8,
    ):
        self.nic_name = nic_name
        self.interval = max(interval, 0.1)

        self.fixed_warning_bps = warning_mbps * 1024 * 1024 * 8
        self.fixed_critical_bps = critical_mbps * 1024 * 1024 * 8

        self.baseline_seconds = baseline_seconds
        self.warmup_seconds = warmup_seconds
        self.min_baseline_samples = min_baseline_samples
        self.warning_multiplier = warning_multiplier
        self.critical_multiplier = critical_multiplier
        self.warning_mad_factor = warning_mad_factor
        self.critical_mad_factor = critical_mad_factor
        self.warning_sustain_seconds = warning_sustain_seconds
        self.critical_sustain_seconds = critical_sustain_seconds
        self.recovery_seconds = recovery_seconds
        self.cooldown_seconds = cooldown_seconds
        self.recovery_ratio = recovery_ratio

        self.last_stats = None
        self.last_time = None
        self.start_time = None
        self.total_bps_window = deque(
            maxlen=max(self.min_baseline_samples, int(self.baseline_seconds / self.interval))
        )

        self.warning_sustain_samples = self.seconds_to_samples(self.warning_sustain_seconds)
        self.critical_sustain_samples = self.seconds_to_samples(self.critical_sustain_seconds)
        self.recovery_samples = self.seconds_to_samples(self.recovery_seconds)

        self.warning_streak = 0
        self.critical_streak = 0
        self.recovery_streak = 0
        self.active_level = None
        self.last_alert_at = {"warning": 0, "critical": 0}
        self.first_warning_sent = False

    def seconds_to_samples(self, seconds):
        return max(1, int(math.ceil(seconds / self.interval)))

    def samples_to_seconds(self, samples):
        return int(round(samples * self.interval))

    def get_nic_stats(self):
        stats = psutil.net_io_counters(pernic=True)
        return stats.get(self.nic_name)

    def calculate_rate(self):
        current_stats = self.get_nic_stats()
        current_time = time.time()

        if current_stats is None:
            return None

        if self.last_stats is None:
            self.last_stats = current_stats
            self.last_time = current_time
            return None

        time_delta = current_time - self.last_time
        if time_delta <= 0:
            return None

        rx_bps = (current_stats.bytes_recv - self.last_stats.bytes_recv) * 8 / time_delta
        tx_bps = (current_stats.bytes_sent - self.last_stats.bytes_sent) * 8 / time_delta

        self.last_stats = current_stats
        self.last_time = current_time

        return {
            "rx_bps": max(0, rx_bps),
            "tx_bps": max(0, tx_bps),
            "total_bps": max(0, rx_bps + tx_bps),
        }

    def build_baseline(self):
        if len(self.total_bps_window) < self.min_baseline_samples:
            return None

        values = list(self.total_bps_window)
        median_bps = float(statistics.median(values))
        deviations = [abs(value - median_bps) for value in values]
        mad_bps = float(statistics.median(deviations)) if deviations else 0.0
        p95_bps = percentile(values, 95)

        warning_dynamic = max(
            self.fixed_warning_bps,
            p95_bps * self.warning_multiplier,
            median_bps + self.warning_mad_factor * mad_bps,
        )
        critical_dynamic = max(
            self.fixed_critical_bps,
            p95_bps * self.critical_multiplier,
            median_bps + self.critical_mad_factor * mad_bps,
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

    def get_threshold_context(self):
        now = time.time()
        elapsed = 0 if self.start_time is None else max(0, now - self.start_time)
        baseline = self.build_baseline()
        is_warmup = elapsed < self.warmup_seconds or baseline is None

        if baseline is None:
            warning_bps = self.fixed_warning_bps
            critical_bps = self.fixed_critical_bps
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
            "warmup_remaining_s": max(0, int(math.ceil(self.warmup_seconds - elapsed))),
            "alerting_mode": "fixed_critical_only" if is_warmup else "dynamic",
            "warning_bps": warning_bps,
            "critical_bps": critical_bps,
            "warning_mbps": bps_to_mbps(warning_bps),
            "critical_mbps": bps_to_mbps(critical_bps),
            "fixed_warning_mbps": bps_to_mbps(self.fixed_warning_bps),
            "fixed_critical_mbps": bps_to_mbps(self.fixed_critical_bps),
            "baseline": baseline_payload,
        }

    def should_emit(self, level, timestamp):
        if timestamp - self.last_alert_at[level] < self.cooldown_seconds:
            return False

        self.last_alert_at[level] = timestamp
        return True

    def build_trigger_alert(self, level, total_bps, context, duration_s):
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
            "type": "alert",
            "message": reason,
            "timestamp": int(time.time()),
            "data": {
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
            },
        }

    def build_first_warning_alert(self, total_bps):
        current_mbps = bps_to_mbps(total_bps)
        message = (
            f"traffic crossed the initial warning floor of "
            f"{bps_to_mbps(self.fixed_warning_bps):.2f} MB/s, current {current_mbps:.2f} MB/s"
        )
        return {
            "type": "alert",
            "message": message,
            "timestamp": int(time.time()),
            "data": {
                "level": "warning",
                "state": "first_warning",
                "message": message,
                "nic": self.nic_name,
                "current_mbps": current_mbps,
                "threshold_mbps": bps_to_mbps(self.fixed_warning_bps),
            },
        }

    def build_recovery_alert(self, context):
        recovery_duration_s = self.samples_to_seconds(self.recovery_streak)
        message = (
            f"traffic recovered after {recovery_duration_s}s below "
            f"{context['warning_mbps'] * self.recovery_ratio:.2f} MB/s"
        )
        previous_level = self.active_level or "warning"
        return {
            "type": "alert",
            "message": message,
            "timestamp": int(time.time()),
            "data": {
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
            },
        }

    def evaluate_alert(self, total_bps):
        context = self.get_threshold_context()
        timestamp = int(time.time())

        if not context["is_warmup"] and not self.first_warning_sent and total_bps >= self.fixed_warning_bps:
            self.first_warning_sent = True
            return self.build_first_warning_alert(total_bps), context

        if context["is_warmup"]:
            warning_trigger_bps = float("inf")
            critical_trigger_bps = self.fixed_critical_bps
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

        recovery_threshold_bps = context["warning_bps"] * self.recovery_ratio
        if self.active_level and total_bps < recovery_threshold_bps:
            self.recovery_streak += 1
        else:
            self.recovery_streak = 0

        if self.active_level == "warning" and self.critical_streak >= self.critical_sustain_samples:
            if self.should_emit("critical", timestamp):
                self.active_level = "critical"
                return (
                    self.build_trigger_alert(
                        "critical",
                        total_bps,
                        context,
                        self.samples_to_seconds(self.critical_streak),
                    ),
                    context,
                )

        if self.active_level is None:
            if self.critical_streak >= self.critical_sustain_samples and self.should_emit("critical", timestamp):
                self.active_level = "critical"
                return (
                    self.build_trigger_alert(
                        "critical",
                        total_bps,
                        context,
                        self.samples_to_seconds(self.critical_streak),
                    ),
                    context,
                )

            if self.warning_streak >= self.warning_sustain_samples and self.should_emit("warning", timestamp):
                self.active_level = "warning"
                return (
                    self.build_trigger_alert(
                        "warning",
                        total_bps,
                        context,
                        self.samples_to_seconds(self.warning_streak),
                    ),
                    context,
                )

        if self.active_level and self.recovery_streak >= self.recovery_samples:
            alert = self.build_recovery_alert(context)
            self.active_level = None
            self.warning_streak = 0
            self.critical_streak = 0
            self.recovery_streak = 0
            return alert, context

        return None, context

    def build_realtime_output(self, rate, context):
        now = int(time.time())
        total_mbps = bps_to_mbps(rate["total_bps"])
        return {
            "type": "realtime_data",
            "message": "realtime data",
            "timestamp": now,
            "data": {
                self.nic_name: {
                    "timestamp": now,
                    "rx_bps": rate["rx_bps"],
                    "tx_bps": rate["tx_bps"],
                    "total_bps": rate["total_bps"],
                    "rx_mbps": bps_to_mbps(rate["rx_bps"]),
                    "tx_mbps": bps_to_mbps(rate["tx_bps"]),
                    "total_mbps": total_mbps,
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
            },
        }

    def run(self):
        self.start_time = time.time()
        print(
            json.dumps(
                {
                    "type": "info",
                    "message": f"traffic monitor started for {self.nic_name}",
                    "timestamp": int(time.time()),
                }
            ),
            flush=True,
        )

        try:
            while True:
                rate = self.calculate_rate()

                if rate:
                    alert, context = self.evaluate_alert(rate["total_bps"])
                    print(json.dumps(self.build_realtime_output(rate, context), ensure_ascii=False), flush=True)

                    if alert:
                        print(json.dumps(alert, ensure_ascii=False), flush=True)

                    self.total_bps_window.append(rate["total_bps"])

                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(
                json.dumps(
                    {
                        "type": "info",
                        "message": "traffic monitor stopped",
                        "timestamp": int(time.time()),
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight traffic monitor")
    parser.add_argument("--nic", required=True, help="NIC name")
    parser.add_argument("--warning-mbps", type=float, default=100, help="fixed warning floor in MB/s")
    parser.add_argument("--critical-mbps", type=float, default=200, help="fixed critical floor in MB/s")
    parser.add_argument("--interval", type=float, default=1.0, help="sampling interval in seconds")
    parser.add_argument("--baseline-seconds", type=int, default=300, help="rolling baseline window in seconds")
    parser.add_argument("--warmup-seconds", type=int, default=60, help="startup warmup duration in seconds")
    parser.add_argument("--min-baseline-samples", type=int, default=30, help="minimum samples before dynamic mode")
    parser.add_argument("--warning-multiplier", type=float, default=1.3, help="P95 multiplier for warning")
    parser.add_argument("--critical-multiplier", type=float, default=1.8, help="P95 multiplier for critical")
    parser.add_argument("--warning-mad-factor", type=float, default=3.0, help="MAD factor for warning")
    parser.add_argument("--critical-mad-factor", type=float, default=5.0, help="MAD factor for critical")
    parser.add_argument("--warning-sustain-seconds", type=int, default=10, help="warning sustain time in seconds")
    parser.add_argument("--critical-sustain-seconds", type=int, default=5, help="critical sustain time in seconds")
    parser.add_argument("--recovery-seconds", type=int, default=15, help="recovery hold time in seconds")
    parser.add_argument("--cooldown-seconds", type=int, default=60, help="minimum seconds between same-level alerts")
    parser.add_argument("--recovery-ratio", type=float, default=0.8, help="recovery threshold ratio")

    args = parser.parse_args()

    monitor = SimpleTrafficMonitor(
        nic_name=args.nic,
        warning_mbps=args.warning_mbps,
        critical_mbps=args.critical_mbps,
        interval=args.interval,
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
    monitor.run()
