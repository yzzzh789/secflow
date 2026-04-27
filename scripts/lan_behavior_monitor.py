from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import sys
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _set_default_dir_env(name: str, path: Path, fallback: Path | None = None) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        if fallback is None:
            print(f"[lan_behavior_monitor] failed to prepare {name} directory {path}: {exc}", file=sys.stderr, flush=True)
            return
        try:
            fallback.mkdir(parents=True, exist_ok=True)
        except OSError as fallback_exc:
            print(
                f"[lan_behavior_monitor] failed to prepare {name} directories {path} and {fallback}: {exc}; {fallback_exc}",
                file=sys.stderr,
                flush=True,
            )
            return
        path = fallback
    os.environ.setdefault(name, str(path))


_RUNTIME_CONFIG_DIR = _PROJECT_ROOT / ".runtime" / "xdg"
_set_default_dir_env("XDG_CONFIG_HOME", _RUNTIME_CONFIG_DIR)

_SCAPY_CONFIG_DIR = _RUNTIME_CONFIG_DIR / "scapy"
_SCAPY_FALLBACK_CONFIG_DIR = Path(tempfile.gettempdir()) / "secflow-scapy" / "scapy"
_set_default_dir_env("SCAPY_CONFIG_FOLDER", _SCAPY_CONFIG_DIR, _SCAPY_FALLBACK_CONFIG_DIR)

_COMMON_PYTHON_DIR = _PROJECT_ROOT / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

from secflow_common.classification import LAN_MALICIOUS_KEYWORDS, LANWebsiteClassifier
from secflow_common.domains import extract_domain_from_tcp_payload, normalize_domain
from secflow_common.formatting import format_bytes, format_duration
from secflow_common.output_messages import (
    build_behavior_report_message,
    build_error_output_message,
    build_security_alert_message,
    build_status_output_message,
)

scapy = None
DNS = None
DNSQR = None
DNSRR = None
IP = None
TCP = None
Raw = None

WebsiteClassifier = LANWebsiteClassifier

IGNORED_DOMAIN_SUFFIXES = (".arpa", ".local")
RISK_EVENT_LEVELS = {"high", "critical"}
IPV4_ADDRESS_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")


def debug(message: str) -> None:
    print(f"[lan_behavior_monitor] {message}", file=sys.stderr, flush=True)


def ensure_packet_dependencies() -> None:
    global scapy, DNS, DNSQR, DNSRR, IP, TCP, Raw
    if scapy is not None:
        return

    import scapy.all as scapy_module
    from scapy.layers.dns import DNS as dns_layer
    from scapy.layers.dns import DNSQR as dns_query_layer
    from scapy.layers.dns import DNSRR as dns_answer_layer
    from scapy.layers.inet import IP as ip_layer
    from scapy.layers.inet import TCP as tcp_layer
    from scapy.packet import Raw as raw_layer

    scapy = scapy_module
    DNS = dns_layer
    DNSQR = dns_query_layer
    DNSRR = dns_answer_layer
    IP = ip_layer
    TCP = tcp_layer
    Raw = raw_layer


@lru_cache(maxsize=8192)
def is_lan_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class IPBehaviorTracker:
    def __init__(self, ip_address: str) -> None:
        now = time.time()
        self.ip = ip_address
        self.first_seen = now
        self.last_seen = now
        self.domains: dict[str, dict[str, Any]] = defaultdict(self._new_domain_info)
        self.total_requests = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.category_stats: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0, "bytes": 0})
        self.risk_events: list[dict[str, Any]] = []

    @staticmethod
    def _new_domain_info() -> dict[str, Any]:
        return {
            "count": 0,
            "first_seen": 0.0,
            "last_seen": 0.0,
            "category": "unknown",
            "label": "unknown",
            "risk": "low",
            "bytes_sent": 0,
            "bytes_received": 0,
        }

    def add_domain_access(
        self,
        domain: str,
        classification: dict[str, str],
        packet_size: int,
        direction: str,
        timestamp: float | None = None,
    ) -> None:
        now = timestamp or time.time()
        self.last_seen = now
        self.total_requests += 1

        info = self.domains[domain]
        if info["count"] == 0:
            info["first_seen"] = now
            info["category"] = classification["category"]
            info["label"] = classification["label"]
            info["risk"] = classification["risk"]

        info["count"] += 1
        info["last_seen"] = now
        if direction == "out":
            info["bytes_sent"] += packet_size
            self.total_bytes_sent += packet_size
        else:
            info["bytes_received"] += packet_size
            self.total_bytes_received += packet_size

        category = classification["category"]
        self.category_stats[category]["count"] += 1
        self.category_stats[category]["bytes"] += packet_size

        if classification["risk"] in RISK_EVENT_LEVELS:
            event = {
                "time": now,
                "domain": domain,
                "category": classification["label"],
                "risk": classification["risk"],
            }
            if not self.risk_events or self.risk_events[-1]["domain"] != domain or now - self.risk_events[-1]["time"] > 30:
                self.risk_events.append(event)
                self.risk_events = self.risk_events[-20:]

    def _calculate_risk_score(self) -> int:
        high_risk_count = sum(info["count"] for info in self.domains.values() if info["risk"] in RISK_EVENT_LEVELS)
        entertainment_count = (
            self.category_stats["video"]["count"]
            + self.category_stats["game"]["count"]
            + self.category_stats["social"]["count"]
        )
        entertainment_ratio = entertainment_count / max(self.total_requests, 1)
        score = min(high_risk_count * 4, 45)
        score += int(entertainment_ratio * 30)
        if self.category_stats["stock"]["count"] > 0:
            score += 15
        if any(info["risk"] == "critical" for info in self.domains.values()):
            score += 25
        return min(score, 100)

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def get_summary(self) -> dict[str, Any]:
        duration = self.last_seen - self.first_seen
        top_domains = sorted(self.domains.items(), key=lambda item: item[1]["count"], reverse=True)[:10]
        risk_score = self._calculate_risk_score()
        return {
            "ip": self.ip,
            "first_seen": datetime.fromtimestamp(self.first_seen).strftime("%H:%M:%S"),
            "last_seen": datetime.fromtimestamp(self.last_seen).strftime("%H:%M:%S"),
            "duration": format_duration(duration),
            "total_requests": self.total_requests,
            "total_bytes_sent": format_bytes(self.total_bytes_sent),
            "total_bytes_received": format_bytes(self.total_bytes_received),
            "unique_domains": len(self.domains),
            "top_domains": [
                {
                    "domain": domain,
                    "count": info["count"],
                    "label": info["label"],
                    "category": info["category"],
                    "risk": info["risk"],
                    "bytes": format_bytes(info["bytes_sent"] + info["bytes_received"]),
                }
                for domain, info in top_domains
            ],
            "category_stats": {
                category: {
                    "count": int(stats["count"]),
                    "bytes": format_bytes(int(stats["bytes"])),
                    "percentage": round(stats["count"] / max(self.total_requests, 1) * 100, 1),
                }
                for category, stats in self.category_stats.items()
            },
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "risk_events": self.risk_events[-5:],
        }


class LANBehaviorMonitor:
    DNS_CACHE_TTL = 10 * 60
    THREAT_CACHE_TTL = 60 * 60
    TRACKER_IDLE_TTL = 20 * 60
    REPORT_INTERVAL = 10
    CLEANUP_INTERVAL = 30

    def __init__(self, interface: str, threat_intel_enabled: bool = True) -> None:
        self.interface = interface
        self.is_running = False
        self.threat_intel_enabled = threat_intel_enabled
        self.classifier = WebsiteClassifier()
        self.ip_trackers: dict[str, IPBehaviorTracker] = {}
        self.lock = threading.RLock()
        self.dns_cache: dict[str, tuple[str, float]] = {}
        self.threat_cache: dict[str, tuple[bool, float]] = {}
        self.last_cleanup = 0.0

    def _emit_output(self, output: Any) -> None:
        print(json.dumps(output, ensure_ascii=False), flush=True)

    def _is_lan_ip(self, ip: str) -> bool:
        return is_lan_ip(ip)

    def _remember_domain(self, ip: str, domain: str, ttl: int | None = None) -> None:
        with self.lock:
            self.dns_cache[ip] = (domain, time.time() + float(ttl or self.DNS_CACHE_TTL))

    def _lookup_domain(self, ip: str) -> str | None:
        with self.lock:
            entry = self.dns_cache.get(ip)
            if not entry:
                return None
            domain, expires_at = entry
            if expires_at < time.time():
                self.dns_cache.pop(ip, None)
                return None
            return domain

    def _cleanup_state(self, now: float) -> None:
        if now - self.last_cleanup < self.CLEANUP_INTERVAL:
            return
        self.last_cleanup = now
        self.dns_cache = {ip: entry for ip, entry in self.dns_cache.items() if entry[1] >= now}
        self.threat_cache = {domain: entry for domain, entry in self.threat_cache.items() if entry[1] >= now}
        self.ip_trackers = {
            ip: tracker for ip, tracker in self.ip_trackers.items() if now - tracker.last_seen <= self.TRACKER_IDLE_TTL
        }

    def packet_callback(self, packet: Any) -> None:
        ensure_packet_dependencies()
        if not packet.haslayer(IP):
            return

        now = time.time()
        with self.lock:
            self._cleanup_state(now)

        has_dns = packet.haslayer(DNS)
        if has_dns and packet.haslayer(DNSQR):
            self._process_dns_query(packet, now)
        if has_dns and packet[DNS].qr == 1 and packet[DNS].ancount > 0:
            self._process_dns_response(packet)
        if packet.haslayer(TCP):
            self._process_tcp_packet(packet, now)

    def _tracker_for(self, local_ip: str) -> IPBehaviorTracker:
        tracker = self.ip_trackers.get(local_ip)
        if tracker is None:
            tracker = IPBehaviorTracker(local_ip)
            self.ip_trackers[local_ip] = tracker
        return tracker

    def _record_access(self, local_ip: str, domain: str, packet_size: int, direction: str, timestamp: float) -> None:
        classification = self.classifier.classify(domain)
        with self.lock:
            tracker = self._tracker_for(local_ip)
            tracker.add_domain_access(domain, classification, packet_size, direction, timestamp)
        if self.threat_intel_enabled and self._check_threat_intel(domain, local_ip):
            debug(f"threat intel matched for {domain} from {local_ip}")

    def _process_dns_query(self, packet: Any, timestamp: float) -> None:
        try:
            src_ip = packet[IP].src
            if not self._is_lan_ip(src_ip):
                return
            domain = normalize_domain(packet[DNSQR].qname, ignored_suffixes=IGNORED_DOMAIN_SUFFIXES)
            if not domain:
                return
            self._record_access(src_ip, domain, len(packet), "out", timestamp)
        except Exception as exc:
            debug(f"failed to process DNS query: {exc}")

    def _iter_dns_answers(self, packet: Any) -> Iterator[Any]:
        answer = packet[DNS].an
        for _ in range(packet[DNS].ancount):
            if not isinstance(answer, DNSRR):
                break
            yield answer
            answer = answer.payload

    def _process_dns_response(self, packet: Any) -> None:
        try:
            domain = normalize_domain(packet[DNSQR].qname, ignored_suffixes=IGNORED_DOMAIN_SUFFIXES)
            if not domain:
                return
            for answer in self._iter_dns_answers(packet):
                if answer.type == 1:
                    self._remember_domain(str(answer.rdata), domain)
        except Exception as exc:
            debug(f"failed to process DNS response: {exc}")

    def _extract_tcp_domain(self, packet: Any, remote_ip: str) -> str | None:
        payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        if payload:
            domain, _ = extract_domain_from_tcp_payload(payload, ignored_suffixes=IGNORED_DOMAIN_SUFFIXES)
            if domain:
                self._remember_domain(remote_ip, domain)
                return domain
        return self._lookup_domain(remote_ip)

    def _process_tcp_packet(self, packet: Any, timestamp: float) -> None:
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)
            local_ip: str | None = None
            remote_ip: str | None = None
            direction = "out"

            if self._is_lan_ip(src_ip) and not self._is_lan_ip(dst_ip):
                local_ip = src_ip
                remote_ip = dst_ip
                direction = "out"
            elif self._is_lan_ip(dst_ip) and not self._is_lan_ip(src_ip):
                local_ip = dst_ip
                remote_ip = src_ip
                direction = "in"
            else:
                return

            domain = self._extract_tcp_domain(packet, remote_ip) or remote_ip
            self._record_access(local_ip, domain, packet_size, direction, timestamp)
        except Exception as exc:
            debug(f"failed to process TCP packet: {exc}")

    def _check_threat_intel(self, domain: str, src_ip: str) -> bool:
        if IPV4_ADDRESS_PATTERN.fullmatch(domain):
            return False

        now = time.time()
        cache_key = domain.lower()
        with self.lock:
            cached = self.threat_cache.get(cache_key)
            if cached and cached[1] >= now:
                is_malicious = cached[0]
            else:
                is_malicious = any(keyword in cache_key for keyword in LAN_MALICIOUS_KEYWORDS)
                self.threat_cache[cache_key] = (is_malicious, now + self.THREAT_CACHE_TTL)

        if is_malicious:
            self._send_alert(src_ip, domain, "malicious_domain")
        return is_malicious

    def _send_alert(self, ip: str, domain: str, alert_type: str) -> None:
        self._emit_output(
            build_security_alert_message(
                message=f"Suspicious domain detected: {domain}",
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip=ip,
                domain=domain,
                alert_type=alert_type,
                severity="critical",
            )
        )

    def report_loop(self) -> None:
        while self.is_running:
            time.sleep(self.REPORT_INTERVAL)
            with self.lock:
                self._cleanup_state(time.time())
                if not self.ip_trackers:
                    continue
                reports = [tracker.get_summary() for tracker in self.ip_trackers.values()]

            reports.sort(key=lambda item: item["risk_score"], reverse=True)
            self._emit_output(
                build_behavior_report_message(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    total_ips=len(reports),
                    reports=reports,
                )
            )

    def start(self) -> None:
        self.is_running = True
        report_thread = threading.Thread(target=self.report_loop, daemon=True)
        report_thread.start()

        self._emit_output(build_status_output_message(f"LAN behavior monitor started on {self.interface}"))
        try:
            ensure_packet_dependencies()
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda _: not self.is_running,
            )
        except Exception as exc:
            self._emit_output(build_error_output_message(f"LAN monitor error: {exc}"))
        finally:
            self.is_running = False

    def stop(self) -> None:
        self.is_running = False


def main() -> None:
    parser = argparse.ArgumentParser(description="LAN behavior monitor")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("--no-threat-intel", action="store_true", help="Disable threat intelligence checks")
    args = parser.parse_args()

    monitor = LANBehaviorMonitor(interface=args.interface, threat_intel_enabled=not args.no_threat_intel)

    def signal_handler(_sig: int, _frame: Any) -> None:
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    monitor.start()


if __name__ == "__main__":
    main()
