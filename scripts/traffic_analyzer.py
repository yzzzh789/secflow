from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

_RUNTIME_CONFIG_DIR = Path(__file__).resolve().parents[1] / ".runtime" / "xdg"
os.environ.setdefault("XDG_CONFIG_HOME", str(_RUNTIME_CONFIG_DIR))

_COMMON_PYTHON_DIR = Path(__file__).resolve().parents[1] / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

from secflow_common.ai_client import AIClient
from secflow_common.classification import (
    TRAFFIC_ENTERTAINMENT_TYPES as ENTERTAINMENT_TYPES,
    TRAFFIC_RISK_RULES as RISK_RULES,
    TRAFFIC_SERVICE_FAMILY_RULES as SERVICE_FAMILY_RULES,
    TRAFFIC_SERVICE_LABEL_RULES as SERVICE_LABEL_RULES,
    traffic_build_violation_events as build_violation_events,
    traffic_classify_app_by_domain as classify_app_by_domain,
    traffic_classify_service as classify_service,
    traffic_evidence_level_from_source as evidence_level_from_source,
    traffic_extract_search_event as extract_search_event,
    traffic_higher_risk_level as higher_risk_level,
    traffic_merge_evidence_level as merge_evidence_level,
    traffic_risk_level_from_score as risk_level_from_score,
)
from secflow_common.domains import (
    extract_domain_from_tcp_payload,
    is_ip_address,
    normalize_domain,
    root_domain,
)
from secflow_common.formatting import format_capture_time, format_duration
from secflow_common.output_messages import (
    build_activity_log_message,
    build_error_output_message,
    build_status_output_message,
)
from secflow_common.protocol_types import (
    BehaviorAnalysisResult,
    BehaviorSessionSnapshot,
    SearchEvent,
    TrafficRequestRecord,
    TrafficServiceProfile,
    ViolationEvent,
)
from secflow_common.traffic_utils import clamp, event_signature, packet_size, safe_int

scapy = None
DNS = None
DNSQR = None
IP = None
TCP = None
Raw = None


IGNORED_DOMAIN_SUFFIXES = (".arpa",)
IGNORED_DOMAIN_PATTERNS = (
    "connectivitycheck",
    "msftconnecttest",
    "time.windows.com",
    "ocsp",
    "crl",
    "telemetry",
)


def debug(message: str) -> None:
    print(f"[traffic_analyzer] {message}", file=sys.stderr, flush=True)


def ensure_runtime_config_dir() -> None:
    _RUNTIME_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def ensure_packet_dependencies() -> None:
    global scapy, DNS, DNSQR, IP, TCP, Raw
    if scapy is not None:
        return

    import scapy.all as scapy_module
    from scapy.layers.dns import DNS as dns_layer
    from scapy.layers.dns import DNSQR as dns_query_layer
    from scapy.layers.inet import IP as ip_layer
    from scapy.layers.inet import TCP as tcp_layer
    from scapy.packet import Raw as raw_layer

    scapy = scapy_module
    DNS = dns_layer
    DNSQR = dns_query_layer
    IP = ip_layer
    TCP = tcp_layer
    Raw = raw_layer

SEARCH_SIGNATURE_KEYS = ("captured_at", "engine", "keyword", "src_ip")
VIOLATION_SIGNATURE_KEYS = ("captured_at", "violation_type", "reason", "src_ip")
VALID_RISK_LEVELS = {"low", "medium", "high"}


@dataclass(slots=True)
class BehaviorSession:
    session_id: str
    main_domain: str
    start_time: float
    last_updated: float
    requests: list[TrafficRequestRecord] = field(default_factory=list)
    pending_search_events: list[SearchEvent] = field(default_factory=list)
    pending_violation_events: list[ViolationEvent] = field(default_factory=list)
    seen_search_signatures: set[str] = field(default_factory=set)
    seen_violation_signatures: set[str] = field(default_factory=set)
    request_count: int = 0
    total_bytes: int = 0
    risk_score: int = 0
    risk_level: str = "low"
    behavior_chain: list[str] = field(default_factory=list)
    main_service: str = ""
    full_host: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    app_name: str = ""
    app_category: str = "网站"
    evidence_level: str = "low"
    service_type: str = "website"
    service_type_label: str = "普通网站"
    service_icon: str = "网站"
    productivity_category: str = "Neutral"
    risk_reason: str = ""
    ai_analyzed: bool = False
    analysis_source: str = "pending"
    last_analyzed_request_count: int = 0

    def add_request(
        self,
        domain: str,
        full_host: str,
        timestamp: float,
        source: str,
        src_ip: str,
        dst_ip: str,
        packet_bytes: int,
        app_name: str,
        category: str,
        search_event: SearchEvent | None,
        violations: list[ViolationEvent],
    ) -> None:
        normalized_bytes = max(0, packet_bytes)
        self.last_updated = timestamp
        self.request_count += 1
        self.total_bytes += normalized_bytes
        self.main_domain = domain
        self.full_host = full_host or domain
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.app_name = app_name
        self.app_category = category
        self.evidence_level = merge_evidence_level(self.evidence_level, evidence_level_from_source(source))

        if search_event is not None:
            signature = event_signature(search_event, SEARCH_SIGNATURE_KEYS)
            if signature not in self.seen_search_signatures:
                self.pending_search_events.append(search_event)
                self.seen_search_signatures.add(signature)

        for violation in violations:
            signature = event_signature(violation, VIOLATION_SIGNATURE_KEYS)
            if signature not in self.seen_violation_signatures:
                self.pending_violation_events.append(violation)
                self.seen_violation_signatures.add(signature)

        last_request = self.requests[-1] if self.requests else None
        if last_request and last_request["domain"] == self.full_host and timestamp - last_request["time"] < 1.5:
            last_request["source"] = source
            last_request["bytes"] = last_request.get("bytes", 0) + normalized_bytes
            return
        self.requests.append({"time": timestamp, "domain": self.full_host, "source": source, "bytes": normalized_bytes})
        if len(self.requests) > 60:
            self.requests.pop(0)

    def to_dict(self) -> BehaviorSessionSnapshot:
        label = " / ".join(self.behavior_chain[:2]) if self.behavior_chain else "Analyzing"
        return {
            "session_id": self.session_id,
            "captured_at": format_capture_time(self.last_updated),
            "start_time": time.strftime("%H:%M", time.localtime(self.start_time)),
            "duration": format_duration(self.last_updated - self.start_time),
            "main_service": self.main_service or self.main_domain,
            "main_domain": self.main_domain,
            "domain": self.main_domain,
            "full_host": self.full_host or self.main_domain,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "app_name": self.app_name or self.main_service or self.main_domain,
            "category": self.app_category,
            "bytes": self.total_bytes,
            "evidence_level": self.evidence_level,
            "service_type": self.service_type,
            "service_type_label": self.service_type_label,
            "service_icon": self.service_icon,
            "productivity_category": self.productivity_category,
            "behavior_label": label,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_reason": self.risk_reason,
            "behavior_chain": self.behavior_chain,
            "requests": sorted(self.requests, key=lambda item: item["time"]),
            "request_count": self.request_count,
            "analysis_source": self.analysis_source,
            "search_events": list(self.pending_search_events),
            "violations": list(self.pending_violation_events),
        }


class SessionManager:
    def __init__(self, timeout_seconds: int = 45, retention_seconds: int = 15 * 60) -> None:
        self.timeout_seconds = timeout_seconds
        self.retention_seconds = retention_seconds
        self.active_sessions: dict[str, BehaviorSession] = {}

    def _service_key(self, domain: str) -> str:
        domain_lower = domain.lower()
        for family_key, patterns in SERVICE_FAMILY_RULES:
            if any(pattern in domain_lower for pattern in patterns):
                return family_key
        base = root_domain(domain)
        return base.replace(".", "_")

    def process_domain(self, domain: str, timestamp: float, source: str) -> BehaviorSession:
        key = self._service_key(domain)
        session = self.active_sessions.get(key)
        if session is None or timestamp - session.last_updated > self.timeout_seconds:
            session = BehaviorSession(
                session_id=f"sess_{int(timestamp)}_{key}",
                main_domain=domain,
                start_time=timestamp,
                last_updated=timestamp,
            )
            self.active_sessions[key] = session
        return session

    def cleanup_stale(self, now: float) -> None:
        stale_keys = [
            key
            for key, session in self.active_sessions.items()
            if now - session.last_updated > self.retention_seconds
        ]
        for key in stale_keys:
            del self.active_sessions[key]


class TrafficAnalyzer:
    def __init__(
        self,
        interface: str,
        provider: str = "ollama",
        api_key: str | None = None,
        api_base: str | None = None,
        model: str = "deepseek-r1:8b",
        limit_minutes: int = 30,
    ) -> None:
        self.interface = interface
        self.limit_minutes = limit_minutes
        self.is_running = False
        self.ai_client = AIClient(
            provider=provider,
            api_key=api_key,
            model=model,
            api_base=api_base,
            timeout=45,
            allow_api_base_override=True,
            request_max_tokens=800,
            json_response_providers=(),
            verbose_http_errors=True,
        )
        self.session_manager = SessionManager()
        self.lock = threading.Lock()
        self.pending_analysis: dict[str, BehaviorSession] = {}
        self.analysis_idle_seconds = 3
        self.analysis_batch_threshold = 3

    def _emit_output(self, output: Any) -> None:
        print(json.dumps(output, ensure_ascii=False), flush=True)

    def _extract_domain(self, packet: Any) -> tuple[str | None, str | None, str, bytes]:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = normalize_domain(
                packet[DNSQR].qname,
                ignored_suffixes=IGNORED_DOMAIN_SUFFIXES,
                ignored_patterns=IGNORED_DOMAIN_PATTERNS,
                max_length=253,
            )
            if query:
                return root_domain(query), query, "dns", b""

        if not packet.haslayer(TCP):
            return None, None, "", b""

        tcp_layer = packet[TCP]
        raw_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        if raw_bytes:
            full_host, source = extract_domain_from_tcp_payload(
                raw_bytes,
                enable_http=tcp_layer.dport in {80, 8080, 8000, 8888},
                enable_tls=tcp_layer.dport == 443,
                ignored_suffixes=IGNORED_DOMAIN_SUFFIXES,
                ignored_patterns=IGNORED_DOMAIN_PATTERNS,
                max_length=253,
            )
            if full_host:
                return root_domain(full_host), full_host, source, raw_bytes

        return None, None, "", raw_bytes

    def packet_callback(self, packet: Any) -> None:
        if not packet.haslayer(IP):
            return

        captured_at = time.time()
        domain, full_host, source, raw_payload = self._extract_domain(packet)
        if not domain:
            return

        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        packet_bytes = packet_size(packet, ip_layer)
        app_name, category = classify_app_by_domain(full_host or domain)
        evidence_level = evidence_level_from_source(source)
        search_event = extract_search_event(full_host or domain, raw_payload, src_ip, captured_at, evidence_level)
        violations = build_violation_events(full_host or domain, category, src_ip, captured_at, search_event)

        with self.lock:
            session = self.session_manager.process_domain(domain, captured_at, source)
            session.evidence_level = merge_evidence_level(session.evidence_level, evidence_level)
            self.pending_analysis[session.session_id] = session
            session.add_request(
                domain=domain,
                full_host=full_host or domain,
                timestamp=captured_at,
                source=source,
                src_ip=src_ip,
                dst_ip=dst_ip,
                packet_bytes=packet_bytes,
                app_name=app_name,
                category=category,
                search_event=search_event,
                violations=violations,
            )

    def _collect_ready_sessions(self) -> list[BehaviorSession]:
        now = time.time()
        ready: list[BehaviorSession] = []
        with self.lock:
            self.session_manager.cleanup_stale(now)
            stale_pending = [sid for sid, session in self.pending_analysis.items() if now - session.last_updated > 20 * 60]
            for sid in stale_pending:
                del self.pending_analysis[sid]

            for session_id, session in list(self.pending_analysis.items()):
                new_requests = session.request_count - session.last_analyzed_request_count
                is_idle = now - session.last_updated >= self.analysis_idle_seconds
                should_analyze = new_requests > 0 and (
                    is_idle or new_requests >= self.analysis_batch_threshold or not session.ai_analyzed
                )
                if should_analyze:
                    ready.append(session)
                    del self.pending_analysis[session_id]
        return ready

    def analyze_loop(self) -> None:
        while self.is_running:
            time.sleep(2)
            for session in self._collect_ready_sessions():
                self.analyze_session(session)

    def _build_prompt(self, session: BehaviorSession) -> str:
        request_samples = [
            {
                "time": time.strftime("%H:%M:%S", time.localtime(item["time"])),
                "domain": item["domain"],
                "source": item.get("source", "unknown"),
            }
            for item in session.requests[-20:]
        ]
        return f"""
You are a network security and behavior analysis assistant.
Analyze the browsing session below and respond with strict JSON only.

Main domain: {session.main_domain}
Requests: {json.dumps(request_samples, ensure_ascii=False)}

Return:
{{
  "main_service": "service name",
  "service_type": "video|game|social|shopping|finance|work|system|website|ip",
  "service_type_label": "type label in Chinese",
  "behavior_chain": ["step 1", "step 2", "step 3"],
  "risk_score": 0,
  "risk_level": "low",
  "risk_reason": "short reason"
}}

Rules:
- If the session is mainly video, game, social, shopping, or stock/finance, do not return 0 risk_score.
- Entertainment browsing should receive a non-zero score according to how distracting it is.
- Infrastructure, update, telemetry, and plain DNS helper domains can stay low.
""".strip()

    def _parse_ai_response(self, content: str) -> BehaviorAnalysisResult:
        cleaned = content.strip()
        if not cleaned:
            raise ValueError("AI response is empty")
        if "```" in cleaned:
            match = re.search(r"```(?:json)?\s*(.*?)```", cleaned, re.DOTALL)
            if match:
                cleaned = match.group(1).strip()
            else:
                cleaned = cleaned.replace("```json", "").replace("```", "").strip()
        try:
            result = json.loads(cleaned)
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start < 0 or end <= start:
                raise
            result = json.loads(cleaned[start : end + 1])
        if not isinstance(result, dict):
            raise ValueError("AI response JSON must be an object")
        return cast(BehaviorAnalysisResult, result)

    def _heuristic_analysis(self, session: BehaviorSession) -> BehaviorAnalysisResult:
        domains = [item["domain"] for item in session.requests]
        unique_domains = sorted({domain for domain in domains})
        score = 0
        profile_cache: dict[str, TrafficServiceProfile] = {}

        def cached_profile(domain: str) -> TrafficServiceProfile:
            profile = profile_cache.get(domain)
            if profile is None:
                profile = classify_service(domain)
                profile_cache[domain] = profile
            return profile

        main_profile = cached_profile(session.main_domain)
        dominant_profile = main_profile
        type_counts: dict[str, int] = {}
        service = session.main_domain if is_ip_address(session.main_domain) else root_domain(session.main_domain)
        main_domain_lower = session.main_domain.lower()
        for label, patterns in SERVICE_LABEL_RULES:
            if any(pattern in main_domain_lower for pattern in patterns):
                service = label
                break

        for domain in domains:
            profile = cached_profile(domain)
            service_type = str(profile["service_type"])
            type_counts[service_type] = type_counts.get(service_type, 0) + 1
            if type_counts[service_type] > type_counts.get(str(dominant_profile["service_type"]), 0):
                dominant_profile = profile

        matched_risks = [
            weight
            for domain in unique_domains
            for keyword, weight in RISK_RULES
            if keyword in domain.lower()
        ]
        score += sum(matched_risks[:6])
        score += int(dominant_profile["base_score"])

        entertainment_requests = sum(
            1 for domain in domains if cached_profile(domain)["service_type"] in ENTERTAINMENT_TYPES
        )
        entertainment_ratio = entertainment_requests / max(len(domains), 1)
        if entertainment_ratio >= 0.75:
            score += 18
        elif entertainment_ratio >= 0.45:
            score += 12
        elif entertainment_ratio >= 0.2:
            score += 6

        if dominant_profile["service_type"] in {"video", "game", "finance"}:
            score += min(session.request_count * 2, 16)
        elif dominant_profile["service_type"] in {"social", "shopping"}:
            score += min(session.request_count, 10)

        if len(unique_domains) >= 8:
            score += 10
        unique_domain_lowers = [domain.lower() for domain in unique_domains]
        if any(domain.endswith((".ru", ".xyz", ".top")) for domain in unique_domain_lowers):
            score += 12
        if any(domain.startswith(("api.", "auth.", "login.")) for domain in unique_domain_lowers):
            score += 6
        score = clamp(score)

        steps = [f"Visited {service}"]
        steps.append(f"Classified as {dominant_profile['service_type_label']}")
        sources = {item.get("source") for item in session.requests}
        if "dns" in sources:
            steps.append("Resolved domains via DNS")
        if "tls_sni" in sources:
            steps.append("Opened TLS sessions to external services")
        if "http_host" in sources:
            steps.append("Requested HTTP application content")
        if len(unique_domains) > 4:
            steps.append("Loaded supporting assets and third-party endpoints")
        if not steps:
            steps = ["Observed network activity"]

        risk_reason = f"{dominant_profile['service_type_label']}占比 {entertainment_ratio:.0%}" if dominant_profile["service_type"] in ENTERTAINMENT_TYPES else "heuristic fallback"

        return {
            "main_service": service,
            "service_type": dominant_profile["service_type"],
            "service_type_label": dominant_profile["service_type_label"],
            "service_icon": dominant_profile["service_icon"],
            "productivity_category": dominant_profile["productivity_category"],
            "behavior_chain": steps[:4],
            "risk_score": score,
            "risk_level": risk_level_from_score(score),
            "risk_reason": risk_reason,
        }

    def analyze_session(self, session: BehaviorSession) -> None:
        baseline = self._heuristic_analysis(session)
        analysis_source = "ai"
        try:
            result = self._parse_ai_response(self.ai_client.chat(self._build_prompt(session)))
        except Exception as exc:
            debug(f"AI analysis failed for {session.session_id}: {exc}")
            result = baseline
            analysis_source = "heuristic"

        session.main_service = str(result.get("main_service") or baseline["main_service"] or session.main_service or session.main_domain)
        session.service_type = str(result.get("service_type") or baseline["service_type"])
        session.service_type_label = str(result.get("service_type_label") or baseline["service_type_label"])
        session.service_icon = str(result.get("service_icon") or baseline["service_icon"])
        session.productivity_category = str(result.get("productivity_category") or baseline["productivity_category"])
        chain = result.get("behavior_chain") or []
        if not isinstance(chain, list):
            chain = [str(chain)]
        session.behavior_chain = [str(step).strip() for step in chain if str(step).strip()][:5] or baseline["behavior_chain"]
        ai_score = clamp(safe_int(result.get("risk_score"), baseline["risk_score"]))
        session.risk_score = max(ai_score, int(baseline["risk_score"]))
        session.risk_level = higher_risk_level(
            str(result.get("risk_level") or risk_level_from_score(ai_score)).lower(),
            risk_level_from_score(session.risk_score),
        )
        if session.risk_level not in VALID_RISK_LEVELS:
            session.risk_level = risk_level_from_score(session.risk_score)
        session.risk_reason = str(result.get("risk_reason") or baseline["risk_reason"])
        session.ai_analyzed = analysis_source == "ai"
        session.analysis_source = analysis_source
        session.last_analyzed_request_count = session.request_count

        if analysis_source == "heuristic":
            self._emit_output(build_status_output_message(f"AI analysis unavailable, fallback used for {session.main_domain}"))
        self._emit_output(build_activity_log_message([session.to_dict()]))
        session.pending_search_events = []
        session.pending_violation_events = []

    def start(self) -> None:
        ensure_packet_dependencies()
        self.is_running = True
        analysis_thread = threading.Thread(target=self.analyze_loop, daemon=True)
        analysis_thread.start()
        self._emit_output(build_status_output_message(f"Started Session Analysis on {self.interface}"))

        try:
            scapy.sniff(
                iface=self.interface,
                filter="udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080",
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda _: not self.is_running,
            )
        except Exception as exc:
            self._emit_output(build_error_output_message(f"Sniff error: {exc}"))

    def stop(self) -> None:
        self.is_running = False


def main() -> None:
    ensure_runtime_config_dir()

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument(
        "--provider",
        default="ollama",
        choices=["ollama", "openai", "deepseek", "nvidia", "custom"],
        help="AI provider",
    )
    parser.add_argument("--api-key", type=str, help="API key for cloud providers")
    parser.add_argument("--api-base", type=str, help="API base URL")
    parser.add_argument("--model", default="deepseek-r1:8b", help="Model name")
    parser.add_argument("--limit", type=int, default=30, help="Entertainment time limit in minutes")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer(
        interface=args.interface,
        provider=args.provider,
        api_key=args.api_key,
        api_base=args.api_base,
        model=args.model,
        limit_minutes=args.limit,
    )

    def signal_handler(_sig: int, _frame: Any) -> None:
        analyzer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    analyzer.start()


if __name__ == "__main__":
    main()
