from __future__ import annotations

from typing import Any, Literal, Mapping, Sequence, TypedDict


class ErrorOutput(TypedDict):
    error: str


class OutputMessage(TypedDict, total=False):
    type: str
    message: str
    timestamp: int | float | str
    data: dict[str, Any]


class StatusOutputMessage(TypedDict, total=False):
    type: str
    message: str


class ErrorOutputMessage(TypedDict, total=False):
    type: str
    message: str


class ActivityLogOutputMessage(TypedDict):
    type: str
    data: list[dict[str, Any]]


class SecurityAlertOutputMessage(TypedDict, total=False):
    type: str
    message: str
    timestamp: str
    ip: str
    domain: str
    alert_type: str
    severity: str


class BehaviorReportOutputMessage(TypedDict, total=False):
    type: str
    timestamp: str
    total_ips: int
    reports: list[dict[str, Any]]


class TimedOutputMessage(TypedDict, total=False):
    type: str
    message: str
    timestamp: int | float
    data: dict[str, Any]


class NICMonitorCommand(TypedDict, total=False):
    action: str
    nics: list[str]
    seconds: int
    start_ts: int
    end_ts: int


class SearchEvent(TypedDict):
    captured_at: str
    src_ip: str
    domain: str
    engine: str
    keyword: str
    evidence_level: str


class ViolationEvent(TypedDict):
    captured_at: str
    src_ip: str
    domain: str
    violation_type: str
    severity: str
    reason: str


class TrafficServiceProfile(TypedDict):
    service_type: str
    service_type_label: str
    service_icon: str
    productivity_category: str
    base_score: int


class TrafficRequestRecord(TypedDict):
    time: float
    domain: str
    source: str
    bytes: int


class BehaviorAnalysisResult(TypedDict, total=False):
    main_service: str
    service_type: str
    service_type_label: str
    service_icon: str
    productivity_category: str
    behavior_chain: list[str]
    risk_score: int
    risk_level: str
    risk_reason: str


class BehaviorSessionSnapshot(TypedDict):
    session_id: str
    captured_at: str
    start_time: str
    duration: str
    main_service: str
    main_domain: str
    domain: str
    full_host: str
    src_ip: str
    dst_ip: str
    app_name: str
    category: str
    bytes: int
    evidence_level: str
    service_type: str
    service_type_label: str
    service_icon: str
    productivity_category: str
    behavior_label: str
    risk_score: int
    risk_level: str
    risk_reason: str
    behavior_chain: list[str]
    requests: list[TrafficRequestRecord]
    request_count: int
    analysis_source: str
    search_events: list[SearchEvent]
    violations: list[ViolationEvent]


class PacketAnalysisResult(TypedDict, total=False):
    is_threat: bool | str
    threat_type: str | None
    reason: str | None
    summary: str
    confidence: str
    firewall_action: str


class PacketPayloadDescription(TypedDict, total=False):
    payload: str
    http_detected: bool
    http_request_line: str


class PacketQuickCheckInput(TypedDict, total=False):
    src: str
    dst: str
    payload: str
    dport: int
    sport: int
    flags: str


ThreatCheckStatus = Literal["threat", "safe", "unknown"]
ThreatCheckResult = tuple[ThreatCheckStatus, str | None, str | None]


class PacketResult(TypedDict):
    id: int
    timestamp: Any
    src: Any
    dst: Any
    proto: Any
    len: Any
    packet_details: dict[str, Any]
    analysis: PacketAnalysisResult


def copy_mapping_items(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(item) for item in items]
