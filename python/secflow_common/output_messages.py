from __future__ import annotations

from typing import Any, Mapping, Sequence, cast

from .protocol_types import (
    ActivityLogOutputMessage,
    BehaviorReportOutputMessage,
    ErrorOutput,
    ErrorOutputMessage,
    OutputMessage,
    SecurityAlertOutputMessage,
    StatusOutputMessage,
    TimedOutputMessage,
    copy_mapping_items,
)


def build_output_payload(**payload: Any) -> dict[str, Any]:
    return dict(payload)


def build_error_output(error: object) -> ErrorOutput:
    return {"error": str(error)}


def build_output_message(message_type: str, **payload: Any) -> OutputMessage:
    message: dict[str, Any] = {"type": message_type}
    message.update(payload)
    return cast(OutputMessage, message)


def build_status_output_message(message: str, **payload: Any) -> StatusOutputMessage:
    output = build_output_message("status", message=message, **payload)
    return cast(StatusOutputMessage, output)


def build_error_output_message(message: str, **payload: Any) -> ErrorOutputMessage:
    output = build_output_message("error", message=message, **payload)
    return cast(ErrorOutputMessage, output)


def build_activity_log_message(data: Sequence[Mapping[str, Any]]) -> ActivityLogOutputMessage:
    return {
        "type": "activity_log",
        "data": copy_mapping_items(data),
    }


def build_security_alert_message(
    message: str,
    timestamp: str,
    ip: str,
    domain: str,
    alert_type: str,
    severity: str,
) -> SecurityAlertOutputMessage:
    return {
        "type": "security_alert",
        "message": message,
        "timestamp": timestamp,
        "ip": ip,
        "domain": domain,
        "alert_type": alert_type,
        "severity": severity,
    }


def build_behavior_report_message(
    timestamp: str,
    total_ips: int,
    reports: Sequence[Mapping[str, Any]],
) -> BehaviorReportOutputMessage:
    return {
        "type": "behavior_report",
        "timestamp": timestamp,
        "total_ips": total_ips,
        "reports": copy_mapping_items(reports),
    }


def build_timed_output_message(
    message_type: str,
    message: str,
    timestamp: int | float,
    data: Mapping[str, Any] | None = None,
) -> TimedOutputMessage:
    output = build_output_message(message_type, message=message, timestamp=timestamp)
    if data is not None:
        output["data"] = dict(data)
    return cast(TimedOutputMessage, output)
