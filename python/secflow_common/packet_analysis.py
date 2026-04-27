from __future__ import annotations

import json
from typing import Any, Mapping, cast

from .protocol_types import PacketAnalysisResult, PacketResult


def build_rule_based_analysis(
    status: str,
    threat_type: str | None,
    reason: str | None,
    summary: str = "",
) -> PacketAnalysisResult:
    if status == "threat":
        return {
            "is_threat": True,
            "threat_type": threat_type,
            "reason": reason,
            "summary": "本地规则检测",
            "confidence": "高",
        }
    if status == "safe":
        return {
            "is_threat": False,
            "threat_type": "正常流量",
            "reason": "本地规则确认为正常流量",
            "summary": summary,
            "confidence": "高",
        }
    raise ValueError(f"unsupported rule status: {status}")


def build_llm_disabled_analysis() -> PacketAnalysisResult:
    return {
        "is_threat": False,
        "threat_type": "LLM Off",
        "reason": "LLM disabled",
        "summary": "LLM disabled",
    }


def parse_llm_analysis_response(raw: str) -> PacketAnalysisResult:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "is_threat": False,
            "threat_type": "Parse Error",
            "reason": "AI response was not valid JSON",
            "summary": "Raw output: " + raw[:50],
        }
    if not isinstance(parsed, dict):
        return {
            "is_threat": False,
            "threat_type": "Parse Error",
            "reason": "AI response was not a JSON object",
            "summary": "Raw output: " + raw[:50],
        }
    return cast(PacketAnalysisResult, parsed)


def analysis_indicates_threat(analysis: Mapping[str, Any]) -> bool:
    is_threat_value = analysis.get("is_threat")
    if isinstance(is_threat_value, bool):
        return is_threat_value
    if isinstance(is_threat_value, str):
        return is_threat_value.lower() == "true"
    return False


def apply_firewall_action(
    analysis: Mapping[str, Any],
    firewall_action: str,
    append_block_reason: bool = False,
) -> PacketAnalysisResult:
    result = dict(analysis)
    if append_block_reason:
        reason = str(result.get("reason") or "")
        suffix = " [已自动封锁 IP]"
        if suffix not in reason:
            result["reason"] = f"{reason}{suffix}" if reason else suffix.strip()
    result["firewall_action"] = firewall_action
    return cast(PacketAnalysisResult, result)


def build_packet_result(
    packet_id: int,
    packet_dict: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> PacketResult:
    return {
        "id": packet_id,
        "timestamp": packet_dict.get("time"),
        "src": packet_dict.get("src"),
        "dst": packet_dict.get("dst"),
        "proto": packet_dict.get("proto"),
        "len": packet_dict.get("len"),
        "packet_details": dict(packet_dict),
        "analysis": cast(PacketAnalysisResult, dict(analysis)),
    }
