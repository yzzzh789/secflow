from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "python"))

from secflow_common import classification
from secflow_common import domains
from secflow_common import interface_discovery
from secflow_common import output_messages
from secflow_common import packet_analysis
from secflow_common import packet_payloads
from secflow_common import packet_rules
from secflow_common import traffic_utils
from scripts import traffic_analyzer


def build_tls_client_hello(hostname: str) -> bytes:
    host = hostname.encode("utf-8")
    server_name = b"\x00" + len(host).to_bytes(2, "big") + host
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    sni_extension = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    extensions = sni_extension

    body = bytearray()
    body.extend(b"\x01")
    handshake_length = 43 + 2 + 1 + 2 + len(extensions)
    body.extend(handshake_length.to_bytes(3, "big"))
    body.extend(b"\x03\x03")
    body.extend(b"\x00" * 32)
    body.extend(b"\x00")
    body.extend((2).to_bytes(2, "big"))
    body.extend(b"\x13\x01")
    body.extend(b"\x01")
    body.extend(b"\x00")
    body.extend(len(extensions).to_bytes(2, "big"))
    body.extend(extensions)

    record = bytearray(b"\x16\x03\x01")
    record.extend(len(body).to_bytes(2, "big"))
    record.extend(body)
    return bytes(record)


class DomainHelpersTests(unittest.TestCase):
    def test_normalize_domain_filters_and_normalizes(self) -> None:
        self.assertEqual(domains.normalize_domain(b" Example.COM. "), "example.com")
        self.assertIsNone(domains.normalize_domain("service.local", ignored_suffixes=(".local",)))
        self.assertIsNone(domains.normalize_domain("bad host"))
        self.assertIsNone(domains.normalize_domain("toolong.example", max_length=5))

    def test_extract_host_header(self) -> None:
        payload = b"GET / HTTP/1.1\r\nHost: Example.COM:8443\r\nUser-Agent: test\r\n\r\n"
        self.assertEqual(domains.extract_host_header(payload), "example.com")

    def test_extract_tls_sni(self) -> None:
        payload = build_tls_client_hello("api.example.com")
        self.assertEqual(domains.extract_tls_sni(payload), "api.example.com")

    def test_extract_domain_from_tcp_payload(self) -> None:
        http_payload = b"GET / HTTP/1.1\r\nHost: Example.COM:8443\r\n\r\n"
        self.assertEqual(
            domains.extract_domain_from_tcp_payload(http_payload),
            ("example.com", "http_host"),
        )

        tls_payload = build_tls_client_hello("api.example.com")
        self.assertEqual(
            domains.extract_domain_from_tcp_payload(tls_payload),
            ("api.example.com", "tls_sni"),
        )
        self.assertEqual(
            domains.extract_domain_from_tcp_payload(http_payload, enable_http=False),
            (None, ""),
        )
        self.assertEqual(
            domains.extract_domain_from_tcp_payload(tls_payload, enable_tls=False),
            (None, ""),
        )


class ClassificationTests(unittest.TestCase):
    def test_extract_search_event(self) -> None:
        event = classification.traffic_extract_search_event(
            "www.google.com",
            b"GET /search?q=secflow HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
            "192.0.2.10",
            time.time(),
            "high",
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["engine"], "google")
        self.assertEqual(event["keyword"], "secflow")
        self.assertEqual(event["evidence_level"], "high")

    def test_build_violation_events(self) -> None:
        timestamp = time.mktime((2024, 1, 1, 21, 30, 0, 0, 0, -1))
        category = classification.traffic_classify_app_by_domain("www.bilibili.com")[1]
        risk_keyword = next(iter(classification.TRAFFIC_HIGH_RISK_KEYWORDS))

        events = classification.traffic_build_violation_events(
            "thepiratebay.org",
            category,
            "192.0.2.11",
            timestamp,
            {"keyword": f"download {risk_keyword}"},
        )

        violation_types = {event["violation_type"] for event in events}
        self.assertIn("blacklist_domain", violation_types)
        self.assertIn("high_risk_keyword", violation_types)
        self.assertIn("off_hours_entertainment", violation_types)

    def test_classify_service_and_lan_classifier(self) -> None:
        ip_service = classification.traffic_classify_service("192.0.2.1")
        self.assertEqual(ip_service["service_type"], "ip")

        work_service = classification.traffic_classify_service("github.com")
        self.assertEqual(work_service["service_type"], "work")
        self.assertEqual(classification.traffic_risk_level_from_score(80), "high")

        classifier = classification.LANWebsiteClassifier()
        self.assertEqual(classifier.classify("github.com")["category"], "work")


class TrafficUtilsTests(unittest.TestCase):
    def test_safe_int_and_clamp(self) -> None:
        self.assertEqual(traffic_utils.safe_int("12"), 12)
        self.assertEqual(traffic_utils.safe_int("bad", 7), 7)
        self.assertEqual(traffic_utils.clamp(120), 100)
        self.assertEqual(traffic_utils.clamp(-5), 0)

    def test_event_signature_and_packet_size(self) -> None:
        event = {"a": 1, "b": "x"}
        self.assertEqual(traffic_utils.event_signature(event, ("a", "b", "c")), "1|x|")

        class FakeIP:
            len = 48

        class FakePacket:
            def __bytes__(self) -> bytes:
                return b"0123456789"

        self.assertEqual(traffic_utils.packet_size(FakePacket(), FakeIP()), 48)
        self.assertEqual(traffic_utils.packet_size(FakePacket(), object()), 10)


class PacketRulesTests(unittest.TestCase):
    def test_quick_threat_check_detects_sql_injection(self) -> None:
        status, threat_type, reason = packet_rules.quick_threat_check(
            {
                "src": "192.0.2.10",
                "dst": "198.51.100.10",
                "payload": "id=1 UNION SELECT password FROM users",
                "dport": 80,
                "sport": 50000,
                "flags": "PA",
            }
        )
        self.assertEqual(status, "threat")
        self.assertEqual(threat_type, "SQL娉ㄥ叆")
        self.assertIn("UNION SELECT", reason or "")

    def test_quick_threat_check_detects_syn_scan(self) -> None:
        status, threat_type, _ = packet_rules.quick_threat_check(
            {
                "src": "192.0.2.10",
                "dst": "198.51.100.10",
                "payload": "",
                "dport": 3389,
                "sport": 50000,
                "flags": "S",
            }
        )
        self.assertEqual(status, "threat")
        self.assertEqual(threat_type, "绔彛鎵弿")

    def test_quick_threat_check_allows_normal_http(self) -> None:
        status, threat_type, reason = packet_rules.quick_threat_check(
            {
                "src": "192.0.2.10",
                "dst": "198.51.100.10",
                "payload": "GET /index.html HTTP/1.1",
                "dport": 80,
                "sport": 50000,
                "flags": "PA",
            }
        )
        self.assertEqual(status, "safe")
        self.assertIsNone(threat_type)
        self.assertIsNone(reason)


class PacketAnalysisTests(unittest.TestCase):
    def test_build_rule_based_analysis(self) -> None:
        threat = packet_analysis.build_rule_based_analysis("threat", "SQL注入", "matched pattern")
        self.assertTrue(threat["is_threat"])
        self.assertEqual(threat["summary"], "本地规则检测")

        safe = packet_analysis.build_rule_based_analysis(
            "safe",
            None,
            None,
            summary="GET /index.html",
        )
        self.assertFalse(safe["is_threat"])
        self.assertEqual(safe["threat_type"], "正常流量")
        self.assertEqual(safe["summary"], "GET /index.html")

    def test_parse_llm_analysis_response_and_threat_flag(self) -> None:
        parsed = packet_analysis.parse_llm_analysis_response('{"is_threat":"true","reason":"risk"}')
        self.assertTrue(packet_analysis.analysis_indicates_threat(parsed))

        fallback = packet_analysis.parse_llm_analysis_response("not-json")
        self.assertFalse(packet_analysis.analysis_indicates_threat(fallback))
        self.assertEqual(fallback["threat_type"], "Parse Error")

    def test_parse_llm_analysis_response_rejects_non_object_json(self) -> None:
        fallback = packet_analysis.parse_llm_analysis_response('["unexpected"]')
        self.assertFalse(packet_analysis.analysis_indicates_threat(fallback))
        self.assertEqual(fallback["threat_type"], "Parse Error")

    def test_apply_firewall_action_and_build_packet_result(self) -> None:
        analysis = packet_analysis.apply_firewall_action(
            {"is_threat": True, "reason": "matched"},
            "Blocked",
            append_block_reason=True,
        )
        self.assertEqual(analysis["firewall_action"], "Blocked")
        self.assertIn("已自动封锁 IP", analysis["reason"])

        packet_result = packet_analysis.build_packet_result(
            3,
            {"time": 1.5, "src": "192.0.2.10", "dst": "198.51.100.10", "proto": 6, "len": 128},
            analysis,
        )
        self.assertEqual(packet_result["id"], 3)
        self.assertEqual(packet_result["analysis"]["firewall_action"], "Blocked")


class TrafficAnalyzerProtocolTests(unittest.TestCase):
    def test_behavior_session_to_dict(self) -> None:
        session = traffic_analyzer.BehaviorSession(
            session_id="sess_1_example",
            main_domain="example.com",
            start_time=1712345600,
            last_updated=1712345665,
        )
        session.add_request(
            domain="example.com",
            full_host="www.example.com",
            timestamp=1712345665,
            source="http_host",
            src_ip="192.0.2.10",
            dst_ip="198.51.100.10",
            packet_bytes=128,
            app_name="Example",
            category="work",
            search_event={
                "captured_at": "2024-04-05 19:47:45",
                "src_ip": "192.0.2.10",
                "domain": "example.com",
                "engine": "google",
                "keyword": "secflow",
                "evidence_level": "high",
            },
            violations=[
                {
                    "captured_at": "2024-04-05 19:47:45",
                    "src_ip": "192.0.2.10",
                    "domain": "example.com",
                    "violation_type": "high_risk_keyword",
                    "severity": "medium",
                    "reason": "matched keyword: secflow",
                }
            ],
        )
        session.main_service = "Example"
        session.service_type = "work"
        session.service_type_label = "Work"
        session.service_icon = "Work"
        session.productivity_category = "Productive"
        session.risk_score = 12
        session.risk_level = "low"
        session.risk_reason = "heuristic fallback"
        session.behavior_chain = ["Visited example.com", "Requested HTTP content"]
        session.analysis_source = "heuristic"

        snapshot = session.to_dict()

        self.assertEqual(snapshot["session_id"], "sess_1_example")
        self.assertEqual(snapshot["main_service"], "Example")
        self.assertEqual(snapshot["main_domain"], "example.com")
        self.assertEqual(snapshot["full_host"], "www.example.com")
        self.assertEqual(snapshot["src_ip"], "192.0.2.10")
        self.assertEqual(snapshot["dst_ip"], "198.51.100.10")
        self.assertEqual(snapshot["request_count"], 1)
        self.assertEqual(snapshot["analysis_source"], "heuristic")
        self.assertEqual(snapshot["requests"][0]["source"], "http_host")
        self.assertEqual(snapshot["search_events"][0]["keyword"], "secflow")
        self.assertEqual(snapshot["violations"][0]["violation_type"], "high_risk_keyword")

    def test_parse_ai_response_with_markdown_json(self) -> None:
        analyzer = traffic_analyzer.TrafficAnalyzer(interface="eth0")
        parsed = analyzer._parse_ai_response(
            """```json
            {"main_service":"Example","service_type":"work","risk_score":12,"risk_level":"low"}
            ```"""
        )
        self.assertEqual(parsed["main_service"], "Example")
        self.assertEqual(parsed["service_type"], "work")
        self.assertEqual(parsed["risk_score"], 12)


class PacketPayloadTests(unittest.TestCase):
    def test_extract_http_request_line(self) -> None:
        request_line = packet_payloads.extract_http_request_line(
            "GET /search?q=secflow HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        self.assertEqual(request_line, "GET /search?q=secflow HTTP/1.1")
        self.assertIsNone(packet_payloads.extract_http_request_line("not an http request"))

    def test_describe_payload_marks_http_and_binary(self) -> None:
        http_payload = packet_payloads.describe_payload(
            b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=a"
        )
        self.assertTrue(http_payload["http_detected"])
        self.assertEqual(http_payload["http_request_line"], "POST /login HTTP/1.1")
        self.assertIn("POST /login", http_payload["payload"])

        class BrokenPayload:
            def __bytes__(self) -> bytes:
                raise ValueError("bad payload")

            def __len__(self) -> int:
                return 7

        binary_payload = packet_payloads.describe_payload(BrokenPayload())
        self.assertEqual(binary_payload["payload"], "<binary data, 7 bytes>")


class OutputMessageTests(unittest.TestCase):
    def test_build_output_payload(self) -> None:
        output = output_messages.build_output_payload(nics=[{"name": "eth0"}], total=1)
        self.assertEqual(
            output,
            {
                "nics": [{"name": "eth0"}],
                "total": 1,
            },
        )

    def test_build_error_output(self) -> None:
        output = output_messages.build_error_output(RuntimeError("boom"))
        self.assertEqual(output, {"error": "boom"})

    def test_build_output_message(self) -> None:
        output = output_messages.build_output_message("status", message="running", count=2)
        self.assertEqual(
            output,
            {
                "type": "status",
                "message": "running",
                "count": 2,
            },
        )

    def test_build_output_message_allows_payload_override(self) -> None:
        output = output_messages.build_output_message("status", type="custom", message="running")
        self.assertEqual(output["type"], "custom")
        self.assertEqual(output["message"], "running")

    def test_build_status_output_message(self) -> None:
        output = output_messages.build_status_output_message("running")
        self.assertEqual(
            output,
            {
                "type": "status",
                "message": "running",
            },
        )

    def test_build_error_output_message(self) -> None:
        output = output_messages.build_error_output_message("failed")
        self.assertEqual(
            output,
            {
                "type": "error",
                "message": "failed",
            },
        )

    def test_build_activity_log_message(self) -> None:
        output = output_messages.build_activity_log_message([{"domain": "example.com"}])
        self.assertEqual(
            output,
            {
                "type": "activity_log",
                "data": [{"domain": "example.com"}],
            },
        )

    def test_build_security_alert_message(self) -> None:
        output = output_messages.build_security_alert_message(
            message="Suspicious domain detected: example.com",
            timestamp="2026-04-26 18:00:00",
            ip="192.0.2.10",
            domain="example.com",
            alert_type="malicious_domain",
            severity="critical",
        )
        self.assertEqual(
            output,
            {
                "type": "security_alert",
                "message": "Suspicious domain detected: example.com",
                "timestamp": "2026-04-26 18:00:00",
                "ip": "192.0.2.10",
                "domain": "example.com",
                "alert_type": "malicious_domain",
                "severity": "critical",
            },
        )

    def test_build_behavior_report_message(self) -> None:
        output = output_messages.build_behavior_report_message(
            timestamp="2026-04-26 18:00:00",
            total_ips=1,
            reports=[{"ip": "192.0.2.10", "risk_score": 40}],
        )
        self.assertEqual(
            output,
            {
                "type": "behavior_report",
                "timestamp": "2026-04-26 18:00:00",
                "total_ips": 1,
                "reports": [{"ip": "192.0.2.10", "risk_score": 40}],
            },
        )

    def test_build_timed_output_message(self) -> None:
        output = output_messages.build_timed_output_message(
            "realtime_data",
            "realtime data",
            1712345678,
            {"nics": ["eth0"]},
        )
        self.assertEqual(
            output,
            {
                "type": "realtime_data",
                "message": "realtime data",
                "timestamp": 1712345678,
                "data": {"nics": ["eth0"]},
            },
        )


class InterfaceDiscoveryTests(unittest.TestCase):
    def test_should_skip_windows_interface(self) -> None:
        self.assertTrue(interface_discovery.should_skip_windows_interface("Npcap Packet Driver (NPCAP)"))
        self.assertFalse(interface_discovery.should_skip_windows_interface("Intel(R) Ethernet Controller"))

    def test_unique_name(self) -> None:
        existing = {"Wi-Fi"}
        self.assertEqual(interface_discovery.unique_name(existing, "Wi-Fi"), "Wi-Fi (2)")
        self.assertEqual(interface_discovery.unique_name(existing, "Ethernet"), "Ethernet")

    def test_normalize_windows_interface_rows(self) -> None:
        rows = [
            {"rawName": "eth0", "displayName": "Ethernet"},
            {"rawName": "eth0", "displayName": "Ethernet duplicate"},
            {"rawName": "npcap", "displayName": "Npcap Packet Driver (NPCAP)"},
            {"rawName": "wlan0", "displayName": ""},
        ]
        self.assertEqual(
            interface_discovery.normalize_windows_interface_rows(rows),
            [
                {"rawName": "eth0", "displayName": "Ethernet"},
                {"rawName": "wlan0", "displayName": "wlan0"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
