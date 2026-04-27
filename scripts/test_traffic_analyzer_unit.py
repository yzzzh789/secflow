from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import traffic_analyzer as analyzer


def add_test_request(
    session: analyzer.BehaviorSession,
    domain: str,
    timestamp: float,
    source: str,
) -> None:
    app_name, category = analyzer.classify_app_by_domain(domain)
    session.add_request(
        domain=analyzer.root_domain(domain),
        full_host=domain,
        timestamp=timestamp,
        source=source,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.10",
        packet_bytes=0,
        app_name=app_name,
        category=category,
        search_event=None,
        violations=[],
    )


class TrafficAnalyzerHeuristicTests(unittest.TestCase):
    def test_root_domain_keeps_ip_address(self) -> None:
        self.assertEqual(analyzer.root_domain("10.70.20.82"), "10.70.20.82")

    def test_entertainment_session_gets_type_and_score(self) -> None:
        now = time.time()
        session = analyzer.BehaviorSession(
            session_id="sess_video",
            main_domain="www.bilibili.com",
            start_time=now,
            last_updated=now,
        )
        add_test_request(session, "www.bilibili.com", now, "dns")
        add_test_request(session, "api.bilibili.com", now + 1, "tls_sni")
        add_test_request(session, "hdslb.com", now + 2, "tls_sni")

        result = analyzer.TrafficAnalyzer(interface="test0")._heuristic_analysis(session)

        self.assertEqual(result["service_type"], "video")
        self.assertEqual(result["service_type_label"], "视频娱乐")
        self.assertGreater(result["risk_score"], 0)
        self.assertIn(result["risk_level"], {"medium", "high"})

    def test_work_session_stays_lower_than_entertainment(self) -> None:
        now = time.time()
        work_session = analyzer.BehaviorSession(
            session_id="sess_work",
            main_domain="github.com",
            start_time=now,
            last_updated=now,
        )
        add_test_request(work_session, "github.com", now, "dns")
        add_test_request(work_session, "api.github.com", now + 1, "tls_sni")
        work_result = analyzer.TrafficAnalyzer(interface="test0")._heuristic_analysis(work_session)

        video_session = analyzer.BehaviorSession(
            session_id="sess_video_2",
            main_domain="youtube.com",
            start_time=now,
            last_updated=now,
        )
        add_test_request(video_session, "youtube.com", now, "dns")
        add_test_request(video_session, "googlevideo.com", now + 1, "tls_sni")
        video_result = analyzer.TrafficAnalyzer(interface="test0")._heuristic_analysis(video_session)

        self.assertEqual(work_result["service_type"], "work")
        self.assertGreater(video_result["risk_score"], work_result["risk_score"])


if __name__ == "__main__":
    unittest.main()
