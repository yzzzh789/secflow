from __future__ import annotations

import unittest

from lan_behavior_monitor import IPBehaviorTracker, LANBehaviorMonitor


class CapturingLANBehaviorMonitor(LANBehaviorMonitor):
    def __init__(self) -> None:
        super().__init__(interface="test0", threat_intel_enabled=True)
        self.outputs: list[dict] = []

    def _emit_output(self, output):
        self.outputs.append(output)


class LANBehaviorMonitorUnitTests(unittest.TestCase):
    def test_ip_behavior_tracker_summary_includes_risk_and_top_domains(self) -> None:
        tracker = IPBehaviorTracker("192.168.1.10")
        tracker.first_seen = 1000.0

        tracker.add_domain_access(
            "video.example",
            {"category": "video", "label": "Video", "risk": "low"},
            packet_size=2048,
            direction="out",
            timestamp=1001.0,
        )
        for offset in range(12):
            tracker.add_domain_access(
                "malware.example",
                {"category": "security", "label": "Malware", "risk": "critical"},
                packet_size=1024,
                direction="in",
                timestamp=1002.0 + offset,
            )

        summary = tracker.get_summary()

        self.assertEqual(summary["ip"], "192.168.1.10")
        self.assertEqual(summary["total_requests"], 13)
        self.assertEqual(summary["unique_domains"], 2)
        self.assertEqual(summary["risk_level"], "high")
        self.assertGreaterEqual(summary["risk_score"], 70)
        self.assertEqual(summary["top_domains"][0]["domain"], "malware.example")
        self.assertEqual(summary["top_domains"][0]["count"], 12)
        self.assertEqual(summary["category_stats"]["video"]["count"], 1)
        self.assertEqual(len(summary["risk_events"]), 1)
        self.assertEqual(summary["risk_events"][0]["domain"], "malware.example")

    def test_check_threat_intel_uses_keyword_cache_and_ignores_ips(self) -> None:
        monitor = CapturingLANBehaviorMonitor()

        self.assertFalse(monitor._check_threat_intel("203.0.113.10", "192.168.1.10"))
        self.assertEqual(monitor.outputs, [])

        self.assertTrue(monitor._check_threat_intel("login-malware.example", "192.168.1.10"))
        self.assertEqual(len(monitor.outputs), 1)
        self.assertIn("login-malware.example", str(monitor.outputs[0]))

        self.assertTrue(monitor._check_threat_intel("login-malware.example", "192.168.1.10"))
        self.assertEqual(len(monitor.outputs), 2)
        self.assertIn("login-malware.example", monitor.threat_cache)


if __name__ == "__main__":
    unittest.main()
