"""Tests des règles de détection du module logs."""

import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from src.logs import compute_stats, detect, read_logs


class DetectTests(unittest.TestCase):
    def setUp(self):
        self.rules = {
            "R1": {"max_failures": 3, "window_minutes": 10},
            "R2": {"min_failures": 2, "window_minutes": 10},
        }

    @staticmethod
    def event(minute, event_type="FAILURE", user="alice", ip="192.0.2.10"):
        return {
            "date": datetime(2026, 11, 25, 10, minute),
            "type": event_type,
            "user": user,
            "ip": ip,
        }

    def test_r1_alerts_inside_window_but_not_outside(self):
        inside = [self.event(0), self.event(4), self.event(9)]
        outside = [self.event(0), self.event(11), self.event(22)]

        self.assertEqual([a["rule"] for a in detect(inside, self.rules)], ["R1"])
        self.assertEqual(detect(outside, self.rules), [])

    def test_r2_requires_prior_failures_for_same_user_and_ip(self):
        matching = [self.event(1), self.event(5), self.event(6, "SUCCESS")]
        wrong_user = [self.event(1), self.event(5), self.event(6, "SUCCESS", user="bob")]
        too_old = [self.event(0), self.event(11), self.event(12, "SUCCESS")]

        matching_alerts = detect(matching, self.rules)
        self.assertIn("R2", [alert["rule"] for alert in matching_alerts])
        self.assertNotIn("R2", [alert["rule"] for alert in detect(wrong_user, self.rules)])
        self.assertNotIn("R2", [alert["rule"] for alert in detect(too_old, self.rules)])

    def test_same_data_produces_stable_alert_ids(self):
        events = [self.event(1), self.event(2), self.event(3)]
        first = detect(events, self.rules)
        second = detect(events, self.rules)
        self.assertEqual([a["id"] for a in first], [a["id"] for a in second])

    def test_read_logs_sorts_events_and_counts_unrecognized_lines(self):
        # Le fichier temporaire évite d'ajouter des données de test au dépôt.
        with TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "auth_ssh.txt"
            log_path.write_text(
                "Nov 25 10:02:00 host sshd[22]: Failed password for alice from 192.0.2.10 port 22 ssh2\n"
                "ligne volontairement inconnue\n"
                "Nov 25 10:01:00 host sshd[21]: Accepted password for bob from 192.0.2.11 port 22 ssh2\n",
                encoding="utf-8",
            )

            events, unrecognized_count = read_logs([log_path], 2026)

        self.assertEqual(unrecognized_count, 1)
        self.assertEqual([event["type"] for event in events], ["SUCCESS", "FAILURE"])
        self.assertEqual(events[0]["date"], datetime(2026, 11, 25, 10, 1))

    def test_stats_count_failures_only_and_return_top_three(self):
        events = [
            self.event(1, ip="192.0.2.1"),
            self.event(2, ip="192.0.2.1"),
            self.event(3, ip="192.0.2.2"),
            self.event(4, "SUCCESS", ip="192.0.2.3"),
        ]

        stats = compute_stats(events)

        self.assertEqual(stats["failures_by_ip"], {"192.0.2.1": 2, "192.0.2.2": 1})
        self.assertEqual(stats["failures_by_user"], {"alice": 3})
        self.assertEqual(stats["top3_ips"][0], {"ip": "192.0.2.1", "failures": 2})


if __name__ == "__main__":
    unittest.main()
