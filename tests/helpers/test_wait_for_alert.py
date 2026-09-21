"""Non-root regression tests; no attack simulations or host changes are run."""

from datetime import datetime, timedelta, timezone
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import wait_for_alert as verifier


class AlertVerificationTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.until = self.start + timedelta(seconds=1)
        self.alert = {
            "ts": self.start.isoformat(),
            "ref_id": "HER-2026-0921-001",
            "severity": "High",
            "title": "Web server spawned a shell",
            "detection": "D1",
        }

    def match(self, **changes):
        alert = dict(self.alert, **changes)
        return verifier.matching_alert(
            json.dumps(alert), self.start, self.until, "Web server"
        )

    def test_accepts_fresh_high_and_critical(self):
        for severity in ("High", "Critical"):
            with self.subTest(severity=severity):
                self.assertIsNotNone(self.match(severity=severity))

    def test_rejects_old_alert_even_in_same_second(self):
        old = self.start - timedelta(microseconds=1)
        self.assertIsNone(self.match(ts=old.isoformat()))

    def test_rejects_future_alert(self):
        future = self.until + timedelta(microseconds=1)
        self.assertIsNone(self.match(ts=future.isoformat()))

    def test_compares_timestamps_not_strings(self):
        offset = timezone(timedelta(hours=2))
        self.assertIsNotNone(self.match(ts=self.start.astimezone(offset).isoformat()))
        self.assertIsNotNone(self.match(ts=self.start.isoformat().replace("+00:00", "Z")))
        self.assertIsNotNone(self.match(ts=self.start.isoformat().replace("+00:00", "000Z")))

    def test_accepts_chrono_fractional_timestamp_formats(self):
        for fraction in ("", ".1", ".123", ".123456", ".123456789"):
            with self.subTest(fraction=fraction):
                stamp = verifier.parse_timestamp("2026-09-21T12:00:00" + fraction + "Z")
                self.assertEqual(stamp.tzinfo, timezone.utc)
                self.assertEqual(stamp.microsecond, int(fraction[1:7].ljust(6, "0")))

    def test_rejects_low_severity_even_when_title_matches(self):
        for severity in ("Info", "Low"):
            with self.subTest(severity=severity):
                self.assertIsNone(self.match(severity=severity))

    def test_matches_only_title_not_other_fields(self):
        self.assertIsNone(self.match(title="Unrelated alert", what="Web server"))
        self.assertIsNone(verifier.matching_alert(
            json.dumps(self.alert), self.start, self.until, "D1"
        ))

    def test_empty_store_does_not_pass(self):
        self.assertIsNone(verifier.matching_alert("\n", self.start, self.until, "Web server"))

    def test_malformed_records_fail_closed(self):
        for output in ("not JSON", "[]", "null", "{}", '{"severity":"High"}'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                verifier.matching_alert(output, self.start, self.until, "Web server")
        for changes in ({"ts": "invalid"}, {"ts": "2026-09-21T00:00:00"},
                        {"severity": "unknown"}, {"title": None}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.match(**changes)

    def test_bad_record_after_match_still_fails(self):
        with self.assertRaises(ValueError):
            verifier.matching_alert(
                json.dumps(self.alert) + "\ninvalid", self.start, self.until, "Web server"
            )

    def test_empty_pattern_is_rejected(self):
        with self.assertRaises(ValueError):
            verifier.matching_alert(json.dumps(self.alert), self.start, self.until, "")

    @patch.object(verifier.time, "sleep")
    @patch.object(verifier.time, "monotonic", return_value=0)
    @patch.object(verifier.subprocess, "run")
    def test_polls_until_fresh_evidence(self, run, monotonic, sleep):
        old = dict(self.alert, ts=(self.start - timedelta(seconds=1)).isoformat())
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=json.dumps(old)),
            subprocess.CompletedProcess([], 0, stdout=json.dumps(self.alert)),
        ]
        self.assertEqual(verifier.wait_for_alert(self.start, "Web server"), self.alert)
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(0.5)
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

    @patch.object(verifier.time, "sleep")
    @patch.object(verifier.time, "monotonic", side_effect=[0, 0, 30, 30])
    @patch.object(verifier.subprocess, "run")
    def test_empty_results_time_out(self, run, monotonic, sleep):
        run.return_value = subprocess.CompletedProcess([], 0, stdout="")
        self.assertIsNone(verifier.wait_for_alert(self.start, "Web server"))
        run.assert_called_once()

    @patch.object(verifier.subprocess, "run")
    def test_failed_queries_never_pass(self, run):
        errors = (
            FileNotFoundError("hermian"),
            subprocess.CalledProcessError(1, "hermian", output=json.dumps(self.alert)),
            subprocess.TimeoutExpired("hermian", 5),
        )
        for error in errors:
            with self.subTest(error=error), self.assertRaises(type(error)):
                run.side_effect = error
                verifier.wait_for_alert(self.start, "Web server")

    def test_cli_exit_codes(self):
        cases = (
            (self.alert, None, 0),
            (None, None, 1),
            (None, ValueError("malformed response"), 2),
            (None, subprocess.CalledProcessError(1, "hermian"), 2),
        )
        for result, error, expected in cases:
            with self.subTest(expected=expected, error=error):
                with patch.object(verifier.sys, "argv", [
                    "wait_for_alert.py", self.start.isoformat(), "Web server"
                ]), patch.object(verifier, "wait_for_alert", return_value=result,
                                 side_effect=error), patch.object(
                    verifier.sys, "stdout", new_callable=io.StringIO
                ) as stdout, patch.object(verifier.sys, "stderr", new_callable=io.StringIO):
                    self.assertEqual(verifier.main(), expected)
                    self.assertEqual("Evidence:" in stdout.getvalue(), expected == 0)


if __name__ == "__main__":
    unittest.main()
