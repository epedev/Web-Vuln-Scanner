import unittest
from unittest.mock import Mock, patch

from access_control.detector import (
    check_broken_access_control,
    check_idor,
    check_local_target,
)


class TestIDOR(unittest.TestCase):
    def test_detects_cross_user_profile_access(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200, text="x" * 50)

        result = check_idor(
            "http://127.0.0.1:5000", session, own_user_id=1, probe_ids=[1, 2, 3]
        )

        # own_user_id (1) is skipped; 2 and 3 both return 200 -> two findings
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].cwe, "CWE-639")
        self.assertEqual(result.stats["requests_sent"], 2)

    def test_no_finding_when_access_denied(self):
        session = Mock()
        session.get.return_value = Mock(status_code=403, text="Forbidden")

        result = check_idor(
            "http://127.0.0.1:5000", session, own_user_id=1, probe_ids=[1, 2]
        )

        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.outcomes), 1)

    def test_skips_own_user_id(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200, text="x")

        result = check_idor(
            "http://127.0.0.1:5000", session, own_user_id=1, probe_ids=[1]
        )

        session.get.assert_not_called()
        self.assertEqual(result.findings, [])

    def test_rejects_non_local_target(self):
        session = Mock()
        with self.assertRaises(ValueError):
            check_idor("http://example.com", session, own_user_id=1, probe_ids=[2])


class TestBrokenAccessControl(unittest.TestCase):
    def test_detects_privileged_path_reachable(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200, text="x" * 100)

        result = check_broken_access_control("http://127.0.0.1:5000", session)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].cwe, "CWE-284")
        self.assertEqual(result.findings[0].severity, "critical")

    def test_no_finding_when_denied(self):
        session = Mock()
        session.get.return_value = Mock(status_code=403, text="Forbidden")

        result = check_broken_access_control("http://127.0.0.1:5000", session)

        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.outcomes), 1)

    def test_rejects_non_local_target(self):
        session = Mock()
        with self.assertRaises(ValueError):
            check_broken_access_control("http://example.com", session)


class TestCheckLocalTarget(unittest.TestCase):
    @patch("access_control.detector.check_unauthenticated_access")
    @patch("access_control.detector.login")
    @patch("access_control.detector.check_broken_access_control")
    @patch("access_control.detector.check_idor")
    def test_combines_idor_and_bac_results(
        self, mock_idor, mock_bac, mock_login, mock_unauth
    ):
        mock_login.return_value = Mock()
        mock_unauth.return_value = Mock(
            findings=[], outcomes=[], errors=[], stats={"requests_sent": 0}
        )

        idor_result = Mock(
            findings=["idor-finding"], outcomes=[], errors=[], stats={"requests_sent": 2}
        )
        bac_result = Mock(
            findings=["bac-finding"], outcomes=[], errors=[], stats={"requests_sent": 1}
        )
        mock_idor.return_value = idor_result
        mock_bac.return_value = bac_result

        result = check_local_target("http://127.0.0.1:5000")

        self.assertEqual(len(result.findings), 2)
        # authenticated probes + logins (+ unauth mocked as 0)
        self.assertGreaterEqual(result.stats["requests_sent"], 5)

    def test_rejects_non_local_target(self):
        with self.assertRaises(ValueError):
            check_local_target("http://example.com")


if __name__ == "__main__":
    unittest.main()
