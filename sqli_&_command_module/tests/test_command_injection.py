import unittest
from unittest.mock import Mock, patch

from command_injection.detector import check_local_target


class TestCommandInjection(unittest.TestCase):
    @patch("command_injection.detector.requests.Session")
    def test_detects_output_marker(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client

        baseline = Mock(status_code=200, text="127.0.0.1 ping output")
        test = Mock(status_code=200, text="ping output REDOPS_CMD_TEST")
        client.post.side_effect = [baseline, test]

        result = check_local_target("http://127.0.0.1:5000")

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.cwe, "CWE-78")
        self.assertEqual(result.stats["requests_sent"], 2)
        self.assertTrue(finding.evidence.get("lab_simulation"))
        self.assertFalse(finding.evidence.get("os_shell_executed"))
        self.assertEqual(finding.verification_status, "probable")
        self.assertIn("simulat", finding.description.lower())

    def test_rejects_non_local_target(self):
        with self.assertRaises(ValueError):
            check_local_target("http://example.com")

    @patch("command_injection.detector.requests.Session")
    def test_no_finding_when_marker_is_absent(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client

        baseline = Mock(status_code=200, text="normal ping output")
        test = Mock(status_code=200, text="normal ping output")
        client.post.side_effect = [baseline, test]

        result = check_local_target("http://127.0.0.1:5000")

        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.outcomes), 1)


if __name__ == "__main__":
    unittest.main()
