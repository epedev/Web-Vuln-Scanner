import unittest
from unittest.mock import Mock, patch

from sqli.detector import check_local_target, inspect_response


class TestSQLi(unittest.TestCase):
    @patch("sqli.detector.requests.Session")
    def test_detects_expected_login_bypass_behavior(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client

        baseline = Mock(status_code=200, text="Invalid credentials")
        test = Mock(status_code=302, headers={"Location": "/"})
        client.post.side_effect = [baseline, test]

        result = check_local_target("http://127.0.0.1:5000")

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].cwe, "CWE-89")
        self.assertEqual(result.stats["requests_sent"], 2)

    def test_rejects_non_local_target(self):
        with self.assertRaises(ValueError):
            check_local_target("http://example.com")

    def test_detects_database_error_signature(self):
        result = inspect_response(
            url="http://127.0.0.1:5000/login",
            parameter="username",
            test_value="test-input",
            response_text="sqlite3.OperationalError: near input",
            http_status=500,
        )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].cwe, "CWE-89")

    def test_ignores_normal_response(self):
        result = inspect_response(
            url="http://127.0.0.1:5000/login",
            parameter="username",
            test_value="ordinary-input",
            response_text="Invalid credentials",
            http_status=200,
        )

        self.assertEqual(result.findings, [])



    @patch("sqli.detector.requests.Session")
    def test_crawl_map_error_based(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client

        baseline = Mock(status_code=200, text="Invalid credentials", headers={})
        bypass = Mock(status_code=200, text="still invalid", headers={})
        err = Mock(
            status_code=500,
            text="sqlite3.OperationalError: near \'\'",
            headers={},
        )
        # login baseline+test, then GET error-based probes until match
        client.post.side_effect = [baseline, bypass]
        client.get.return_value = err
        client.request.return_value = err

        crawl = {
            "forms": [],
            "pages": [
                {
                    "url": "http://127.0.0.1:5000/search",
                    "params": [{"name": "q", "value": "x", "source": "query"}],
                }
            ],
        }
        result = check_local_target("http://127.0.0.1:5000", crawl_map=crawl)
        self.assertTrue(any("error-based" in f.title.lower() for f in result.findings))


if __name__ == "__main__":
    unittest.main()
