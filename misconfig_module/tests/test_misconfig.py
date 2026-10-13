
import unittest
from unittest.mock import Mock, patch

from misconfig.detector import check_local_target


class TestMisconfig(unittest.TestCase):
    @patch("misconfig.detector.requests.Session")
    def test_detects_missing_security_headers(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client
        resp = Mock()
        resp.url = "http://127.0.0.1:5000/"
        resp.headers = {"Content-Type": "text/html"}
        resp.text = "<html></html>"
        resp.status_code = 200
        resp.raw.headers.getlist = Mock(return_value=[])
        client.get.return_value = resp

        result = check_local_target("http://127.0.0.1:5000")
        titles = [f.title for f in result.findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("X-Frame-Options" in t for t in titles))

    @patch("misconfig.detector.requests.Session")
    def test_csrf_form_without_token(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client
        resp = Mock()
        resp.url = "http://127.0.0.1:5000/"
        resp.headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
        resp.text = "<html></html>"
        resp.status_code = 200
        resp.raw.headers.getlist = Mock(return_value=[])
        client.get.return_value = resp

        crawl = {
            "forms": [
                {
                    "action": "http://127.0.0.1:5000/transfer",
                    "method": "POST",
                    "fields": [{"name": "amount", "input_type": "text"}],
                }
            ],
            "pages": [],
            "endpoints": [],
        }
        result = check_local_target("http://127.0.0.1:5000", crawl_map=crawl)
        self.assertTrue(any("CSRF" in f.title for f in result.findings))

    @patch("misconfig.detector.requests.Session")
    def test_open_redirect_from_crawl_link(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client
        home = Mock()
        home.url = "http://127.0.0.1:5000/"
        home.headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
        home.text = "<html></html>"
        home.status_code = 200
        home.raw.headers.getlist = Mock(return_value=[])
        redir = Mock()
        redir.status_code = 302
        redir.text = ""
        redir.headers = {
            "Location": "https://example.invalid/vulnsight-redirect-probe"
        }
        err = Mock()
        err.status_code = 404
        err.text = "Not Found"
        client.get.side_effect = [home, redir, err]

        crawl = {
            "forms": [],
            "pages": [
                {
                    "url": "http://127.0.0.1:5000/",
                    "params": [],
                    "links": ["http://127.0.0.1:5000/go?next=/"],
                }
            ],
            "endpoints": [],
        }
        result = check_local_target("http://127.0.0.1:5000", crawl_map=crawl)
        self.assertTrue(any("Open redirect" in f.title for f in result.findings))

    @patch("misconfig.detector.requests.Session")
    def test_tech_disclosure_and_cleartext_login(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client
        resp = Mock()
        resp.url = "http://127.0.0.1:5000/"
        resp.headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Server": "Werkzeug/3.0.0 Python/3.12",
            "X-Powered-By": "DemoLab",
        }
        resp.text = "<html></html>"
        resp.status_code = 200
        resp.raw.headers.getlist = Mock(return_value=[])
        client.get.return_value = resp
        crawl = {
            "forms": [
                {
                    "action": "http://127.0.0.1:5000/login",
                    "method": "POST",
                    "fields": [
                        {"name": "username", "input_type": "text"},
                        {"name": "password", "input_type": "password"},
                    ],
                }
            ],
            "pages": [],
            "endpoints": [],
        }
        result = check_local_target("http://127.0.0.1:5000", crawl_map=crawl)
        titles = [f.title for f in result.findings]
        self.assertTrue(any("Technology disclosure" in t for t in titles))
        self.assertTrue(any("cleartext HTTP" in t for t in titles))
        owasps = {f.owasp for f in result.findings}
        self.assertTrue(any(o and o.startswith("A03:2025") for o in owasps))
        self.assertTrue(any(o and o.startswith("A04:2025") for o in owasps))

    @patch("misconfig.detector.requests.Session")
    def test_ssrf_candidate_signal(self, mock_session):
        client = Mock()
        mock_session.return_value.__enter__.return_value = client
        home = Mock()
        home.url = "http://127.0.0.1:5000/"
        home.headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
        home.raw.headers.getlist = Mock(return_value=[])
        baseline = Mock()
        baseline.status_code = 200
        baseline.text = "ok"
        test = Mock()
        test.status_code = 200
        test.text = "Failed to connect to 127.0.0.1:9 (vulnsight-ssrf-probe)"
        home.text = "<html></html>"
        home.status_code = 200
        err = Mock()
        err.status_code = 404
        err.text = "Not Found"
        client.get.side_effect = [home, baseline, test, err]
        crawl = {
            "forms": [],
            "pages": [
                {
                    "url": "http://127.0.0.1:5000/fetch",
                    "params": [{"name": "target_url"}],
                    "links": [],
                }
            ],
            "endpoints": [],
        }
        result = check_local_target("http://127.0.0.1:5000", crawl_map=crawl, max_requests=10)
        self.assertTrue(any("SSRF" in f.title for f in result.findings))
        ssrf = next(f for f in result.findings if "SSRF" in f.title)
        self.assertTrue(ssrf.owasp.startswith("A01:2025"))

    def test_rejects_non_local(self):
        with self.assertRaises(ValueError):
            check_local_target("http://example.com")


if __name__ == "__main__":
    unittest.main()
