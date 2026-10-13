
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
        home.raw.headers.getlist = Mock(return_value=[])
        redir = Mock()
        redir.status_code = 302
        redir.headers = {
            "Location": "https://example.invalid/vulnsight-redirect-probe"
        }
        client.get.side_effect = [home, redir]

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

    def test_rejects_non_local(self):
        with self.assertRaises(ValueError):
            check_local_target("http://example.com")


if __name__ == "__main__":
    unittest.main()
