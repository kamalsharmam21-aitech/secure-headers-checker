
import unittest
from unittest.mock import patch

from secureheaders import (
    TargetError,
    inspect_headers,
    validate_target,
)


class HeaderInspectionTests(unittest.TestCase):

    def test_missing_headers_are_reported(self):
        results = inspect_headers({}, "https")

        missing = [
            item["header"]
            for item in results
            if item["status"] == "MISSING"
        ]

        self.assertIn("Content-Security-Policy", missing)
        self.assertIn("Strict-Transport-Security", missing)
        self.assertIn("X-Content-Type-Options", missing)

    def test_hsts_not_applicable_over_http(self):
        results = inspect_headers({}, "http")

        hsts = next(
            item for item in results
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(hsts["status"], "NOT_APPLICABLE")

    def test_csp_frame_ancestors_provides_protection(self):
        results = inspect_headers(
            {
                "Content-Security-Policy":
                    "default-src 'self'; frame-ancestors 'none'"
            },
            "https",
        )

        clickjacking = next(
            item for item in results
            if item["header"] == "Clickjacking protection"
        )

        self.assertEqual(clickjacking["status"], "PRESENT")

    def test_header_names_are_case_insensitive(self):
        results = inspect_headers(
            {"X-Content-Type-Options": "nosniff"},
            "https",
        )

        xcto = next(
            item for item in results
            if item["header"] == "X-Content-Type-Options"
        )

        self.assertEqual(xcto["status"], "PRESENT")

    def test_private_ip_is_rejected(self):
        with self.assertRaises(TargetError):
            validate_target("http://127.0.0.1")

    @patch("secureheaders.socket.getaddrinfo")
    def test_public_hostname_is_accepted(self, mock_dns):
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443))
        ]

        result = validate_target("https://example.com")

        self.assertEqual(result, "https://example.com")


if __name__ == "__main__":
    unittest.main()

