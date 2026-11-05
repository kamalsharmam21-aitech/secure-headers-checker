
#!/usr/bin/env python3
"""SecureHeaders Checker: inspect HTTP security response headers."""

import argparse
import ipaddress
import json
import socket
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

USER_AGENT = (
    "SecureHeadersChecker/1.0 "
    "(https://github.com/kamalsharmam21-aitech/secure-headers-checker)"
)
TIMEOUT = 10


class TargetError(ValueError):
    """Raised when a target URL is not permitted."""


def validate_target(target):
    """Allow only HTTP(S) URLs resolving exclusively to public IPs."""
    target = target.strip()

    if not target:
        raise TargetError("Please provide a website URL.")

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise TargetError("A valid hostname is required.")

    if parsed.username or parsed.password:
        raise TargetError("URLs containing credentials are not allowed.")

    if parsed.port is not None and parsed.port not in {80, 443}:
        raise TargetError("Only standard ports 80 and 443 are allowed.")

    if parsed.scheme.lower() == "https" and parsed.port == 80:
        raise TargetError("Port 80 cannot be used with HTTPS.")

    if parsed.scheme.lower() == "http" and parsed.port == 443:
        raise TargetError("Port 443 cannot be used with HTTP.")

    host = parsed.hostname

    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )
        except socket.gaierror as exc:
            raise TargetError(f"Hostname resolution failed: {exc}") from exc

        addresses = {
            ipaddress.ip_address(record[4][0])
            for record in records
        }

    if not addresses:
        raise TargetError("Hostname did not resolve.")

    for address in addresses:
        if not address.is_global:
            raise TargetError(
                "Private, local, or non-public destinations are not allowed."
            )

    return parsed._replace(fragment="").geturl()


def has_frame_ancestors(csp):
    """Check whether CSP defines a frame-ancestors directive."""
    for directive in csp.split(";"):
        parts = directive.strip().lower().split()

        if parts and parts[0] == "frame-ancestors":
            return len(parts) > 1

    return False


def inspect_headers(headers, scheme):
    """Evaluate common HTTP security response headers."""
    values = {
        str(key).lower(): str(value).strip()
        for key, value in headers.items()
    }

    checks = []

    def add(name, present, guidance, detail=""):
        checks.append({
            "header": name,
            "status": "PRESENT" if present else "MISSING",
            "detail": detail,
            "remediation": guidance,
        })

    csp = values.get("content-security-policy", "")

    add(
        "Content-Security-Policy",
        bool(csp),
        "Define a restrictive CSP. Start with default-src 'self' "
        "and explicitly allow required resources. Test using "
        "Content-Security-Policy-Report-Only before enforcement.",
        csp,
    )

    if scheme == "https":
        hsts = values.get("strict-transport-security", "")

        add(
            "Strict-Transport-Security",
            bool(hsts),
            "Configure HSTS with an appropriate max-age, commonly "
            "at least 31536000 seconds, after confirming HTTPS "
            "works across the site.",
            hsts,
        )
    else:
        checks.append({
            "header": "Strict-Transport-Security",
            "status": "NOT_APPLICABLE",
            "detail": "Browsers honor HSTS only when received over HTTPS.",
            "remediation": "Enable HTTPS and return the HSTS header "
            "over HTTPS.",
        })

    xcto = values.get("x-content-type-options", "")

    add(
        "X-Content-Type-Options",
        xcto.lower() == "nosniff",
        "Return X-Content-Type-Options: nosniff.",
        xcto,
    )

    referrer = values.get("referrer-policy", "")

    add(
        "Referrer-Policy",
        bool(referrer),
        "Consider strict-origin-when-cross-origin to limit "
        "referrer information shared with other websites.",
        referrer,
    )

    permissions = values.get("permissions-policy", "")

    add(
        "Permissions-Policy",
        bool(permissions),
        "Define a Permissions-Policy that disables browser "
        "features the application does not need.",
        permissions,
    )

    xfo = values.get("x-frame-options", "")
    frame_protected = (
        xfo.lower() in {"deny", "sameorigin"}
        or has_frame_ancestors(csp)
    )

    add(
        "Clickjacking protection",
        frame_protected,
        "Configure X-Frame-Options: DENY or SAMEORIGIN, "
        "or use CSP frame-ancestors.",
        xfo or (
            "CSP frame-ancestors configured."
            if has_frame_ancestors(csp)
            else ""
        ),
    )

    return checks


def check_website(target):
    """Make one GET request and inspect the first response."""
    safe_url = validate_target(target)
    parsed = urlparse(safe_url)

    response = None

    try:
        response = requests.get(
            safe_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            },
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
        )

        checks = inspect_headers(
            response.headers,
            parsed.scheme.lower(),
        )

        return {
            "target": safe_url,
            "checked_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "http_status": response.status_code,
            "redirect_followed": False,
            "checks": checks,
            "summary": {
                "present": sum(
                    item["status"] == "PRESENT"
                    for item in checks
                ),
                "missing": sum(
                    item["status"] == "MISSING"
                    for item in checks
                ),
                "not_applicable": sum(
                    item["status"] == "NOT_APPLICABLE"
                    for item in checks
                ),
            },
            "limitations": [
                "This is a response-header check, not a penetration test.",
                "Header presence does not prove policy correctness.",
                "Redirects are not followed.",
                "DNS validation before a request does not fully "
                "protect against DNS rebinding.",
            ],
        }

    finally:
        if response is not None:
            response.close()


def print_report(report):
    """Display a readable terminal report."""
    print(f"\nSecureHeaders Checker — {report['target']}")
    print(f"HTTP status: {report['http_status']}")
    print("-" * 72)

    for item in report["checks"]:
        print(f"{item['status']:15} {item['header']}")

        if item["detail"]:
            print(f"                Value: {item['detail']}")

        if item["status"] == "MISSING":
            print(f"                Fix: {item['remediation']}")

    summary = report["summary"]

    print("-" * 72)
    print(
        f"Summary: {summary['present']} present | "
        f"{summary['missing']} missing | "
        f"{summary['not_applicable']} not applicable"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Check HTTP security headers on public websites "
            "you own or are authorized to assess."
        )
    )

    parser.add_argument(
        "url",
        help="Website URL, e.g. https://example.com",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        help="Save the report to a JSON file.",
    )

    args = parser.parse_args()

    try:
        report = check_website(args.url)

    except TargetError as exc:
        print(f"Target rejected: {exc}", file=sys.stderr)
        return 2

    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print_report(report)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")

        print(f"\nJSON report saved to: {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
