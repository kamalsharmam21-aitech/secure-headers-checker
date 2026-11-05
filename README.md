
# SecureHeaders Checker

A lightweight Python command-line tool that checks common HTTP security headers, identifies missing protections, provides remediation guidance, and exports findings as JSON.

## Features

- Checks Content-Security-Policy (CSP)
- Checks Strict-Transport-Security (HSTS)
- Checks X-Content-Type-Options
- Checks Referrer-Policy
- Checks Permissions-Policy
- Checks clickjacking protection
- Generates readable terminal reports
- Exports machine-readable JSON reports
- Uses request timeouts and does not follow redirects
- Rejects private and non-public IP destinations

## Requirements

- Python 3.10 or newer
- Internet access

## Installation

Clone the repository:

    git clone https://github.com/kamalsharmam21-aitech/secure-headers-checker.git

Enter the project directory:

    cd secure-headers-checker

Install dependencies:

    python -m pip install -r requirements.txt

## Usage

Check a website you own or are authorized to assess:

    python secureheaders.py https://example.com

Export the results to JSON:

    python secureheaders.py https://example.com --json report.json

A hostname without a scheme defaults to HTTPS:

    python secureheaders.py example.com

## Run Unit Tests

    python -m unittest discover -s tests -v

## Security and Scope

- Use only on public websites you own or have permission to assess.
- Makes one GET request.
- Does not crawl pages, submit forms, or exploit vulnerabilities.
- Does not follow redirects.
- Allows only standard HTTP/HTTPS ports.
- Checks DNS results before connecting and rejects non-public destinations.

## Limitations

This tool is a basic HTTP response-header checker, not a penetration testing tool, vulnerability scanner, compliance certification, or complete security assessment.

Header presence alone does not prove that a policy is correctly configured or effective. Review each policy in the context of the application.

The DNS validation is a useful local CLI safeguard, not a complete defence against DNS rebinding.

## License

MIT License
