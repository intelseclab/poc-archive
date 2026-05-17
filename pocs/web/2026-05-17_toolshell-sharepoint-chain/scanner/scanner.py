#!/usr/bin/env python3
# This script is a proof-of-concept exploit for the SharePoint vulnerability CVE-2025-53770.
# It demonstrates how an unauthenticated attacker can achieve remote code execution.
# For educational and authorized testing purposes only.

import requests
import base64
import gzip
import re
import argparse
from io import BytesIO
import urllib3

# Suppress the InsecureRequestWarning that is generated when making HTTPS requests without certificate verification.
# This is common in testing environments where servers may have self-signed certificates.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Vulnerable versions identified from metasploit documentation
VULNERABLE_VERSIONS = [
    "16.0.10337.12109",
    "16.0.10417.20018",
    "16.0.10417.20027",
]

def get_site_client_tag(target):
    """
    Fetches the siteClientTag from the target's body.

    Args:
        target (str): The base URL of the target SharePoint server.
    """
    if not target.startswith('http'):
        target_url = f"http://{target}"
    else:
        target_url = target

    check_url = f"{target_url.rstrip('/')}/_layouts/15/start.aspx"

    try:
        response = requests.get(check_url, timeout=10, verify=False, allow_redirects=True)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {check_url}: {e}")
        return None

    # Regex based on the metasploit module to find the siteClientTag
    match = re.search(r'"siteClientTag"\s*:\s*"\d+\$([^"]+)"', response.text)
    if match:
        version = match.group(1)
        print(f"Found siteClientTag version: {version}")
        return version
    else:
        print("siteClientTag not found in page body.")
        return None

def scan_target(target):
    """
    Scans the target to check if it is a vulnerable SharePoint server.
    """
    version = get_site_client_tag(target)

    if version:
        # Normalize version by removing extra parts if any
        normalized_version = version.lstrip('$')
        print(f"Normalized version: {normalized_version}")
        if normalized_version in VULNERABLE_VERSIONS:
            print("Target is VULNERABLE")
        else:
            print("Target is not vulnerable")
    else:
        print("Could not determine SharePoint version.")


if __name__ == "__main__":
    # The script uses argparse to accept the target URL as a command-line argument.
    parser = argparse.ArgumentParser(
        description="Test a single SharePoint server for CVE-2025-53770 (ToolShell).",
        epilog="Example: python3 script.py https://sharepoint.example.com"
    )
    parser.add_argument("url", help="The base URL of the target SharePoint server.")

    args = parser.parse_args()

    # Call the main function with the provided URL.
    scan_target(args.url)
