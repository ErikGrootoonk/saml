#!/usr/bin/env python3
"""Show validity dates for all .pem certificates in the current directory."""

import glob
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def parse_openssl_date(date_str):
    """Parse openssl date format: 'Jan 25 21:03:48 2026 GMT'"""
    return datetime.strptime(date_str.strip(), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def get_cert_dates(pem_file):
    result = subprocess.run(
        ["openssl", "x509", "-in", pem_file, "-noout", "-dates", "-subject"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None, None, None

    not_before = not_after = subject = None
    for line in result.stdout.splitlines():
        if line.startswith("notBefore="):
            not_before = parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith("notAfter="):
            not_after = parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith("subject="):
            subject = line.split("=", 1)[1].strip()

    return not_before, not_after, subject


def main():
    pem_files = sorted(glob.glob("*.pem"))
    if not pem_files:
        print("No .pem files found in the current directory.")
        return

    now = datetime.now(timezone.utc)

    print(f"Found {len(pem_files)} certificate(s)\n")
    print(f"{'File':<40} {'Valid From':<22} {'Valid Until':<22} {'Status'}")
    print("-" * 100)

    for pem_file in pem_files:
        not_before, not_after, subject = get_cert_dates(pem_file)
        if not_before is None:
            print(f"{pem_file:<40} {'ERROR: could not parse certificate'}")
            continue

        if now < not_before:
            status = "NOT YET VALID"
        elif now > not_after:
            days_expired = (now - not_after).days
            status = f"EXPIRED ({days_expired}d ago)"
        else:
            days_left = (not_after - now).days
            status = f"Valid ({days_left}d remaining)"

        print(
            f"{pem_file:<40} "
            f"{not_before.strftime('%Y-%m-%d %H:%M UTC'):<22} "
            f"{not_after.strftime('%Y-%m-%d %H:%M UTC'):<22} "
            f"{status}"
        )
        if subject:
            print(f"  Subject: {subject}")
        print()


if __name__ == "__main__":
    main()
