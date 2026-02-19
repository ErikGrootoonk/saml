#!/usr/bin/env python3
"""
Download Microsoft Federation Metadata and extract the currently active
SAML signing certificate.

The certificate embedded in the XML <Signature> block is the key Azure AD
is actively using to sign both the metadata document and SAML assertions.
This is the certificate Splunk needs for IdP verification.
"""

import urllib.request
import xml.etree.ElementTree as ET
import textwrap
import sys
import subprocess

METADATA_URL = "https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml"
OUTPUT_FILE = "active_signing_cert.pem"

DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def download_metadata(url):
    print(f"Downloading federation metadata from {url}...")
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except Exception as e:
        print(f"Error downloading metadata: {e}", file=sys.stderr)
        sys.exit(1)


def extract_metadata_signing_cert(xml_content):
    """
    Find the X509Certificate inside the top-level <Signature> block.

    Azure AD signs the metadata document itself with whichever key it is
    currently using to sign SAML assertions, so this certificate is the
    single authoritative active signing cert.
    """
    root = ET.fromstring(xml_content)

    ns = {"ds": DS_NS}

    # <Signature> is a direct child of <EntityDescriptor>
    cert_elem = root.find(
        "ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns
    )

    if cert_elem is None:
        print("Error: <Signature> block not found in the metadata XML.", file=sys.stderr)
        sys.exit(1)

    return cert_elem.text


def to_pem(cert_b64):
    cert_b64 = "".join(cert_b64.split())
    wrapped = "\n".join(textwrap.wrap(cert_b64, 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def cert_info(pem):
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-serial", "-dates"],
        input=pem,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("Warning: openssl not available, skipping cert info", file=sys.stderr)
        return None
    return result.stdout.strip()


def main():
    xml_content = download_metadata(METADATA_URL)
    cert_b64 = extract_metadata_signing_cert(xml_content)
    pem = to_pem(cert_b64)

    info = cert_info(pem)
    if info:
        print("\nActive signing certificate:")
        for line in info.splitlines():
            print(f"  {line}")

    with open(OUTPUT_FILE, "w") as f:
        f.write(pem)

    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
