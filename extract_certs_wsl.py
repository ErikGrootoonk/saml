#!/usr/bin/env python3
"""
Extract certificates from Microsoft Federation Metadata XML and convert to PEM format
Usage: python3 extract_federation_certs.py
"""

import urllib.request
import xml.etree.ElementTree as ET
import textwrap
import sys
import subprocess
import shutil
import logging
import os
from pathlib import Path

IDP_CERT_DIR = "/splunk/etc/auth/idpCerts"
LOG_FILE = "/var/log/splunk_saml_cert_update.log"

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

log = logging.getLogger(__name__)

# Microsoft Federation Metadata URL
METADATA_URL = "https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml"

def download_metadata(url):
    """Download the federation metadata XML"""
    log.info(f"Downloading metadata from {url}")
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except Exception as e:
        log.error(f"Error downloading metadata: {e}")
        sys.exit(1)

def extract_certificates(xml_content):
    """Extract X509Certificates from the IDPSSODescriptor (SAML 2.0) element only"""
    log.info("Parsing XML and extracting certificates from IDPSSODescriptor")

    root = ET.fromstring(xml_content)

    namespaces = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    }

    # Find IDPSSODescriptor elements with SAML 2.0 protocol support
    idp_descriptors = root.findall('.//md:IDPSSODescriptor', namespaces)

    certificates = []
    for idp in idp_descriptors:
        protocol = idp.get('protocolSupportEnumeration', '')
        if 'urn:oasis:names:tc:SAML:2.0:protocol' in protocol:
            certs = idp.findall('.//ds:X509Certificate', namespaces)
            certificates.extend(certs)

    return certificates

def format_as_pem(cert_data, cert_number):
    """Format Base64 certificate data as PEM"""
    # Remove any whitespace
    cert_data = ''.join(cert_data.split())
    
    # Wrap at 64 characters per line
    wrapped = '\n'.join(textwrap.wrap(cert_data, 64))
    
    # Add PEM headers
    pem = f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"
    
    return pem

REQUIRED_SUBJECT = "subject=CN=accounts.accesscontrol.windows.net"

def normalize_subject(subject):
    """Normalize subject string by removing spaces around = signs (openssl output varies by version)"""
    if subject is None:
        return None
    return subject.replace(' = ', '=').replace('= ', '=').replace(' =', '=')

def get_cert_subject(pem_data):
    """Get the subject of a PEM certificate using openssl"""
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject'],
            input=pem_data,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        log.error("openssl is required but not found in PATH")
        sys.exit(1)
    return None

def main():
    setup_logging()
    log.info("=== Splunk SAML certificate update started ===")

    # Ensure IDP cert directory exists
    Path(IDP_CERT_DIR).mkdir(parents=True, exist_ok=True)

    # Download metadata
    xml_content = download_metadata(METADATA_URL)

    # Extract certificates
    certificates = extract_certificates(xml_content)

    if not certificates:
        log.error("No certificates found in the metadata!")
        sys.exit(1)

    log.info(f"Found {len(certificates)} certificate(s), filtering for: {REQUIRED_SUBJECT}")

    saved_count = 0

    for i, cert in enumerate(certificates, 1):
        cert_data = cert.text
        if not cert_data:
            continue

        pem = format_as_pem(cert_data, i)
        subject = get_cert_subject(pem)

        if normalize_subject(subject) != REQUIRED_SUBJECT:
            log.info(f"Skipping cert {i}: {subject}")
            continue

        saved_count += 1
        filename = f"microsoft_federation_cert_{saved_count}.pem"

        # Save to current directory
        with open(filename, 'w') as f:
            f.write(pem)
        shutil.chown(filename, user='splunk', group='splunk')
        log.info(f"Saved {filename} ({subject})")

        # Copy to IDP cert directory
        dest = os.path.join(IDP_CERT_DIR, filename)
        shutil.copy2(filename, dest)
        shutil.chown(dest, user='splunk', group='splunk')
        log.info(f"Copied to {dest}")

    log.info(f"=== Done: {saved_count} certificate(s) saved to {IDP_CERT_DIR} ===")

if __name__ == "__main__":
    main()
