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

# Microsoft Federation Metadata URL
METADATA_URL = "https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml"

def download_metadata(url):
    """Download the federation metadata XML"""
    print(f"Downloading metadata from {url}...")
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except Exception as e:
        print(f"Error downloading metadata: {e}")
        sys.exit(1)

def extract_certificates(xml_content):
    """Extract X509Certificates from the IDPSSODescriptor (SAML 2.0) element only"""
    print("Parsing XML and extracting certificates from IDPSSODescriptor...")

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
        print("Error: openssl is required but not found in PATH")
        sys.exit(1)
    return None

def main():
    # Download metadata
    xml_content = download_metadata(METADATA_URL)
    
    # Extract certificates
    certificates = extract_certificates(xml_content)
    
    if not certificates:
        print("No certificates found in the metadata!")
        sys.exit(1)

    print(f"Found {len(certificates)} certificate(s)")
    print(f"Filtering for: {REQUIRED_SUBJECT}")
    
    # Filter and save certificates
    all_certs_pem = []
    saved_count = 0

    for i, cert in enumerate(certificates, 1):
        cert_data = cert.text
        if not cert_data:
            continue

        pem = format_as_pem(cert_data, i)
        subject = get_cert_subject(pem)

        if subject != REQUIRED_SUBJECT:
            print(f"  Skipping cert {i}: {subject}")
            continue

        saved_count += 1
        all_certs_pem.append(pem)

        # Save individual certificate
        filename = f"microsoft_federation_cert_{saved_count}.pem"
        with open(filename, 'w') as f:
            f.write(pem)
        shutil.chown(filename, user='splunk', group='splunk')
        print(f"✓ Saved {filename} ({subject})")
    
    if not all_certs_pem:
        print(f"\nNo certificates matched {REQUIRED_SUBJECT}")
        sys.exit(1)

    # Save all certificates in one file (useful for Splunk)
    combined_filename = "microsoft_federation_certs_all.pem"
    with open(combined_filename, 'w') as f:
        f.write('\n'.join(all_certs_pem))
    shutil.chown(combined_filename, user='splunk', group='splunk')
    print(f"✓ Saved {saved_count} matching certificate(s) to {combined_filename}")
    
    print("\nDone! You can now use these PEM files in your Splunk configuration.")
    print(f"For Splunk SAML, typically use: {combined_filename}")

if __name__ == "__main__":
    main()
