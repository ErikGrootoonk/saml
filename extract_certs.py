#!/usr/bin/env python3
"""
Extract certificates from Microsoft Federation Metadata XML and convert to PEM format
Usage: python3 extract_federation_certs.py
"""

import urllib.request
import xml.etree.ElementTree as ET
import textwrap
import sys

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
    """Extract all X509Certificate elements from the XML"""
    print("Parsing XML and extracting certificates...")
    
    # Parse XML with namespace handling
    root = ET.fromstring(xml_content)
    
    # Common namespaces in federation metadata
    namespaces = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'fed': 'http://docs.oasis-open.org/wsfed/federation/200706',
        'md': 'urn:oasis:names:tc:SAML:2.0:protocol'
    }
    
    # Find all X509Certificate elements
    certificates = []
    
    # Try multiple XPath expressions to find certificates
    xpath_expressions = [
        './/ds:X509Certificate',
        './/{http://www.w3.org/2000/09/xmldsig#}X509Certificate',
        './/X509Certificate'
    ]
    
    for xpath in xpath_expressions:
        try:
            certs = root.findall(xpath, namespaces)
            if certs:
                certificates.extend(certs)
                break
        except:
            continue
    
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

def main():
    # Download metadata
    xml_content = download_metadata(METADATA_URL)
    
    # Extract certificates
    certificates = extract_certificates(xml_content)
    
    if not certificates:
        print("No certificates found in the metadata!")
        sys.exit(1)
    
    print(f"Found {len(certificates)} certificate(s)")
    
    # Save certificates
    all_certs_pem = []
    
    for i, cert in enumerate(certificates, 1):
        cert_data = cert.text
        if not cert_data:
            continue
            
        pem = format_as_pem(cert_data, i)
        all_certs_pem.append(pem)
        
        # Save individual certificate
        filename = f"microsoft_federation_cert_{i}.pem"
        with open(filename, 'w') as f:
            f.write(pem)
        print(f"✓ Saved {filename}")
    
    # Save all certificates in one file (useful for Splunk)
    combined_filename = "microsoft_federation_certs_all.pem"
    with open(combined_filename, 'w') as f:
        f.write('\n'.join(all_certs_pem))
    print(f"✓ Saved all certificates to {combined_filename}")
    
    print("\nDone! You can now use these PEM files in your Splunk configuration.")
    print(f"For Splunk SAML, typically use: {combined_filename}")

if __name__ == "__main__":
    main()
