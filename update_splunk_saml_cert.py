#!/usr/bin/env python3
"""
Check the Microsoft Azure AD active SAML signing certificate and update
the Splunk IdP certificate if it has changed.

Workflow:
  1. Download Microsoft Federation Metadata
  2. Extract the active signing certificate (from the <Signature> block)
  3. Compare it with the current Splunk IdP certificate on disk
  4. If different: back up the old cert, write the new cert, reload Splunk auth via REST API
"""

import urllib.request
import xml.etree.ElementTree as ET
import textwrap
import sys
import subprocess
import shutil
import os
import ssl
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration — adjust these before running
# ---------------------------------------------------------------------------

METADATA_URL = (
    "https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml"
)

# Full path to the Splunk IdP certificate file
SPLUNK_CERT_PATH = "/splunk/etc/auth/idpCerts/idpCert.pem"

# Splunk REST API base URL
SPLUNK_REST_URL = "https://localhost:8089"

# Splunk authentication token (generate via: Settings > Tokens in Splunk Web)
SPLUNK_AUTH_TOKEN = "YOUR_SPLUNK_AUTH_TOKEN_HERE"

# REST endpoint used to reload authentication after a cert update.
# Default reloads the full authentication configuration.
# Override if you need to target a specific provider, e.g.:
#   f"{SPLUNK_REST_URL}/services/authentication/providers/SAML/_reload"
SPLUNK_RELOAD_ENDPOINT = f"{SPLUNK_REST_URL}/services/configs/conf-authentication/_reload"

# Optional: write log entries to this file in addition to stdout.
# Set to None to log to stdout only.
LOG_FILE = None

# ---------------------------------------------------------------------------
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    if LOG_FILE:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")


# ---------------------------------------------------------------------------
# Certificate retrieval (same logic as get_active_signing_cert.py)
# ---------------------------------------------------------------------------

def download_metadata(url):
    log(f"Downloading federation metadata from {url} ...")
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except Exception as e:
        log(f"ERROR: Failed to download metadata: {e}")
        sys.exit(1)


def extract_metadata_signing_cert(xml_content):
    """
    Extract the active signing cert from the top-level <Signature> block.

    Azure AD signs the metadata document with the same key it uses to sign
    SAML assertions, so this is the single authoritative active signing cert.
    """
    root = ET.fromstring(xml_content)
    ns = {"ds": DS_NS}
    cert_elem = root.find(
        "ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns
    )
    if cert_elem is None:
        log("ERROR: <Signature> block not found in the metadata XML.")
        sys.exit(1)
    return cert_elem.text


def to_pem(cert_b64):
    cert_b64 = "".join(cert_b64.split())
    wrapped = "\n".join(textwrap.wrap(cert_b64, 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def cert_info(pem):
    """Return a human-readable summary of a PEM certificate via openssl."""
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-serial", "-dates"],
        input=pem,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _strip_pem(pem):
    """Return the raw base64 content of a PEM, with all whitespace removed."""
    lines = pem.strip().splitlines()
    b64 = "".join(line for line in lines if not line.startswith("-----"))
    return "".join(b64.split())


def certs_differ(pem_a, pem_b):
    """Return True when the two PEM certificates contain different keys."""
    return _strip_pem(pem_a) != _strip_pem(pem_b)


# ---------------------------------------------------------------------------
# Splunk cert management
# ---------------------------------------------------------------------------

def read_splunk_cert(path):
    """Read the Splunk IdP certificate. Returns None if the file does not exist."""
    if not os.path.exists(path):
        log(f"Splunk cert file not found: {path}")
        return None
    with open(path, "r") as f:
        return f.read()


def backup_cert(path):
    """Create a timestamped backup copy of the current cert file."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{path}.backup_{ts}"
    shutil.copy2(path, backup_path)
    log(f"Backed up existing cert to: {backup_path}")


def write_splunk_cert(path, pem):
    """Write the new PEM certificate to the Splunk cert path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(pem)
    try:
        shutil.chown(path, user="splunk", group="splunk")
    except (PermissionError, LookupError) as e:
        log(f"Warning: Could not set splunk:splunk ownership on {path}: {e}")
    log(f"Wrote new cert to: {path}")


# ---------------------------------------------------------------------------
# Splunk REST API
# ---------------------------------------------------------------------------

def reload_splunk_auth(endpoint, token):
    """POST to the Splunk REST endpoint to reload the authentication config."""
    log(f"Reloading Splunk auth via POST {endpoint} ...")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        endpoint,
        method="POST",
        data=b"",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            log(f"Splunk reload response: HTTP {resp.status}")
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log(f"ERROR: Splunk reload failed: HTTP {e.code} — {body[:300]}")
        return False
    except Exception as e:
        log(f"ERROR: Splunk reload request failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=== Splunk SAML certificate check started ===")

    # 1. Fetch the current active signing cert from Microsoft
    xml_content = download_metadata(METADATA_URL)
    cert_b64 = extract_metadata_signing_cert(xml_content)
    pem_online = to_pem(cert_b64)

    online_info = cert_info(pem_online)
    if online_info:
        log("Online active signing certificate:")
        for line in online_info.splitlines():
            log(f"  {line}")

    # 2. Read the cert currently installed in Splunk
    pem_splunk = read_splunk_cert(SPLUNK_CERT_PATH)

    if pem_splunk is None:
        log("No existing Splunk cert found — installing cert for the first time.")
        write_splunk_cert(SPLUNK_CERT_PATH, pem_online)
        reload_splunk_auth(SPLUNK_RELOAD_ENDPOINT, SPLUNK_AUTH_TOKEN)
        log("=== Done ===")
        return

    # 3. Compare
    if not certs_differ(pem_online, pem_splunk):
        log("Splunk SAML certificate is already up to date. No action needed.")
        log("=== Done ===")
        return

    log("Certificate change detected — update required.")

    splunk_info = cert_info(pem_splunk)
    if splunk_info:
        log("Current Splunk certificate (to be replaced):")
        for line in splunk_info.splitlines():
            log(f"  {line}")

    # 4. Back up old cert and write the new one
    backup_cert(SPLUNK_CERT_PATH)
    write_splunk_cert(SPLUNK_CERT_PATH, pem_online)

    # 5. Reload Splunk authentication
    if reload_splunk_auth(SPLUNK_RELOAD_ENDPOINT, SPLUNK_AUTH_TOKEN):
        log("Splunk authentication reloaded successfully.")
    else:
        log("WARNING: Splunk reload may have failed — check Splunk logs.")

    log("=== Done ===")


if __name__ == "__main__":
    main()
