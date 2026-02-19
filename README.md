● Here's what the new script update_splunk_saml_cert.py does:

  Workflow:
  1. Downloads the Microsoft Federation Metadata XML
  2. Extracts the active signing cert from the <Signature> block (same logic as get_active_signing_cert.py)
  3. Reads the cert currently at /splunk/etc/auth/idpCerts/idpCert.pem
  4. Compares the two by stripping PEM headers/whitespace and comparing the raw base64 — if identical, exits cleanly with no changes
  5. If they differ: creates a timestamped backup (e.g. idpCert.pem.backup_20260219_143022), writes the new cert, sets splunk:splunk ownership, then calls the Splunk REST API to reload auth

  Before running, set these variables at the top:

  ┌────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────┐
  │        Variable        │                                           Description                                           │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ SPLUNK_AUTH_TOKEN      │ Your Splunk auth token (Settings → Tokens in Splunk Web)                                        │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ SPLUNK_REST_URL        │ Defaults to https://localhost:8089                                                              │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ SPLUNK_RELOAD_ENDPOINT │ Defaults to reloading the full auth conf; override to target a specific SAML provider if needed │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ LOG_FILE               │ Set to a file path to persist logs (e.g. for cron jobs)                                         │
  └────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────┘

  For scheduled runs (cron example):
  0 6 * * * /usr/bin/python3 /path/to/update_splunk_saml_cert.py >> /var/log/splunk_saml_cert.log 2>&1
  Or set LOG_FILE in the script and omit the redirect.
