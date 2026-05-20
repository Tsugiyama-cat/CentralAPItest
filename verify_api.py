#!/usr/bin/env python3
"""
Aruba New Central API IP restriction verification tool.
Checks whether HPE GreenLake IP allowlist is blocking or permitting the current host.
"""

import os
import sys
import json
import requests
from datetime import datetime, timezone

# ── helpers ────────────────────────────────────────────────────────────────────

def log(level: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [{level}] {msg}", flush=True)

def info(msg):  log("INFO ", msg)
def warn(msg):  log("WARN ", msg)
def error(msg): log("ERROR", msg)


def get_public_ip() -> str:
    """Fetch the public IP of this host from an external resolver."""
    resolvers = [
        ("https://ifconfig.me/ip",          lambda r: r.text.strip()),
        ("https://api.ipify.org",            lambda r: r.text.strip()),
        ("https://checkip.amazonaws.com",    lambda r: r.text.strip()),
    ]
    for url, extract in resolvers:
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            return extract(r)
        except Exception as exc:
            warn(f"IP resolver {url} failed: {exc}")
    raise RuntimeError("All public-IP resolvers failed.")


# ── authentication ─────────────────────────────────────────────────────────────

def get_access_token(token_url: str, client_id: str, client_secret: str) -> str:
    """
    Obtain an OAuth2 bearer token from HPE GreenLake SSO.
    Uses client_credentials grant as recommended for service accounts.
    """
    payload = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
    }
    info(f"Requesting OAuth2 token from: {token_url}")
    try:
        r = requests.post(token_url, data=payload, timeout=30)
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Cannot reach token endpoint ({token_url}). "
            "Check TOKEN_URL and network connectivity."
        ) from exc

    if r.status_code == 401:
        raise RuntimeError(
            "Token request returned 401 Unauthorized. "
            "CLIENT_ID or CLIENT_SECRET is likely incorrect."
        )
    if r.status_code == 403:
        raise RuntimeError(
            "Token request returned 403 Forbidden. "
            "This host's IP may be blocked at the GreenLake level BEFORE the Central API is reached. "
            "Add this host's public IP to the GreenLake allowlist."
        )
    if not r.ok:
        raise RuntimeError(
            f"Token request failed with HTTP {r.status_code}: {r.text[:300]}"
        )

    data = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in response: {data}")

    expires_in = data.get("expires_in", "unknown")
    info(f"Access token obtained successfully (expires_in={expires_in}s).")
    return token


# ── API call ───────────────────────────────────────────────────────────────────

def call_api(base_url: str, token: str) -> dict:
    """
    Execute a lightweight GET request against Aruba New Central.
    /platform/device_inventory/v1/devices?limit=1 is the smallest query available.
    """
    # Normalise base URL
    base_url = base_url.rstrip("/")
    endpoint = f"{base_url}/platform/device_inventory/v1/devices"
    params   = {"limit": 1}
    headers  = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    info(f"Calling Central API: GET {endpoint}  params={params}")
    try:
        r = requests.get(endpoint, headers=headers, params=params, timeout=30)
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Cannot reach Central API ({base_url}). "
            "Check BASE_URL and network connectivity."
        ) from exc

    return r


def interpret_response(r) -> None:
    """Print a clear verdict for the most common HTTP status codes."""
    sc = r.status_code

    print()
    print("=" * 60)
    if sc == 200:
        info("✔  HTTP 200 OK — IP restriction is NOT blocking this host.")
        try:
            data = r.json()
            count = data.get("total", data.get("count", "N/A"))
            info(f"   Response sample: total={count}")
        except Exception:
            info(f"   Raw response (first 200 chars): {r.text[:200]}")

    elif sc == 401:
        warn("✘  HTTP 401 Unauthorized")
        warn("   Cause : Authentication credentials are invalid or expired.")
        warn("   Action: Verify CLIENT_ID / CLIENT_SECRET and re-generate if needed.")
        warn("   Note  : The request DID reach the API — IP is not the issue here.")

    elif sc == 403:
        error("✘  HTTP 403 Forbidden")
        error("   Cause (likely): HPE GreenLake IP allowlist is BLOCKING this host.")
        error("   Action: Add the public IP shown above to the GreenLake allowlist,")
        error("           then re-run this tool to confirm.")
        error("   Note  : If credentials are also wrong you may see 403 for both reasons.")
        error(f"   Server message: {r.text[:300]}")

    elif sc == 429:
        warn("✘  HTTP 429 Too Many Requests — rate-limited; try again later.")

    else:
        warn(f"✘  HTTP {sc} — unexpected response.")
        warn(f"   Body: {r.text[:300]}")
    print("=" * 60)
    print()


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    required = ("CLIENT_ID", "CLIENT_SECRET", "BASE_URL")
    missing  = [k for k in required if not os.environ.get(k)]
    if missing:
        error(f"Missing required environment variables: {', '.join(missing)}")
        error("Copy .env.example to .env and fill in your values.")
        return 1

    client_id     = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]
    base_url      = os.environ["BASE_URL"]
    token_url     = os.environ.get(
        "TOKEN_URL",
        "https://sso.common.cloud.hpe.com/as/token.oauth2",
    )

    print()
    print("=" * 60)
    print("  Aruba New Central — IP Restriction Verification Tool")
    print("=" * 60)
    print()

    # Step 1: public IP
    info("Step 1/3  Resolving public IP of this host …")
    try:
        public_ip = get_public_ip()
    except RuntimeError as exc:
        error(str(exc))
        return 1

    print()
    print(f"  ┌─────────────────────────────────────────┐")
    print(f"  │  Public IP : {public_ip:<28}│")
    print(f"  │  → Add this IP to the GreenLake allowlist│")
    print(f"  └─────────────────────────────────────────┘")
    print()

    # Step 2: obtain token
    info("Step 2/3  Authenticating with HPE GreenLake SSO …")
    try:
        token = get_access_token(token_url, client_id, client_secret)
    except RuntimeError as exc:
        error(str(exc))
        return 1

    # Step 3: call API
    info("Step 3/3  Calling Aruba New Central API …")
    try:
        response = call_api(base_url, token)
    except RuntimeError as exc:
        error(str(exc))
        return 1

    interpret_response(response)

    return 0 if response.status_code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
