"""
Threat intelligence helpers:
- WHOIS lookup for domain creation date / age
- Blacklist lookups (PhishTank, Google Safe Browsing)

All external calls are optional and controlled via environment variables:
- PHISHTANK_API_KEY
- GSB_API_KEY  (Google Safe Browsing v4)

If keys are missing or any error happens, the functions fail gracefully
and simply return "unknown" / False flags.
"""

import os
import socket
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import requests

try:
    import whois  # from python-whois
except Exception:  # pragma: no cover - library might be missing in some envs
    whois = None


def _extract_domain(url: str) -> Optional[str]:
    """
    Extract bare domain from URL or hostname.
    Returns None if it cannot be determined.
    """
    if not url:
        return None

    url = url.strip()

    # If no scheme, add http:// to help urlparse
    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        # Remove port if any
        if ":" in host:
            host = host.split(":", 1)[0]
        # Strip www.
        if host.startswith("www."):
            host = host[4:]
        return host or None
    except Exception:
        return None


def get_domain_age_days(url: str) -> Dict[str, Any]:
    """
    Get WHOIS info and compute domain age in days.

    Returns dict:
    {
        "success": bool,
        "domain": str | None,
        "creation_date": iso_str | None,
        "age_days": int | None,
        "error": str | None,
    }
    """
    domain = _extract_domain(url)
    result: Dict[str, Any] = {
        "success": False,
        "domain": domain,
        "creation_date": None,
        "age_days": None,
        "error": None,
    }

    if not domain:
        result["error"] = "Could not extract domain"
        return result

    if whois is None:
        result["error"] = "python-whois library not available"
        return result

    try:
        # Basic DNS check first to avoid long WHOIS timeouts on bad domains
        try:
            socket.gethostbyname(domain)
        except Exception:
            # Non‑resolvable domains are often junk; no age info
            result["error"] = "Domain does not resolve"
            return result

        w = whois.whois(domain)
        creation = getattr(w, "creation_date", None)
        if isinstance(creation, list):
            creation = creation[0] if creation else None

        if not isinstance(creation, datetime):
            result["error"] = "No valid creation_date in WHOIS"
            return result

        # Normalize to UTC
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = max((now - creation).days, 0)

        result.update(
            {
                "success": True,
                "creation_date": creation.isoformat(),
                "age_days": age_days,
                "error": None,
            }
        )
        return result
    except Exception as e:  # pragma: no cover - defensive
        result["error"] = str(e)
        return result


def check_phishtank(url: str) -> Dict[str, Any]:
    """
    Check URL against PhishTank.

    Requires PHISHTANK_API_KEY environment variable.
    Returns dict:
    {
        "enabled": bool,
        "listed": bool | None,
        "verified_phish": bool | None,
        "error": str | None,
    }
    """
    api_key = os.getenv("PHISHTANK_API_KEY")
    result: Dict[str, Any] = {
        "enabled": bool(api_key),
        "listed": None,
        "verified_phish": None,
        "error": None,
    }

    if not api_key:
        result["error"] = "PHISHTANK_API_KEY not set"
        return result

    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url,
                "format": "json",
                "app_key": api_key,
            },
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()

        in_db = data.get("results", {}).get("in_database", False)
        valid = data.get("results", {}).get("valid", False)

        result["listed"] = bool(in_db)
        result["verified_phish"] = bool(valid) if in_db else False
        return result
    except Exception as e:  # pragma: no cover - external service
        result["error"] = str(e)
        return result


def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """
    Check URL against Google Safe Browsing v4.

    Requires GSB_API_KEY environment variable.
    Returns dict:
    {
        "enabled": bool,
        "unsafe": bool | None,
        "threat_types": list | None,
        "error": str | None,
    }
    """
    api_key = os.getenv("GSB_API_KEY")
    result: Dict[str, Any] = {
        "enabled": bool(api_key),
        "unsafe": None,
        "threat_types": None,
        "error": None,
    }

    if not api_key:
        result["error"] = "GSB_API_KEY not set"
        return result

    try:
        payload = {
            "client": {
                "clientId": "phishing-link-detector",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        resp = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": api_key},
            json=payload,
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
            result["unsafe"] = True
            result["threat_types"] = threat_types
        else:
            result["unsafe"] = False
            result["threat_types"] = []

        return result
    except Exception as e:  # pragma: no cover - external service
        result["error"] = str(e)
        return result


def get_threat_intel(url: str) -> Dict[str, Any]:
    """
    Convenience helper to get all threat intel for a URL.

    Returns a dict combining:
    - WHOIS / domain age
    - PhishTank result
    - Google Safe Browsing result
    """
    whois_info = get_domain_age_days(url)
    phishtank_info = check_phishtank(url)
    gsb_info = check_google_safe_browsing(url)

    # High‑level flags that can be used by callers
    listed_blacklist = bool(
        (phishtank_info.get("enabled") and phishtank_info.get("verified_phish"))
        or (gsb_info.get("enabled") and gsb_info.get("unsafe"))
    )

    very_young_domain = (
        whois_info.get("success")
        and isinstance(whois_info.get("age_days"), int)
        and whois_info["age_days"] >= 0
        and whois_info["age_days"] < 30
    )

    return {
        "whois": whois_info,
        "phishtank": phishtank_info,
        "google_safe_browsing": gsb_info,
        "flags": {
            "listed_in_blacklist": listed_blacklist,
            "very_young_domain": bool(very_young_domain),
        },
    }

