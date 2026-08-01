import re
from urllib.parse import urlparse
import tldextract
from .brand_detector import detect_brand_impersonation

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "link", "work", "date", "loan", "download", "racing",
    "win", "stream", "gdn", "bid", "trade"
}


def analyze_url(url: str) -> dict:
    if not url:
        return _empty_result()

    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
    except Exception:
        return _empty_result()

    domain = f"{ext.domain}.{ext.suffix}" if ext.domain else ""
    full_domain = parsed.netloc.split(":")[0]
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []

    # --- individual signal checks ---

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", full_domain))
    uses_https = parsed.scheme == "https"
    suspicious_tld = ext.suffix in SUSPICIOUS_TLDS
    excessive_subdomains = len(subdomain_parts) >= 3
    excessive_hyphens = ext.domain.count("-") >= 3
    long_url = len(url) > 100
    has_at_symbol = "@" in url
    has_double_slash_redirect = url.count("//") > 1

    brand_result = detect_brand_impersonation(
        domain=ext.domain,
        text=url
    )

    reasons = []
    if is_ip:
        reasons.append("URL uses a raw IP address instead of a domain name")
    if not uses_https:
        reasons.append("Connection is not encrypted (HTTP instead of HTTPS)")
    if suspicious_tld:
        reasons.append(f"Suspicious top-level domain (.{ext.suffix}) commonly used in phishing")
    if excessive_subdomains:
        reasons.append(f"Excessive subdomains detected ({ext.subdomain}) — common obfuscation tactic")
    if excessive_hyphens:
        reasons.append(f"Excessive hyphens in domain ({ext.domain}) — common phishing pattern")
    if long_url:
        reasons.append(f"Unusually long URL ({len(url)} characters) — often used to obscure destination")
    if has_at_symbol:
        reasons.append("@ symbol in URL — browser ignores everything before it, classic redirect trick")
    if has_double_slash_redirect:
        reasons.append("Double slash redirect detected in URL path")
    if brand_result["brand"] and not brand_result["is_legitimate"]:
        reasons.append(
            f"Brand impersonation detected: '{brand_result['brand']}' "
            f"(via {brand_result['method']}, {brand_result['confidence']}% confidence)"
        )

    return {
        "domain": domain,
        "https": uses_https,
        "suspicious_tld": suspicious_tld,
        "ip_address": is_ip,
        "long_url": long_url,
        "excessive_subdomains": excessive_subdomains,
        "excessive_hyphens": excessive_hyphens,
        "has_at_symbol": has_at_symbol,
        "brand_impersonation": brand_result["brand"] if not brand_result["is_legitimate"] else None,
        "brand_confidence": brand_result["confidence"] if not brand_result["is_legitimate"] else 0,
        "uses_typosquatting": (
            brand_result["method"] in ("known_typosquat", "fuzzy_match")
            and not brand_result["is_legitimate"]
        ),
        "reasons": reasons,
    }


def _empty_result() -> dict:
    return {
        "domain": None,
        "https": True,
        "suspicious_tld": False,
        "ip_address": False,
        "long_url": False,
        "excessive_subdomains": False,
        "excessive_hyphens": False,
        "has_at_symbol": False,
        "brand_impersonation": None,
        "brand_confidence": 0,
        "uses_typosquatting": False,
        "reasons": [],
    }