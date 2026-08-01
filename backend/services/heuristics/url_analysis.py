import re
from urllib.parse import urlparse
import tldextract


SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top"
}


BRANDS = {
    "paypal": ["paypa1", "paypaI"],
    "google": ["goog1e", "g00gle"],
    "amazon": ["amaz0n", "arnazon"],
    "microsoft": ["micros0ft"],
    "apple": ["app1e"],
    "netflix": ["netf1ix"]
}

def analyze_url(url):

    parsed = urlparse(url)

    ext = tldextract.extract(url)

    domain = f"{ext.domain}.{ext.suffix}"


    result = {
    "domain": domain,
    "https": parsed.scheme == "https",
    "suspicious_tld": ext.suffix in SUSPICIOUS_TLDS,
    "ip_address": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.netloc.split(":")[0])),
    "long_url": len(url) > 75,
    "brand_impersonation": None,
    "uses_typosquatting": False
    }


    domain_lower = ext.domain.lower()

    for brand, variants in BRANDS.items():

        for variant in variants:

            if variant in domain_lower:
                result["brand_impersonation"] = brand
                result["uses_typosquatting"] = True


    return result