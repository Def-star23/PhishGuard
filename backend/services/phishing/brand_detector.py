import re
from rapidfuzz import fuzz

BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "amazon",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "github",
    "dropbox",
]

# Known hardcoded typosquat variants as a first pass
KNOWN_TYPOSQUATS = {
    "paypal":    ["paypa1", "paypai", "paypa1", "paypall", "pay-pal"],
    "microsoft": ["micr0soft", "m1crosoft", "mlcrosoft", "microsoftt"],
    "google":    ["goog1e", "g00gle", "googie", "gooogle"],
    "amazon":    ["amaz0n", "arnazon", "amazoon", "arnazon"],
    "apple":     ["app1e", "appie", "aplle"],
    "netflix":   ["netf1ix", "netfl1x", "netfix"],
    "facebook":  ["faceb00k", "facebok", "faceboook"],
    "instagram": ["1nstagram", "instagran", "lnstagram"],
    "linkedin":  ["1inkedin", "linke din", "linkedln"],
    "github":    ["g1thub", "githubb", "gthub"],
    "dropbox":   ["dr0pbox", "dropb0x", "dropboxx"],
}


def detect_brand_impersonation(domain: str, text: str = "") -> dict:
    """
    Detects brand impersonation in a domain and/or text body.
    Returns the matched brand, confidence score, and method of detection.
    """
    domain_lower = domain.lower() if domain else ""
    text_lower = text.lower()

    result = {
        "brand": None,
        "confidence": 0,
        "method": None,
        "is_legitimate": False,
    }

    for brand in BRANDS:
        # 1. Exact legitimate domain check — skip, it's real
        if domain_lower == brand or domain_lower == f"www.{brand}":
            result["brand"] = brand
            result["confidence"] = 100
            result["method"] = "exact_match"
            result["is_legitimate"] = True
            return result

        # 2. Known hardcoded typosquat variants
        for variant in KNOWN_TYPOSQUATS.get(brand, []):
            if variant in domain_lower:
                result["brand"] = brand
                result["confidence"] = 95
                result["method"] = "known_typosquat"
                result["is_legitimate"] = False
                return result

        # 3. Fuzzy similarity on domain (catches novel typosquats)
        similarity = fuzz.ratio(brand, domain_lower.split(".")[0])
        if 75 <= similarity < 100:
            result["brand"] = brand
            result["confidence"] = similarity
            result["method"] = "fuzzy_match"
            result["is_legitimate"] = False
            return result

        # 4. Brand name appears in domain combined with suspicious keywords
        suspicious_combos = ["login", "secure", "verify", "update", "account", "support", "help", "signin"]
        if brand in domain_lower:
            for keyword in suspicious_combos:
                if keyword in domain_lower:
                    result["brand"] = brand
                    result["confidence"] = 90
                    result["method"] = "brand_plus_keyword"
                    result["is_legitimate"] = False
                    return result

        # 5. Brand mentioned in text body even if not in domain
        if brand in text_lower and domain_lower and brand not in domain_lower:
            result["brand"] = brand
            result["confidence"] = 60
            result["method"] = "text_mention_only"
            result["is_legitimate"] = False

    return result