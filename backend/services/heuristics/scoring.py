def calculate_keyword_score(keyword_result):

    score = 0

    score += min(len(keyword_result.get("urgency_flags", [])) * 12, 36)
    score += min(len(keyword_result.get("credential_request_flags", [])) * 20, 40)
    score += min(len(keyword_result.get("attachment_flags", [])) * 10, 20)

    return min(score, 100)


def calculate_score(result, keyword_result=None):

    score = 0

    # No HTTPS
    if not result["https"]:
        score += 20

    # Suspicious domain endings
    if result["suspicious_tld"]:
        score += 45

    # Fake brand
    if result.get("brand_impersonation"):
        score += 40

    # Long URL
    if result["long_url"]:
        score += 10

    # Typosquatting
    if result.get("uses_typosquatting"):
        score += 35

    # IP address used instead of domain
    if result.get("ip_address"):
        score += 25

    # Keyword/manipulation language
    if keyword_result:
        score += calculate_keyword_score(keyword_result)

    return min(score, 100)


def get_label(score):

    if score < 30:
        return "Safe"

    elif score < 70:
        return "Suspicious"

    else:
        return "Dangerous"