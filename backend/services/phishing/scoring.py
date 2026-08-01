def calculate_score(url_analysis: dict, email_analysis: dict, brand_result: dict) -> dict:
    score = 0
    reasons = []

    # ── HIGH WEIGHT: Technical indicators ──────────────────────────────────

    # Brand impersonation (not legitimate)
    if url_analysis.get("brand_impersonation"):
        score += 35
        reasons.append(
            f"Brand impersonation detected ({url_analysis['brand_impersonation'].title()})"
        )

    # Typosquatting
    if url_analysis.get("uses_typosquatting"):
        score += 25
        reasons.append(
            f"Typosquatting detected ({url_analysis.get('domain', '')})"
        )

    # Suspicious TLD
    if url_analysis.get("suspicious_tld"):
        score += 20
        reasons.append(
            f"Suspicious TLD detected"
        )

    # IP-based URL
    if url_analysis.get("ip_address"):
        score += 45
        reasons.append("URL uses raw IP address instead of domain name")

    # No HTTPS
    if not url_analysis.get("https", True):
        score += 15
        reasons.append("Connection is not encrypted (HTTP)")

    # Excessive subdomains
    if url_analysis.get("excessive_subdomains"):
        score += 10
        reasons.append("Excessive subdomains — common obfuscation tactic")

    # Excessive hyphens
    if url_analysis.get("excessive_hyphens"):
        score += 15
        reasons.append("Excessive hyphens in domain")

    # @ symbol in URL
    if url_analysis.get("has_at_symbol"):
        score += 15
        reasons.append("@ symbol in URL — classic redirect trick")

    # Long URL
    if url_analysis.get("long_url"):
        score += 5
        reasons.append("Unusually long URL")

    # Sender spoofing
    if email_analysis.get("sender_spoofed"):
        score += 30
        sender_reasons = [
            r for r in email_analysis.get("reasons", [])
            if "sent from" in r
        ]
        reasons.extend(sender_reasons or ["Sender domain does not match claimed brand"])

    # ── MODERATE WEIGHT: Content indicators ────────────────────────────────

    findings = email_analysis.get("findings", {})

    if findings.get("urgency_tactics"):
        score += 15
        reasons.append("Urgency / fear tactics detected")

    if findings.get("credential_requests"):
        score += 25
        reasons.append("Credential harvesting language detected")

    if findings.get("account_suspension"):
        score += 20
        reasons.append("Account suspension threat detected")

    if findings.get("security_alerts"):
        score += 20
        reasons.append("Security alert language detected")

    if findings.get("payment_failures"):
        score += 15
        reasons.append("Payment failure / invoice scam language detected")

    if findings.get("password_reset"):
        score += 18
        reasons.append("Password reset lure detected")

    if findings.get("verification_requests"):
        score += 15
        reasons.append("Verification request detected")

    if findings.get("attachment_lures"):
        score += 15
        reasons.append("Suspicious attachment lure detected")

    score = min(score, 100)
    label = get_label(score)

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
    }


def get_label(score: int) -> str:
    if score < 15:
        return "Safe"
    elif score < 55:
        return "Suspicious"
    else:
        return "Dangerous"