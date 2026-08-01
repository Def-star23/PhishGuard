import re
from .brand_detector import detect_brand_impersonation

# --- Pattern groups ---

ACCOUNT_SUSPENSION = [
    r"account.{0,20}(will be|has been|is).{0,10}(suspended|disabled|deactivated|locked|terminated)",
    r"(suspend|disable|deactivate|lock).{0,20}(your|the).{0,10}account",
    r"failure to.{0,20}(verify|confirm|respond).{0,20}(will result|may result)",
    r"(24|48|72).{0,10}hour.{0,20}(suspend|disable|deactivate|terminate)",
    r"account.{0,20}(expire|expir)",
]

SECURITY_ALERTS = [
    r"(unusual|suspicious|unauthorized).{0,20}(activity|access|login|sign.?in)",
    r"security.{0,10}(alert|warning|notice|breach|issue|threat)",
    r"(we|our system).{0,20}detect.{0,20}(suspicious|unusual|unauthorized)",
    r"your.{0,20}account.{0,20}(compromised|hacked|accessed|breached)",
    r"(someone|new device|unrecognized).{0,20}(sign|log).{0,10}(in|into).{0,20}account",
]

PAYMENT_FAILURES = [
    r"payment.{0,20}(fail|declin|unsuccessful|could not be processed)",
    r"(billing|payment).{0,20}(information|details|method).{0,20}(update|verify|confirm)",
    r"(invoice|receipt|order).{0,20}(attach|enclosed|included|below)",
    r"(card|credit|debit).{0,20}(declin|expir|invalid)",
    r"(outstanding|unpaid|overdue).{0,20}(balance|invoice|payment|amount)",
]

PASSWORD_RESET = [
    r"(reset|change|update).{0,20}(your|the).{0,10}password",
    r"password.{0,20}(reset|expir|compromised|weak)",
    r"(click|follow).{0,20}(link|here).{0,20}(reset|change).{0,10}password",
    r"temporary.{0,20}password",
]

VERIFICATION_REQUESTS = [
    r"(verify|confirm|validate).{0,20}(your|the).{0,20}(account|email|identity|information)",
    r"(click|tap|follow).{0,20}(here|link|below).{0,20}(verify|confirm|validate)",
    r"(your|the).{0,20}(account|email).{0,20}(not|hasn.t).{0,20}(verified|confirmed)",
    r"complete.{0,20}(verification|validation|confirmation)",
]

URGENCY_TACTICS = [
    r"(act|respond|reply).{0,10}(now|immediately|urgently|asap)",
    r"(urgent|immediate|critical|important).{0,20}(action|attention|response|notice)",
    r"(limited|running out of).{0,10}time",
    r"(expire|expir).{0,20}(today|soon|shortly|in \d+)",
    r"(last|final).{0,10}(warning|notice|chance|reminder)",
    r"do not (ignore|delay|wait)",
]

CREDENTIAL_REQUESTS = [
    r"(enter|provide|confirm|verify|submit).{0,20}(your|the).{0,20}(password|credentials|login)",
    r"(social security|ssn|national id).{0,10}number",
    r"(credit|debit).{0,10}card.{0,20}(number|details|information)",
    r"(bank|banking).{0,10}(details|information|credentials|account)",
    r"(date of birth|dob).{0,20}(verify|confirm|provide)",
    r"pin.{0,10}(number|code).{0,20}(enter|provide|confirm)",
]

ATTACHMENT_LURES = [
    r"(open|view|download|see).{0,20}(attach|document|file|invoice|receipt)",
    r"(attach|enclosed).{0,20}(invoice|receipt|document|file|statement)",
    r"(your|the).{0,20}(invoice|receipt|statement|document).{0,20}(attach|enclosed|below)",
    r"(pdf|doc|docx|xls).{0,20}(attach|enclosed|included)",
]


def _match_patterns(text: str, patterns: list[str]) -> list[str]:
    matches = []
    for pattern in patterns:
        found = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if found:
            matches.append(found.group(0).strip())
    return matches


def extract_sender_info(text: str) -> dict:
    """
    Tries to extract display name and email domain from raw email text.
    """
    email_match = re.search(r"[\w\.-]+@([\w\.-]+)", text)
    display_name_match = re.search(
        r"(from|sender|reply.to)\s*[:\-]?\s*(.+?)[\n<]",
        text, re.IGNORECASE
    )

    sender_email = email_match.group(0) if email_match else None
    sender_domain = email_match.group(1) if email_match else None
    display_name = display_name_match.group(2).strip() if display_name_match else None

    return {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "display_name": display_name,
    }


def analyze_sender(sender_info: dict, brand: str | None) -> dict:
    """
    Checks if the sender domain matches the claimed brand.
    e.g. Display Name: 'Microsoft Security' but email from 'random-domain.net'
    """
    if not brand or not sender_info.get("sender_domain"):
        return {"spoofed": False, "reason": None}

    domain = sender_info["sender_domain"].lower()
    legitimate_domains = {
        "paypal":    ["paypal.com"],
        "microsoft": ["microsoft.com", "outlook.com", "hotmail.com"],
        "google":    ["google.com", "gmail.com"],
        "amazon":    ["amazon.com", "amazonaws.com"],
        "apple":     ["apple.com", "icloud.com"],
        "netflix":   ["netflix.com"],
        "facebook":  ["facebook.com", "meta.com"],
        "instagram": ["instagram.com"],
        "linkedin":  ["linkedin.com"],
        "github":    ["github.com"],
        "dropbox":   ["dropbox.com"],
    }

    expected = legitimate_domains.get(brand, [])
    is_legit = any(domain.endswith(legit) for legit in expected)

    if not is_legit and expected:
        return {
            "spoofed": True,
            "reason": (
                f"Email claims to be from {brand.title()} "
                f"but was sent from '{domain}' "
                f"instead of an official {brand}.com address"
            )
        }

    return {"spoofed": False, "reason": None}


def analyze_email(text: str) -> dict:
    findings = {
        "account_suspension":   _match_patterns(text, ACCOUNT_SUSPENSION),
        "security_alerts":      _match_patterns(text, SECURITY_ALERTS),
        "payment_failures":     _match_patterns(text, PAYMENT_FAILURES),
        "password_reset":       _match_patterns(text, PASSWORD_RESET),
        "verification_requests":_match_patterns(text, VERIFICATION_REQUESTS),
        "urgency_tactics":      _match_patterns(text, URGENCY_TACTICS),
        "credential_requests":  _match_patterns(text, CREDENTIAL_REQUESTS),
        "attachment_lures":     _match_patterns(text, ATTACHMENT_LURES),
    }

    sender_info = extract_sender_info(text)

    # Detect brand from body text
    brand_result = detect_brand_impersonation(domain="", text=text)
    sender_analysis = analyze_sender(sender_info, brand_result.get("brand"))

    reasons = []
    if findings["account_suspension"]:
        reasons.append("Account suspension threat detected")
    if findings["security_alerts"]:
        reasons.append("Security alert language detected")
    if findings["payment_failures"]:
        reasons.append("Payment failure / invoice scam language detected")
    if findings["password_reset"]:
        reasons.append("Password reset lure detected")
    if findings["verification_requests"]:
        reasons.append("Verification request detected")
    if findings["urgency_tactics"]:
        reasons.append("Urgency / fear tactics detected")
    if findings["credential_requests"]:
        reasons.append("Credential harvesting language detected")
    if findings["attachment_lures"]:
        reasons.append("Suspicious attachment lure detected")
    if sender_analysis["spoofed"]:
        reasons.append(sender_analysis["reason"])

    return {
        "findings": findings,
        "sender_info": sender_info,
        "sender_spoofed": sender_analysis["spoofed"],
        "reasons": reasons,
    }