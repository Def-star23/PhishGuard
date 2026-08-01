import re

URGENCY_PHRASES = [
    "act now",
    "act immeadiately",
    "urgent action required",
    "immediate action required",
    "confirm your identity",
    "click here immediately",
    "you have won",
    "claim your prize",
    "your payment failed",
    "update your billing",
    "update your payment",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password",
    "provide your password",
    "confirm your password",
    "enter your ssn",
    "social security number",
    "enter your card number",
    "enter your pin",
    "banking details",
    "verify your password",
]

ATTACHMENT_FLAGS = [
    "see attached invoice",
    "open the attachment",
    "download the attached file",
    "attached document",
    "view attachment",
]

def scan_keywords(text: str) -> dict:
    text_lower = text.lower()

    urgency_matches = [p for p in URGENCY_PHRASES if p in text_lower]
    credential_matches = [p for p in CREDENTIAL_REQUEST_PHRASES if p in text_lower]
    attachment_matches = [p for p in ATTACHMENT_FLAGS if p in text_lower]

    contains_link = bool(re.search(r"https?://", text_lower))

    return {
        "urgency_flags": urgency_matches,
        "credentials_request_flags":credential_matches,
        "attachment_flags": attachment_matches,
        "conatins_link": contains_link,
    }