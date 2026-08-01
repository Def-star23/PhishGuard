def build_explanation(score_result: dict, url_analysis: dict, email_analysis: dict) -> dict:
    """
    Builds a structured human-readable explanation from all analysis results.
    """
    label = score_result["label"]
    reasons = score_result["reasons"]

    # Build a plain-text summary
    if label == "Safe":
        summary = (
            "No significant phishing indicators were detected. "
            "This appears to be a legitimate URL or message based on available signals."
        )
    elif label == "Suspicious":
        summary = (
            "Some suspicious signals were detected. "
            "Exercise caution — this may or may not be phishing, "
            "but it has characteristics worth investigating before acting on it."
        )
    else:
        summary = (
            "Multiple high-confidence phishing indicators were detected. "
            "This URL or message is very likely malicious. "
            "Do not click any links, enter any credentials, or follow any instructions in it."
        )

    # Standard recommendations based on label
    if label == "Safe":
        recommendations = [
            "Continue to verify the sender through an official channel if you have any doubts.",
            "Ensure the connection uses HTTPS before entering any information.",
            "Keep your browser and security software up to date.",
        ]
    elif label == "Suspicious":
        recommendations = [
            "Do not click any links until you have verified the sender's identity.",
            "Navigate directly to the official website instead of using links in the message.",
            "Contact the organization through official channels to confirm the message is legitimate.",
            "Report it to your IT or security team if this arrived at a work email.",
        ]
    else:
        recommendations = [
            "Do not click any links or download any attachments.",
            "Do not enter any credentials, payment information, or personal details.",
            "Report this as phishing to your email provider.",
            "If you've already clicked a link or entered details, change your passwords immediately.",
            "Contact your bank if any financial information was shared.",
        ]

    return {
        "label": label,
        "score": score_result["score"],
        "summary": summary,
        "reasons": reasons,
        "recommendations": recommendations,
    }