import re
from fastapi import APIRouter
from services.phishing.url_analyzer import analyze_url
from services.phishing.email_analyzer import analyze_email
from services.phishing.brand_detector import detect_brand_impersonation
from services.phishing.scoring import calculate_score
from services.phishing.explanation import build_explanation
from services.llm_service import explain_result
from db import SessionLocal
from models.history import ScanHistory

router = APIRouter()


def extract_first_url(text: str):
    match = re.search(r"https?://\S+", text)
    return match.group(0) if match else None


@router.post("/scan")
def scan(data: dict):
    content = data.get("url") or data.get("content") or ""

    if not content.strip():
        return {"error": "No input provided"}

    # 1. Determine if input contains a URL
    is_direct_url = content.strip().startswith(("http://", "https://"))
    found_url = content.strip() if is_direct_url else extract_first_url(content)

    # 2. URL analysis
    url_analysis = analyze_url(found_url) if found_url else analyze_url("")

    # 3. Email/text analysis (always run on full content)
    email_analysis = analyze_email(content)

    # 4. Brand detection
    brand_result = detect_brand_impersonation(
        domain=url_analysis.get("domain") or "",
        text=content
    )

    # 5. Scoring
    score_result = calculate_score(url_analysis, email_analysis, brand_result)

    # 6. Explainability layer
    explanation = build_explanation(score_result, url_analysis, email_analysis)

    # 7. AI explanation
    combined_analysis = {
        "url_analysis": url_analysis,
        "email_analysis": {
            "findings": email_analysis.get("findings", {}),
            "sender_spoofed": email_analysis.get("sender_spoofed", False),
        },
        "brand": brand_result,
    }

    try:
        ai_result = explain_result(
            combined_analysis,
            score_result["score"],
            score_result["label"],
            content
        )
    except Exception as e:
        print(f"[scan router] LLM call failed: {e}")
        ai_result = {
            "explanation": explanation["summary"],
            "recommendations": explanation["recommendations"],
        }

    # 8. Save to DB
    db = SessionLocal()
    new_scan = ScanHistory(
        url=content,
        risk_score=score_result["score"],
        label=score_result["label"],
        analysis=combined_analysis,
        explanation=ai_result.get("explanation", explanation["summary"])
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    db.close()

    return {
        "id": new_scan.id,
        "url": content,
        "risk_score": score_result["score"],
        "label": score_result["label"],
        "analysis": {
            "url_analysis": url_analysis,
            "keyword_analysis": email_analysis.get("findings", {}),
            "sender_info": email_analysis.get("sender_info", {}),
            "sender_spoofed": email_analysis.get("sender_spoofed", False),
        },
        "reasons": explanation["reasons"],
        "ai_explanation": {
            "explanation": ai_result.get("explanation", explanation["summary"]),
            "recommendations": ai_result.get("recommendations", explanation["recommendations"]),
        }
    }


@router.get("/history")
def scan_history():
    db = SessionLocal()
    scans = (
        db.query(ScanHistory)
        .order_by(ScanHistory.id.desc())
        .limit(20)
        .all()
    )
    db.close()
    return scans