import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url="https://openrouter.ai/api/v1"
)

def explain_result(
        analysis,
        score,
        label,
        url
):

    prompt = f"""
You are a cybersecurity assistant.

Explain ONLY the provided detection signals.
Do not guess brands or invent information.

URL:
{url}

Risk score:
{score}/100

Label:
{label}

Detection results:
{json.dumps(analysis)}

Rules:
- If brand_impersonation exists, mention that exact brand.
- If uses_typosquatting is true, explain typosquatting.
- Do not mention any other brand.
- Keep the explanation under 100 words.

Return JSON:

{{
"explanation": "...",
"recommendations": [
"tip 1",
"tip 2",
"tip 3"
]
}}
"""

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b:free",
        response_format={
            "type": "json_object"
        },
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    if not response.choices:
        raise RuntimeError(f"LLM call failed or returned no choices: {response}")

    return json.loads(
        response.choices[0].message.content
    )