import os
import re
import hashlib
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from google import genai

# ----------------------------
# Setup
# ----------------------------
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# If you want "regex-only mode" when no key exists, comment this out.
if not API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY in .env")

client = genai.Client(api_key=API_KEY)

app = FastAPI(title="ShieldLens Backend", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Models
# ----------------------------
class UploadAnalyzeRequest(BaseModel):
    text: str = Field(..., max_length=300_000)
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    page_url: Optional[str] = None


class UploadAnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    detected_types: List[str]
    evidence_snippets: List[str]
    explanation: str
    remediation_steps: List[str]
    proof_hash: str


# ----------------------------
# Helpers
# ----------------------------
def risk_level(score: int) -> str:
    if score >= 71:
        return "high"
    if score >= 31:
        return "medium"
    return "low"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact_snippet(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}****{s[-4:]}"


REGEX_RULES = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS_SECRET_ACCESS_KEY_HINT", re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]")),
    ("PASSWORD_HINT", re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]")),
    ("API_KEY_HINT", re.compile(r"(?i)\b(api_key|apikey|token|secret)\b\s*[:=]")),
    ("ETH_PRIVATE_KEY", re.compile(r"\b0x[a-fA-F0-9]{64}\b")),
    ("SEED_PHRASE_HINT", re.compile(r"(?i)\b(seed phrase|recovery phrase|mnemonic)\b")),
]


def regex_prescan(text: str) -> Dict[str, Any]:
    found_types = set()
    evidence = []

    for name, rx in REGEX_RULES:
        for m in rx.finditer(text):
            found_types.add(name)
            snippet = text[max(0, m.start() - 25): min(len(text), m.end() + 25)]
            evidence.append(snippet)
            if len(evidence) >= 8:
                break

    score = 0
    if "ETH_PRIVATE_KEY" in found_types or "SEED_PHRASE_HINT" in found_types:
        score = max(score, 90)
    if "AWS_ACCESS_KEY_ID" in found_types or "AWS_SECRET_ACCESS_KEY_HINT" in found_types:
        score = max(score, 80)
    if "SSN" in found_types:
        score = max(score, 70)
    if "PASSWORD_HINT" in found_types:
        score = max(score, 60)
    if "API_KEY_HINT" in found_types:
        score = max(score, 55)

    return {"types": sorted(found_types), "evidence": evidence[:8], "score": score}


def safe_evidence_snippets(raw: List[str]) -> List[str]:
    redacted = []
    for s in raw:
        s2 = re.sub(r"(AKIA[0-9A-Z]{16})", lambda m: redact_snippet(m.group(1)), s)
        s2 = re.sub(r"(0x[a-fA-F0-9]{64})", lambda m: redact_snippet(m.group(1)), s2)
        s2 = re.sub(r"(\b\d{3}-\d{2}-\d{4}\b)", "****-**-****", s2)
        # mask common key/value patterns
        s2 = re.sub(r"(?i)(aws_secret_access_key\s*[:=]\s*)(\S+)", r"\1****", s2)
        s2 = re.sub(r"(?i)(password\s*[:=]\s*)(\S+)", r"\1****", s2)
        s2 = re.sub(r"(?i)(api_key\s*[:=]\s*)(\S+)", r"\1****", s2)
        redacted.append(s2.strip())
    return redacted[:8]


UPLOAD_MODELS = [
    "models/gemini-2.5-flash",
    "models/gemini-flash-latest",
    "models/gemini-flash-lite-latest",
]


async def gemini_upload_analyze(text: str) -> Dict[str, Any]:
    prompt = f"""
You are a security scanner for browser uploads.
Analyze the text and detect sensitive information:
- SSNs / government IDs
- passwords
- API keys / tokens
- private keys, seed phrases
- cloud credentials (AWS, GCP, etc.)

Return ONLY valid JSON (no markdown, no extra text) with keys:
risk_score (0-100 integer),
detected_types (array of strings),
evidence_snippets (array of short strings; REDACT secrets with ****),
explanation (string),
remediation_steps (array of strings).

Text:
\"\"\"{text[:120000]}\"\"\"
"""
    last_err = None
    for model in UPLOAD_MODELS:
        try:
            resp = client.models.generate_content(
                model=model,
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )
            import json
            return json.loads(resp.text)
        except Exception as e:
            last_err = e
    raise HTTPException(status_code=502, detail=f"Gemini upload analyze failed: {last_err}")


# ----------------------------
# Routes
# ----------------------------
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/")
def root():
    return {"name": "ShieldLens Backend", "ok": True, "docs": "/docs"}


@app.post("/analyze/upload", response_model=UploadAnalyzeResponse)
async def analyze_upload(req: UploadAnalyzeRequest):
    if not req.text or len(req.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="Empty text")

    prescan = regex_prescan(req.text)

    # Gemini call with fallback to regex-only
    try:
        gem = await gemini_upload_analyze(req.text)
    except Exception:
        gem = {
            "risk_score": prescan["score"],
            "detected_types": prescan["types"],
            "evidence_snippets": safe_evidence_snippets(prescan["evidence"]),
            "explanation": "AI scan unavailable; showing regex-based detection.",
            "remediation_steps": [
                "Remove sensitive data before uploading.",
                "Rotate any exposed credentials immediately.",
                "Use a secrets manager for API keys."
            ]
        }

    score = int(max(prescan["score"], int(gem.get("risk_score", 0))))
    score = max(0, min(100, score))

    detected = sorted(set(prescan["types"]) | set(gem.get("detected_types", []) or []))
    evidence = safe_evidence_snippets(prescan["evidence"] + (gem.get("evidence_snippets") or []))

    explanation = str(gem.get("explanation", ""))
    remediation = gem.get("remediation_steps") or [
        "Remove sensitive data before uploading.",
        "Rotate exposed credentials immediately.",
        "Use a secrets manager and least-privilege access."
    ]

    # Proof hash uses only redacted evidence + types (never raw file contents)
    proof_material = ("|".join(detected) + "|" + "|".join(evidence)).encode("utf-8")
    proof = sha256_hex(proof_material)

    return UploadAnalyzeResponse(
        risk_score=score,
        risk_level=risk_level(score),
        detected_types=detected,
        evidence_snippets=evidence,
        explanation=explanation,
        remediation_steps=remediation,
        proof_hash=proof,
    )