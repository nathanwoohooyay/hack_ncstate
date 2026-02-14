import os
import re
import base64
import hashlib
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# Gemini SDK (google-genai)
from google import genai

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY in .env")

client = genai.Client(api_key=API_KEY)

app = FastAPI(title="ShieldLens Backend", version="0.1.0")


# ----------------------------
# Models
# ----------------------------
class UploadAnalyzeRequest(BaseModel):
    text: str = Field(..., max_length=300_000)  # keep sane for MVP
    filename: Optional[str] = None
    mime_type: Optional[str] = None


class UploadAnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    detected_types: List[str]
    evidence_snippets: List[str]
    explanation: str
    remediation_steps: List[str]
    proof_hash: str


class DeepfakeAnalyzeRequest(BaseModel):
    frames: List[str] = Field(..., min_items=1, max_items=12)  # MVP: up to 12 frames
    frame_count: Optional[int] = None
    page_url: Optional[str] = None
    video: Optional[Dict[str, Any]] = None


class DeepfakeAnalyzeResponse(BaseModel):
    deepfake_percentage: int
    risk_level: str
    signals: List[str]
    explanation: str
    recommendation: str
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
    # Basic redaction: keep small prefix/suffix, mask middle
    s = s.strip()
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}****{s[-4:]}"


REGEX_RULES = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY_HINT", re.compile(r"(?i)\b(private_key|secret_key|api_key|password)\b\s*[:=]")),
    ("ETH_PRIVATE_KEY", re.compile(r"\b0x[a-fA-F0-9]{64}\b")),
    ("SEED_PHRASE_HINT", re.compile(r"(?i)\b(seed phrase|recovery phrase|mnemonic)\b")),
]


def regex_prescan(text: str) -> Dict[str, Any]:
    found_types = set()
    evidence = []

    for name, rx in REGEX_RULES:
        for m in rx.finditer(text):
            found_types.add(name)
            snippet = text[max(0, m.start() - 20): min(len(text), m.end() + 20)]
            evidence.append(snippet)

            if len(evidence) >= 6:
                break

    # Base score from findings
    score = 0
    if "ETH_PRIVATE_KEY" in found_types or "SEED_PHRASE_HINT" in found_types:
        score = max(score, 85)
    if "AWS_ACCESS_KEY_ID" in found_types:
        score = max(score, 75)
    if "SSN" in found_types:
        score = max(score, 65)
    if "PRIVATE_KEY_HINT" in found_types:
        score = max(score, 55)

    return {
        "types": sorted(found_types),
        "evidence": evidence[:6],
        "score": score
    }


def safe_evidence_snippets(raw: List[str]) -> List[str]:
    # Redact any obvious key-like values in the evidence snippets
    redacted = []
    for s in raw:
        # mask long tokens
        s2 = re.sub(r"(AKIA[0-9A-Z]{16})", lambda m: redact_snippet(m.group(1)), s)
        s2 = re.sub(r"(0x[a-fA-F0-9]{64})", lambda m: redact_snippet(m.group(1)), s2)
        s2 = re.sub(r"(\b\d{3}-\d{2}-\d{4}\b)", "****-**-****", s2)
        redacted.append(s2.strip())
    return redacted[:6]


async def gemini_upload_analyze(text: str) -> Dict[str, Any]:
    prompt = f"""
You are a security scanner for browser uploads. Analyze the text content and detect sensitive information:
- SSNs, government IDs
- passwords, API keys, tokens
- private keys, seed phrases, recovery phrases
- AWS keys or cloud credentials
Return ONLY valid JSON with keys:
risk_score (0-100 integer),
detected_types (array of strings),
evidence_snippets (array of short strings, REDACT secrets with ****),
explanation (string),
remediation_steps (array of strings).
Text:
\"\"\"{text[:120000]}\"\"\"
"""

    model = "gemini-2.5-flash"
    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config={"response_mime_type": "application/json"},
    )

    # google-genai typically returns text JSON in resp.text
    try:
        import json
        return json.loads(resp.text)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Gemini JSON parse error: {e}")


async def gemini_deepfake_analyze(frames_b64: List[str]) -> Dict[str, Any]:
    # Minimal: send frames as inline data, ask for structured JSON.
    # For hackathon: keep model fast/cheap.
    model = "gemini-1.5-flash"

    # Build multimodal contents: text + images
    parts = [{
        "text": (
            "You are analyzing sequential video frames for deepfake/manipulation. "
            "Look for facial blending artifacts, inconsistent lighting/shadows, geometry warping, "
            "lip-sync inconsistencies, unnatural eyes/teeth, and temporal inconsistencies. "
            "Return ONLY valid JSON with keys: deepfake_percentage (0-100 int), signals (array), "
            "explanation (string), recommendation (string)."
        )
    }]

    # Convert data URLs to raw bytes
    for data_url in frames_b64[:12]:
        if not data_url.startswith("data:image"):
            continue
        header, b64 = data_url.split(",", 1)
        img_bytes = base64.b64decode(b64)
        parts.append({
            "inline_data": {
                "mime_type": "image/jpeg" if "jpeg" in header or "jpg" in header else "image/png",
                "data": img_bytes
            }
        })

    resp = client.models.generate_content(
        model=model,
        contents=[{"role": "user", "parts": parts}],
        config={"response_mime_type": "application/json"},
    )

    try:
        import json
        return json.loads(resp.text)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Gemini JSON parse error: {e}")


# ----------------------------
# Routes
# ----------------------------
@app.get("/health")
def health():
    return {"ok": True}


@app.post("/analyze/upload", response_model=UploadAnalyzeResponse)
async def analyze_upload(req: UploadAnalyzeRequest):
    if not req.text or len(req.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="Empty text")

    prescan = regex_prescan(req.text)
    gem = await gemini_upload_analyze(req.text)

    # Combine scores: take max, but keep bounded
    score = int(max(prescan["score"], int(gem.get("risk_score", 0))))
    score = max(0, min(100, score))

    detected = sorted(set(prescan["types"]) | set(gem.get("detected_types", [])))

    evidence = safe_evidence_snippets(prescan["evidence"] + (gem.get("evidence_snippets") or []))
    explanation = str(gem.get("explanation", ""))
    remediation = gem.get("remediation_steps") or [
        "Remove sensitive data before uploading.",
        "Rotate exposed credentials immediately.",
        "Use a secrets manager and least-privilege access."
    ]

    # Proof hash: hash of redacted evidence + detected types (not raw content)
    proof_material = ("|".join(detected) + "|" + "|".join(evidence)).encode("utf-8")
    proof = sha256_hex(proof_material)

    return UploadAnalyzeResponse(
        risk_score=score,
        risk_level=risk_level(score),
        detected_types=detected,
        evidence_snippets=evidence,
        explanation=explanation,
        remediation_steps=remediation,
        proof_hash=proof
    )


@app.post("/analyze/deepfake", response_model=DeepfakeAnalyzeResponse)
async def analyze_deepfake(req: DeepfakeAnalyzeRequest):
    if not req.frames:
        raise HTTPException(status_code=400, detail="No frames provided")

    gem = await gemini_deepfake_analyze(req.frames)

    pct = int(gem.get("deepfake_percentage", 0))
    pct = max(0, min(100, pct))

    signals = gem.get("signals") or []
    explanation = str(gem.get("explanation", ""))
    recommendation = str(gem.get("recommendation", ""))

    proof_material = (str(pct) + "|" + "|".join(map(str, signals)) + "|" + (req.page_url or "")).encode("utf-8")
    proof = sha256_hex(proof_material)

    return DeepfakeAnalyzeResponse(
        deepfake_percentage=pct,
        risk_level=risk_level(pct),
        signals=[str(s) for s in signals][:10],
        explanation=explanation,
        recommendation=recommendation,
        proof_hash=proof
    )