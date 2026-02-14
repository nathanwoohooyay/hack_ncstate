import os
import re
import base64
import binascii
import hashlib
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Gemini SDK (google-genai)
from google import genai

# ----------------------------
# Setup
# ----------------------------
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY in .env")

client = genai.Client(api_key=API_KEY)

app = FastAPI(title="ShieldLens Backend", version="0.1.0")

# CORS (hackathon-safe). Tighten in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


class UploadAnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    detected_types: List[str]
    evidence_snippets: List[str]
    explanation: str
    remediation_steps: List[str]
    proof_hash: str


class DeepfakeAnalyzeRequest(BaseModel):
    frames: List[str] = Field(..., min_items=1, max_items=12)
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

    score = 0
    if "ETH_PRIVATE_KEY" in found_types or "SEED_PHRASE_HINT" in found_types:
        score = max(score, 85)
    if "AWS_ACCESS_KEY_ID" in found_types:
        score = max(score, 75)
    if "SSN" in found_types:
        score = max(score, 65)
    if "PRIVATE_KEY_HINT" in found_types:
        score = max(score, 55)

    return {"types": sorted(found_types), "evidence": evidence[:6], "score": score}


def safe_evidence_snippets(raw: List[str]) -> List[str]:
    redacted = []
    for s in raw:
        s2 = re.sub(r"(AKIA[0-9A-Z]{16})", lambda m: redact_snippet(m.group(1)), s)
        s2 = re.sub(r"(0x[a-fA-F0-9]{64})", lambda m: redact_snippet(m.group(1)), s2)
        s2 = re.sub(r"(\b\d{3}-\d{2}-\d{4}\b)", "****-**-****", s2)
        redacted.append(s2.strip())
    return redacted[:6]


TYPE_ALIASES = {
    "Social Security Number (SSN)": "SSN",
    "AWS Secret Access Key": "AWS_SECRET_ACCESS_KEY",
    "AWS Access Key ID": "AWS_ACCESS_KEY_ID",
}


def normalize_types(types: List[str]) -> List[str]:
    out = set()
    for t in types or []:
        t = str(t).strip()
        out.add(TYPE_ALIASES.get(t, t))
    return sorted(out)


def extract_image_bytes(data_url: str) -> tuple[str, bytes]:
    if "," not in data_url:
        raise ValueError("Frame must be a data URL like data:image/png;base64,...")

    header, b64 = data_url.split(",", 1)

    if not header.startswith("data:image/"):
        raise ValueError("Frame must start with data:image/...")

    mime = "image/jpeg" if ("jpeg" in header or "jpg" in header) else "image/png"

    try:
        img_bytes = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Invalid base64 in frame.")

    return mime, img_bytes


# ----------------------------
# Gemini Calls
# ----------------------------
UPLOAD_MODELS = [
    "models/gemini-2.5-flash",
    "models/gemini-flash-latest",
    "models/gemini-flash-lite-latest",
]

DEEPFAKE_MODELS = [
    "models/gemini-2.5-flash-image",
    "models/gemini-2.5-pro",
]


async def gemini_upload_analyze(text: str) -> Dict[str, Any]:
    prompt = f"""
You are a security scanner for browser uploads. Analyze the text content and detect sensitive information:
- SSNs, government IDs
- passwords, API keys, tokens
- private keys, seed phrases, recovery phrases
- AWS keys or cloud credentials

Return ONLY valid JSON (no markdown, no extra text) with keys:
risk_score (0-100 integer),
detected_types (array of strings),
evidence_snippets (array of short strings; REDACT any secrets with ****),
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


async def gemini_deepfake_analyze(frames_b64: List[str]) -> Dict[str, Any]:
    import json

    parts = [{
        "text": (
            "You are analyzing sequential video frames for deepfake/manipulation. "
            "Look for facial blending artifacts, inconsistent lighting/shadows, geometry warping, "
            "lip-sync inconsistencies, unnatural eyes/teeth, and temporal inconsistencies. "
            "Return ONLY valid JSON (no markdown, no extra text) with keys: "
            "deepfake_percentage (0-100 int), signals (array of short strings), "
            "explanation (string), recommendation (string)."
        )
    }]

    added = 0
    for data_url in frames_b64[:12]:
        if not data_url.startswith("data:image"):
            continue
        mime, img_bytes = extract_image_bytes(data_url)
        parts.append({"inline_data": {"mime_type": mime, "data": img_bytes}})
        added += 1

    if added == 0:
        raise ValueError("No valid data:image frames were provided.")

    last_err = None
    for model in DEEPFAKE_MODELS:
        try:
            resp = client.models.generate_content(
                model=model,
                contents=[{"role": "user", "parts": parts}],
                config={"response_mime_type": "application/json"},
            )
            return json.loads(resp.text)
        except Exception as e:
            last_err = e

    raise HTTPException(status_code=502, detail=f"Gemini deepfake analyze failed: {last_err}")


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

    # Gemini call with fallback to regex-only if it errors
    try:
        gem = await gemini_upload_analyze(req.text)
    except Exception:
        gem = {
            "risk_score": prescan["score"],
            "detected_types": prescan["types"],
            "evidence_snippets": safe_evidence_snippets(prescan["evidence"]),
            "explanation": "AI scan temporarily unavailable; showing regex-based detection.",
            "remediation_steps": [
                "Remove sensitive data before uploading.",
                "Rotate any exposed credentials immediately."
            ]
        }

    score = int(max(prescan["score"], int(gem.get("risk_score", 0))))
    score = max(0, min(100, score))

    detected = normalize_types(list(set(prescan["types"]) | set(gem.get("detected_types", []))))
    evidence = safe_evidence_snippets(prescan["evidence"] + (gem.get("evidence_snippets") or []))

    explanation = str(gem.get("explanation", ""))
    remediation = gem.get("remediation_steps") or [
        "Remove sensitive data before uploading.",
        "Rotate exposed credentials immediately.",
        "Use a secrets manager and least-privilege access."
    ]

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

    try:
        gem = await gemini_deepfake_analyze(req.frames)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Deepfake analyze failed: {repr(e)}")

    pct = int(gem.get("deepfake_percentage", 0))
    pct = max(0, min(100, pct))

    signals = gem.get("signals") or []
    explanation = str(gem.get("explanation", ""))
    recommendation = str(gem.get("recommendation", "")) or "Use caution and verify via trusted channels."

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