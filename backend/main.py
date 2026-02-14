import os
import re
import json
import hashlib
from typing import List, Optional, Dict, Any
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    desc,
)
from sqlalchemy.orm import sessionmaker, declarative_base

from google import genai

# ----------------------------
# Config / Setup
# ----------------------------
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

# Store DB on Vultr disk. Recommended: /opt/shieldlens/shieldlens.db
DB_PATH = os.getenv("DB_PATH", "./shieldlens.db").strip()
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Gemini models to try (fallback)
UPLOAD_MODELS = [
    "models/gemini-2.5-flash",
    "models/gemini-flash-latest",
    "models/gemini-flash-lite-latest",
]

# If you want the server to work even with no Gemini key (regex-only), set this to False
REQUIRE_GEMINI = False

if REQUIRE_GEMINI and not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY in .env")

client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

app = FastAPI(title="ShieldLens Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Database (SQLite)
# ----------------------------
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    page_url = Column(Text, nullable=True)
    filename = Column(String(512), nullable=True)
    mime_type = Column(String(128), nullable=True)
    source_ip = Column(String(64), nullable=True)

    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(16), nullable=False)
    detected_types_json = Column(Text, nullable=False)      # JSON string
    evidence_snippets_json = Column(Text, nullable=False)   # JSON string
    proof_hash = Column(String(64), nullable=False)


Base.metadata.create_all(bind=engine)


def db_save_scan(
    *,
    page_url: Optional[str],
    filename: Optional[str],
    mime_type: Optional[str],
    source_ip: Optional[str],
    risk_score: int,
    risk_level: str,
    detected_types: List[str],
    evidence_snippets: List[str],
    proof_hash: str,
) -> int:
    db = SessionLocal()
    try:
        row = ScanLog(
            page_url=page_url,
            filename=filename,
            mime_type=mime_type,
            source_ip=source_ip,
            risk_score=risk_score,
            risk_level=risk_level,
            detected_types_json=json.dumps(detected_types),
            evidence_snippets_json=json.dumps(evidence_snippets),
            proof_hash=proof_hash,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


# ----------------------------
# API Models
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
            snippet = text[max(0, m.start() - 25) : min(len(text), m.end() + 25)]
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
        s2 = re.sub(r"(?i)(aws_secret_access_key\s*[:=]\s*)(\S+)", r"\1****", s2)
        s2 = re.sub(r"(?i)(password\s*[:=]\s*)(\S+)", r"\1****", s2)
        s2 = re.sub(r"(?i)(api_key\s*[:=]\s*)(\S+)", r"\1****", s2)
        redacted.append(s2.strip())
    return redacted[:8]


async def gemini_upload_analyze(text: str) -> Dict[str, Any]:
    if client is None:
        raise RuntimeError("Gemini client not configured (no GEMINI_API_KEY).")

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
            return json.loads(resp.text)
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Gemini analyze failed: {last_err}")


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def root():
    return {"name": "ShieldLens Backend", "ok": True, "docs": "/docs"}


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/reports/latest")
def latest_reports(limit: int = 10):
    db = SessionLocal()
    try:
        rows = db.query(ScanLog).order_by(desc(ScanLog.id)).limit(max(1, min(limit, 50))).all()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r.id,
                    "created_at": r.created_at.isoformat() + "Z",
                    "filename": r.filename,
                    "mime_type": r.mime_type,
                    "page_url": r.page_url,
                    "source_ip": r.source_ip,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "detected_types": json.loads(r.detected_types_json),
                    "evidence_snippets": json.loads(r.evidence_snippets_json),
                    "proof_hash": r.proof_hash,
                }
            )
        return out
    finally:
        db.close()


@app.post("/analyze/upload", response_model=UploadAnalyzeResponse)
async def analyze_upload(req: UploadAnalyzeRequest, request: Request):
    if not req.text or len(req.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="Empty text")

    prescan = regex_prescan(req.text)

    # Gemini (optional) with fallback to regex-only
    gem = None
    explanation = ""
    remediation = None

    if client is not None:
        try:
            gem = await gemini_upload_analyze(req.text)
        except Exception:
            gem = None

    if gem is None:
        score = prescan["score"]
        detected = prescan["types"]
        evidence = safe_evidence_snippets(prescan["evidence"])
        explanation = "AI scan unavailable; showing regex-based detection."
        remediation = [
            "Remove sensitive data before uploading.",
            "Rotate any exposed credentials immediately.",
            "Use a secrets manager for API keys.",
        ]
    else:
        score = int(max(prescan["score"], int(gem.get("risk_score", 0))))
        score = max(0, min(100, score))

        detected = sorted(set(prescan["types"]) | set(gem.get("detected_types", []) or []))
        evidence = safe_evidence_snippets(prescan["evidence"] + (gem.get("evidence_snippets") or []))

        explanation = str(gem.get("explanation", "")) or "Scan complete."
        remediation = gem.get("remediation_steps") or [
            "Remove sensitive data before uploading.",
            "Rotate exposed credentials immediately.",
            "Use a secrets manager and least-privilege access.",
        ]

    level = risk_level(score)

    # Proof hash uses only redacted evidence + types (NEVER raw content)
    proof_material = ("|".join(detected) + "|" + "|".join(evidence)).encode("utf-8")
    proof = sha256_hex(proof_material)

    source_ip = request.client.host if request.client else None

    # Store log to SQLite on Vultr
    db_save_scan(
        page_url=req.page_url,
        filename=req.filename,
        mime_type=req.mime_type,
        source_ip=source_ip,
        risk_score=score,
        risk_level=level,
        detected_types=detected,
        evidence_snippets=evidence,
        proof_hash=proof,
    )

    return UploadAnalyzeResponse(
        risk_score=score,
        risk_level=level,
        detected_types=detected,
        evidence_snippets=evidence,
        explanation=explanation,
        remediation_steps=remediation,
        proof_hash=proof,
    )