import os
import re
import json
import base64
import hashlib
from pathlib import Path
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

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/opt/shieldlens/uploads")).resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

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

    # New: file identity
    file_sha256 = Column(String(64), nullable=True, index=True)
    file_size_bytes = Column(Integer, nullable=False, default=0)
    cached = Column(Integer, nullable=False, default=0)  # 0/1 for sqlite-friendly

    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(16), nullable=False)
    detected_types_json = Column(Text, nullable=False)      # JSON string
    evidence_snippets_json = Column(Text, nullable=False)   # JSON string
    proof_hash = Column(String(64), nullable=False)


class StoredFile(Base):
    __tablename__ = "stored_files"

    sha256 = Column(String(64), primary_key=True)  # file hash
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    filename = Column(String(512), nullable=True)
    mime_type = Column(String(128), nullable=True)
    size_bytes = Column(Integer, nullable=False)
    storage_path = Column(Text, nullable=False)  # path on disk


Base.metadata.create_all(bind=engine)


# ----------------------------
# API Models
# ----------------------------
class UploadAnalyzeRequest(BaseModel):
    text: str = Field(..., max_length=300_000)
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    page_url: Optional[str] = None


class FileBase64AnalyzeRequest(BaseModel):
    file_base64: str = Field(..., max_length=20_000_000)  # adjust if you need bigger
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


def file_store_path(file_hash: str, filename: Optional[str]) -> Path:
    ext = ""
    if filename and "." in filename:
        ext = "." + filename.split(".")[-1][:10]
    return UPLOAD_DIR / f"{file_hash}{ext}"


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


def db_get_latest_scan_by_hash(file_hash: str) -> Optional[ScanLog]:
    db = SessionLocal()
    try:
        return (
            db.query(ScanLog)
            .filter(ScanLog.file_sha256 == file_hash)
            .order_by(desc(ScanLog.id))
            .first()
        )
    finally:
        db.close()


def db_store_file_if_new(file_hash: str, raw: bytes, filename: Optional[str], mime_type: Optional[str]) -> None:
    db = SessionLocal()
    try:
        existing = db.query(StoredFile).filter(StoredFile.sha256 == file_hash).first()
        if existing:
            return

        path = file_store_path(file_hash, filename)
        if not path.exists():
            path.write_bytes(raw)

        row = StoredFile(
            sha256=file_hash,
            filename=filename,
            mime_type=mime_type,
            size_bytes=len(raw),
            storage_path=str(path),
        )
        db.add(row)
        db.commit()
    finally:
        db.close()


def save_scan_log(
    *,
    page_url: Optional[str],
    filename: Optional[str],
    mime_type: Optional[str],
    source_ip: Optional[str],
    file_sha256: Optional[str],
    file_size_bytes: int,
    cached: int,
    risk_score: int,
    risk_level_str: str,
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
            file_sha256=file_sha256,
            file_size_bytes=file_size_bytes,
            cached=cached,
            risk_score=risk_score,
            risk_level=risk_level_str,
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
                    "file_sha256": r.file_sha256,
                    "file_size_bytes": r.file_size_bytes,
                    "cached": bool(r.cached),
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
    # Text-only endpoint (still dedupes/stores)
    if not req.text or len(req.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="Empty text")

    raw = req.text.encode("utf-8", errors="ignore")
    file_hash = sha256_hex(raw)

    # Dedupe: if already scanned, return cached result (skip re-scan and re-store)
    existing = db_get_latest_scan_by_hash(file_hash)
    if existing:
        return UploadAnalyzeResponse(
            risk_score=existing.risk_score,
            risk_level=existing.risk_level,
            detected_types=json.loads(existing.detected_types_json),
            evidence_snippets=json.loads(existing.evidence_snippets_json),
            explanation="Cached: this exact upload was already scanned.",
            remediation_steps=[
                "This content has already been scanned previously.",
                "If you changed it, upload the modified version (hash will differ).",
            ],
            proof_hash=existing.proof_hash,
        )

    # Store the "file" version of this text (useful for audit)
    db_store_file_if_new(file_hash, raw, req.filename, req.mime_type)

    prescan = regex_prescan(req.text)

    gem = None
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
    proof_material = ("|".join(detected) + "|" + "|".join(evidence)).encode("utf-8")
    proof = sha256_hex(proof_material)
    source_ip = request.client.host if request.client else None

    save_scan_log(
        page_url=req.page_url,
        filename=req.filename,
        mime_type=req.mime_type,
        source_ip=source_ip,
        file_sha256=file_hash,
        file_size_bytes=len(raw),
        cached=0,
        risk_score=score,
        risk_level_str=level,
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


@app.post("/analyze/file_base64", response_model=UploadAnalyzeResponse)
async def analyze_file_base64(req: FileBase64AnalyzeRequest, request: Request):
    # Decode base64
    try:
        raw = base64.b64decode(req.file_base64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64")

    file_hash = sha256_hex(raw)

    # Dedupe: if already scanned, return cached result
    existing = db_get_latest_scan_by_hash(file_hash)
    if existing:
        return UploadAnalyzeResponse(
            risk_score=existing.risk_score,
            risk_level=existing.risk_level,
            detected_types=json.loads(existing.detected_types_json),
            evidence_snippets=json.loads(existing.evidence_snippets_json),
            explanation="Cached: this exact file was already scanned.",
            remediation_steps=[
                "This file has already been scanned previously.",
                "If you changed it, upload the modified version (hash will differ).",
            ],
            proof_hash=existing.proof_hash,
        )

    # Store file once
    db_store_file_if_new(file_hash, raw, req.filename, req.mime_type)

    # Best-effort text extraction
    text = ""
    # If it is probably text, decode; otherwise create a placeholder
    text = raw.decode("utf-8", errors="ignore")
    if not text.strip():
        text = f"[BINARY FILE] filename={req.filename or ''} mime={req.mime_type or ''} size={len(raw)}"

    prescan = regex_prescan(text)

    gem = None
    if client is not None:
        try:
            gem = await gemini_upload_analyze(text)
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
    proof_material = ("|".join(detected) + "|" + "|".join(evidence)).encode("utf-8")
    proof = sha256_hex(proof_material)
    source_ip = request.client.host if request.client else None

    save_scan_log(
        page_url=req.page_url,
        filename=req.filename,
        mime_type=req.mime_type,
        source_ip=source_ip,
        file_sha256=file_hash,
        file_size_bytes=len(raw),
        cached=0,
        risk_score=score,
        risk_level_str=level,
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