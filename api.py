from __future__ import annotations

import io
import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

APP_VERSION = "0.1.1"
MAX_IMAGE_BYTES = 8 * 1024 * 1024

logger = logging.getLogger(__name__)

origins_env = os.getenv(
    "SCAMSHIELD_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://192.168.0.110:5173",
)

allowed_origins = [
    item.strip()
    for item in origins_env.split(",")
    if item.strip()
]

app = FastAPI(
    title="ScamShield Analysis API",
    version=APP_VERSION,
    description="API adapter for the existing ScamShield analysis pipeline.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=12000)
    source_mode: Literal["Message", "Link"] = "Message"


# ============================================================
# ANALYZER INITIALIZATION
# ============================================================

@lru_cache(maxsize=1)
def get_analyzer():
    """Load the existing ScamShield analyzer once per process."""
    try:
        from core.analyzer import ScamAnalyzer
    except Exception as exc:
        logger.exception(
            "Could not import core.analyzer.ScamAnalyzer"
        )
        raise RuntimeError(
            "Could not import ScamAnalyzer. Verify that the core "
            "modules and Python dependencies are installed."
        ) from exc

    return ScamAnalyzer()


# ============================================================
# INPUT NORMALIZATION
# ============================================================

def _normalize_url(text: str) -> str:
    value = text.strip()

    if value and not value.lower().startswith(
        ("http://", "https://")
    ):
        value = "https://" + value

    return value


# ============================================================
# CENTRAL ANALYSIS PIPELINE
# ============================================================

def _analyze_text(
    text: str,
    source_mode: Literal["Message", "Link", "Screenshot"],
):
    clean_text = text.strip()

    if not clean_text:
        raise HTTPException(
            status_code=422,
            detail=(
                "Add a message, screenshot with readable text, "
                "or URL first."
            ),
        )

    if len(clean_text) > 12000:
        raise HTTPException(
            status_code=413,
            detail="Input exceeds the 12,000-character limit.",
        )

    if source_mode == "Link":
        clean_text = _normalize_url(clean_text)

    try:
        result = get_analyzer().analyze(clean_text)

    except Exception as exc:
        # Full details go to server logs, not to public responses.
        logger.exception(
            "ScamShield analysis pipeline failed "
            "(source_mode=%s, input_length=%d)",
            source_mode,
            len(clean_text),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "ScamShield could not complete the analysis. "
                "Check the backend logs for the internal error."
            ),
        ) from exc

    if not isinstance(result, dict) or not result.get("success", False):
        detail = (
            result.get(
                "error",
                "The analysis engine returned an unexpected result.",
            )
            if isinstance(result, dict)
            else "The analysis engine returned an unexpected result."
        )

        logger.error(
            "Analysis returned an unsuccessful result: %s",
            str(detail)[:500],
        )

        raise HTTPException(
            status_code=500,
            detail="The analysis engine could not complete the request.",
        )

    # Attach request metadata without persisting submitted content.
    result["source_mode"] = source_mode
    result["created_at"] = datetime.now(timezone.utc).isoformat()

    # Do not expose internal request fields.
    result.pop("_submitted_text", None)

    return {
        "success": True,
        "result": result,
        "analyzed_text": clean_text,
        "source_mode": source_mode,
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():
    """
    Check API liveness.

    This endpoint does not guarantee that the AI model or
    the analysis pipeline is available.
    """
    ai_provider = (
        "gemini"
        if os.getenv("GEMINI_API_KEY")
        else "ollama"
    )

    return {
        "status": "ok",
        "service": "ScamShield Analysis API",
        "version": APP_VERSION,
        "runtime": "server",
        "ai_provider": ai_provider,
        "storage": "no server-side persistence in this adapter",
    }


# ============================================================
# MESSAGE AND LINK ANALYSIS
# ============================================================

@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    return _analyze_text(
        request.text,
        request.source_mode,
    )


# ============================================================
# SCREENSHOT ANALYSIS
# ============================================================

@app.post("/api/analyze-screenshot")
async def analyze_screenshot(file: UploadFile = File(...)):
    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=415,
            detail="Upload a PNG, JPG, or WEBP image.",
        )

    try:
        content = await file.read(MAX_IMAGE_BYTES + 1)

        if len(content) > MAX_IMAGE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="The screenshot must be 8 MB or smaller.",
            )

        try:
            from PIL import Image
        except ImportError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Image support is missing. Install Pillow."
                ),
            ) from exc

        try:
            import pytesseract
        except ImportError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "OCR support is missing. Install pytesseract "
                    "and Pillow, and ensure the Tesseract program "
                    "is installed on the server."
                ),
            ) from exc

        try:
            image = Image.open(io.BytesIO(content)).convert("RGB")
            extracted = pytesseract.image_to_string(image).strip()

        except Exception as exc:
            logger.exception("Screenshot OCR failed")

            raise HTTPException(
                status_code=503,
                detail=(
                    "Local OCR could not process the image. "
                    "Check the OCR installation and backend logs."
                ),
            ) from exc

        if not extracted:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No readable text was found. Try a clearer "
                    "screenshot or paste the text in Message mode."
                ),
            )

        response = _analyze_text(extracted, "Screenshot")
        response["ocr_text"] = extracted
        response["filename"] = file.filename or "screenshot"

        return response

    finally:
        await file.close()
