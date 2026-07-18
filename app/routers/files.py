"""
files.py — File generation endpoints.

POST /files/generate/pdf
POST /files/generate/pptx
POST /files/generate/docx
POST /files/generate/html

All four accept the same request body:
  {
    "title": "Suggested title (used as a fallback only)",
    "content": "The raw chat message text to turn into a file",
    "workflow_title": "Optional workflow name"
  }

`content` is passed through a dedicated, isolated AI call
(structure_text_for_file) that reorganizes it into a title + sections
structure, which is then rendered by app.services.file_generator. This
replaced an earlier design where the main chat agent tried to emit a JSON
spec inline in its reply — that kept breaking under real load (fence-tag
drift, truncated output). Structuring is now its own small, tool-forced call
triggered only when the user clicks Export, decoupled entirely from
conversational chat.

Streams back the file as a download with correct Content-Type headers.
"""

import os
import mimetypes
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel
from typing import Optional

from app.config import settings
from app.dependencies import get_current_user
from app.services.file_generator import build_file_from_structured
from app.services.anthropic import structure_text_for_file
from app.services.firebase import upload_file_to_storage
from app.services.local_storage import save_file_locally, resolve_local_path
from app.services.file_settings import get_file_settings
from app.limiter import limiter

router = APIRouter()

MAX_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB


class FileGenerateRequest(BaseModel):
    title: str
    content: str
    workflow_title: Optional[str] = ""


# ── PDF ───────────────────────────────────────────────────────────────────────

@router.post("/generate/pdf")
@limiter.limit("20/minute")
def export_pdf(
    request: Request,
    body: FileGenerateRequest,
    user: dict = Depends(get_current_user),
):
    """Structure the given text via a dedicated AI call, then render it as a PDF."""
    try:
        file_settings = get_file_settings()
        spec = structure_text_for_file(body.content, "pdf", body.workflow_title or "", file_settings)
        pdf_bytes, filename = build_file_from_structured(
            file_type="pdf",
            title=spec["title"],
            sections=spec["sections"],
            workflow_title=body.workflow_title or "",
            branding=file_settings,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── PPTX ──────────────────────────────────────────────────────────────────────

@router.post("/generate/pptx")
@limiter.limit("20/minute")
def export_pptx(
    request: Request,
    body: FileGenerateRequest,
    user: dict = Depends(get_current_user),
):
    """Structure the given text via a dedicated AI call, then render it as a PowerPoint deck."""
    try:
        file_settings = get_file_settings()
        spec = structure_text_for_file(body.content, "pptx", body.workflow_title or "", file_settings)
        pptx_bytes, filename = build_file_from_structured(
            file_type="pptx",
            title=spec["title"],
            sections=spec["sections"],
            workflow_title=body.workflow_title or "",
            branding=file_settings,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PPTX generation failed: {str(e)}")

    return Response(
        content=pptx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── DOCX ──────────────────────────────────────────────────────────────────────

@router.post("/generate/docx")
@limiter.limit("20/minute")
def export_docx(
    request: Request,
    body: FileGenerateRequest,
    user: dict = Depends(get_current_user),
):
    """Structure the given text via a dedicated AI call, then render it as a Word (.docx) document."""
    try:
        file_settings = get_file_settings()
        spec = structure_text_for_file(body.content, "docx", body.workflow_title or "", file_settings)
        docx_bytes, filename = build_file_from_structured(
            file_type="docx",
            title=spec["title"],
            sections=spec["sections"],
            workflow_title=body.workflow_title or "",
            branding=file_settings,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DOCX generation failed: {str(e)}")

    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── HTML ──────────────────────────────────────────────────────────────────────

@router.post("/generate/html")
@limiter.limit("20/minute")
def export_html(
    request: Request,
    body: FileGenerateRequest,
    user: dict = Depends(get_current_user),
):
    """Structure the given text via a dedicated AI call, then render it as a styled HTML page."""
    try:
        file_settings = get_file_settings()
        spec = structure_text_for_file(body.content, "html", body.workflow_title or "", file_settings)
        html_bytes, filename = build_file_from_structured(
            file_type="html",
            title=spec["title"],
            sections=spec["sections"],
            workflow_title=body.workflow_title or "",
            branding=file_settings,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"HTML generation failed: {str(e)}")

    return Response(
        content=html_bytes,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Preview (inline HTML, no download) ───────────────────────────────────────

@router.post("/preview/html")
@limiter.limit("30/minute")
def preview_html(
    request: Request,
    body: FileGenerateRequest,
    user: dict = Depends(get_current_user),
):
    """
    Return rendered HTML inline (no download header) for in-chat preview.
    Uses the same AI-structuring step as the download endpoint, so preview
    and download always match.
    The frontend can embed this in an <iframe srcdoc="..."> or a sandboxed iframe.
    """
    try:
        file_settings = get_file_settings()
        spec = structure_text_for_file(body.content, "html", body.workflow_title or "", file_settings)
        html_bytes, _ = build_file_from_structured(
            file_type="html",
            title=spec["title"],
            sections=spec["sections"],
            workflow_title=body.workflow_title or "",
            branding=file_settings,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"HTML preview failed: {str(e)}")

    return Response(
        content=html_bytes,
        media_type="text/html; charset=utf-8",
    )


# ── Upload (user-provided files, e.g. submission attachments) ─────────────────

@router.post("/upload")
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    """
    Accept a multipart file upload and store it via the configured backend
    (settings.storage_backend — "local" disk by default, or "firebase" once
    Storage is set up). Returns a stable download URL to save on the
    resulting record (e.g. a submission's `link` field).
    """
    contents = await file.read()

    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 15MB)")

    safe_name = os.path.basename(file.filename or "upload")
    timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
    dest_path = f"submissions/{user['uid']}/{timestamp}_{safe_name}"

    try:
        if settings.storage_backend == "firebase":
            url = upload_file_to_storage(
                file_bytes=contents,
                dest_path=dest_path,
                content_type=file.content_type or "application/octet-stream",
            )
        else:
            save_file_locally(contents, dest_path)
            base_url = str(request.base_url).rstrip("/")
            url = f"{base_url}/files/uploads/{dest_path}"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

    return {"url": url, "filename": safe_name, "size": len(contents)}


@router.get("/uploads/{file_path:path}")
async def serve_uploaded_file(file_path: str):
    """
    Serve a file previously stored via the "local" storage backend.
    Not used when storage_backend="firebase" (those URLs point straight at
    Firebase Storage instead). No auth check here — same trust model as a
    Firebase Storage download-token URL: unguessable path, not access-controlled.
    """
    try:
        full_path = resolve_local_path(file_path)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid file path")

    if not full_path.exists() or not full_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    media_type, _ = mimetypes.guess_type(str(full_path))
    return FileResponse(full_path, media_type=media_type or "application/octet-stream")