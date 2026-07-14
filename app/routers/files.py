"""
files.py — File generation endpoints.

POST /files/generate/pdf
POST /files/generate/pptx
POST /files/generate/docx
POST /files/generate/html

All four accept the same request body:
  {
    "title": "My Report",
    "content": "Markdown text...",
    "workflow_title": "Optional workflow name"
  }

And stream back the file as a download with correct Content-Type headers.
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
from app.services.file_generator import generate_pdf, generate_pptx, generate_docx, generate_html
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
    """Generate and download a PDF from AI output."""
    try:
        pdf_bytes, filename = generate_pdf(
            title=body.title,
            content=body.content,
            workflow_title=body.workflow_title or "",
            branding=get_file_settings(),
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
    """Generate and download a PowerPoint presentation from AI output."""
    try:
        pptx_bytes, filename = generate_pptx(
            title=body.title,
            content=body.content,
            workflow_title=body.workflow_title or "",
            branding=get_file_settings(),
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
    """Generate and download a Word (.docx) document from AI output."""
    try:
        docx_bytes, filename = generate_docx(
            title=body.title,
            content=body.content,
            workflow_title=body.workflow_title or "",
            branding=get_file_settings(),
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
    """Generate a styled HTML file from AI output (also suitable for inline preview)."""
    try:
        html_bytes, filename = generate_html(
            title=body.title,
            content=body.content,
            workflow_title=body.workflow_title or "",
            branding=get_file_settings(),
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
    The frontend can embed this in an <iframe srcdoc="..."> or a sandboxed iframe.
    """
    try:
        html_bytes, _ = generate_html(
            title=body.title,
            content=body.content,
            workflow_title=body.workflow_title or "",
            branding=get_file_settings(),
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