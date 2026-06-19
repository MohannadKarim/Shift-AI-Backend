"""
files.py — File generation endpoints.

POST /files/generate/pdf
POST /files/generate/pptx
POST /files/generate/html

All three accept the same request body:
  {
    "title": "My Report",
    "content": "Markdown text...",
    "workflow_title": "Optional workflow name"
  }

And stream back the file as a download with correct Content-Type headers.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional

from app.dependencies import get_current_user
from app.services.file_generator import generate_pdf, generate_pptx, generate_html
from app.limiter import limiter

router = APIRouter()


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
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PPTX generation failed: {str(e)}")

    return Response(
        content=pptx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
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
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"HTML preview failed: {str(e)}")

    return Response(
        content=html_bytes,
        media_type="text/html; charset=utf-8",
    )