from fastapi import APIRouter, Depends, HTTPException
from app.dependencies import admin_only
from app.services.firebase import get_db
from app.services import token_tracker, file_settings as file_settings_service
from app.models.models import FileGenerationSettings, FileGenerationSettingsUpdate

router = APIRouter()


@router.get("/stats")
def get_stats(user: dict = Depends(admin_only)):
    db = get_db()
    users = len(list(db.collection("users").stream()))
    workflows = len(list(db.collection("workflows").stream()))
    all_submissions = list(db.collection("submissions").stream())
    prompts = len(list(db.collection("prompts").stream()))
    pending = sum(1 for doc in all_submissions if doc.to_dict().get("status") == "pending")
    return {
        "total_users": users,
        "total_workflows": workflows,
        "total_submissions": len(all_submissions),
        "pending_submissions": pending,
        "total_prompts": prompts,
    }


@router.get("/tokens/org")
def org_token_usage(user: dict = Depends(admin_only)):
    """Admin: get today's org-wide token usage."""
    return token_tracker.get_org_usage()


@router.get("/tokens/org/history")
def org_token_history(user: dict = Depends(admin_only)):
    """Admin: get 30-day org-wide token usage history (most recent first)."""
    return token_tracker.get_org_usage_history(days=30)


@router.get("/tokens/org/summary")
def org_token_summary(user: dict = Depends(admin_only)):
    """Admin: get daily/weekly/monthly org-wide token totals + chart history."""
    return token_tracker.get_org_usage_summary()


@router.put("/tokens/org/budget")
def set_org_budget(body: dict, user: dict = Depends(admin_only)):
    """
    Admin: override the org-wide daily token budget.
    Body: { "daily_budget": 2000000 }
    """
    budget = body.get("daily_budget")
    if not isinstance(budget, int) or budget < 0:
        raise HTTPException(status_code=400, detail="daily_budget must be a non-negative integer")
    token_tracker.admin_set_org_budget(budget)
    return {"message": f"Org daily token budget set to {budget}"}


# ── File Generation Settings ─────────────────────────────────────────────────

@router.get("/file-settings", response_model=FileGenerationSettings)
def get_file_generation_settings(user: dict = Depends(admin_only)):
    """
    Admin: get org-wide file generation defaults (brand colors, logo, footer,
    and written guidance for PDF/PPTX/HTML output) applied to every file the
    agent or the export endpoints generate.
    """
    return file_settings_service.get_file_settings()


@router.put("/file-settings", response_model=FileGenerationSettings)
def update_file_generation_settings(
    body: FileGenerationSettingsUpdate,
    user: dict = Depends(admin_only),
):
    """Admin: update any subset of the org-wide file generation settings."""
    return file_settings_service.update_file_settings(body.model_dump(exclude_unset=True))