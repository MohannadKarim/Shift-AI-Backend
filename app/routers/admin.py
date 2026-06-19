from fastapi import APIRouter, Depends
from app.dependencies import admin_only
from app.services.firebase import get_db
from app.services import token_tracker

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
    """Admin: get 7-day org-wide token usage history."""
    from datetime import datetime, timezone, timedelta
    today = datetime.now(timezone.utc)
    results = []
    for i in range(7):
        date_str = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        results.append(token_tracker.get_org_usage(date_str))
    return results
