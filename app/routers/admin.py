from fastapi import APIRouter, Depends
from app.dependencies import admin_only
from app.services.firebase import get_db

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
