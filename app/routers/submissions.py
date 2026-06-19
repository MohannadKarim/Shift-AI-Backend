from fastapi import APIRouter, HTTPException, Depends
from app.dependencies import get_current_user, admin_only
from app.services.firebase import get_db
from app.services.anthropic import analyze_submission as ai_analyze
from app.models.models import SubmissionCreate, ApproveSubmissionRequest, AnalyzeSubmissionRequest, AnalyzeSubmissionResponse
from datetime import datetime, timezone

router = APIRouter()


@router.get("/")
def list_all_submissions(user: dict = Depends(admin_only)):
    db = get_db()
    docs = db.collection("submissions").order_by("createdAt", direction="DESCENDING").stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.get("/mine")
def list_my_submissions(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = (
        db.collection("submissions")
        .where("userId", "==", user["uid"])
        .order_by("createdAt", direction="DESCENDING")
        .stream()
    )
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.get("/recent")
def recent_submissions(department: str | None = None, limit: int = 5, user: dict = Depends(get_current_user)):
    """
    Public (non-private) recent submissions, for the Dashboard activity feed
    and Department page. Filters/sorts in Python to avoid composite indexes.
    """
    db = get_db()
    docs = db.collection("submissions").where("isPrivate", "==", False).stream()
    items = [{"id": doc.id, **doc.to_dict()} for doc in docs]
    if department:
        items = [i for i in items if i.get("department") == department]
    items.sort(key=lambda i: i.get("createdAt", ""), reverse=True)
    return items[:limit]


@router.post("/analyze")
def analyze_submission_endpoint(body: AnalyzeSubmissionRequest, user: dict = Depends(get_current_user)):
    result = ai_analyze(body.title, body.description)
    return AnalyzeSubmissionResponse(
        tags=result.get("tags", []),
        insights=result.get("insights", []),
    )


@router.get("/{submission_id}")
def get_submission(submission_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection("submissions").document(submission_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Submission not found")
    data = doc.to_dict()
    user_role = user.get("role", "Team Member")
    if data.get("isPrivate") and data.get("userId") != user["uid"] and user_role not in ["Admin", "Super Admin"]:
        raise HTTPException(status_code=403, detail="This submission is private")
    return {"id": doc.id, **data}


@router.post("/")
def create_submission(body: SubmissionCreate, user: dict = Depends(get_current_user)):
    db = get_db()
    doc_ref = db.collection("submissions").document()
    data = body.model_dump()
    data["userId"] = user["uid"]
    data["userName"] = user.get("name", user.get("email", ""))
    data["status"] = "pending"
    data["pointsAwarded"] = 0
    data["createdAt"] = datetime.now(timezone.utc).isoformat()
    doc_ref.set(data)
    return {"id": doc_ref.id, **data}


@router.put("/{submission_id}/approve")
def approve_submission(
    submission_id: str,
    body: ApproveSubmissionRequest,
    user: dict = Depends(admin_only),
):
    db = get_db()
    doc_ref = db.collection("submissions").document(submission_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Submission not found")
    submission = doc.to_dict()
    doc_ref.update({"status": "approved", "pointsAwarded": body.pointsAwarded})
    user_ref = db.collection("users").document(submission["userId"])
    user_doc = user_ref.get()
    if user_doc.exists:
        current_points = user_doc.to_dict().get("points", 0) + body.pointsAwarded
        new_level = max(1, current_points // 100)
        user_ref.update({"points": current_points, "level": new_level})
    return {"message": "Submission approved", "pointsAwarded": body.pointsAwarded}


@router.put("/{submission_id}/reject")
def reject_submission(submission_id: str, user: dict = Depends(admin_only)):
    db = get_db()
    doc = db.collection("submissions").document(submission_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Submission not found")
    db.collection("submissions").document(submission_id).update({"status": "rejected"})
    return {"message": "Submission rejected"}