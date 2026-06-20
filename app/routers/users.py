from fastapi import APIRouter, HTTPException, Depends
from app.dependencies import get_current_user, admin_only, super_admin_only
from app.services.firebase import get_db
from app.services import token_tracker
import firebase_admin.auth as fb_auth

router = APIRouter()


# ── Self ──────────────────────────────────────────────────────────────────────

@router.get("/me")
def get_me(user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection("users").document(user["uid"]).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User profile not found")
    return {"id": doc.id, **doc.to_dict()}


# ── Leaderboard ───────────────────────────────────────────────────────────────

@router.get("/leaderboard")
def leaderboard(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = db.collection("users").order_by("points", direction="DESCENDING").limit(50).stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.get("/leaderboard/{department}")
def leaderboard_by_dept(department: str, user: dict = Depends(get_current_user)):
    db = get_db()
    docs = (
        db.collection("users")
        .where("department", "==", department)
        .order_by("points", direction="DESCENDING")
        .limit(50)
        .stream()
    )
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


# ── Admin: list & manage users ────────────────────────────────────────────────

@router.get("/")
def list_users(user: dict = Depends(admin_only)):
    db = get_db()
    docs = db.collection("users").stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.put("/{uid}/role")
def update_role(uid: str, body: dict, user: dict = Depends(admin_only)):
    db = get_db()
    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    role = body.get("role")
    if role not in ["Team Member", "Admin", "Super Admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    db.collection("users").document(uid).update({"role": role})
    return {"message": f"Role updated to {role}"}


@router.delete("/{uid}")
def delete_user(uid: str, user: dict = Depends(admin_only)):
    """
    Delete a user from Firebase Auth and their Firestore profile.
    Only Admins and Super Admins can do this.
    A Super Admin cannot delete themselves.
    """
    if uid == user["uid"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    db = get_db()

    # Delete Firestore profile
    user_doc = db.collection("users").document(uid).get()
    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    db.collection("users").document(uid).delete()

    # Delete from Firebase Auth
    try:
        fb_auth.delete_user(uid)
    except fb_auth.UserNotFoundError:
        pass  # Already gone from Auth — still fine, Firestore doc is deleted

    return {"message": f"User {uid} deleted successfully"}


# ── Token usage (self) ────────────────────────────────────────────────────────

@router.get("/me/tokens")
def my_token_usage(user: dict = Depends(get_current_user)):
    """Return today's token usage and budget for the current user."""
    return token_tracker.get_user_usage(user["uid"])


@router.get("/me/tokens/history")
def my_token_history(user: dict = Depends(get_current_user)):
    """Return last 30 days of usage for the current user (most recent first)."""
    return token_tracker.get_user_usage_history(user["uid"], days=30)


@router.get("/me/tokens/summary")
def my_token_summary(user: dict = Depends(get_current_user)):
    """Return daily/weekly/monthly token totals + chart history for the current user."""
    return token_tracker.get_user_usage_summary(user["uid"])


# ── Token usage (admin) ───────────────────────────────────────────────────────

@router.get("/{uid}/tokens")
def user_token_usage(uid: str, user: dict = Depends(admin_only)):
    """Admin: get today's token usage for any user."""
    return token_tracker.get_user_usage(uid)


@router.get("/{uid}/tokens/history")
def user_token_history(uid: str, user: dict = Depends(admin_only)):
    """Admin: get 30-day token history for any user."""
    return token_tracker.get_user_usage_history(uid, days=30)


@router.get("/{uid}/tokens/summary")
def user_token_summary(uid: str, user: dict = Depends(admin_only)):
    """Admin: get daily/weekly/monthly token totals + chart history for any user."""
    return token_tracker.get_user_usage_summary(uid)


@router.put("/{uid}/tokens/budget")
def set_user_budget(uid: str, body: dict, user: dict = Depends(admin_only)):
    """
    Admin: override the default daily token budget for a specific user.
    Body: { "daily_budget": 100000 }
    """
    budget = body.get("daily_budget")
    if not isinstance(budget, int) or budget < 0:
        raise HTTPException(status_code=400, detail="daily_budget must be a non-negative integer")
    token_tracker.admin_set_user_budget(uid, budget)
    return {"message": f"Daily token budget for {uid} set to {budget}"}