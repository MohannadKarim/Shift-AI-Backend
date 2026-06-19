from fastapi import APIRouter, HTTPException, Depends
from app.dependencies import get_current_user, admin_only, super_admin_only
from app.services.firebase import set_user_role, get_db
from datetime import datetime, timezone

router = APIRouter()

SUPER_ADMIN_EMAILS = {"asayeh@telfaz11.com"}


@router.post("/verify")
def verify(user: dict = Depends(get_current_user)):
    """
    Called on every app load after Firebase Auth.
    Returns the user's full profile from Firestore.
    If the user has no Firestore doc yet (first login), creates one with status=pending.
    Super Admin emails are auto-approved.
    """
    db = get_db()
    uid = user.get("uid")
    email = user.get("email", "")

    doc = db.collection("users").document(uid).get()

    if doc.exists:
        data = doc.to_dict()
        return {
            "uid": uid,
            "email": email,
            "role": data.get("role", "Team Member"),
            "status": data.get("status", "approved"),
            **data,
        }

    # First time this user has hit the backend — create their profile
    is_super_admin = email in SUPER_ADMIN_EMAILS
    new_profile = {
        "uid": uid,
        "email": email,
        "firstName": user.get("firstName", ""),
        "lastName": user.get("lastName", ""),
        "department": user.get("department", "Creative"),
        "role": "Super Admin" if is_super_admin else "Team Member",
        "status": "approved" if is_super_admin else "pending",
        "points": 0,
        "level": 1,
        "badges": [],
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    db.collection("users").document(uid).set(new_profile)
    return new_profile


# ── Pending users (admin) ─────────────────────────────────────────────────────

@router.get("/pending")
def list_pending_users(user: dict = Depends(admin_only)):
    """Return all users with status=pending."""
    db = get_db()
    docs = db.collection("users").where("status", "==", "pending").stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.put("/approve/{uid}")
def approve_user(uid: str, user: dict = Depends(admin_only)):
    """Approve a pending user — grants them access to the platform."""
    db = get_db()
    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    if doc.to_dict().get("status") == "approved":
        raise HTTPException(status_code=400, detail="User is already approved")
    db.collection("users").document(uid).update({
        "status": "approved",
        "approvedAt": datetime.now(timezone.utc).isoformat(),
        "approvedBy": user["uid"],
    })
    return {"message": f"User {uid} approved"}


@router.put("/reject/{uid}")
def reject_user(uid: str, user: dict = Depends(admin_only)):
    """Reject (and delete) a pending user."""
    db = get_db()
    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    db.collection("users").document(uid).delete()
    try:
        import firebase_admin.auth as fb_auth
        fb_auth.delete_user(uid)
    except Exception:
        pass
    return {"message": f"User {uid} rejected and removed"}


# ── Role management ───────────────────────────────────────────────────────────

@router.post("/set-role")
def assign_role(body: dict, user: dict = Depends(super_admin_only)):
    uid = body.get("uid")
    role = body.get("role")
    if not uid or not role:
        raise HTTPException(status_code=400, detail="uid and role are required")
    if role not in ["Team Member", "Admin", "Super Admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    try:
        set_user_role(uid, role)
        return {"message": f"Role '{role}' assigned to {uid}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
