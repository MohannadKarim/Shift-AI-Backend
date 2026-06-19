from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.services.firebase import verify_token

bearer_scheme = HTTPBearer()

# ── TEST ACCOUNT — remove before final production ─────────────────────────────
# Use this token to bypass Firebase auth during testing:
#   Authorization: Bearer shift-test-superadmin-2026
TEST_SUPER_ADMIN_TOKEN = "shift-test-superadmin-2026"
TEST_SUPER_ADMIN_USER = {
    "uid": "test-super-admin",
    "email": "superadmin@shiftai.test",
    "role": "Super Admin",
    "firstName": "Shift",
    "lastName": "Admin",
    "status": "approved",
}
# ─────────────────────────────────────────────────────────────────────────────


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    token = credentials.credentials

    # Test account bypass — remove before final production
    if token == TEST_SUPER_ADMIN_TOKEN:
        return TEST_SUPER_ADMIN_USER

    try:
        decoded = verify_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    # Enforce approval — pending users are blocked from all API calls
    user_status = decoded.get("status", "approved")
    if user_status == "pending":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="account_pending_approval",
        )

    return decoded


def require_role(*roles: str):
    def checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "Team Member")
        if user_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required: {list(roles)}",
            )
        return user
    return checker


def admin_only(user: dict = Depends(get_current_user)) -> dict:
    user_role = user.get("role", "Team Member")
    if user_role not in ["Admin", "Super Admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def super_admin_only(user: dict = Depends(get_current_user)) -> dict:
    user_role = user.get("role", "Team Member")
    if user_role != "Super Admin":
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return user
