import json
import firebase_admin
from firebase_admin import credentials, auth, firestore
from app.config import settings

_db = None


def init_firebase():
    """Initialize Firebase Admin SDK. Called once on startup."""
    if firebase_admin._apps:
        return

    if settings.firebase_credentials_json:
        cred_dict = json.loads(settings.firebase_credentials_json)
        cred = credentials.Certificate(cred_dict)
    else:
        cred = credentials.Certificate(settings.firebase_credentials_path)

    firebase_admin.initialize_app(cred)


def get_db() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.client()
    return _db


def verify_token(id_token: str) -> dict:
    """
    Verify a Firebase ID token and enrich with Firestore profile data
    (role, status) so dependencies.py has everything it needs in one place.
    """
    decoded = auth.verify_id_token(id_token)
    uid = decoded.get("uid")

    db = get_db()
    doc = db.collection("users").document(uid).get()
    if doc.exists:
        profile = doc.to_dict()
        decoded["role"] = profile.get("role", "Team Member")
        decoded["status"] = profile.get("status", "approved")
    else:
        # No Firestore profile yet — treat as pending until /auth/verify creates it
        decoded["role"] = "Team Member"
        decoded["status"] = "pending"

    return decoded


def set_user_role(uid: str, role: str):
    """Set custom claim 'role' on a Firebase user."""
    auth.set_custom_user_claims(uid, {"role": role})


def get_user(uid: str) -> auth.UserRecord:
    return auth.get_user(uid)
