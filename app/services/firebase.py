import json
import uuid
from urllib.parse import quote

import firebase_admin
from firebase_admin import credentials, auth, firestore, storage as fb_storage
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

    options = {}
    if settings.firebase_storage_bucket:
        options["storageBucket"] = settings.firebase_storage_bucket

    firebase_admin.initialize_app(cred, options)


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


def get_bucket():
    """Return the default Firebase Storage bucket (Admin SDK — bypasses Storage security rules)."""
    return fb_storage.bucket()


def upload_file_to_storage(file_bytes: bytes, dest_path: str, content_type: str) -> str:
    """
    Upload bytes to Firebase Storage via the Admin SDK and return a public,
    non-expiring download URL in the same format the Firebase client SDK's
    getDownloadURL() produces (path + a firebaseStorageDownloadTokens token).

    Using the Admin SDK here means the upload always succeeds regardless of
    client-side Storage security rules, since it authenticates as a service
    account rather than as the end user.
    """
    bucket = get_bucket()
    blob = bucket.blob(dest_path)
    token = str(uuid.uuid4())
    blob.metadata = {"firebaseStorageDownloadTokens": token}
    blob.upload_from_string(file_bytes, content_type=content_type)

    encoded_path = quote(dest_path, safe="")
    return f"https://firebasestorage.googleapis.com/v0/b/{bucket.name}/o/{encoded_path}?alt=media&token={token}"
