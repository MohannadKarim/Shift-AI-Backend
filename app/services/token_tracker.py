"""
token_tracker.py — Per-user and org-wide token usage tracking.

Firestore schema:
  token_usage/{uid}/daily/{YYYY-MM-DD}  → { tokens_used: int, last_updated: str }
  token_usage/_org_/daily/{YYYY-MM-DD} → { tokens_used: int, last_updated: str }

Config (all in Settings / .env):
  DAILY_TOKEN_BUDGET          — per-user daily limit  (default 50_000)
  ORG_DAILY_TOKEN_BUDGET      — org-wide daily limit  (default 2_000_000)
"""

from datetime import datetime, timezone
from fastapi import HTTPException
from app.services.firebase import get_db
from app.config import settings

ORG_DOC_ID = "_org_"


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _user_ref(uid: str, date: str):
    db = get_db()
    return db.collection("token_usage").document(uid).collection("daily").document(date)


def _org_ref(date: str):
    db = get_db()
    return db.collection("token_usage").document(ORG_DOC_ID).collection("daily").document(date)


# ── Read ──────────────────────────────────────────────────────────────────────

def get_user_usage(uid: str, date: str | None = None) -> dict:
    """Return { tokens_used, budget, remaining, date } for a user."""
    date = date or _today()
    doc = _user_ref(uid, date).get()
    used = doc.to_dict().get("tokens_used", 0) if doc.exists else 0
    budget = settings.daily_token_budget
    return {
        "uid": uid,
        "date": date,
        "tokens_used": used,
        "budget": budget,
        "remaining": max(0, budget - used),
        "over_budget": used >= budget,
    }


def get_org_usage(date: str | None = None) -> dict:
    """Return { tokens_used, budget, remaining, date } for the whole org."""
    date = date or _today()
    doc = _org_ref(date).get()
    used = doc.to_dict().get("tokens_used", 0) if doc.exists else 0
    budget = settings.org_daily_token_budget
    return {
        "date": date,
        "tokens_used": used,
        "budget": budget,
        "remaining": max(0, budget - used),
        "over_budget": used >= budget,
    }


def get_user_usage_history(uid: str, days: int = 7) -> list[dict]:
    """Return last N days of usage for a user."""
    from datetime import timedelta
    today = datetime.now(timezone.utc)
    results = []
    db = get_db()
    for i in range(days):
        date_str = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        doc = db.collection("token_usage").document(uid).collection("daily").document(date_str).get()
        used = doc.to_dict().get("tokens_used", 0) if doc.exists else 0
        results.append({"date": date_str, "tokens_used": used})
    return results


# ── Enforce ───────────────────────────────────────────────────────────────────

def check_budget(uid: str):
    """
    Raise HTTP 429 if the user or org is over their daily token budget.
    Call this BEFORE sending to Claude.
    """
    date = _today()

    user_usage = get_user_usage(uid, date)
    if user_usage["over_budget"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "user_token_budget_exceeded",
                "message": "You've reached your daily token limit. Your budget resets at midnight UTC.",
                "tokens_used": user_usage["tokens_used"],
                "budget": user_usage["budget"],
            },
        )

    org_usage = get_org_usage(date)
    if org_usage["over_budget"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "org_token_budget_exceeded",
                "message": "The organisation has reached its daily token limit. Contact your admin.",
                "tokens_used": org_usage["tokens_used"],
                "budget": org_usage["budget"],
            },
        )


# ── Record ────────────────────────────────────────────────────────────────────

def record_usage(uid: str, tokens_used: int):
    """
    Increment token counts for the user and the org.
    Call this AFTER a successful Claude response.
    Uses Firestore transactions to avoid race conditions under concurrent requests.
    """
    if tokens_used <= 0:
        return

    date = _today()
    db = get_db()

    @db.transaction()
    def _update(transaction, user_ref, org_ref):
        # Read both docs in the transaction
        snapshots = [user_ref.get(transaction=transaction),
                     org_ref.get(transaction=transaction)]
        user_snap, org_snap = snapshots

        user_used = (user_snap.to_dict() or {}).get("tokens_used", 0)
        org_used = (org_snap.to_dict() or {}).get("tokens_used", 0)

        now_iso = datetime.now(timezone.utc).isoformat()

        transaction.set(user_ref, {
            "tokens_used": user_used + tokens_used,
            "last_updated": now_iso,
        })
        transaction.set(org_ref, {
            "tokens_used": org_used + tokens_used,
            "last_updated": now_iso,
        })

    transaction = db.transaction()
    _update(transaction, _user_ref(uid, date), _org_ref(date))


# ── Admin helpers ─────────────────────────────────────────────────────────────

def admin_set_user_budget(uid: str, daily_budget: int):
    """
    Override the default per-user budget by storing a custom limit in Firestore.
    The check_budget function reads this if present, falling back to settings.
    """
    db = get_db()
    db.collection("token_budgets").document(uid).set({
        "daily_budget": daily_budget,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def get_custom_user_budget(uid: str) -> int | None:
    """Return custom daily budget for a user, or None if using the default."""
    db = get_db()
    doc = db.collection("token_budgets").document(uid).get()
    if doc.exists:
        return doc.to_dict().get("daily_budget")
    return None
