"""
token_tracker.py — Per-user and org-wide token usage tracking.

Firestore schema:
  token_usage/{uid}/daily/{YYYY-MM-DD}  → { tokens_used: int, last_updated: str }
  token_usage/_org_/daily/{YYYY-MM-DD} → { tokens_used: int, last_updated: str }
  token_budgets/{uid}                  → { daily_budget: int, updated_at: str }
  token_budgets/_org_                  → { daily_budget: int, updated_at: str }

Config (all in Settings / .env):
  DAILY_TOKEN_BUDGET          — per-user daily limit  (default 50_000)
  ORG_DAILY_TOKEN_BUDGET      — org-wide daily limit  (default 2_000_000)

Custom budgets stored in `token_budgets` always take precedence over the
.env defaults above, for both individual users and the org as a whole.
"""

from datetime import datetime, timezone, timedelta
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


# ── Custom budget overrides ──────────────────────────────────────────────────

def get_custom_user_budget(uid: str) -> int | None:
    """Return custom daily budget for a user, or None if using the default."""
    db = get_db()
    doc = db.collection("token_budgets").document(uid).get()
    if doc.exists:
        return doc.to_dict().get("daily_budget")
    return None


def get_custom_org_budget() -> int | None:
    """Return custom daily budget for the org, or None if using the default."""
    db = get_db()
    doc = db.collection("token_budgets").document(ORG_DOC_ID).get()
    if doc.exists:
        return doc.to_dict().get("daily_budget")
    return None


def admin_set_user_budget(uid: str, daily_budget: int):
    """Override the default per-user budget."""
    db = get_db()
    db.collection("token_budgets").document(uid).set({
        "daily_budget": daily_budget,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def admin_set_org_budget(daily_budget: int):
    """Override the default org-wide budget."""
    db = get_db()
    db.collection("token_budgets").document(ORG_DOC_ID).set({
        "daily_budget": daily_budget,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


# ── Read ──────────────────────────────────────────────────────────────────────

def get_user_usage(uid: str, date: str | None = None) -> dict:
    """Return { tokens_used, budget, remaining, date } for a user."""
    date = date or _today()
    doc = _user_ref(uid, date).get()
    used = doc.to_dict().get("tokens_used", 0) if doc.exists else 0
    budget = get_custom_user_budget(uid) or settings.daily_token_budget
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
    budget = get_custom_org_budget() or settings.org_daily_token_budget
    return {
        "date": date,
        "tokens_used": used,
        "budget": budget,
        "remaining": max(0, budget - used),
        "over_budget": used >= budget,
    }


def get_user_usage_history(uid: str, days: int = 30) -> list[dict]:
    """Return last N days of usage for a user, most recent first."""
    today = datetime.now(timezone.utc)
    results = []
    db = get_db()
    for i in range(days):
        date_str = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        doc = db.collection("token_usage").document(uid).collection("daily").document(date_str).get()
        used = doc.to_dict().get("tokens_used", 0) if doc.exists else 0
        results.append({"date": date_str, "tokens_used": used})
    return results


def get_org_usage_history(days: int = 30) -> list[dict]:
    """Return last N days of org-wide usage, most recent first."""
    today = datetime.now(timezone.utc)
    results = []
    db = get_db()
    for i in range(days):
        date_str = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        doc = (
            db.collection("token_usage")
            .document(ORG_DOC_ID)
            .collection("daily")
            .document(date_str)
            .get()
        )
        used = doc.to_dict().get("tokens_used", 0) if doc.exists else 0
        results.append({"date": date_str, "tokens_used": used})
    return results


def get_user_usage_summary(uid: str) -> dict:
    """Daily / weekly / monthly totals + the raw 30-day history, for charts."""
    history = get_user_usage_history(uid, days=30)
    budget = get_custom_user_budget(uid) or settings.daily_token_budget
    return {
        "uid": uid,
        "budget": budget,
        "daily": history[0]["tokens_used"] if history else 0,
        "weekly": sum(h["tokens_used"] for h in history[:7]),
        "monthly": sum(h["tokens_used"] for h in history[:30]),
        "history": list(reversed(history)),  # oldest → newest, easier for charts
    }


def get_org_usage_summary() -> dict:
    """Daily / weekly / monthly totals + the raw 30-day history, for charts."""
    history = get_org_usage_history(days=30)
    budget = get_custom_org_budget() or settings.org_daily_token_budget
    return {
        "budget": budget,
        "daily": history[0]["tokens_used"] if history else 0,
        "weekly": sum(h["tokens_used"] for h in history[:7]),
        "monthly": sum(h["tokens_used"] for h in history[:30]),
        "history": list(reversed(history)),
    }


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
    """
    if tokens_used <= 0:
        return

    date = _today()
    db = get_db()

    user_ref = _user_ref(uid, date)
    org_ref = _org_ref(date)

    # Read current values
    user_snap = user_ref.get()
    org_snap = org_ref.get()

    user_used = (user_snap.to_dict() or {}).get("tokens_used", 0) if user_snap.exists else 0
    org_used = (org_snap.to_dict() or {}).get("tokens_used", 0) if org_snap.exists else 0

    now_iso = datetime.now(timezone.utc).isoformat()

    user_ref.set({"tokens_used": user_used + tokens_used, "last_updated": now_iso})
    org_ref.set({"tokens_used": org_used + tokens_used, "last_updated": now_iso})