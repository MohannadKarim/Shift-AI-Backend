from fastapi import APIRouter, HTTPException, Depends
from app.dependencies import get_current_user, admin_only
from app.services.firebase import get_db
from app.services.anthropic import optimize_prompt as ai_optimize
from app.models.models import PromptCreate, OptimizePromptRequest, OptimizePromptResponse
from datetime import datetime, timezone

router = APIRouter()


@router.get("/")
def list_prompts(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = db.collection("prompts").order_by("votes", direction="DESCENDING").stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.get("/{prompt_id}")
def get_prompt(prompt_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection("prompts").document(prompt_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Prompt not found")
    return {"id": doc.id, **doc.to_dict()}


@router.post("/optimize")
def optimize_prompt_endpoint(body: OptimizePromptRequest, user: dict = Depends(get_current_user)):
    optimized = ai_optimize(body.prompt, body.tool)
    return OptimizePromptResponse(optimized_prompt=optimized)


@router.post("/")
def create_prompt(body: PromptCreate, user: dict = Depends(get_current_user)):
    db = get_db()
    doc_ref = db.collection("prompts").document()
    data = body.model_dump()
    data["authorId"] = user["uid"]
    data["authorName"] = user.get("name", user.get("email", ""))
    data["votes"] = 0
    data["voters"] = []
    data["createdAt"] = datetime.now(timezone.utc).isoformat()
    doc_ref.set(data)
    return {"id": doc_ref.id, **data}


@router.put("/{prompt_id}")
def update_prompt(prompt_id: str, body: PromptCreate, user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection("prompts").document(prompt_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Prompt not found")
    data = doc.to_dict()
    user_role = user.get("role", "Team Member")
    if data.get("authorId") != user["uid"] and user_role not in ["Admin", "Super Admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    db.collection("prompts").document(prompt_id).update(body.model_dump())
    return {"id": prompt_id, **body.model_dump()}


@router.delete("/{prompt_id}")
def delete_prompt(prompt_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection("prompts").document(prompt_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Prompt not found")
    data = doc.to_dict()
    user_role = user.get("role", "Team Member")
    if data.get("authorId") != user["uid"] and user_role not in ["Admin", "Super Admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    db.collection("prompts").document(prompt_id).delete()
    return {"message": "Prompt deleted"}


@router.post("/{prompt_id}/vote")
def vote_prompt(prompt_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    doc_ref = db.collection("prompts").document(prompt_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Prompt not found")
    data = doc.to_dict()
    voters = data.get("voters", [])
    uid = user["uid"]
    if uid in voters:
        voters.remove(uid)
        votes = max(0, data.get("votes", 1) - 1)
    else:
        voters.append(uid)
        votes = data.get("votes", 0) + 1
    doc_ref.update({"votes": votes, "voters": voters})
    return {"votes": votes, "voted": uid in voters}
