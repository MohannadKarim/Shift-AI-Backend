from fastapi import APIRouter, HTTPException, Depends, Request
from app.dependencies import get_current_user
from app.services.firebase import get_db
from app.services.anthropic import run_agent
from app.services.token_tracker import check_budget, record_usage
from app.models.models import AgentChatRequest, AgentChatResponse
from app.limiter import limiter

router = APIRouter()


@router.post("/{workflow_id}/chat", response_model=AgentChatResponse)
@limiter.limit("30/minute")   # Max 30 AI chat calls per IP per minute
def agent_chat(
    request: Request,          # Required by slowapi for per-route limits
    workflow_id: str,
    body: AgentChatRequest,
    user: dict = Depends(get_current_user),
):
    uid = user["uid"]

    # ── 1. Enforce token budgets BEFORE calling Claude ────────────────────────
    check_budget(uid)

    # ── 2. Load workflow ──────────────────────────────────────────────────────
    db = get_db()
    doc = db.collection("workflows").document(workflow_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Workflow not found")

    workflow = doc.to_dict()
    db.collection("workflows").document(workflow_id).update(
        {"usageCount": workflow.get("usageCount", 0) + 1}
    )

    # ── 3. Run Claude ─────────────────────────────────────────────────────────
    result = run_agent(
        workflow_title=workflow.get("title", ""),
        workflow_department=workflow.get("department", ""),
        workflow_problem=workflow.get("problem", ""),
        workflow_instructions=workflow.get("instructions", []),
        master_prompt=workflow.get("masterPrompt", ""),
        agent_prompt=workflow.get("agentPrompt", ""),
        history=[msg.model_dump() for msg in body.history],
        user_message=body.message,
        user_image=body.image,
    )

    # ── 4. Record actual token usage AFTER success ────────────────────────────
    total_tokens = result["usage"].get("total_tokens", 0)
    record_usage(uid, total_tokens)

    return AgentChatResponse(
        response=result["response"],
        usage=result["usage"],
    )