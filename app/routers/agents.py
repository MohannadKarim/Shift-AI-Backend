from fastapi import APIRouter, HTTPException, Depends, Request
from app.dependencies import get_current_user
from app.services.firebase import get_db
from app.services.anthropic import run_agent
from app.services.token_tracker import check_budget, record_usage
from app.models.models import AgentChatRequest, AgentChatResponse
from app.limiter import limiter

router = APIRouter()


@router.post("/{workflow_id}/chat", response_model=AgentChatResponse)
@limiter.limit("30/minute")
def agent_chat(
    request: Request,
    workflow_id: str,
    body: AgentChatRequest,
    user: dict = Depends(get_current_user),
):
    uid = user["uid"]

    check_budget(uid)

    db = get_db()
    doc = db.collection("workflows").document(workflow_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Workflow not found")

    workflow = doc.to_dict()

    # Only count usage once per session — the first message has empty history.
    # Without this check, every follow-up message in a conversation was
    # incrementing usageCount, which inflated the number far beyond actual
    # distinct uses of the workflow.
    if not body.history:
        db.collection("workflows").document(workflow_id).update(
            {"usageCount": workflow.get("usageCount", 0) + 1}
        )

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

    total_tokens = result["usage"].get("total_tokens", 0)
    record_usage(uid, total_tokens)

    return AgentChatResponse(
        response=result["response"],
        usage=result["usage"],
    )