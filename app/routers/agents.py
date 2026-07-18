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

    # Only count usage once per session.
    #
    # IMPORTANT: the frontend seeds `messages` with an initial greeting
    # (role "model") before the user types anything, and sends the full
    # `messages` array as `history` on every request — including the very
    # first one. That means `body.history` is NEVER actually empty, even
    # on a brand-new session, so checking `if not body.history` never
    # increments usageCount.
    #
    # The correct signal for "this is the first real turn of the session"
    # is "no USER message has appeared in history yet" — the greeting
    # itself doesn't count.
    has_prior_user_message = any(msg.role == "user" for msg in body.history)

    if not has_prior_user_message:
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
        file=result.get("file"),
    )