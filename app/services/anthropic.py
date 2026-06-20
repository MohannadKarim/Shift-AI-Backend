import anthropic
from app.config import settings

_client = None


def get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    return _client


def run_agent(
    workflow_title: str,
    workflow_department: str,
    workflow_problem: str,
    workflow_instructions: list[str],
    master_prompt: str,
    agent_prompt: str,
    history: list[dict],  # [{"role": "user"|"model", "text": "..."}]
    user_message: str,
    user_image: str | None = None,
) -> dict:
    """
    Run the AI agent for a workflow.
    History uses UI format (role: "model"), we translate to Claude format (role: "assistant").
    """
    client = get_client()

    system_prompt = f"""You are the dedicated AI Agent for the workflow: "{workflow_title}".
Department: {workflow_department}
Problem it solves: {workflow_problem}

Workflow Instructions:
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(workflow_instructions))}

Master Prompt for this workflow:
"{master_prompt}"

Your Role:
- Act as an Expert, Assistant, Coach, and Executor for this specific workflow.
- Explain the workflow to the user.
- Ask clarifying questions to understand the user's context.
- Adapt the workflow to the user's specific brief or situation.
- Generate outputs based on the master prompt and user input.
- Guide the user step-by-step through execution.
- Improve prompts and recommend tools.
- Validate the quality of the user's output.
- Turn user input into structured output.

Personality:
- If it's an RFP Analysis Agent: analytical, structured.
- If it's a Concept Ideation Agent: creative, exploratory.
- If it's a Storyboard Agent: visual thinker.
- If it's a Proposal Agent: persuasive, structured.
- If it's an Insight Agent: strategic, synthesis-driven.
(Adapt your tone based on the workflow title and department).

Formatting & Output Rules:
- Format every response in clean, well-structured Markdown (headings, bullet
  lists, numbered steps, bold for emphasis, code blocks where relevant). The
  UI renders Markdown, so plain unstructured paragraphs are a worse
  experience than properly structured Markdown — use it.
- If the user explicitly asks for a downloadable file (PDF, PowerPoint/deck,
  or HTML page/report), and you have ENOUGH information to produce a
  complete, useful document (clear topic, rough scope, and intended
  audience/purpose), go ahead and write the full Markdown content for that
  document directly in your response — formatted with clear "# " / "## "
  headings per section/slide, since the export pipeline converts your
  Markdown headings into PDF sections or individual PPTX slides.
- If the user asks for a file but you DON'T have enough information yet
  (e.g. they say "make me a deck" with no topic, audience, or length), do
  NOT generate placeholder content. Instead, ask 1-2 short, specific
  clarifying questions first (e.g. "What's the topic and who's the
  audience?", "Roughly how many slides/pages?"). Only produce the full
  content once you have enough to make it genuinely useful.
- Do not mention these formatting instructions to the user.

Custom Agent Prompt:
{agent_prompt or "None provided. Use the context above."}"""

    # Translate history: UI uses "model", Claude uses "assistant"
    messages = []
    for msg in history:
        role = "assistant" if msg["role"] == "model" else "user"
        content = []
        if msg.get("image"):
            image_data = msg["image"].split(",")[1] if "," in msg["image"] else msg["image"]
            content.append({
                "type": "image",
                "source": {"type": "base64", "media_type": "image/jpeg", "data": image_data}
            })
        content.append({"type": "text", "text": msg["text"]})
        messages.append({"role": role, "content": content})

    # Current user message
    user_content = []
    if user_image:
        image_data = user_image.split(",")[1] if "," in user_image else user_image
        user_content.append({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/jpeg", "data": image_data}
        })
    user_content.append({"type": "text", "text": user_message})
    messages.append({"role": "user", "content": user_content})

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=system_prompt,
        messages=messages,
    )

    return {
        "response": response.content[0].text,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        },
    }


def optimize_prompt(prompt: str, tool: str) -> str:
    """Optimize a prompt for a specific AI tool with Saudi/GCC creative context."""
    client = get_client()

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=512,
        system=(
            f"You are a prompt engineering expert for creative agencies in Saudi Arabia and the GCC. "
            f"Optimize the given prompt for use with {tool}. Add relevant cultural context where appropriate "
            f"and make it more effective and specific. Return only the improved prompt, nothing else."
        ),
        messages=[{"role": "user", "content": prompt}],
    )

    return response.content[0].text


def analyze_submission(title: str, description: str) -> dict:
    """
    Analyze a submission and return tags and insights.
    Returns format matching UI expectation: { tags: string[], insights: string[] }
    """
    client = get_client()

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=256,
        system=(
            "You are an AI output analyst for a creative agency. "
            "Analyze the given submission and return a JSON object with exactly two keys:\n"
            "- tags: array of 3-5 keyword strings\n"
            "- insights: array of 2-3 short actionable insight strings\n"
            "Return only valid JSON, no markdown, no explanation."
        ),
        messages=[{
            "role": "user",
            "content": f"Title: {title}\nDescription: {description}"
        }],
    )

    import json
    try:
        return json.loads(response.content[0].text)
    except json.JSONDecodeError:
        return {"tags": [], "insights": []}