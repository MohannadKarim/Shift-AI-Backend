import anthropic
import json
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

    This is plain conversational chat only — it does not generate files.
    File generation is a separate, dedicated call (see structure_text_for_file
    below), triggered only when the user clicks an explicit Export button.
    Earlier versions asked the model to emit a file_json block inline in chat
    replies; under real-world load this kept breaking (fence-tag drift,
    truncated output, occasional malformed JSON reaching the user) because it
    mixed a strict machine-readable contract into an open-ended conversational
    response. Splitting it into its own focused, tool-forced call removes
    that whole failure class rather than patching around it again.
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
- Format every chat response in clean, well-structured Markdown (headings,
  bullet lists, numbered steps, bold for emphasis, code blocks where
  relevant). The UI renders Markdown, so plain unstructured paragraphs are a
  worse experience than properly structured Markdown — use it.
- Do not attempt to generate downloadable files (PDF/PowerPoint/Word/HTML)
  yourself. If the user asks for one, just tell them to use the Export
  button on your response once you've written the content they want
  exported — a separate step handles turning it into an actual file.

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
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": system_prompt,
                # The whole system prompt (workflow config + file-gen contract +
                # org file settings) is identical on every turn of a given
                # conversation, so this is a good caching candidate — cached
                # reads cost a fraction of normal input tokens.
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=messages,
    )

    raw_text = response.content[0].text

    return {
        "response": raw_text.strip(),
        "file": None,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        },
    }


FILE_STRUCTURE_TOOL = {
    "name": "structure_document",
    "description": "Structure the given source text into a title and an ordered list of sections/slides for document generation.",
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "A short, descriptive title for the document."},
            "sections": {
                "type": "array",
                "description": "Ordered sections (report sections for PDF/Word/HTML, or individual slides for PowerPoint).",
                "items": {
                    "type": "object",
                    "properties": {
                        "heading": {"type": "string", "description": "Section or slide title."},
                        "body": {"type": "string", "description": "Optional paragraph text for this section."},
                        "bullets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional bullet points for this section.",
                        },
                    },
                    "required": ["heading"],
                },
            },
        },
        "required": ["title", "sections"],
    },
}

_FORMAT_LABELS = {"pdf": "PDF report", "pptx": "PowerPoint presentation", "docx": "Word document", "html": "HTML page"}


def structure_text_for_file(
    text: str,
    file_type: str,
    workflow_title: str = "",
    file_settings: dict | None = None,
) -> dict:
    """
    Dedicated, isolated AI call that reformats already-written chat text into
    a {"title": ..., "sections": [...]} structure ready for
    build_file_from_structured. Runs only when the user clicks an Export
    button — completely separate from the conversational chat turn.

    Uses a forced tool call (tool_choice pins the model to the
    structure_document tool) instead of asking the model to hand-write a JSON
    fence block, so the SDK hands back an already-parsed dict — there's no
    fence-tag guessing, no free-form text to mis-parse, and no way for the
    model to drift into some other output shape.
    """
    client = get_client()
    file_settings = file_settings or {}
    format_label = _FORMAT_LABELS.get(file_type, file_type)

    per_format_instruction = (file_settings.get(f"{file_type}_instructions") or "").strip()
    general_instruction = (file_settings.get("general_instructions") or "").strip()

    guidance_lines = []
    if general_instruction:
        guidance_lines.append(f"- General: {general_instruction}")
    if per_format_instruction:
        guidance_lines.append(f"- {format_label}: {per_format_instruction}")
    guidance_block = (
        "\n\nOrg-wide formatting guidelines (apply unless they conflict with the source text):\n"
        + "\n".join(guidance_lines)
    ) if guidance_lines else ""

    slide_note = (
        " Treat each section as one slide — keep bullets short, 6 max per slide, and keep slide titles under 8 words."
        if file_type == "pptx" else ""
    )

    system_prompt = (
        f"You convert existing chat text into a structured {format_label}.\n\n"
        "You will be given the ORIGINAL TEXT below. Reorganize it into a clear "
        "title and an ordered list of sections using the structure_document "
        "tool. Do not translate or change the language of the content — if "
        "the original text is in Arabic, keep the title/headings/body/bullets "
        "in Arabic; if English, keep English (match whatever language or mix "
        "the original text uses). Preserve the original meaning and level of "
        "detail — you are reformatting for a document, not summarizing away "
        f"content, unless the text is extremely long, in which case you may "
        f"tighten wording while keeping all key points.{slide_note}{guidance_block}"
    )

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": f"ORIGINAL TEXT:\n\n{text}"}],
        tools=[FILE_STRUCTURE_TOOL],
        tool_choice={"type": "tool", "name": "structure_document"},
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "structure_document":
            spec = block.input  # already a parsed dict — no JSON text parsing needed
            title = spec.get("title") or workflow_title or "Document"
            sections = spec.get("sections") or []
            return {"title": title, "sections": sections}

    # Shouldn't happen with tool_choice forcing the tool, but guard anyway.
    raise RuntimeError("Model did not return a structured document for file export.")


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