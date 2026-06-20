import anthropic
import base64
import json
import re
from app.config import settings
from app.services.file_generator import build_file_from_structured

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
- Format every chat response in clean, well-structured Markdown (headings,
  bullet lists, numbered steps, bold for emphasis, code blocks where
  relevant). The UI renders Markdown, so plain unstructured paragraphs are a
  worse experience than properly structured Markdown — use it.

File generation (PDF / PowerPoint / HTML report):
- If the user explicitly asks for a downloadable file (PDF, PowerPoint/deck,
  or HTML page/report), and you have ENOUGH information to produce a
  complete, useful document (clear topic, rough scope, and intended
  audience/purpose), respond with BOTH of the following, in this order:
    1. A short plain-Markdown text summary (1-3 sentences) of what you
       produced, written as you normally would in chat. This is shown to
       the user above the file download card.
    2. A single fenced code block, language tag "file_json", containing
       ONLY valid JSON (no comments, no trailing text) describing the
       document, in this exact shape:
       ```file_json
       {
         "type": "pdf" | "pptx" | "html",
         "title": "Short Document Title",
         "sections": [
           {"heading": "Section or Slide Title", "body": "Optional paragraph text.", "bullets": ["Point one", "Point two"]}
         ]
       }
       ```
       - Use "pptx" sections as individual slides (keep bullets short, 6 max
         per section). Use "pdf"/"html" sections as report sections (body
         text and/or bullets are both fine).
       - Every section needs a "heading". "body" and "bullets" are each
         optional but include whichever fits the content.
       - Do not wrap the JSON in anything else, and do not include this
         JSON block unless you are actually generating a file this turn.
- If the user asks for a file but you DON'T have enough information yet
  (e.g. they say "make me a deck" with no topic, audience, or length), do
  NOT generate placeholder content and do NOT include a file_json block.
  Instead, ask 1-2 short, specific clarifying questions first (e.g. "What's
  the topic and who's the audience?", "Roughly how many slides/pages?").
  Only produce the file_json block once you have enough to make it
  genuinely useful.
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
        max_tokens=2048,
        system=system_prompt,
        messages=messages,
    )

    raw_text = response.content[0].text
    text_summary, generated_file = _extract_file_block(raw_text, workflow_title)

    return {
        "response": text_summary,
        "file": generated_file,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        },
    }


_FILE_JSON_BLOCK_RE = re.compile(r"```file_json\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_file_block(raw_text: str, workflow_title: str) -> tuple[str, dict | None]:
    """
    Look for a ```file_json {...}``` block in the model's raw response.
    If found: build the actual file via file_generator, base64-encode it,
    and return (text_with_block_removed, file_dict). Otherwise (None).
    """
    match = _FILE_JSON_BLOCK_RE.search(raw_text)
    if not match:
        return raw_text.strip(), None

    text_summary = (raw_text[:match.start()] + raw_text[match.end():]).strip()

    try:
        spec = json.loads(match.group(1))
        file_type = spec["type"]
        title = spec.get("title") or "Document"
        sections = spec.get("sections") or []

        file_bytes, filename = build_file_from_structured(
            file_type=file_type,
            title=title,
            sections=sections,
            workflow_title=workflow_title,
        )

        mime_types = {
            "pdf": "application/pdf",
            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "html": "text/html",
        }

        generated_file = {
            "type": file_type,
            "title": title,
            "filename": filename,
            "mime_type": mime_types[file_type],
            "data_base64": base64.b64encode(file_bytes).decode("ascii"),
            "previewable": file_type in ("pdf", "html"),
        }
        if not text_summary:
            text_summary = f"Here's your {file_type.upper()} — \"{title}\"."
        return text_summary, generated_file
    except Exception:
        # If parsing/building fails, fall back to showing the raw text
        # (minus the broken block) rather than erroring the whole chat turn.
        return text_summary or raw_text.strip(), None


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