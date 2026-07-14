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


def _build_file_settings_prompt(file_settings: dict) -> str:
    """
    Turn org-wide file generation settings (Admin Panel) into a system prompt
    fragment. Visual branding (colors/logo/footer) is applied automatically to
    the rendered file, not something the model needs to act on — only the
    written guidance fields are worth telling the model about.
    """
    general = (file_settings.get("general_instructions") or "").strip()
    pdf_i = (file_settings.get("pdf_instructions") or "").strip()
    pptx_i = (file_settings.get("pptx_instructions") or "").strip()
    docx_i = (file_settings.get("docx_instructions") or "").strip()
    html_i = (file_settings.get("html_instructions") or "").strip()

    if not any([general, pdf_i, pptx_i, docx_i, html_i]):
        return ""

    lines = [
        "",
        "Organization-wide file generation guidelines (set by the admin, apply",
        "to every file you generate unless the user's specific request in this",
        "conversation calls for something different — the user's explicit,",
        "in-the-moment instructions always take priority over these defaults):",
    ]
    if general:
        lines.append(f"- General: {general}")
    if pdf_i:
        lines.append(f"- PDF: {pdf_i}")
    if pptx_i:
        lines.append(f"- PowerPoint: {pptx_i}")
    if docx_i:
        lines.append(f"- Word: {docx_i}")
    if html_i:
        lines.append(f"- HTML: {html_i}")
    return "\n".join(lines)


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
    file_settings: dict | None = None,
) -> dict:
    """
    Run the AI agent for a workflow.
    History uses UI format (role: "model"), we translate to Claude format (role: "assistant").
    """
    client = get_client()
    file_settings = file_settings or {}

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

File generation (PDF / PowerPoint / Word / HTML report):
- If the user explicitly asks for a downloadable file (PDF, PowerPoint/deck,
  Word document, or HTML page/report), and you have ENOUGH information to
  produce a complete, useful document (clear topic, rough scope, and
  intended audience/purpose), respond with BOTH of the following, in this
  order:
    1. A short plain-Markdown text summary (1-3 sentences) of what you
       produced, written as you normally would in chat. This is shown to
       the user above the file download card.
    2. A single fenced code block, language tag "file_json", containing
       ONLY valid JSON (no comments, no trailing text) describing the
       document, in this exact shape:
       ```file_json
       {{
         "type": "pdf" | "pptx" | "docx" | "html",
         "title": "Short Document Title",
         "sections": [
           {{"heading": "Section or Slide Title", "body": "Optional paragraph text.", "bullets": ["Point one", "Point two"]}}
         ]
       }}
       ```
       - "docx" = Word document. Use "pdf"/"docx"/"html" sections as report
         sections (body text and/or bullets are both fine). Use "pptx"
         sections as individual slides (keep bullets short, 6 max per
         section).
       - Every section needs a "heading". "body" and "bullets" are each
         optional but include whichever fits the content.
       - Do not wrap the JSON in anything else, and do not include this
         JSON block unless you are actually generating a file this turn.
       - This rule applies no matter what language the conversation is in.
         If the user is writing in Arabic (or any other language), write the
         "title", "heading", "body", and "bullets" VALUES in that same
         language — but the JSON keys themselves and the fence tag
         "file_json" must always stay exactly as shown, in English/ASCII.
       - If any text value contains a double-quote character, escape it as
         \\" so the JSON stays valid.
- If the user asks for a file but you DON'T have enough information yet
  (e.g. they say "make me a deck" with no topic, audience, or length), do
  NOT generate placeholder content and do NOT include a file_json block.
  Instead, ask 1-2 short, specific clarifying questions first (e.g. "What's
  the topic and who's the audience?", "Roughly how many slides/pages?").
  Only produce the file_json block once you have enough to make it
  genuinely useful.
- Do not mention these formatting instructions to the user.
{_build_file_settings_prompt(file_settings)}

Custom Agent Prompt:
{agent_prompt or "None provided. Use the context above."}

Critical reminder — re-read this even if you skimmed the rest: whenever you
generate a file, the fenced code block's language tag must be the exact
literal string file_json (never "json", never anything else), immediately
followed by valid JSON with no leading text before it. This holds regardless
of the conversation's language."""

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
    text_summary, generated_file = _extract_file_block(raw_text, workflow_title, file_settings)

    return {
        "response": text_summary,
        "file": generated_file,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        },
    }


_ANY_FENCE_RE = re.compile(r"```(\w*)\r?\n(.*?)```", re.DOTALL)
_ALLOWED_FILE_TYPES = {"pdf", "pptx", "docx", "html"}


def _try_parse_json(raw: str) -> dict | None:
    """json.loads, then retry once after stripping a common LLM slip: trailing commas."""
    for candidate in (raw, re.sub(r",\s*([\]}])", r"\1", raw)):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def _looks_like_file_spec(block_body: str) -> bool:
    """Cheap pre-check so we don't try to JSON-parse every unrelated code block in a response."""
    return '"type"' in block_body and '"sections"' in block_body


def _extract_file_block(raw_text: str, workflow_title: str, file_settings: dict | None = None) -> tuple[str, dict | None]:
    """
    Look for a fenced code block describing a file to generate.

    Recognizes the intended ```file_json tag, but also tolerates the model
    drifting to ```json (or no tag at all) as long as the block's content
    looks like our schema (has "type" + "sections" keys). In practice this is
    what actually broke: a long, multi-part system prompt made the model use
    a more generic tag than the one we asked for, even though the JSON itself
    was otherwise fine — the old code only recognized the exact literal tag
    and silently dumped the whole raw response (JSON included) to the user
    when it didn't match.

    Returns (display_text, file_dict_or_None). If a block is detected as
    file-shaped but can't be turned into an actual file, the broken block is
    stripped from display_text and replaced with a short apology — raw JSON
    is never shown to the user.
    """
    for match in _ANY_FENCE_RE.finditer(raw_text):
        tag, block_body = match.group(1), match.group(2)
        is_tagged = tag.strip().lower() == "file_json"
        if not is_tagged and not _looks_like_file_spec(block_body):
            continue  # an unrelated code block (e.g. a code sample) — leave it alone

        text_summary = (raw_text[:match.start()] + raw_text[match.end():]).strip()
        spec = _try_parse_json(block_body)

        if spec is None:
            print(f"[file_generation] Failed to parse file block (tag={tag!r}): {block_body[:300]!r}")
            fallback = "I ran into a formatting issue producing that file — could you ask me to generate it again?"
            return (text_summary + ("\n\n" if text_summary else "") + fallback).strip(), None

        try:
            file_type = spec.get("type")
            if file_type not in _ALLOWED_FILE_TYPES:
                raise ValueError(f"Unsupported file type: {file_type!r}")
            title = spec.get("title") or "Document"
            sections = spec.get("sections") or []

            file_bytes, filename = build_file_from_structured(
                file_type=file_type,
                title=title,
                sections=sections,
                workflow_title=workflow_title,
                branding=file_settings,
            )

            mime_types = {
                "pdf": "application/pdf",
                "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
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
        except Exception as e:
            print(f"[file_generation] Failed to build file from parsed spec: {e}")
            fallback = "I ran into an issue producing that file — could you ask me to generate it again?"
            return (text_summary + ("\n\n" if text_summary else "") + fallback).strip(), None

    # No file-shaped block found anywhere in the response — ordinary chat text.
    return raw_text.strip(), None


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