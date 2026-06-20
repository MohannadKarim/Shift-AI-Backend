from pydantic import BaseModel
from typing import Optional, Literal, List
from enum import Enum


# ── Enums (matching UI types.ts exactly) ─────────────────────────────────────

class Department(str, Enum):
    biz_dev = "Biz Dev"
    client_serving = "Client Serving"
    creative = "Creative"
    operations = "Operations"
    strategy_media = "Strategy & Media"


class UserRole(str, Enum):
    team_member = "Team Member"
    admin = "Admin"
    super_admin = "Super Admin"


class SubmissionStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


# ── User ──────────────────────────────────────────────────────────────────────

class User(BaseModel):
    uid: str
    firstName: str
    lastName: str
    email: str
    department: Department
    role: UserRole
    points: int = 0
    level: int = 1
    badges: List[str] = []
    createdAt: str


class UpdateUserRoleRequest(BaseModel):
    uid: str
    role: UserRole


# ── Workflow ──────────────────────────────────────────────────────────────────

class Workflow(BaseModel):
    id: Optional[str] = None
    title: str
    department: Department
    problem: str
    instructions: List[str]
    tools: List[str]
    toolAccess: str
    masterPrompt: str
    expectedOutput: str
    isCertified: bool = False
    contributors: List[str] = []
    usageCount: int = 0
    agentPrompt: str


class WorkflowCreate(BaseModel):
    title: str
    department: Department
    problem: str
    instructions: List[str]
    tools: List[str]
    toolAccess: str
    masterPrompt: str
    expectedOutput: str
    isCertified: bool = False
    agentPrompt: str = ""


# ── Agent / Chat ──────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: Literal["user", "model"]  # UI uses "model" not "assistant"
    text: str
    image: Optional[str] = None  # Base64 image


class AgentChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []
    image: Optional[str] = None  # Base64 image from user


class GeneratedFile(BaseModel):
    type: Literal["pdf", "pptx", "html"]
    title: str
    filename: str
    mime_type: str
    data_base64: str  # the generated file, base64-encoded, ready for the UI to decode/download/preview
    previewable: bool  # true for pdf/html — UI may render an in-app preview


class AgentChatResponse(BaseModel):
    response: str
    usage: dict
    file: Optional[GeneratedFile] = None


# ── Prompt Library ────────────────────────────────────────────────────────────

class PromptMedia(BaseModel):
    type: Literal["image", "video", "link"]
    url: str
    title: Optional[str] = None


class Prompt(BaseModel):
    id: Optional[str] = None
    title: str
    category: str
    content: str
    tool: str
    authorId: str
    authorName: str
    votes: int = 0
    voters: List[str] = []
    createdAt: str
    thumbnail: Optional[str] = None
    media: Optional[List[PromptMedia]] = []
    labels: Optional[List[str]] = []


class PromptCreate(BaseModel):
    title: str
    category: str
    content: str
    tool: str
    thumbnail: Optional[str] = None
    labels: Optional[List[str]] = []


class OptimizePromptRequest(BaseModel):
    prompt: str
    tool: str  # e.g. "Midjourney", "ChatGPT", "Claude"


class OptimizePromptResponse(BaseModel):
    optimized_prompt: str


# ── Submissions ───────────────────────────────────────────────────────────────

class Submission(BaseModel):
    id: Optional[str] = None
    userId: str
    userName: str
    workflowId: str
    workflowTitle: str
    title: str
    description: str
    outputType: str
    link: Optional[str] = None
    fileUrl: Optional[str] = None
    department: Department
    isPrivate: bool = False
    pointsAwarded: int = 0
    status: SubmissionStatus = SubmissionStatus.pending
    createdAt: str


class SubmissionCreate(BaseModel):
    workflowId: str
    workflowTitle: str
    title: str
    description: str
    outputType: str
    link: Optional[str] = None
    department: Department
    isPrivate: bool = False


class AnalyzeSubmissionRequest(BaseModel):
    title: str
    description: str


class AnalyzeSubmissionResponse(BaseModel):
    tags: List[str]
    insights: List[str]


class ApproveSubmissionRequest(BaseModel):
    pointsAwarded: int


# ── Admin Stats ───────────────────────────────────────────────────────────────

class AdminStats(BaseModel):
    total_users: int
    total_workflows: int
    total_submissions: int
    pending_submissions: int
    total_prompts: int
