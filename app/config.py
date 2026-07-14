from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    app_env: str = "development"
    debug: bool = True

    # Firebase
    firebase_credentials_path: str = "firebase-credentials.json"
    firebase_credentials_json: str = ""  # Use this in production (Fly.io secret)
    firebase_storage_bucket: str = ""  # e.g. "your-project.appspot.com" — only used if storage_backend="firebase"

    # File uploads: "local" stores on the container's own disk (no billing/setup
    # required — good for demos; add a Railway volume at local_storage_path to
    # survive redeploys). Switch to "firebase" once Storage is set up (Blaze
    # plan + firebase_storage_bucket configured) for real/production use.
    storage_backend: str = "local"  # "local" | "firebase"
    local_storage_path: str = "uploads_data"


    # Anthropic
    anthropic_api_key: str = "sk-ant-placeholder"

    # CORS — update with real frontend URL in production
    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://shift-ai-frontend.fly.dev",  # placeholder — update when deployed
    ]

    # Super admin
    super_admin_email: str = "asayeh@telfaz11.com"

    # Token budget per user per day
    daily_token_budget: int = 50_000

    # Token budget for the whole org per day
    org_daily_token_budget: int = 2_000_000

    # Sentry
    sentry_dsn: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
