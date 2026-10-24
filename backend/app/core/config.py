from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./failproof.db"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    frontend_origin: str = "http://localhost:5173"
    log_level: str = "INFO"
    scan_allowed_roots: str = Field(default="", validation_alias="FAILPROOF_SCAN_ALLOWED_ROOTS")
    scan_temp_dir: str = Field(default="", validation_alias="FAILPROOF_SCAN_TEMP_DIR")
    ai_provider: str = Field(default="", validation_alias="FAILPROOF_AI_PROVIDER")
    ai_base_url: str = Field(default="https://api.openai.com/v1", validation_alias="FAILPROOF_AI_BASE_URL")
    ai_model: str = Field(default="", validation_alias="FAILPROOF_AI_MODEL")
    ai_api_key: str = Field(default="", validation_alias="FAILPROOF_AI_API_KEY")
    gemini_api_key: str = Field(default="", validation_alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-3.8-flash", validation_alias="GEMINI_MODEL")
    ai_timeout_seconds: float = Field(default=30.0, ge=1.0, le=90.0, validation_alias="FAILPROOF_AI_TIMEOUT_SECONDS")
    ai_max_response_bytes: int = Field(default=128_000, ge=1024, le=512_000, validation_alias="FAILPROOF_AI_MAX_RESPONSE_BYTES")
    github_app_id: str = Field(default="", validation_alias="GITHUB_APP_ID")
    github_app_slug: str = Field(default="", validation_alias="GITHUB_APP_SLUG")
    github_client_id: str = Field(default="", validation_alias="GITHUB_CLIENT_ID")
    github_client_secret: str = Field(default="", validation_alias="GITHUB_CLIENT_SECRET")
    github_app_private_key_path: str = Field(default="", validation_alias="GITHUB_APP_PRIVATE_KEY_PATH")
    github_callback_url: str = Field(default="", validation_alias="GITHUB_CALLBACK_URL")
    github_workspace_dir: str = Field(default="", validation_alias="FAILPROOF_GITHUB_WORKSPACE_DIR")
    github_import_max_files: int = Field(default=1200, ge=1, le=5000, validation_alias="FAILPROOF_GITHUB_IMPORT_MAX_FILES")
    github_import_max_total_bytes: int = Field(default=20_000_000, ge=1024, le=100_000_000, validation_alias="FAILPROOF_GITHUB_IMPORT_MAX_TOTAL_BYTES")
    github_import_max_file_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000, validation_alias="FAILPROOF_GITHUB_IMPORT_MAX_FILE_BYTES")
    github_import_timeout_seconds: int = Field(default=90, ge=5, le=300, validation_alias="FAILPROOF_GITHUB_IMPORT_TIMEOUT_SECONDS")
    github_import_concurrency: int = Field(default=2, ge=1, le=8, validation_alias="FAILPROOF_GITHUB_IMPORT_CONCURRENCY")

    # Resolve the repository-root .env regardless of whether uvicorn is launched
    # from the repository root or the backend directory.
    model_config = SettingsConfigDict(env_file=Path(__file__).resolve().parents[3] / ".env", env_file_encoding="utf-8", extra="ignore", populate_by_name=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
