from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    database_url: str = "sqlite:///./bountyguard.db"
    gemini_api_key: Optional[str] = None
    maintainer_token: Optional[str] = None
    paypal_client_id: Optional[str] = None
    paypal_client_secret: Optional[str] = None
    paypal_webhook_id: Optional[str] = None
    paypal_api_base: str = "https://api-m.sandbox.paypal.com"
    request_timeout_seconds: float = 15.0


@lru_cache()
def get_settings() -> AppSettings:
    """Returns cached application settings loaded from .env and environment variables."""
    return AppSettings()
