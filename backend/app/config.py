import os
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    app_name: str = "OWASP Sentinel"
    app_version: str = "3.0.0"
    app_env: str = "development"
    secret_key: str = "change-me-in-production"
    debug: bool = False
    log_level: str = "INFO"

    # Backend
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000

    # Database
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # MinIO
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket_reports: str = "sentinel-reports"
    minio_bucket_payloads: str = "sentinel-payloads"
    minio_secure: bool = False

    # Meilisearch
    meilisearch_url: str = "http://localhost:7700"
    meilisearch_master_key: str = ""

    # JWT
    jwt_secret_key: str = "change-me-jwt-secret-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # CORS
    cors_origins: List[str] = ["http://localhost:3000"]

    # Tools
    nuclei_templates_path: str = "/app/nuclei-templates"
    tool_timeout: int = 300
    max_concurrent_scans: int = 5

    # Email
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@owasp-sentinel.io"

    # Slack
    slack_webhook_url: str = ""

    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
        "extra": "ignore",
    }


settings = Settings(_env_file=".env" if os.path.exists(".env") else None)
