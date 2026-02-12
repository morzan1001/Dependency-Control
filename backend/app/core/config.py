from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Dependency Control"
    API_V1_STR: str = "/api/v1"

    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "dependency_control"

    # Redis Cache Settings
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_PREFIX: str = "dc:"
    CACHE_DEFAULT_TTL_HOURS: int = 24

    SECRET_KEY: str = "changeme"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # External APIs
    OPEN_SOURCE_MALWARE_API_KEY: str = ""

    # Email
    SMTP_HOST: str | None = None
    SMTP_PORT: int | None = None
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM_EMAIL: str = "noreply@dependency-control.com"

    # Worker Settings
    WORKER_COUNT: int = 2

    # Frontend
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    # Time (seconds) a scan can be in 'processing' before considered stuck
    # Increase this if your analysis typically takes longer
    HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS: int = 1800  # 30 minutes

    # Timeout for webhook deliveries (depends on webhook endpoint response times)
    WEBHOOK_TIMEOUT_SECONDS: float = 30.0
    WEBHOOK_MAX_RETRIES: int = 3

    # Timeout for notification providers (Slack, Mattermost API latency)
    NOTIFICATION_HTTP_TIMEOUT_SECONDS: float = 30.0

    # Enrichment service settings
    ENRICHMENT_MAX_RETRIES: int = 3
    ENRICHMENT_RETRY_DELAY: float = 1.0

    # Pod lifecycle settings
    # Maximum time (seconds) a pod can run before it should restart
    # Set to 0 to disable automatic restarts
    # Default: 43200 (12 hours) - helps manage memory growth
    MAX_POD_UPTIME_SECONDS: int = 43200

    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env")


settings = Settings()
