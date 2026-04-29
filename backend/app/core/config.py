from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Dependency Control"
    API_V1_STR: str = "/api/v1"

    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "dependency_control"
    # Read preference for replica sets: primary, primaryPreferred, secondary,
    # secondaryPreferred, nearest. Use secondaryPreferred in production to
    # distribute read load across replicas.
    MONGODB_READ_PREFERENCE: str = "primary"

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
    # Set False in production to block webhook targets at loopback hosts.
    WEBHOOK_ALLOW_LOCALHOST: bool = True

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

    # Trivy Server Mode (empty = use local CLI)
    # When set, the Trivy CLI uses --server flag to offload scanning to a
    # central server. This avoids storing the 1GB Trivy DB on every pod.
    TRIVY_SERVER_URL: str = ""  # e.g. "http://trivy-server:4954"

    # S3 / Archive Storage Settings
    S3_ENDPOINT_URL: str = ""  # e.g. "http://minio:9000" (empty = archive disabled)
    S3_ACCESS_KEY: str = ""
    S3_SECRET_KEY: str = ""
    S3_BUCKET_NAME: str = "dc-archives"
    S3_REGION: str = "us-east-1"
    S3_USE_SSL: bool = False  # True for AWS S3, False for local MinIO

    # Archive Encryption (empty = archives not encrypted)
    ARCHIVE_ENCRYPTION_KEY: str = ""

    # Ollama / LLM
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    OLLAMA_MODEL: str = "gemma4:26b"
    OLLAMA_TIMEOUT_SECONDS: int = 120
    OLLAMA_NUM_CTX: int = 16384

    # Chat — feature flag is deployment-time (set true in Helm only when the
    # ollama sub-chart is also deployed). Runtime tunables (rate limits, tool
    # rounds) stay in SystemSettings so admins can adjust them via the UI.
    CHAT_ENABLED: bool = False
    CHAT_MAX_HISTORY_MESSAGES: int = 15
    CHAT_MAX_TOKEN_BUDGET: int = 12000
    CHAT_RATE_LIMIT_PER_MINUTE: int = 10
    CHAT_RATE_LIMIT_PER_HOUR: int = 60
    # Maximum rounds of the LLM ↔ tool call loop before we synthesise a
    # fallback message. Raising this lets the model chain more tool calls
    # at the cost of worst-case latency per message.
    CHAT_MAX_TOOL_ROUNDS: int = 20

    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env")


settings = Settings()
