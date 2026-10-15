from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Dependency Control"
    API_V1_STR: str = "/api/v1"

    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "dependency_control"

    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_PREFIX: str = "dc:"
    CACHE_DEFAULT_TTL_HOURS: int = 24

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    WORKER_COUNT: int = 2

    FRONTEND_BASE_URL: str = "http://localhost:3000"

    @field_validator("FRONTEND_BASE_URL")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS: int = 1800

    WEBHOOK_TIMEOUT_SECONDS: float = 30.0
    WEBHOOK_MAX_RETRIES: int = 3
    # Local development only: a loopback target is the backend's own host.
    WEBHOOK_ALLOW_LOCALHOST: bool = False

    NOTIFICATION_HTTP_TIMEOUT_SECONDS: float = 30.0

    ENRICHMENT_MAX_RETRIES: int = 3
    ENRICHMENT_RETRY_DELAY: float = 1.0

    # 0 disables the restart; recycling pods bounds memory growth.
    MAX_POD_UPTIME_SECONDS: int = 43200

    # Empty runs the local Trivy CLI; a server spares every pod the 1GB Trivy DB.
    TRIVY_SERVER_URL: str = ""

    S3_ENDPOINT_URL: str = ""  # empty disables the archive
    S3_ACCESS_KEY: str = ""
    S3_SECRET_KEY: str = ""
    S3_BUCKET_NAME: str = "dc-archives"
    S3_REGION: str = "us-east-1"
    S3_USE_SSL: bool = False

    # Empty leaves archives unencrypted.
    ARCHIVE_ENCRYPTION_KEY: str = ""

    # Plain http is intentional: the default in-cluster service is reached over the mesh-encrypted network.
    OLLAMA_BASE_URL: str = "http://ollama:11434"  # NOSONAR
    OLLAMA_MODEL: str = "gemma4:26b"
    OLLAMA_TIMEOUT_SECONDS: int = 120
    OLLAMA_NUM_CTX: int = 16384

    # Deployment-time: true only where Helm deploys the ollama sub-chart; runtime tunables live in SystemSettings.
    CHAT_ENABLED: bool = False
    CHAT_MAX_HISTORY_MESSAGES: int = 15

    POLICY_AUDIT_MIN_PRUNE_DAYS: int = 90
    # 0 keeps entries forever.
    POLICY_AUDIT_RETENTION_DAYS: int = 0

    COMPLIANCE_REPORT_RETENTION_DAYS: int = 90

    UPDATE_FREQUENCY_ROLLUP_ENABLED: bool = True
    # Off until the backfill has run: without deltas the comparison can only report a project as pending.
    UPDATE_FREQUENCY_USE_ROLLUP: bool = False
    # Off until the backfill has run, or the nightly reconcile becomes a backfill stuck at its per-night cap.
    UPDATE_FREQUENCY_RECONCILE_ENABLED: bool = False

    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env")


settings = Settings()


def scan_link(project_id: str, scan_id: str) -> str:
    return f"{settings.FRONTEND_BASE_URL}/projects/{project_id}/scans/{scan_id}"
