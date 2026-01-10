from pydantic_settings import BaseSettings


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
    SMTP_user: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM_EMAIL: str = "noreply@dependency-control.com"

    # Worker Settings
    WORKER_COUNT: int = 2

    # Frontend
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
