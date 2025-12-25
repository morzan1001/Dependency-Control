from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Dependency Control"
    API_V1_STR: str = "/api/v1"

    MONGODB_URL: str
    DATABASE_NAME: str = "dependency_control"

    # Redis Cache Settings
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_PREFIX: str = "dc:"
    CACHE_DEFAULT_TTL_HOURS: int = 24

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # External APIs
    OPEN_SOURCE_MALWARE_API_KEY: str = ""

    # Worker Settings
    WORKER_COUNT: int = 2

    # Frontend
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
