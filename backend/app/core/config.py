from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, field_validator
from typing import List, Union

class Settings(BaseSettings):
    PROJECT_NAME: str = "Dependency Control"
    API_V1_STR: str = "/api/v1"
    
    MONGODB_URL: str
    DATABASE_NAME: str = "dependency_control"
    
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # External APIs
    OPEN_SOURCE_MALWARE_API_KEY: str = ""

    # Worker Settings
    WORKER_COUNT: int = 2

    # Notifications
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAILS_FROM_EMAIL: str = "info@dependencycontrol.local"
    
    SLACK_BOT_TOKEN: str = ""
    
    # Mattermost
    MATTERMOST_BOT_TOKEN: str = ""
    MATTERMOST_URL: str = "" # e.g. https://mattermost.example.com

    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
