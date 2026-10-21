from pydantic import BaseModel


class StatusMessage(BaseModel):
    message: str
