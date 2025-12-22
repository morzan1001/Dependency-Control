from pydantic import BaseModel, Field


class Stats(BaseModel):
    critical: int = Field(0, description="Count of critical findings")
    high: int = Field(0, description="Count of high severity findings")
    medium: int = Field(0, description="Count of medium severity findings")
    low: int = Field(0, description="Count of low severity findings")
    info: int = Field(0, description="Count of informational findings")
    unknown: int = Field(0, description="Count of findings with unknown severity")
    risk_score: float = Field(0.0, description="Calculated risk score")
