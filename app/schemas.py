from typing import List

from pydantic import BaseModel, Field, field_validator


class EmailInput(BaseModel):
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=998)
    body: str = Field(min_length=1, max_length=50000)

    @field_validator("sender", "subject", "body")
    @classmethod
    def trim_fields(cls, value: str) -> str:
        return value.strip()

    @field_validator("body")
    @classmethod
    def nonempty_body(cls, value: str) -> str:
        if not value:
            raise ValueError("Add some email content to analyze.")
        return value


class Signal(BaseModel):
    id: str
    name: str
    category: str
    points: int
    explanation: str
    matches: List[str]


class AnalysisResult(BaseModel):
    id: str
    sender: str
    subject: str
    body: str
    verdict: str
    score: int
    summary: str
    signals: List[Signal]
    categories: dict
    word_count: int
    link_count: int
    elapsed_ms: float
    engine_version: str
    created_at: str
