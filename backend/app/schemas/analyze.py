# Request/response models for the analyze API.
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

MAX_TEXT_LENGTH = 5000


class AnalyzeRequest(BaseModel):
    text: str = ""
    url: str = ""
    language: str = "english"

    @model_validator(mode="after")
    def require_content(self):
        if not (self.text.strip() or self.url.strip()):
            raise ValueError("Provide 'text' or 'url' to analyze")
        if len(self.text) > MAX_TEXT_LENGTH:
            raise ValueError(f"text must be at most {MAX_TEXT_LENGTH} characters")
        return self


class Signal(BaseModel):
    name: str
    score: int = 0
    detail: Optional[str] = None


class AnalyzeResponse(BaseModel):
    classification: str  # SAFE | SUSPICIOUS | SCAM
    risk_score: int      # 0-100 prototype score
    signals: List[Signal] = []
    explanation: str = ""
    recommendations: List[str] = []
    urls: List[str] = []
    extracted: dict = {}
    sources: dict = {}
    prototype: bool = True  # scores are prototype weights, not probabilities
