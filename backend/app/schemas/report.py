# Request/response models for scam reports and threats.
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

MONEY_LOST_VALUES = ("no", "almost", "yes")


class ReportCreate(BaseModel):
    scam_type: str = Field(min_length=1, max_length=64)
    message: str = Field(default="", max_length=5000)
    url: str = Field(default="", max_length=2048)
    phone: str = Field(default="", max_length=32)
    upi_id: str = Field(default="", max_length=128)
    location: str = Field(default="South Chennai", max_length=128)
    money_lost: str = Field(default="no")
    anonymous: bool = True

    @model_validator(mode="after")
    def validate_money_lost(self):
        if self.money_lost.lower() not in MONEY_LOST_VALUES:
            raise ValueError(f"money_lost must be one of {MONEY_LOST_VALUES}")
        self.money_lost = self.money_lost.lower()
        return self


class ReportOut(BaseModel):
    id: str
    stored: bool = False
    graph_indexed: bool = False
    message: str = ""


class Threat(BaseModel):
    id: str
    title: str
    category: str
    area: str
    reports: int = 0
    risk: str = "MEDIUM"  # HIGH | MEDIUM | LOW
    description: Optional[str] = None


class Alert(BaseModel):
    id: str
    title: str
    detail: str
    area: str
    reports: int = 0
    risk: str = "HIGH"


class ThreatsResponse(BaseModel):
    source: str  # "supabase" | "seed"
    threats: List[Threat] = []
    alerts: List[Alert] = []
