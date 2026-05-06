from pydantic import BaseModel
from typing import Any, List, Optional


class FindingIn(BaseModel):
    fingerprint: str
    title: str
    severity: str
    status: str = "new"
    module: Optional[str] = None
    remediation_priority: Optional[str] = None
    raw: dict[str, Any] = {}


class ScanIn(BaseModel):
    profile: str = "default"
    risk_score: int = 0
    risk_level: str = "Low"
    findings: List[FindingIn] = []


class FindingOut(FindingIn):
    id: int

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    profile: str
    risk_score: int
    risk_level: str
    findings: List[FindingOut] = []

    class Config:
        from_attributes = True