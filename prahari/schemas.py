from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal["phishing", "sqli", "xss", "command_injection", "path_traversal"]
CATEGORIES = ("phishing", "sqli", "xss", "command_injection", "path_traversal")


class ScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_type: Literal["url", "http_request", "payload"]
    content: str = Field(min_length=1, max_length=10000)
    content_type: Literal[
        "text/plain", "application/json", "application/x-www-form-urlencoded"
    ] = "text/plain"

    @field_validator("content")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Content must not be blank")
        return value


class Finding(BaseModel):
    detector: str
    category: Category
    evidence_kind: Literal["rule", "model"]
    summary: str
    score: float = Field(ge=0, le=100)
    component: str
    rule_id: str | None = None
    view: str | None = None
    start: int | None = None
    end: int | None = None
    transformations: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    created_at: str
    status: Literal["complete", "partial"]
    decision: Literal["Allow", "Review", "Block"]
    risk_score: float | None
    risk_kind: str = "experimental_policy_index"
    action_taken: str = "none"
    enforcement_events: list[dict] = Field(default_factory=list)
    category_scores: dict[str, float | None]
    findings: list[Finding]
    coverage: dict[str, str]
    reasons: list[str]
    model_signals: dict
    versions: dict[str, str]
    analysis_ms: float


class EnforcementEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(pattern=r"^[a-zA-Z0-9-]{1,64}$")
    scan_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    mode: Literal["monitor", "enforce"]
    action: Literal["allowed", "blocked", "held"]
