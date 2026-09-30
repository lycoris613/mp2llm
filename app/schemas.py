"""Spring Boot ↔ FastAPI 내부 API 계약 (REST API 설계서 §4.5)"""

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNCERTAIN = "UNCERTAIN"


class RuleInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ruleId: NonEmptyText
    vulnerabilityType: NonEmptyText
    cweId: NonEmptyText
    severity: NonEmptyText
    title: NonEmptyText
    description: NonEmptyText


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relativePath: NonEmptyText
    language: NonEmptyText
    startLine: int = Field(ge=1)
    endLine: int = Field(ge=1)


class CodeContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    startLine: int = Field(ge=1)
    endLine: int = Field(ge=1)
    lines: list[str] = Field(min_length=1)


class ExplainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findingId: int = Field(gt=0)
    promptVersion: Literal["v1.0"]
    rule: RuleInfo
    location: Location
    codeContext: CodeContext


class LLMContent(BaseModel):
    """모델은 설명만 생성한다. Scanner의 탐지 필드는 받아도 버린다."""

    model_config = ConfigDict(extra="ignore")

    verdict: Verdict | None = None
    confidence: int | None = Field(default=None, ge=0, le=100, strict=True)
    explanation: NonEmptyText
    riskDescription: str | None = None
    attackScenario: str | None = None
    remediation: NonEmptyText
    fixedCode: str | None = None


class ExplainResponse(LLMContent):
    findingId: int
    modelName: str
    promptVersion: str
    promptTokens: int = 0
    completionTokens: int = 0
    rawResponse: str


class HealthResponse(BaseModel):
    status: Literal["UP"] = "UP"
    model: str
    promptVersion: str = "v1.0"
