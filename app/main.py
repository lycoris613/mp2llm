"""Internal FastAPI entry point for LLM explanations."""

import hmac
import os
from dotenv import load_dotenv

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import ValidationError

from .schemas import ExplainRequest, ExplainResponse, HealthResponse, LLMContent, Verdict
from .llm_client import (
    DEFAULT_MODEL,
    PROMPT_VERSION,
    Settings,
    create_client,
    LLMConfigurationError,
    LLMSchemaError,
    LLMServiceError,
    LLMTimeoutError,
)


# 로컬 --reload 자식 프로세스가 부모의 이전 --env-file 값을 상속해도 최신 .env를 사용한다.
load_dotenv(override=True)

app = FastAPI(title="CodeGuard AI LLM Internal API", version=PROMPT_VERSION)
internal_token_header = APIKeyHeader(
    name="X-Internal-Token",
    scheme_name="InternalToken",
    description="Spring Boot와 공유하는 INTERNAL_SHARED_SECRET",
    auto_error=False,
)


async def verify_internal_token(
    x_internal_token: str | None = Security(internal_token_header),
) -> None:
    shared_secret = os.getenv("INTERNAL_SHARED_SECRET", "")
    if not shared_secret:
        raise HTTPException(status_code=503, detail="Internal token is not configured")
    if not x_internal_token or not hmac.compare_digest(x_internal_token, shared_secret):
        raise HTTPException(status_code=401, detail="Invalid internal token")

# §4.5.2 - 헬스체크
@app.get("/internal/llm/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    model = "mock" if os.getenv("LLM_PROVIDER", "gemini").lower() == "mock" else os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
    return HealthResponse(model=model)

# §4.5.1 - Internal API 계약
@app.post(
    "/internal/llm/explain",
    response_model=ExplainResponse,
    dependencies=[Depends(verify_internal_token)],
)
async def explain(
    finding: ExplainRequest,
):
    try:
        client = create_client(Settings.from_env())
    except LLMConfigurationError:
        raise HTTPException(status_code=503, detail="LLM client is not configured") from None

    # The prototype pipeline retries transport errors; model schema errors retry here once.
    for _ in range(2):
        try:
            reply = await client.generate(finding)
            content = LLMContent.model_validate_json(reply.text)
        except LLMSchemaError as exc:
            raw_response = exc.raw_response
        except ValidationError:
            raw_response = reply.text
        except LLMTimeoutError:
            return JSONResponse(
                status_code=504,
                content={"findingId": finding.findingId, "errorCode": "LLM_TIMEOUT", "message": "LLM 응답 시간이 초과되었습니다"},
            )
        except LLMServiceError:
            return JSONResponse(
                status_code=502,
                content={"findingId": finding.findingId, "errorCode": "LLM_SERVICE_UNAVAILABLE", "message": "LLM 서비스 호출에 실패했습니다"},
            )
        else:
            return ExplainResponse(
                findingId=finding.findingId,
                modelName=reply.model,
                promptVersion=PROMPT_VERSION,
                promptTokens=reply.input_tokens,
                completionTokens=reply.output_tokens,
                rawResponse=reply.text,
                **{**content.model_dump(), "verdict": content.verdict or Verdict.UNCERTAIN},
            )

    return JSONResponse(
        status_code=422,
        content={
            "findingId": finding.findingId,
            "errorCode": "LLM_SCHEMA_INVALID",
            "message": "LLM 응답이 정의된 JSON 스키마를 만족하지 않습니다",
            "rawResponse": raw_response,
        },
    )
