"""Internal FastAPI entry point for LLM explanations."""

import hmac
import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
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


app = FastAPI(title="CodeGuard AI LLM Internal API", version=PROMPT_VERSION)

# §4.5.2 - 헬스체크
@app.get("/internal/llm/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    model = "mock" if os.getenv("LLM_PROVIDER", "gemini").lower() == "mock" else os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
    return HealthResponse(model=model)

# §4.5.1 - Internal API 계약
@app.post("/internal/llm/explain", response_model=ExplainResponse)
async def explain(
    finding: ExplainRequest,
    x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
):
    shared_secret = os.getenv("INTERNAL_SHARED_SECRET", "")
    if not shared_secret:
        raise HTTPException(status_code=503, detail="Internal token is not configured")
    if not x_internal_token or not hmac.compare_digest(x_internal_token, shared_secret):
        raise HTTPException(status_code=401, detail="Invalid internal token")

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
