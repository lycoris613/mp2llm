"""Async Gemini client for one scanner finding at a time."""

import json
import logging
import os
from dataclasses import dataclass
from typing import Protocol

import httpx
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

# 모델 기본값·temperature·프롬프트 버전은 config.py 한 곳에서만 정의한다.
# (main.py 가 여기서 DEFAULT_MODEL, PROMPT_VERSION 을 가져가므로 이름은 그대로 노출한다)
from .config import DEFAULT_MODEL, MAX_OUTPUT_TOKENS, PROMPT_VERSION, TEMPERATURE
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import ExplainRequest, LLMContent

# 로그에는 오류 코드만 남기고 사용자 코드·응답 본문은 남기지 않는다 (BR-L010).
log = logging.getLogger("codeguard.llm")


class LLMConfigurationError(Exception):
    pass


class LLMTimeoutError(Exception):
    pass


class LLMServiceError(Exception):
    pass


class LLMSchemaError(Exception):
    def __init__(self, raw_response: str):
        self.raw_response = raw_response
        super().__init__("LLM response is empty or invalid")


@dataclass(frozen=True)
class Settings:
    llm_provider: str
    gemini_api_key: str
    gemini_model: str
    llm_timeout_seconds: float
    gemini_max_output_tokens: int

    @classmethod
    def from_env(cls) -> "Settings":
        try:
            timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "180"))
            max_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", str(MAX_OUTPUT_TOKENS)))
        except ValueError as exc:
            raise LLMConfigurationError("Invalid Gemini client configuration") from exc
        if timeout <= 0 or max_tokens <= 0:
            raise LLMConfigurationError("Gemini timeout and token limit must be positive")
        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", "gemini").lower(),
            gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
            gemini_model=os.getenv("GEMINI_MODEL", DEFAULT_MODEL),
            llm_timeout_seconds=timeout,
            gemini_max_output_tokens=max_tokens,
        )


@dataclass(frozen=True)
class LlmRaw:
    text: str
    model: str
    input_tokens: int
    output_tokens: int


class LlmClient(Protocol):
    async def generate(self, finding: ExplainRequest) -> LlmRaw: ...


class GeminiClient:
    """Google Gen AI SDK adapter; each call closes its async HTTP client."""

    def __init__(self, settings: Settings):
        self.settings = settings

    async def complete(self, system: str, messages: list[dict[str, str]]) -> LlmRaw:
        contents = [
            types.Content(
                role="model" if message["role"] == "assistant" else "user",
                parts=[types.Part(text=message["content"])],
            )
            for message in messages
        ]
        try:
            sdk_client = genai.Client(
                api_key=self.settings.gemini_api_key,
                http_options=types.HttpOptions(timeout=int(self.settings.llm_timeout_seconds * 1000)),
            )
            async with sdk_client.aio as async_client:
                response = await async_client.models.generate_content(
                    model=self.settings.gemini_model,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=system,
                        max_output_tokens=self.settings.gemini_max_output_tokens,
                        response_mime_type="application/json",
                        response_schema=LLMContent,
                        temperature=TEMPERATURE,
                    ),
                )
        except (TimeoutError, httpx.TimeoutException) as exc:
            log.warning("gemini timeout (%s)", type(exc).__name__)
            raise LLMTimeoutError() from exc
        except genai_errors.APIError as exc:
            code = getattr(exc, "code", None)
            # 원인(키·모델명·한도) 구분용. 메시지 본문은 남기지 않는다.
            log.error("gemini api error code=%s status=%s model=%s",
                      code, getattr(exc, "status", None), self.settings.gemini_model)
            if code in (408, 504):
                raise LLMTimeoutError() from exc
            raise LLMServiceError() from exc
        except httpx.HTTPError as exc:
            log.error("gemini http error (%s)", type(exc).__name__)
            raise LLMServiceError() from exc

        try:
            text = response.text or ""
        except ValueError as exc:
            raise LLMSchemaError("") from exc
        if not text.strip():
            raise LLMSchemaError(text)

        usage = response.usage_metadata
        return LlmRaw(
            text=text,
            model=response.model_version or self.settings.gemini_model,
            input_tokens=(usage.prompt_token_count or 0) if usage else 0,
            output_tokens=(usage.candidates_token_count or 0) if usage else 0,
        )

    async def generate(self, finding: ExplainRequest) -> LlmRaw:
        return await self.complete(
            SYSTEM_PROMPT,
            [{"role": "user", "content": build_user_prompt(finding)}],
        )


class MockClient:
    """Opt-in local response for Spring integration without a Gemini key."""

    async def generate(self, finding: ExplainRequest) -> LlmRaw:
        body = {
            "verdict": "TRUE_POSITIVE",
            "confidence": 90,
            "explanation": "[MOCK] 외부 입력이 검증 없이 위험한 위치에 사용되고 있습니다.",
            "riskDescription": "[MOCK] 공격자가 입력값을 조작해 의도하지 않은 동작을 일으킬 수 있습니다.",
            "attackScenario": "[MOCK] 조작된 파라미터로 요청을 보냅니다.",
            "remediation": "[MOCK] 입력값을 검증하고 안전한 API를 사용하세요.",
            "fixedCode": "// [MOCK] 개선 코드",
        }
        return LlmRaw(json.dumps(body, ensure_ascii=False), "mock", 0, 0)


def create_client(settings: Settings) -> LlmClient:
    if settings.llm_provider == "mock":
        return MockClient()
    if settings.llm_provider != "gemini":
        raise LLMConfigurationError("Unknown LLM_PROVIDER")
    if not settings.gemini_api_key or not settings.gemini_model:
        raise LLMConfigurationError("GEMINI_API_KEY and GEMINI_MODEL are required")
    return GeminiClient(settings)
