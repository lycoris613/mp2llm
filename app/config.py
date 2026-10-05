"""튜닝 가능한 상수 모음. 비밀 값(API 키, 내부 토큰)은 여기 두지 않고 .env 로만 관리한다.

값을 바꿀 때의 주의:
- PROMPT_VERSION: prompts.py 를 수정하면 반드시 올린다 (BR-L009). 단, schemas.ExplainRequest 의
  promptVersion 이 Literal["v1.0"] 로 고정돼 있으므로 올릴 때 그쪽도 같이 바꿔야 요청이 422 로 거부되지 않는다.
"""

# ── 프롬프트 ────────────────────────────────────────────
PROMPT_VERSION = "v1.0"

# ── 모델 (.env 의 GEMINI_MODEL 이 우선한다) ───────────────
DEFAULT_MODEL = "gemini-3.5-flash-lite"   # llm_client.py 가 이 값을 사용한다. .env.example 과 동일하게 유지
TEMPERATURE = 0.2                         # 설명 톤은 일정하게, 판정은 흔들리지 않게
MAX_OUTPUT_TOKENS = 2048

# ── 지원 취약점 유형 (BR-S002: MVP 3종) ─────────────────────
SUPPORTED_VULN_TYPES = ("SQL_INJECTION", "HARDCODED_SECRET", "XSS")

# ── LLM 단계 처리 규칙 (01 도메인 설계서 §2.1.3, pipeline 에서 사용) ─
CONTEXT_PADDING = 20        # 취약 라인 앞뒤로 보낼 줄 수 (BR-L005)
MAX_PARALLEL = 4            # 동시 호출 수 (BR-L004)
STAGE_TIMEOUT_SECONDS = 180  # LLM 단계 전체 제한 (BR-A007)

# ── 오탐 배지 기준 (02 Entity isLikelyFalsePositive 와 동일) ───
FALSE_POSITIVE_CONFIDENCE_BELOW = 50
