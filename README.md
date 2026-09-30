# llm-service (FastAPI)

CodeGuard AI 의 LLM 내부 서비스. Spring Boot 만 호출한다 (REST API 설계서 v1.1 §4.5).

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
# .env의 INTERNAL_SHARED_SECRET, GEMINI_API_KEY를 실제 값으로 수정
.venv\Scripts\python -m uvicorn app.main:app --env-file .env --host 127.0.0.1 --port 8000
```

Swagger에서 테스트할 때는 `http://127.0.0.1:8000/docs`의 **Authorize**에서 `InternalToken`에 `.env`의 `INTERNAL_SHARED_SECRET` 값(예: `local-dev`)을 입력한 뒤 `POST /internal/llm/explain`을 실행한다. `.env` 값을 바꾼 뒤에는 Uvicorn을 재시작한다.

| 메서드 | 경로                    | 용도                            |
| ------ | ----------------------- | ------------------------------- |
| POST   | `/internal/llm/explain` | 취약점 1건 설명 (설계서 §4.5.1) |
| GET    | `/internal/llm/health`  | 헬스체크 (§4.5.2)               |

에러 응답: `{findingId, errorCode, message, rawResponse}`

- 422 요청 형식 오류 (FastAPI 기본 검증 응답)
- 401 X-Internal-Token 불일치
- 422 `LLM_SCHEMA_INVALID` 2회 모두 스키마 검증 실패 (rawResponse 포함)
- 502 `LLM_SERVICE_UNAVAILABLE` / 504 `LLM_TIMEOUT`

## LLM 공급자

Google Gemini (`google-genai` SDK). 기본 모델은 `gemini-3.5-flash-lite`이며 `.env` 의 `GEMINI_MODEL` 로 바꿀 수 있다.
`response_mime_type="application/json"` 으로 JSON 출력을 요청하고 Pydantic으로 응답 필드를 검증한다.
`LLM_PROVIDER=mock` 이면 API 키 없이 고정 응답이 나온다.
