"""Finding 목록 → `LLM 분석` 테이블 레코드 변환 (01 도메인 설계서 §2.1.3, BR-L001~L013).

Spring 워커의 EXPLAINING 단계에 해당한다. Finding 1건마다 정확히 1개의 레코드(SUCCESS 또는 FAILED)를 만든다.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from pydantic import BaseModel

from .prompts import PROMPT_VERSION
from .schemas import CodeContext, ExplainRequest, ExplainResponse, Location, RuleInfo
from .service import ExplainService, LlmError

log = logging.getLogger("codeguard.pipeline")

MAX_PARALLEL = 4            # BR-L004
CONTEXT_PADDING = 20        # BR-L005
STAGE_TIMEOUT_SECONDS = 180  # BR-A007 (LLM 단계 전체)
RETRYABLE = {"LLM_TIMEOUT", "LLM_SERVICE_UNAVAILABLE"}  # 스키마 실패는 service 안에서 이미 재시도함


# ── 입력 ────────────────────────────────────────────────
class FileInput(BaseModel):
    relativePath: str
    language: str
    content: str


class FindingInput(BaseModel):
    """Scanner 가 만든 FindingVulnerability 1건."""
    findingId: int
    relativePath: str
    rule: RuleInfo
    startLine: int
    endLine: int
    codeSnippet: str


# ── 출력: `LLM 분석` 테이블 1행 ───────────────────────────
class LlmAnalysisRecord(BaseModel):
    findingId: int                       # finding_id (UNIQUE, 1:1)
    status: str                          # SUCCESS | FAILED
    explanation: str | None = None       # SQL 의 cause (02 Entity 는 explanation)
    riskDescription: str | None = None
    attackScenario: str | None = None
    remediation: str | None = None
    fixedCode: str | None = None
    verdict: str | None = None
    confidence: int | None = None
    modelName: str | None = None
    promptVersion: str | None = None
    rawResponse: str | None = None       # 실패해도 원문 보관 (BR-L006)
    promptTokens: int = 0
    completionTokens: int = 0
    errorMessage: str | None = None      # FAILED 일 때, 500자 이내


class PipelineResult(BaseModel):
    records: list[LlmAnalysisRecord]
    total: int
    success: int
    failed: int
    reused: int                          # 중복 재사용으로 호출을 아낀 건수 (BR-L012)
    promptTokens: int
    completionTokens: int


# ── 문맥 추출 (BR-L005) ──────────────────────────────────
def extract_context(content: str, start: int, end: int, padding: int = CONTEXT_PADDING) -> CodeContext:
    lines = content.split("\n")
    first = max(1, start - padding)
    last = min(len(lines), end + padding)
    return CodeContext(
        startLine=first, endLine=last,
        lines=[f"{n}: {lines[n - 1]}" for n in range(first, last + 1)],
    )


class ExplainPipeline:
    def __init__(self, service: ExplainService, *, max_parallel: int = MAX_PARALLEL,
                 stage_timeout: float = STAGE_TIMEOUT_SECONDS):
        self.service = service
        self.max_parallel = max_parallel
        self.stage_timeout = stage_timeout

    def run(self, findings: list[FindingInput], files: list[FileInput],
            on_progress: Callable[[int, int], None] | None = None) -> PipelineResult:
        """on_progress(done, total): 폴링 응답의 explainedFindings 갱신용."""
        by_path = {f.relativePath: f for f in files}
        deadline = time.monotonic() + self.stage_timeout

        # 같은 ruleId + 같은 codeSnippet 은 1회만 호출 (BR-L012)
        groups: dict[tuple[str, str], list[FindingInput]] = {}
        for f in findings:
            groups.setdefault((f.rule.ruleId, f.codeSnippet), []).append(f)

        results: dict[int, LlmAnalysisRecord] = {}
        done = 0

        def work(group: list[FindingInput]) -> list[LlmAnalysisRecord]:
            lead = group[0]  # 대표 1건으로 호출하고 나머지는 결과 복제
            rec = self._explain_one(lead, by_path.get(lead.relativePath), deadline)
            out = [rec]
            for other in group[1:]:
                out.append(rec.model_copy(update={"findingId": other.findingId,
                                                  "promptTokens": 0, "completionTokens": 0}))
            return out

        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            for recs in pool.map(work, groups.values()):
                for r in recs:
                    results[r.findingId] = r
                    done += 1
                if on_progress:
                    on_progress(done, len(findings))

        ordered = [results[f.findingId] for f in findings]  # 입력 순서 유지
        ok = sum(r.status == "SUCCESS" for r in ordered)
        return PipelineResult(
            records=ordered, total=len(ordered), success=ok, failed=len(ordered) - ok,
            reused=len(findings) - len(groups),
            promptTokens=sum(r.promptTokens for r in ordered),
            completionTokens=sum(r.completionTokens for r in ordered),
        )

    # ── 1건 처리: 실패해도 예외를 밖으로 내보내지 않는다 (BR-L007) ──
    def _explain_one(self, f: FindingInput, file: FileInput | None, deadline: float) -> LlmAnalysisRecord:
        if file is None:
            return self._failed(f.findingId, "FILE_NOT_FOUND", "탐지된 파일 본문을 찾을 수 없습니다")
        req = ExplainRequest(
            findingId=f.findingId, promptVersion=PROMPT_VERSION, rule=f.rule,
            location=Location(relativePath=f.relativePath, language=file.language,
                              startLine=f.startLine, endLine=f.endLine),
            codeContext=extract_context(file.content, f.startLine, f.endLine),
        )
        for attempt in (1, 2):  # 호출 실패 시 건별 1회 재시도
            if time.monotonic() > deadline:
                return self._failed(f.findingId, "LLM_TIMEOUT", "LLM 단계 전체 시간 초과")
            try:
                return self._success(self.service.explain(req))
            except LlmError as e:
                if e.code in RETRYABLE and attempt == 1:
                    continue
                return self._failed(f.findingId, e.code, e.message, e.raw)
            except Exception as e:  # 예상 밖 오류도 이 건만 FAILED 처리
                log.error("finding=%s unexpected %s", f.findingId, type(e).__name__)  # 본문 로깅 금지
                return self._failed(f.findingId, "LLM_SERVICE_UNAVAILABLE", "예기치 못한 오류")
        raise AssertionError("unreachable")

    def _success(self, r: ExplainResponse) -> LlmAnalysisRecord:
        return LlmAnalysisRecord(
            findingId=r.findingId, status="SUCCESS", explanation=r.explanation,
            riskDescription=r.riskDescription, attackScenario=r.attackScenario,
            remediation=r.remediation, fixedCode=r.fixedCode,
            verdict=r.verdict.value, confidence=r.confidence,
            modelName=r.modelName, promptVersion=r.promptVersion, rawResponse=r.rawResponse,
            promptTokens=r.promptTokens, completionTokens=r.completionTokens,
        )

    def _failed(self, finding_id: int, code: str, message: str, raw: str | None = None) -> LlmAnalysisRecord:
        return LlmAnalysisRecord(
            findingId=finding_id, status="FAILED", errorMessage=f"{code}: {message}"[:500],
            rawResponse=raw, modelName=self.service.settings.llm_model, promptVersion=PROMPT_VERSION,
        )
