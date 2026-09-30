"""fixtures/*.json 을 앱(/internal/llm/explain)에 넣어 verdict 가 expected.json 과 맞는지 확인한다.

    python fixtures/run_fixtures.py

서버를 띄울 필요 없이 앱을 프로세스 안에서 호출한다. .env 의 LLM_PROVIDER 를 그대로 따른다.
  - gemini: 실제 호출 (fixtures 개수만큼 API 호출)
  - mock  : 항상 TRUE_POSITIVE 가 나오므로 연결 확인용
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402  (import 시 .env 로드)


def main() -> int:
    token = os.getenv("INTERNAL_SHARED_SECRET", "")
    if not token:
        print("INTERNAL_SHARED_SECRET 이 없습니다. .env 를 확인하세요.")
        return 2
    client = TestClient(app)
    expected = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))
    hit = 0
    for name, exp in expected.items():
        body = json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))
        r = client.post("/internal/llm/explain", json=body, headers={"X-Internal-Token": token})
        allowed = exp if isinstance(exp, list) else [exp]
        if r.status_code != 200:
            print(f"[ERR ] {name}: HTTP {r.status_code} {r.text[:120]}")
            continue
        d = r.json()
        ok = d["verdict"] in allowed
        hit += ok
        print(f"[{'OK  ' if ok else 'MISS'}] {name}: 기대={'/'.join(allowed)} 실제={d['verdict']}({d['confidence']})")
        print(f"        {d['explanation'][:110]}")
    print(f"\n판정 일치 {hit}/{len(expected)}")
    return 0 if hit == len(expected) else 1


if __name__ == "__main__":
    sys.exit(main())
