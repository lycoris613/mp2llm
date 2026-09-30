"""검증용 코드 샘플 → Swagger 에 그대로 붙여넣을 수 있는 요청 JSON(ExplainRequest) + expected.json 생성.

    python fixtures/build_fixtures.py

샘플을 고치려면 이 파일의 SAMPLES 를 수정하고 다시 실행한다. (탐지 라인/문맥 번호를 자동으로 맞춰 준다)
"""
import json
from pathlib import Path

OUT = Path(__file__).parent
PADDING = 20

# Scanner 룰 메타데이터 (01 도메인 설계서 §2.1.2 룰 표)
RULES = {
    "SQLI-001": ("SQL_INJECTION", "CWE-89", "CRITICAL", "SQL 문자열 결합",
                 "SQL 문자열에 + 연산자로 변수를 직접 결합하고 있습니다."),
    "SQLI-003": ("SQL_INJECTION", "CWE-89", "CRITICAL", "템플릿 리터럴 SQL 삽입",
                 "SQL 문자열 안에서 ${} 보간으로 외부 입력을 직접 결합하고 있습니다."),
    "SECRET-001": ("HARDCODED_SECRET", "CWE-798", "HIGH", "비밀번호 변수에 문자열 리터럴 대입",
                   "password/pwd 변수에 문자열 리터럴이 직접 대입되어 있습니다."),
    "SECRET-002": ("HARDCODED_SECRET", "CWE-798", "HIGH", "API 키/토큰 리터럴 대입",
                   "apiKey/secret/token 변수에 8자 이상 문자열 리터럴이 대입되어 있습니다."),
    "SECRET-003": ("HARDCODED_SECRET", "CWE-798", "CRITICAL", "AWS Access Key 형식",
                   "AWS Access Key ID 형식(AKIA...)의 문자열이 소스에 포함되어 있습니다."),
    "XSS-001": ("XSS", "CWE-79", "HIGH", "innerHTML 에 변수 대입",
                "innerHTML/outerHTML 에 변수 값이 그대로 대입되고 있습니다."),
    "XSS-003": ("XSS", "CWE-79", "MEDIUM", "dangerouslySetInnerHTML 사용",
                "dangerouslySetInnerHTML 로 HTML 문자열을 그대로 렌더링하고 있습니다."),
}

# (파일명, ruleId, 경로, 언어, 코드, 탐지 라인에 들어있는 문자열, 기대 verdict[문자열 또는 허용 목록])
SAMPLES = [
    ("sqli_tp_js_template", "SQLI-003", "src/routes/users.ts", "TypeScript", """\
import express from 'express';
import db from './database';

app.get('/api/users', async (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const result = await db.query(query);
  res.json(result.rows);
});""", "SELECT * FROM users", "TRUE_POSITIVE"),

    ("sqli_fp_const_table_bind", "SQLI-003", "src/routes/orders.ts", "TypeScript", """\
import db from './database';

const TABLE = 'orders';  // 서버 상수, 사용자 입력 아님

app.get('/api/orders', async (req, res) => {
  const query = `SELECT * FROM ${TABLE} WHERE id = $1`;
  const result = await db.query(query, [req.query.id]);
  res.json(result.rows);
});""", "FROM ${TABLE}", "FALSE_POSITIVE"),

    ("sqli_tp_java_concat", "SQLI-001", "src/main/java/UserDao.java", "Java", """\
public class UserDao {
    public User findByName(HttpServletRequest req) throws SQLException {
        String name = req.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery(sql);
        return map(rs);
    }
}""", "String sql =", "TRUE_POSITIVE"),

    ("secret_tp_java_password", "SECRET-001", "src/main/java/Db.java", "Java", """\
public class Db {
    private static final String URL = "jdbc:mysql://db.internal:3306/pay";
    private static final String DB_PASSWORD = "Sup3rS3cret!2024";

    Connection open() throws SQLException {
        return DriverManager.getConnection(URL, "admin", DB_PASSWORD);
    }
}""", "DB_PASSWORD =", "TRUE_POSITIVE"),

    ("secret_fp_placeholder", "SECRET-002", "config/example.config.js", "JavaScript", """\
// 신규 팀원용 설정 예시 파일입니다. 실제 값은 .env 에 넣으세요.
module.exports = {
  apiKey: "your-api-key",
  region: "ap-northeast-2",
};""", "apiKey:", "FALSE_POSITIVE"),

    ("secret_tp_aws_key", "SECRET-003", "src/storage/s3.js", "JavaScript", """\
const AWS = require('aws-sdk');

const s3 = new AWS.S3({
  accessKeyId: "AKIAJ4Q7ZK2M5N8P3R6T",
  secretAccessKey: process.env.AWS_SECRET,
});""", "accessKeyId:", "TRUE_POSITIVE"),

    ("xss_tp_innerhtml_hash", "XSS-001", "public/welcome.js", "JavaScript", """\
const name = decodeURIComponent(location.hash.slice(1));
const box = document.getElementById('welcome');
box.innerHTML = '환영합니다, ' + name;""", "box.innerHTML", "TRUE_POSITIVE"),

    ("xss_fp_static_string", "XSS-001", "public/status.js", "JavaScript", """\
const box = document.getElementById('status');
box.innerHTML = "<b>Loading...</b>";""", "box.innerHTML", "FALSE_POSITIVE"),

    # 어려운 케이스: 정화 함수를 거치므로 FALSE_POSITIVE 가 맞지만 설정을 알 수 없어 UNCERTAIN 도 허용
    ("xss_fp_dompurify_react", "XSS-003", "src/components/Post.jsx", "JavaScript", """\
import DOMPurify from 'dompurify';

export default function Post({ html }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
  );
}""", "dangerouslySetInnerHTML", ["FALSE_POSITIVE", "UNCERTAIN"]),
]


def build() -> None:
    expected = {}
    for i, (name, rule_id, path, lang, code, needle, exp) in enumerate(SAMPLES, start=1):
        lines = code.split("\n")
        n = next(k for k, ln in enumerate(lines, 1) if needle in ln)
        first, last = max(1, n - PADDING), min(len(lines), n + PADDING)
        vtype, cwe, sev, title, desc = RULES[rule_id]
        req = {
            "findingId": 9000 + i,
            "promptVersion": "v1.0",
            "rule": {"ruleId": rule_id, "vulnerabilityType": vtype, "cweId": cwe,
                     "severity": sev, "title": title, "description": desc},
            "location": {"relativePath": path, "language": lang, "startLine": n, "endLine": n},
            "codeContext": {"startLine": first, "endLine": last,
                            "lines": [f"{k}: {lines[k - 1]}" for k in range(first, last + 1)]},
        }
        (OUT / f"{name}.json").write_text(json.dumps(req, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        expected[f"{name}.json"] = exp
    (OUT / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{len(SAMPLES)}개 샘플 생성 -> {OUT}")


if __name__ == "__main__":
    build()
