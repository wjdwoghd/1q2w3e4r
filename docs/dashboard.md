# Phase 11 읽기 전용 Dashboard MVP

2026-10-17 구현 범위다. 기존 분석·조치·검증 결과의 조회를 연결했고 Phase 11 전체와
Phase 12 보고서는 완료하지 않았다. Flask 3.1.3은 로컬 GET API, Streamlit 1.57.0은
조회 화면에 사용한다. 기존 기술 계획을 따르며 DB·HTTP 클라이언트·설정 읽기는
표준 라이브러리를 사용한다. 두 직접 의존성 이외의 분석 패키지를 추가하지 않았다.

## 실행과 DB 선택

저장소 루트에서 프로젝트 가상환경을 사용한다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

로컬 `.env`에 기존 DB를 별칭으로 등록한다. 아래 경로는 사용자가 실제 경로로 교체할
예제다. 한 줄 JSON이며 Windows에서는 `/` 또는 JSON 이스케이프된 `\\`를 사용한다.

```dotenv
DASHBOARD_DATABASES={"기존 Lab":"C:/실제/기존실행/lab.db","새 CLI 실행":"C:/실제/새실행/lab.db"}
DASHBOARD_API_URL=http://127.0.0.1:5000
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
```

기존 호스트 Lab에서 보존한 `lab.db`, 공통 `scripts.e2e`가 만든 새 실행 디렉터리의
`lab.db`를 같은 방법으로 등록한다. 위치가 기억나지 않으면 저장소 루트에서 다음과 같이
**파일 경로만 조회**할 수 있다. 파일을 자동 선택하거나 최신 Run으로 바꾸지 않는다.

```powershell
Get-ChildItem -LiteralPath . -Recurse -Filter lab.db | Select-Object FullName
```

CLI 실행·재개 방법은 [기존 실행 가이드](lab_e2e_runbook.md)를 따른다.
Dashboard 실행을 위해 Lab이나 Scanner를 기동할 필요는 없다.
다른 위치·파일명의 SQLite DB도 등록할 수 있고 특정 Run ID·출력 루트를 가정하지 않는다.
상대 경로는 API 실행 작업 디렉터리를 기준으로 해석하므로 저장소 루트에서 실행한다.
API 설정을 바꾸면 API 서버를 재시작한다. Dashboard의 API 주소 변경도 서버 재시작을 권장한다.
환경변수가 `.env`보다 우선하며 단순 `KEY=value`만 지원한다. shell 확장·실행은 하지 않는다.

서로 다른 터미널에서 실행한다.

```powershell
# 터미널 A
.\.venv\Scripts\python.exe -m app.main

# 터미널 B
.\.venv\Scripts\python.exe -m streamlit run app/dashboard/Home.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

화면 주소는 `http://127.0.0.1:8501`이다. 실행 DB → 금융서비스 → 자산을 고른 뒤
SBOM 또는 Finding을 선택한다. Finding의 관측을 선택하면 해당 관측의 CVE·CVSS·CWE·KEV와
저장된 Risk Score·P1~P4·규칙 버전·가점 근거를 확인할 수 있다. 관측은 최신값으로 합치지 않는다.
Recommendation은 관측별로 선택하며, Remediation 상세에는 연결된 Recommendation ID와
해당 내용도 표시한다. Verification 목록에서 **시도 ID와 attempt key를 확인해 선택**한다.
부모 DB·서비스·자산·Finding·조치가 바뀌면 해당 하위 선택은 초기화된다.

등록이 비면 설정 안내, 목록이 비면 빈 데이터 안내, 없는 ID는 404,
소속 불일치·선택 누락·잘못된 ID는 400, 없는/잠긴/호환되지 않는 DB는 503으로 표시한다.
이전 DB의 스키마는 [DB 문서](database.md)를 확인해 별도 관리한다.
조회 서버는 DB 생성·초기화·마이그레이션을 실행하지 않는다.

## 데이터 흐름과 조회 API

```text
Streamlit Home → DashboardClient (HTTP GET)
→ Flask /api → DashboardService (읽기 facade)
→ 기존 Asset/Finding/Recommendation/Remediation/Verification Service
→ 기존 Repository + SQLiteDashboardRepository (SBOM 목록만 보완)

선택한 시도 상세 → 기존 ComparisonService
→ SQLiteComparisonRepository → 불변 Before/After 사본과 원래 판정
→ 기존 SBOM Diff·Phase 10 구조화 지표 → API JSON → 화면 표시
```

`app/`에는 선택 검증·호출·출력 형식만 둔다. 비교·집계·소속 확인은 core와 기존 Repository를
통하며 SQL은 Repository에만 있다. 조회에는 AI·외부 CVE API·Risk 계산·Scanner·재판정을
호출하지 않는다. 기존 빈 `pages/`는 보존하며 명시적 navigation으로 MVP 단일 화면만 표시한다.

모든 API는 GET 전용이며 DB 선택은 서버에 등록한 `database` 별칭으로 제한한다.
파일 경로를 요청 인자로 넘겨 새 DB를 열 수 없다. 각 조회는 `mode=ro`, `query_only=ON`과
읽기 트랜잭션을 사용하며 한 요청 내 일관된 DB 상태를 읽고 연결을 닫는다.

| 경로 | 필수 선택 (`database`는 `/databases` 외 모두 필수) | 반환 |
| --- | --- | --- |
| `/api/databases` | 없음 | 등록된 이름·실제 DB 경로 |
| `/api/services` | 없음 | 금융서비스 목록 |
| `/api/assets` | 선택적 `service_id` | 자산 목록·Context |
| `/api/asset` | `asset_id` | 자산 상세 |
| `/api/sboms` | `asset_id` | SBOM 목록·발생 수 |
| `/api/sbom` | `asset_id`, `sbom_id` | 원본·발생별 구성요소 |
| `/api/findings` | `asset_id` | 자산+CVE당 한 Finding·현재 상태 |
| `/api/finding` | `asset_id`, `finding_id` | 모든 관측·Risk·매칭 증거·상태 이력·통제 매핑 |
| `/api/recommendations` | `asset_id`, `finding_id` | 관측별 개선안 전체 상세 |
| `/api/remediations` | `asset_id`, `finding_id` | 조치 목록·상세 |
| `/api/remediation` | 위 + `remediation_id` | 조치 계획·적용 기록·Before |
| `/api/attempts` | 위 + `remediation_id` | 시도 ID·attempt key·상태·시점·After 존재 여부 |
| `/api/attempt` | 위 + `remediation_id`, `verification_id` | 선택·기능 결과·Finding 비교·자산 비교 |

예: `/api/attempt?database=기존별칭&asset_id=1&finding_id=2&remediation_id=1&verification_id=1`
의 ID는 실제 목록에서 확인한 값으로 교체한다. DB가 다르면 숫자가 같아도 다른 대상이다.
구조화 응답의 `comparison`은 Phase 10 결과를 그대로 유지한다. `asset_comparison`은
**현재 선택한 한 시도**를 명시해 기존 `compare_asset()`을 호출한 결과다. 여러 Finding·시도의
동시 선택·공동 집계 화면은 이번 MVP에 포함하지 않는다.

## 증거·집계·미확인 표시

[Phase 10 계약](before_after.md)의 정책을 변경하지 않았다.

- Before Snapshot, 시도에 복사된 원본 SBOM, Recommendation 입력 사실, After Evidence와
  원래 판정·규칙·이유를 사용한다. 현재 원본 SBOM/매칭 데이터로 과거 비교를 보충하지 않는다.
- SBOM Diff는 추가·제거·버전 집합 변화·발생 수 변화를 보존한다. 중복 패키지는 별도 발생이고
  CVE/Finding은 자산+CVE를 중복 계산하지 않는다.
- 구성요소·취약 구성요소·CVE·Critical·KEV·EOL·우선순위별 Finding·Risk 지표를 기존
  결과 범위에서 표시한다. CVSS 기술적 심각도와 내부 대응 우선순위는 별도 표시한다.
- `None`은 화면 표에서 **미확인**, JSON에서는 `null`로 보존한다. 사유·분석 범위·집계 기준·출처·
  수집 시점·기록 시점·증거 ID·After digest를 펼쳐 확인할 수 있다. 증거가 없는 After Risk·EOL을
  0·P4·지원 중으로 바꾸지 않는다. 빈 기능 결과는 미확인 안내를 표시한다.
- 분석 범위가 다르거나 값이 미확인이면 증감을 표시하지 않고 비교 불가 사유를 보여준다.
  현재 Finding 목록은 과거 전체 자산 Snapshot이 아니다. 전체 Before 취약점 분석이 없으면
  자산 Before CVE 수 등을 현재 목록으로 재구성하지 않는다.
- 부분 재매칭·특정 CVE Scanner 결과를 전체 자산 미탐지로 확대하지 않는다. Failed 또는
  In Progress는 원래 상태를 유지한다. After가 저장돼도 완료 판정이 없으면 진행 중이다.

## 검증 결과와 남은 범위

```powershell
.\.venv\Scripts\python.exe -m unittest tests.integration.test_dashboard -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

신규 오프라인 테스트 16개는 기존 Phase 9/10 fixture와 서비스를 재사용한다. 목록·상세·비교
JSON, 명시적 반복 시도, 잘못된 소속·없는 ID, 미완료·Failed·기능 실패, 증거 누락·None,
부분 범위, 중복 발생과 Finding 단위, 과거 가변 원본 변경, GET 전용, DB 파일/판정/Snapshot
불변성을 검사한다. Streamlit AppTest는 실제 화면 코드를 실행해 선택·부모 변경 초기화·
미확인 지표·오류 표시를 확인한다. 전체 오프라인 테스트 **208개 (기존 192 + 신규 16)**가
통과했고 `pip check`, Python 구문 검사와 `git diff --check`도 통과했다.

2026-10-17 로컬 실행 확인에서는 기존 수동 Lab DB와 공통 CLI 최종 실행 DB를 별칭 두 개로
등록했다. 임시 loopback Flask·Streamlit 서버가 기동했고 UI HTTP 200·health `ok`를 확인했다.
실제 HTTP API를 사용하는 AppTest로 두 DB 각각 자산 1 → Finding 2 → 조치 1 → 시도 1을
선택해 기존 Passed·기능 테스트 2건·지표·근거를 렌더링했다. 두 DB의 Finding 목록은 각각
8건이었고, 대상 CVE 검증을 나머지 Finding의 종료로 확대하지 않았다. 재조회는 같았으며
두 DB 파일 SHA-256은 조회 전후 동일했다. 확인 후 임시 서버는 종료했다.
로컬 증거는 Git 제외 `data/output/dashboard-check/result.json`과 서버 로그에 있다.

브라우저를 사람이 조작하는 육안 검사·스크린샷·다양한 해상도 검사는 수행하지 않았다.
운영 인증/권한·TLS·배포, 대용량 페이지네이션·성능 검증, 다중 시도 공동 집계 UI는 남아 있다.
현재 서버는 신뢰하는 로컬 사용자를 위한 MVP이고 운영 배포를 제공하지 않는다.
분석·패치·Scanner 실행, 재판정, Risk Accepted 승인, Phase 12 보고서, AI 연동 확대,
새 Lab·머신러닝은 제외한다. 기존 CLI 및 Phase 4~10 정책·스키마는 변경하지 않았다.
