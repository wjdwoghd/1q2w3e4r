# 데이터베이스 설계

현재 Phase 1, 공통 SBOM 저장 지원 작업과 Phase 4 매칭 결과 저장은 Python 표준 라이브러리 `sqlite3`를 사용한다.
연결과 스키마 초기화는 `database/database.py`, SQL 접근은 `database/repositories/`에
한정한다. API와 `core/`는 SQL을 직접 실행하지 않는다.

```text
BusinessService 1 ── N Asset 1 ── N SBOM 1 ── N Component
Component 1 ── N VulnerabilityMatchRun 1 ── N VulnerabilityMatchEvidence
```

Asset은 운영/개발 환경, 인터넷 노출, 업무 중요도, 고객·신용정보 처리 여부, 패치 상태,
vendor와 owner를 저장한다. enum과 boolean은 core 검증뿐 아니라 DB CHECK 제약으로도
보호한다. 하나의 금융서비스 안에서 자산 이름은 중복될 수 없다.

SBOM은 자산, 원본 출처, CycloneDX 버전과 원본 문서를 보존한다. Component는 병합하지
않고 SBOM 내 발생 순서별 레코드로 저장하여 동일 패키지의 여러 설치 증거를 잃지 않는다.
현재 마이그레이션 도구와 운영 DB 제품은 아직 선정하지 않았다.

Phase 4의 `MatchResult`는 `vulnerability_match_runs`에 구성요소 발생 ID, 분석 키,
`MATCHED`·`NO_MATCH`·`UNMATCHED`·`AMBIGUOUS`·`ERROR` 상태, PURL, 근거, OSV 조회
식별자·출처·시점을 저장한다. `vulnerability_match_evidence`는 확인된 CVE별로 OSV
기록 ID·URL·조회 시점, NVD의 원본 CVE ID·출처·조회 시점·CVSS·CWE, CISA KEV
카탈로그 버전·발행 시점·조회 시점 및 해당 CVE 등록 항목을 저장한다. 검증에 사용한
전체 KEV 스냅샷은 분석 실행당 한 번 저장해 조회한 `MatchResult` 계약을 유지한다.
누락된 CVSS는 `None`, CWE는 빈 목록으로
유지하며, KEV 조회 오류는 `ERROR`로 저장한다. `NO_MATCH`는 성공한 OSV 조회에
결과가 없었다는 뜻이며 안전성 판정이 아니다.

한 분석 실행은 호출자가 지정하는 `analysis_key`로 식별한다. 같은 구성요소·키·내용의
재전달은 기존 실행을 반환하고, 같은 키의 다른 내용은 오류로 거부한다. 새 키는
결과가 같아도 재분석 이력으로 추가한다. CVE 증거 저장은 실행 기록과 한 트랜잭션으로
처리한다. 구성요소별·CVE별 이력 조회를 제공한다. 기존 DB에는
`database/migrations/0002_vulnerability_matches.sql`을 적용할 수 있다. 운영 DB
제품과 자동 마이그레이션 도구는 아직 선정하지 않았다.

## Phase 6 Finding

`0003_findings.sql`은 기존 테이블을 바꾸지 않고 `findings`,
`finding_observations`, `finding_status_history`를 추가한다. `findings`의
`UNIQUE(asset_id, cve_id)`가 관리 단위를 고정한다. 같은 CVE가 한 자산의 여러
구성요소에서 탐지되어도 Finding은 하나이며, 매칭 증거 행별 관측은 각각 남는다.
`finding_observations.match_evidence_id`는 고유 FK다. 관측은 매칭 실행 ID·분석 키·
구성요소 ID에 연결되어 OSV·NVD·KEV 원본 증거를 역추적할 수 있고, 당시의
`RiskResult` 및 `AssetContext`를 JSON 스냅샷으로 보존한다. 같은 매칭 증거의
재처리는 멱등이며 위험 결과나 Context가 달라지면 거부한다. 새 분석 키는 별도
매칭 실행·증거와 새 관측을 만든다. DB 트리거도 관측의 증거 CVE와 원본
구성요소 소속 자산이 Finding의 CVE·자산과 일치하는지 검사한다.

Finding 최초 생성 시 `finding_status_history`에 Open 이벤트를 한 번 기록한다.
Phase 8은 `recommendation_created`, `remediation_applied`를 DB CHECK와 Enum에
추가했다. Phase 9은 아래 검증 상태를 추가한다. 여러 CVE의 저장은 한 트랜잭션이며 중간
제약 오류 시 Finding·관측·상태 이력 모두 롤백한다.

## Phase 7.1 보안통제 참고용 매핑

`0004_finding_control_mappings.sql`은 기존 테이블 변경 없이 관측에 종속된
`finding_control_mappings`를 추가한다. `observation_id` FK와
`UNIQUE(observation_id, control_key)`가 관측별 중복을 막는다. `control_type`은
기술적·관리적 값만 허용하고 JSON·필수 문자열에는 CHECK 제약을 적용한다.
통제의 문서명·발행자·판본·발행일·식별자·출처 URL과 매핑 규칙·이유·관측 사실을
저장 시점의 스냅샷으로 남긴다. 재분석은 새 관측에 새 매핑을 추가하며 과거
매핑을 수정하지 않는다. 같은 관측·통제·내용의 재실행은 멱등이고 내용 충돌은
거부한다. 매핑 묶음 중 한 건이라도 실패하면 전체 저장을 롤백한다.
카탈로그 원본은 `core/compliance/standards/`의 검증된 JSON 파일이며,
별도 가변 통제 마스터 테이블은 두지 않는다.

## Phase 7.2 Recommendation

`0005_recommendations.sql`은 관측별 `recommendations`를 추가한다. 고유 관측 ID
FK가 중복 생성을 막고, 입력 SHA-256·모델명·구조화 입력·구조화 내용을 저장한다.
같은 관측의 입력이 같으면 기존 결과를 반환하며 내용이 다른 입력은 충돌로 거부한다.
새 분석 관측은 별도 행을 만들므로 과거 입력과 개선안이 보존된다. JSON 유효성,
필수 값과 FK는 DB에서도 검사한다. AI 출력 검증이나 API 실패 시에는 행을 쓰지 않는다.

## Phase 8 Remediation

`0006_remediations.sql`은 Finding 및 상태 이력의 CHECK를 좁게 확장하고 기존 Open
행과 ID를 보존한다. `remediations`는 Finding·Recommendation·관측 FK, 조치 키,
계획 내용·담당자·생성 시점 및 Before JSON을 저장한다. Before에는 당시 구성요소
ID·이름·버전·PURL, CVE, Risk 점수·Priority·근거·규칙 버전과 관측 출처가 있다.
`UNIQUE(recommendation_id, action_key)`가 중복 계획을 막고 트리거가 소속 관계 및
계획의 수정·삭제를 제한한다. 새 분석 관측은 별도 Recommendation과 조치로 남는다.

`remediation_applications`는 조치당 한 행으로 실제 수행 내용·담당자·시간대가 있는
수행 시점·증거 유형·참조·출처를 보존한다. 비어 있는 증거와 미지원 유형은 거부하고
적용 기록의 수정·삭제도 제한한다. 계획과 적용 기록, Finding 상태 및 상태 이력은
각각 한 트랜잭션으로 갱신된다. DB 전이 트리거는 계획 없이 `Recommendation Created`,
적용 기록 없이 `Remediation Applied`로 바꾸는 것을 거부한다. 이 증거는 수행 기록의
출처이지 취약점 제거 증명은 아니며 독립 재분석은 Phase 9 범위다.

## Phase 9 Verification

`0007_verifications.sql`은 SQLite CHECK 변경을 위해 `findings`와
`finding_status_history`만 재구성하고 기존 행·ID·소속·Snapshot을 보존한다.
Finding의 `UNIQUE(asset_id,cve_id)` 정책은 유지한다. 상태 이력에 nullable
`verification_id` FK를 추가하고 검증 전 상태는 기존처럼 중복을 막는다.
검증 상태는 `UNIQUE(verification_id,status)`로 시도별 In Progress와 Passed/Failed를
남겨 같은 Finding의 반복 검증을 허용한다. 이력의 수정·삭제를 차단한다.
FindingRepository의 초기 Open 저장은 변경된 고유 제약에도 멱등으로 동작한다.

```text
RemediationApplication 1 ── N Verification
Verification 1 ── 0..1 AfterEvidence 1 ── 0..1 VerificationResult
Verification 1 ── N FindingStatusHistory
```

`verifications`는 적용 기록 FK, Finding·자산 FK, 시도 키, Before·원본 SBOM·적용 기록
사본, 필수 기능 테스트 ID와 시작 시점을 보존한다. `(remediation_id,attempt_key)`는
고유하다. 적용·Recommendation·관측·Finding·자산의 소속, Before 일치, 적용 기록
사본의 일치 및 Finding당 진행 중인 시도 하나를 트리거로 제한한다.

`verification_after_evidence`는 After SBOM FK와 증거 JSON·SHA-256·기록 시점을 저장한다.
원본 문서·발생별 구성요소, 재매칭 실행과 원본 OSV/NVD/KEV 자료, Scanner·기능 테스트의
출처·참조·수집 시점을 분리된 사본으로 보존한다. FK와 트리거는 자산·SBOM·
재매칭 실행·구성요소·테스트 증거 소속을 확인한다. 누락되거나 판정에 부족한 증거도
보존할 수 있으며 JSON 유효성·소속 검사와 통과 조건 판정은 서로 다른 책임이다.

`verification_results`는 After Evidence FK, Passed/Failed, 규칙 버전, 이유,
SBOM Diff와 완료 시점을 저장한다. 세 테이블 모두 수정·삭제를 막는다.
검증 시작과 완료는 기록·Finding 전이·상태 이력을 한 트랜잭션으로 처리한다.
DB 전이는 최신 진행 시도의 결과 없이 Passed/Failed로 바꾸거나 적용 없이 검증을
시작하는 것을 거부한다. 실제 증거 내용의 결정적 판정은 `core/verification/`의 책임이다.

신규 DB는 `initialize_database()`를 사용한다. 이전 Finding 스키마가 있으면 초기화는
`DatabaseMigrationRequiredError`로 중단하며 암묵적으로 변경하지 않는다. Phase 8 DB는
기존 트랜잭션 밖에서 `0007_verifications.sql`을 한 번 적용하고 FK 검사를 확인한다.
SQL 적용 실패 시 ROLLBACK하고 `PRAGMA foreign_keys=ON`을 복구해야 한다.
운영 DB 자동 마이그레이션 도구와 Risk Accepted 승인 테이블은 아직 구현하지 않았다.

## Phase 10 Before / After 조회

`SQLiteComparisonRepository`는 명시적인 자산·Finding·Remediation·Verification ID의
소속을 확인하고 기존 관측의 Recommendation 입력 사실과 시도별 사본·판정을 읽는다.
새 테이블·마이그레이션은 없다. 가변 Phase 4/SBOM 원본의 최신 내용은 집계에 사용하지
않고 Before·After 사본을 재사용한다. 조회·집계는 상태 전이 또는 INSERT/UPDATE/DELETE를
수행하지 않는다. `verification_after_evidence`의 PK인 `verification_id`를 비교 결과의
증거 식별자로 반환한다. 전체 Before 취약점·After Risk·EOL 자료가 없는 한계를 유지하며
임의의 Snapshot을 추가하지 않는다. 자세한 범위는 [비교 계약](before_after.md)을 따른다.

## 공통 CLI 재개와 정확한 SBOM 복구

실행 체크포인트는 Git 제외 Run 디렉터리에 두며 DB 테이블·마이그레이션은 추가하지 않는다.
SBOM 저장 직후 프로세스가 중단된 경우 `SQLiteSBOMRepository.find_by_document()`가
명시적 자산 ID·출처·원본 문서가 모두 같은 행을 반환한다. 정확한 일치가 하나일 때만
재사용하고 여러 행이면 모호성 오류로 중단한다. 최신 행을 선택하거나 구성요소 발생을
병합하지 않는다. 매칭은 구성요소별 정확한 `analysis_key`, 조치는 action key,
Verification은 명시적 시도 ID·attempt key의 기존 멱등 계약으로 복구한다.

## Phase 11 읽기 전용 DB 세션

테이블·마이그레이션·식별 정책 변경은 없다. `open_dashboard_database()`는 서버 설정에
등록한 실행 DB를 `mode=ro`로 열고 `query_only=ON`, 요청별 읽기 트랜잭션을 사용한다.
없는 파일을 생성하거나 과거 스키마를 자동 마이그레이션하지 않는다. 필요한 테이블이
없으면 호환성 오류를 반환한다. 조회 종료 시 commit 없이 연결을 닫는다.
SQL은 기존 Repository 및 SBOM 목록을 보완하는 `SQLiteDashboardRepository`에만 있다.
API가 경로를 직접 입력받지 않고 DB 별칭만 선택하게 하며 DB 경로는 화면에서 확인한다.
현재 목록과 과거 시도의 불변 사본은 구분한다. 실행·데이터 흐름은 [Dashboard 문서](dashboard.md)를 따른다.
