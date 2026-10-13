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
추가했다. Verification 상태는 아직 허용하지 않는다. 여러 CVE의 저장은 한 트랜잭션이며 중간
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
