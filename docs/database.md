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

상태는 현재 `open`만 DB CHECK와 Enum으로 허용한다. Finding 최초 생성 시
`finding_status_history`에 Open 이벤트를 한 번 기록한다. 이후 상태 전이는
Phase 7~9에서 증거 및 전이 규칙과 함께 설계한다. 따라서 Phase 6은 위험 감소나
검증 성공을 상태로 기록하지 않는다. 여러 CVE의 저장은 한 트랜잭션이며 중간
제약 오류 시 Finding·관측·상태 이력 모두 롤백한다.
