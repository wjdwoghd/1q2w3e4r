# SBOM 파서 아키텍처

AGENTS.md의 디렉터리 책임을 따른다.

호출자 → core/sbom/parser.py → ParsedSBOM / ParsedComponent

파서는 CycloneDX JSON의 구성요소와 의존성 기록을 추출한다. 서버, DB, 외부 API에
의존하지 않는다. 입력 검증 실패는 SBOMParsingError로 전달하며 화면/API 계층이
사용자 응답으로 변환한다. 로그에는 처리한 구성요소 수만 기록한다.

Phase 2에서는 생성 도구 실행, DB 저장, 정규화, 취약점 매칭을 구현하지 않는다.
Phase 3 정규화는 core/sbom/normalizer.py에서 담당한다. 생성 도구 실행과
SBOM·Component 저장은 ROADMAP.md의 공통 지원 작업이며 저장은 database 계층을 거친다.
Phase 번호와 범위는 AGENTS.md §24를 기준으로 ROADMAP.md와 함께 유지한다.

Phase 4는 `NormalizedComponent.package_key`가 제공하는 충돌 없는 버전 PURL만
OSV 조회에 사용한다. OSV가 반환한 CVE 식별자를 NVD에서 검증하고 CVSS·CWE를 읽으며,
CISA KEV 카탈로그의 전체 스냅샷으로 등록 여부를 확인한다. 조회 실패와 미등록은
서로 다른 상태다. CPE를 PURL에서 추측해 변환하지 않는다. 매칭은 계속
`core/vulnerability/`에서 수행하고, `database/repositories/vulnerability_repository.py`가
구성요소 발생별 실행·CVE 증거를 저장하고 조회한다. 같은 분석 키는 동일 내용에
한해 멱등이며 새 키는 재분석 이력이다. 격리된 Log4j Core 2.14.1 로컬 SBOM
샘플에서 실제 OSV → NVD → CISA KEV → 메모리 DB 저장·조회 경로를 확인했다.
Syft 1.54.1의 격리 샘플 생성·저장 경로도 검증했으며 첫 Lab 연동은 후속 작업이다.

지원 형식, 데이터 계약, 누락·중복 처리 및 테스트 명령은
[SBOM Parser 문서](../core/sbom/README.md)를 참조한다.

Phase 6은 `core/findings/service.py`가 저장된 Phase 4 매칭 실행을 읽고 자산과
구성요소 소속 관계를 확인한 다음, Phase 5 위험 엔진으로 CVE별 점수를 계산한다.
`database/repositories/finding_repository.py`가 Finding, 분석 관측, 초기 상태 이력을
한 트랜잭션으로 저장한다. API나 Dashboard 연결은 Phase 11 범위다.

Phase 7.1은 `core/compliance/controls.py`의 출처가 확인된 정적 카탈로그와
`mapper.py`의 결정적 규칙을 사용한다. `ControlMappingService`는 저장된 Finding의
각 관측을 읽어 매핑하고, `SQLiteControlMappingRepository`는 관측 소속과 원본
증거 식별자를 확인한 뒤 한 트랜잭션으로 보존한다. 조회 결과에는 관측 ID,
통제 문서 스냅샷, 기술적·관리적 유형, 적용 규칙, 관측 사실과 이유가 포함된다.
이는 관련 통제의 참고용 연결이며 적용 대상 판정이나 공식 준수 판정이 아니다.

Phase 7.2는 `RecommendationService`가 관측 ID를 받아 저장된 Finding, 매칭 실행,
구성요소와 해당 관측의 통제 매핑을 검증한다. `analyzer.py`는 구조화 입력을 만들고
`openai_client.py`는 환경 설정의 키·모델·timeout으로 Responses API의 엄격한
Structured Outputs를 요청한다. 서비스는 AI가 허용된 사실 비주장 문장 중에서 고른
개선 조치·Verification Plan 초안을 검사한 후 사실 영역을 코드에서 조립한다. SQL과 멱등 저장은
`SQLiteRecommendationRepository`가 담당한다. 모델은 위험 점수·우선순위와
검증 결과를 계산하거나 갱신하지 않는다. 검증·보고서 기능은 후속 단계다.

Phase 8은 `RemediationService`가 Recommendation ID, 관측 ID, Finding ID의 소속과
저장된 분석 사실을 대조한다. `SQLiteRemediationRepository`는 계획 및 Before Snapshot을
원자적으로 저장하며, 별도의 적용 기록에 실제 수행 내용·담당자·시점·변경 증거 유형·
참조·출처를 추가한다. 동일 Recommendation의 조치 키는 멱등이고 계획·적용 기록은
수정하거나 삭제할 수 없다. Finding은 계획 저장 때 `Recommendation Created`, 수행
증거 저장 때 `Remediation Applied`로 전이하며 Open 이력은 남는다. 적용 기록은
개선 효과 검증을 의미하지 않는다. 조치 후 재분석·After Snapshot·Verification은
Phase 9 이후다.
