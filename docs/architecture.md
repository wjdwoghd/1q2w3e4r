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
