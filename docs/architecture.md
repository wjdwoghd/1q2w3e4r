# SBOM 파서 아키텍처

AGENTS.md의 디렉터리 책임을 따른다.

호출자 → core/sbom/parser.py → ParsedSBOM / ParsedComponent

파서는 CycloneDX JSON의 구성요소와 의존성 기록을 추출한다. 서버, DB, 외부 API에
의존하지 않는다. 입력 검증 실패는 SBOMParsingError로 전달하며 화면/API 계층이
사용자 응답으로 변환한다. 로그에는 처리한 구성요소 수만 기록한다.

Phase 2에서는 생성 도구 실행, DB 저장, 정규화, 취약점 매칭을 구현하지 않는다.
후속 정규화는 core/sbom/normalizer.py, 저장은 database 계층에서 담당한다.

지원 형식, 데이터 계약, 누락·중복 처리 및 테스트 명령은
[SBOM Parser 문서](../core/sbom/README.md)를 참조한다.
