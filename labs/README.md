# labs

취약 실습환경을 모아두는 영역이다.

각 실습은 분석 플랫폼과 분리하여 `vulnerable/`와 `patched/` 구조를 가진다. 취약 버전에서 SBOM 생성, 취약점 탐지, 위험도 산정, 개선안 도출을 수행하고, 패치 버전에서 재검증 흐름을 확인한다.

Log4Shell은 대표 의존성 분석, Struts2는 장기 미패치 관리, SnakeYAML은 간접 의존성 식별, EOL 구성요소는 수명주기 위험 비교를 위한 계획이다. EOL 분석은 MVP 이후 확장 범위로 구분한다.

실습환경은 격리된 로컬 환경에 구성하고, 실행 중 생성되는 로그와 산출물은 `data/` 또는 `reports/`로 분리한다. `data/`의 모든 파일이 Git에서 자동 제외되는 것은 아니므로 산출물의 추적 여부를 확인한다.

`log4shell/`에는 공통 Java 서비스·Before/After Maven 빌드·로컬 호스트 실행 도구와
Compose 정의가 준비돼 있다. 호스트 빌드·기능·SBOM 연동을 검증했고 Docker 기동과
실제 취약점 분석→조치→Verification 전체 연결은 남아 있다. 나머지 Lab은 자리 파일이다.

첫 번째 Lab은 `log4shell/`이다. 기본 명령어·선행 구현·Evidence 수집·판정·
반복 검증·종료는 [실행 가이드](../docs/lab_e2e_runbook.md), 완료 조건과 실행 기록은
[전체 점검표](../docs/lab_e2e_checklist.md)를 따른다. 문서 준비는 실제 Lab 검증 완료가 아니다.
