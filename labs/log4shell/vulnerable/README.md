# Before: Log4j 2.14.1

`pom.xml`은 `log4j-api`·`log4j-core` 2.14.1을 선언한다. 공통 Java 소스는 `../common/`에
있고 실제 분석 대상은 빌드한 `target/runtime/`이다. CVE-2021-44228의 영향을 조사하는
격리된 테스트용 구성이다. 공개 환경에 배포하지 않는다.

루트에서 `labs/log4shell/build.ps1 -Variant vulnerable`로 빌드한다. 기본 실행·SBOM 범위·
기능 계약·증거 보존·종료는 [Lab README](../README.md)를 따른다.
실제 버전은 JAR Manifest·SBOM으로 확인하고 CVE·CVSS·KEV는 Matcher로 조회한다.
Before 원본·발생·Finding 관측·조치 Snapshot을 보존한 뒤 After로 교체한다.
