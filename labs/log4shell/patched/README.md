# After: Log4j 2.25.5

`pom.xml`은 `log4j-api`·`log4j-core` 2.25.5를 선언하고 Before와 같은 `../common/`
Java 소스·건강·합성 업무 계약을 사용한다. 실제 분석 대상은 `target/runtime/`이다.
이름 `patched`만으로 모든 CVE가 제거됐거나 Verification Passed라고 판단하지 않는다.

루트에서 `labs/log4shell/build.ps1 -Variant patched`로 빌드한다. 기동·교체·SBOM 범위·
독립 증거·종료는 [Lab README](../README.md)를 따른다. Before를 덮어쓰지 않고 별도
SBOM·매칭 실행·실제 기능 결과를 수집해 기존 Verification 규칙으로 판정한다.
