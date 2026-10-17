## 첫 Lab의 시나리오 입력

`scenarios/scenario_01_patch_delay.yaml`은 기존 Log4Shell Lab의 가상 금융 Context와
변경 대상·범위·필수 기능 테스트를 선언한다. production·외부 노출·overdue는 가상의
금융 시나리오 입력이며 실제 localhost Lab이 외부에 공개됐다는 뜻이 아니다.

일반 수동 가이드는 로컬 development Context를 사용한다. 시나리오 Context를 택하면
해당 모드와 입력을 따로 기록하고 자산 등록에 명시적으로 전달한다. CVSS·KEV·EOL·
Risk·Verification 판정은 시나리오에서 추측하지 않는다. YAML 자동 가져오기는 미구현이다.

런타임은 Java 애플리케이션 코드와 전체 Java 의존 JAR이며 JDK·컨테이너 OS는 별도
자산 범위다. Lab의 Syft 설정은 모든 발견 패키지를 보존하고 물리적 파일 메타데이터
레코드는 별도 해시 증거로 관리한다. Before/After에 같은 설정을 사용한다.

실행·준비 상태는 [Lab README](../labs/log4shell/README.md),
실 증거 수집은 [수동 가이드](lab_e2e_runbook.md)를 따른다. 현재 준비 검증은 빌드·
기능·SBOM·저장·Diff까지이며 실제 매칭→조치→검증 전체 실행은 별도로 확인해야 한다.
