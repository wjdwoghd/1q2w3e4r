# scripts

개발과 분석 자동화를 위한 실행 스크립트를 관리한다.

SBOM 생성, SBOM 가져오기, CVE/KEV 동기화, 위험도 계산, 개선 검증처럼 CLI로 반복 실행할 작업을 둔다.

## 현재 실행 상태

2026-10-17부터 공통 실행 진입점은 `python -m scripts.e2e`다. `--help`에서
init/before/plan/lab-switch/apply/start/after/compare/status 인자를 확인할 수 있다.
기존 개별 자리 파일이 자동 구현된 것은 아니다. 전체 실행 명령은
[첫 Lab 가이드](../docs/lab_e2e_runbook.md)의 공통 CLI 절을 따른다.

각 명령은 `--run-dir`, `--db`, `--asset-id`로 같은 실행과 자산을 명시한다.
`init`만 새 자산의 `--asset-context` JSON·서비스 이름 또는 기존 자산 ID를 받는다.
`plan`은 match run ID·CVE·action key·Recommendation 모드를 선택한다.
`apply`는 실제 적용 증거 JSON을 받아 기존 core에 저장하며, `lab-switch`는 기존
Log4Shell 호스트에 한정해 실제 교체를 수행하고 적용 로그를 기록한다.
`start`는 조치 ID·attempt key·필수 테스트 ID를, `after`·`compare`는 조치·검증 ID를 받는다.

Run의 체크포인트는 원자적으로 갱신하지만 증거·판정은 덮어쓰지 않는다. 중단 후 같은
인자의 같은 명령으로 재개한다. 저장된 외부 조회 Error나 Verification Failed를
재조회하여 성공으로 바꾸지 않으며 새 수집에는 새 시도가 필요하다.
`after`는 Passed=0, Failed=1, 입력 충돌·실행 오류=2를 반환한다. `compare`의 종료 0은
조회 성공이며 반환된 판정이 Passed라는 뜻은 아니다. `status`는 시도를 자동 선택하지 않는다.
생성된 Run·DB·로그·SBOM은 `data/output/` 등 Git 제외 경로에 보존한다.

2026-10-14 기준 `generate_sbom.py`, `import_sbom.py`, `sync_cve.py`, `sync_kev.py`,
`calculate_risk.py`, `verify_remediation.py`는 0바이트의 자리 파일이다. `--help`나
가상의 인자를 붙여 호출한 종료 코드 0은 기능 성공을 뜻하지 않는다.
관련 core·Repository는 별도로 구현돼 있다. 현재는 위 공통 CLI로 호출한다.

`verify_phase4_live.py`는 저장소 루트에서 다음처럼 실행할 수 있다.

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_phase4_live
```

이 명령은 fixture와 공개 OSV/NVD/CISA KEV 조회를 사용하고 메모리 DB에만 저장한다.
실제 Lab의 설치·조치·검증을 실행하지 않는다. 종료 코드뿐 아니라 status·CVE·CVSS·KEV도
확인한다. 이 fixture CLI는 실제 Lab E2E 증거를 대체하지 않는다.

첫 Lab의 준비·명령·서비스 호출 예제는 [End-to-End 가이드](../docs/lab_e2e_runbook.md)를 따른다.
실행 CLI를 추가할 때는 해당 core 함수를 호출하고 분석 규칙을 중복 구현하지 않는다.
