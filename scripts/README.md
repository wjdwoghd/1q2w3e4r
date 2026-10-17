# scripts

개발과 분석 자동화를 위한 실행 스크립트를 관리한다.

SBOM 생성, SBOM 가져오기, CVE/KEV 동기화, 위험도 계산, 개선 검증처럼 CLI로 반복 실행할 작업을 둔다.

## 현재 실행 상태

2026-10-14 기준 `generate_sbom.py`, `import_sbom.py`, `sync_cve.py`, `sync_kev.py`,
`calculate_risk.py`, `verify_remediation.py`는 0바이트의 자리 파일이다. `--help`나
가상의 인자를 붙여 호출한 종료 코드 0은 기능 성공을 뜻하지 않는다.
관련 core·Repository는 별도로 구현돼 있다.

`verify_phase4_live.py`는 저장소 루트에서 다음처럼 실행할 수 있다.

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_phase4_live
```

이 명령은 fixture와 공개 OSV/NVD/CISA KEV 조회를 사용하고 메모리 DB에만 저장한다.
실제 Lab의 설치·조치·검증을 실행하지 않는다. 종료 코드뿐 아니라 status·CVE·CVSS·KEV도
확인한다. 이번 문서 작업에서는 실제 외부 조회를 실행하지 않았다.

첫 Lab의 준비·명령·서비스 호출 예제는 [End-to-End 가이드](../docs/lab_e2e_runbook.md)를 따른다.
실행 CLI를 추가할 때는 해당 core 함수를 호출하고 분석 규칙을 중복 구현하지 않는다.
