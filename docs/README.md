# docs

프로젝트 문서를 관리한다.

## 개발 및 협업 원칙

- [GitHub 협업 원칙](./github_collaboration.md): Issue, 브랜치, 한글 커밋, PR 리뷰 및 산출물 관리
- [코드 작성 원칙](./coding_conventions.md): 명명, 모듈 책임, 규칙 기반 분석, 오류 처리 및 검증

## 설계 문서

목표 문서는 `architecture.md`, `database.md`, `risk_model.md`, `verification.md`, `scenarios.md`이다. 각각 전체 구조, 데이터 관계, 규칙 기반 대응 우선순위, 개선 검증, 시연 흐름을 설명한다. `risk_model.md`의 모델은 위험평가 규칙을 의미한다.

기존 `api.md`는 새 핵심 문서 목록에서 제외되었지만 삭제하지 않았다. 설계 문서는 현재
구현과 검증 결과를 기록하며, 구현 변경이 영향을 주면 함께 수정한다.

## 실행·점검 문서

- [첫 Lab End-to-End 실행 가이드](./lab_e2e_runbook.md): 공통 CLI 실행·재개,
  실제 E2E 기록, PowerShell·도구 준비, 증거 수집 및 기존 core 수동 호출 참고
- [첫 Lab 전체 점검표](./lab_e2e_checklist.md): 단계별 확인·증거 ID·완료 조건 기록 양식
- [Before / After 계약](./before_after.md): 시도별 비교 범위·집계 기준·미확인 값
- [Verification 계약](./verification.md): Evidence·판정·이력과 남은 연동
