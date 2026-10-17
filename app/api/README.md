# api

Flask API 엔드포인트를 관리한다.

자산, 스캔, 탐지 결과, 조치, 보고서 관련 라우트를 기능별 파일로 분리한다. SBOM 분석, 규칙 기반 대응 우선순위 계산, AI 컨설팅, 개선 검증은 `core/`에 위임하고 데이터 접근은 `database/`에서 처리한다.

Phase 11 조회 MVP는 `dashboard.py`의 GET API로 구현했다. `python -m app.main`으로
실행한다. `assets.py`의 기존 함수형 진입점과 다른 자리 파일은 보존하며 쓰기 API로
노출하지 않는다. 자산·Finding·조치·검증 ID를 입력 검증한 뒤 읽기 core facade를 호출한다.
경로·설정·오류 코드는 [Dashboard 가이드](../../docs/dashboard.md)를 따른다.
