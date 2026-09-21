# tests

테스트 코드를 관리한다.

단위 테스트는 `unit/`, 여러 계층을 함께 검증하는 테스트는 `integration/`에 둔다.

목표 단위 테스트 파일은 `test_sbom.py`, `test_vulnerability.py`, `test_risk.py`, `test_verification.py`이다. 각각 SBOM 처리, 취약점 정보 매칭, 규칙 기반 점수·우선순위, 개선 전후 검증을 다룬다.

현재 `test_matcher.py`와 `test_risk_engine.py`의 이름 변경은 아직 수행하지 않았다. 기존 `fixtures/`도 이번 README 수정에서는 삭제하지 않았다. 테스트 구현은 비어 있다.
