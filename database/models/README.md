# models

데이터베이스 모델 객체를 관리한다.

확정한 목표 구조는 다음과 같다. 이 디렉터리는 머신러닝 모델이 아닌 데이터베이스 엔티티를 정의한다.

| 파일 | 엔티티 |
| --- | --- |
| `business_service.py` | 금융서비스 |
| `asset.py` | 자산과 운영 맥락 |
| `sbom.py` | 자산별 소프트웨어 구성정보 |
| `component.py` | 구성요소와 버전 |
| `vulnerability.py` | 취약점 |
| `finding.py` | 자산에 연결된 발견사항 |
| `recommendation.py` | 개선 권고 |
| `remediation.py` | 수행한 개선 조치 |
| `verification.py` | 조치 후 검증 결과 |

Phase 1에서 `business_service.py`, `asset.py`와 공통 입력 검증을 구현했다. 나머지 엔티티는 후속 단계이다.
