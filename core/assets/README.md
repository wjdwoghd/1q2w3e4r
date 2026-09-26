# assets

자산 정보와 비즈니스 컨텍스트 처리 로직을 관리한다.

서비스 중요도, 인터넷 노출 여부, 운영 환경, 개인정보 또는 금융정보 취급 여부처럼 위험도 계산에 필요한 자산 맥락을 다룬다.

Phase 1에서는 기존 `asset_service.py`에 금융서비스·자산 등록/조회를 구현했다. `context.py`는 등록된 맥락을 반환하며 Risk 계산이나 보안정보 추측은 하지 않는다. SQL은 database/repositories/assets.py로 분리한다.
