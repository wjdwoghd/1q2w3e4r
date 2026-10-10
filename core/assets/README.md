# assets

자산 정보와 비즈니스 컨텍스트 처리 로직을 관리한다.

서비스 중요도, 인터넷 노출 여부, 운영 환경, 개인정보 또는 금융정보 취급 여부처럼 위험도 계산에 필요한 자산 맥락을 다룬다.

`context.py`는 허용된 환경, 중요도, 패치 상태와 엄격한 boolean 값을 검증한다.
`asset_service.py`는 등록·조회 유스케이스를 제공하며 SQLite 세부 구현은
`database/repositories/asset_repository.py`에 위임한다. API 계층은 이 서비스를 호출한다.

지원 값은 다음과 같다.

- Environment: `production`, `development`
- Business Criticality: `critical`, `high`, `medium`, `low`
- Patch Status: `current`, `pending`, `overdue`, `unknown`

`internet_exposed`, `customer_information`, `credit_information`은 문자열이나 정수가 아닌
JSON/Python boolean이어야 한다. 금융서비스 이름과 자산의 이름·vendor·owner는 필수다.
