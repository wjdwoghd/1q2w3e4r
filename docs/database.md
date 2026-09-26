# Phase 1 데이터 계약

Python 3.11+ 표준 라이브러리 dataclass와 SQLite를 사용한다. 추가 패키지는 없다.

- BusinessService: service_id(PK), name
- Asset: asset_id(PK), name, business_service_id(FK), environment,
  internet_exposed, business_criticality, customer_information,
  credit_information, vendor, owner, patch_status
- 서비스 하나에 자산 여러 개를 연결한다. ID 중복은 덮어쓰지 않고 오류로 처리한다.
- environment: production / development / test / staging
- business_criticality: critical / high / medium / low
- patch_status: unknown(기본) / pending / applied / deferred
- 세 boolean 필드는 실제 bool만 허용한다. 문자열 "false"와 정수 0/1은 입력에서 거부한다.
- 필수 문자열은 빈 값과 앞뒤 공백을 거부한다. 필수값을 추측하거나 자동 보완하지 않는다.
- vendor / owner를 모르는 경우 사용자가 명시적으로 unknown을 입력할 수 있다.
- applied는 사용자가 등록한 조치 상태이며 Verification Passed를 의미하지 않는다.

database/migrations/001_asset_inventory.sql이 최초 스키마를 생성한다.
PRAGMA user_version=1로 버전을 관리하고 알 수 없는 버전은 거부한다.
같은 버전의 initialize 재호출은 데이터를 유지한다. 외래키는 연결마다 활성화한다.
DB 접근은 database/repositories/assets.py에 한정하며 파라미터 바인딩을 사용한다.

Phase 1은 등록/조회만 지원한다. 변경·삭제, 이력, SBOM/Finding 등 후속 엔티티는 미구현이다.
