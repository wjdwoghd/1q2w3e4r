# Phase 1 구현 구조

호출자 → core/assets/asset_service.py → database/repositories/assets.py → SQLite

- database/models/: 불변 데이터 객체와 입력 검증, 공통 Enum.
- core/assets/asset_service.py: 금융서비스/자산 등록·조회, 연결 관계 확인.
- core/assets/context.py: 등록된 값을 JSON 직렬화 가능한 Context로 반환.
- database/database.py: 연결·트랜잭션·스키마 초기화.
- app/config/settings.py: DATABASE_URL 설정 조회. UI/API 및 분석 로직은 아직 없다.

Context는 자산의 전체 필드와 business_service_name을 포함한다.
CVE, Risk Priority, 패치 검증 결과는 생성하지 않는다.
미등록 대상은 InventoryNotFoundError, 중복/관계 충돌은 InventoryConflictError,
저장소 실패는 StorageError, 잘못된 입력은 ValueError로 구분한다.
필수 생성자 인수 누락은 TypeError이다. 기록 로그에 자산 내용이나 접속정보를 넣지 않는다.

## 실행 예시

저장소 루트에서 Python 3.11 이상을 사용한다. pip 설치는 필요 없다.
로컬 .env에 DATABASE_URL=sqlite:///data/assets/inventory.db를 설정한다.
기존 .env를 덮어쓰지 않는다. 상대 DB 경로는 실행 디렉터리 기준이며 부모 폴더는 존재해야 한다.

설정 우선순위는 프로세스 환경변수 → .env이다.
.env는 DATABASE_URL=값 또는 따옴표로 감싼 값만 읽는다.
변수 치환, export 접두사, 값 뒤의 인라인 주석은 지원하지 않는다.
이 최소 설정 리더는 범용 dotenv 파서가 아니다.

다음 코드를 루트에서 Python으로 실행하면 샘플을 등록하고 조회할 수 있다.
샘플은 가상 데이터이며 운영 상태나 스캔 증거가 아니다. 새 DB에서 한 번 실행한다.

```python
import json
from pathlib import Path
from app.config.settings import get_database_url
from core.assets.asset_service import AssetService
from database.database import Database
from database.models.asset import Asset
from database.models.business_service import BusinessService
from database.repositories.assets import AssetRepository

database = Database(get_database_url())
database.initialize()
service = AssetService(AssetRepository(database))
sample = json.loads(Path("data/assets/sample_assets.json").read_text(encoding="utf-8"))
for item in sample["business_services"]:
    service.register_business_service(BusinessService(**item))
for item in sample["assets"]:
    service.register_asset(Asset(**item))
context = service.get_asset_context("AST-001")
```

## 테스트

```text
python -m unittest discover -s tests -v
```

임시 DB를 사용하여 모델 검증, 저장 후 재연결, 중복 방지, 외래키,
서비스별 조회, Context, 마이그레이션 재실행, 설정, 오류와 샘플을 검증한다.
전체 SBOM 파이프라인과 UI는 후속 단계이다.
