# 데이터베이스 설계

현재 Phase 1과 공통 SBOM 저장 지원 작업은 Python 표준 라이브러리 `sqlite3`를 사용한다.
연결과 스키마 초기화는 `database/database.py`, SQL 접근은 `database/repositories/`에
한정한다. API와 `core/`는 SQL을 직접 실행하지 않는다.

```text
BusinessService 1 ── N Asset 1 ── N SBOM 1 ── N Component
```

Asset은 운영/개발 환경, 인터넷 노출, 업무 중요도, 고객·신용정보 처리 여부, 패치 상태,
vendor와 owner를 저장한다. enum과 boolean은 core 검증뿐 아니라 DB CHECK 제약으로도
보호한다. 하나의 금융서비스 안에서 자산 이름은 중복될 수 없다.

SBOM은 자산, 원본 출처, CycloneDX 버전과 원본 문서를 보존한다. Component는 병합하지
않고 SBOM 내 발생 순서별 레코드로 저장하여 동일 패키지의 여러 설치 증거를 잃지 않는다.
현재 마이그레이션 도구와 운영 DB 제품은 아직 선정하지 않았다.

Phase 4의 CVE 매칭 결과는 현재 메모리의 `MatchResult`로 반환한다. 취약점·매칭
근거의 영속 저장과 마이그레이션은 아직 구현하지 않았으며, 기존 스키마는 변경하지 않았다.
