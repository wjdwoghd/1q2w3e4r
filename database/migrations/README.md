# migrations

데이터베이스 스키마 변경 이력을 관리한다.

테이블 추가, 컬럼 변경, 인덱스 변경 등 구조 변경 기록을 이곳에 둔다. 자동 생성 파일도 리뷰 가능한 단위로 커밋한다.

`0007_verifications.sql`은 Phase 8 DB에 한 번 적용한다. 기존 트랜잭션 밖에서 실행하며
Finding CHECK·상태 이력을 재구성하고 검증 테이블을 추가한다. 기존 행과 ID는 보존한다.
적용 후 `PRAGMA foreign_key_check` 결과가 비어 있는지 확인한다. 실패하면 ROLLBACK하고
`PRAGMA foreign_keys=ON`을 다시 설정한다. 신규 DB는 최신 `initialize_database()`를 사용한다.

새 DB의 검증 SQL은 `database/verification_schema.py`에 있다. 검증 제약을 바꿀 때는
마이그레이션 SQL도 같이 검토하고 신규·마이그레이션 DB 테스트를 실행한다.
