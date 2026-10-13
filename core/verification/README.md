# verification

개선 조치 검증 로직을 관리한다.

`VerificationService`가 적용된 Remediation과 Before Snapshot을 검증 시도에 연결하고,
조치 후 SBOM·구성요소·Phase 4 재매칭 또는 Scanner·기능 테스트 결과를 별도 불변
After Evidence로 저장한다. 결정적 규칙으로 Passed/Failed와 이유를 기록한다.

`service.py`는 소속 검증과 흐름, `verifier.py`는 판정 조합, `sbom_verify.py`,
`vulnerability_verify.py`, `functional_verify.py`는 각 증거 검증을 담당한다.
`core/sbom/diff.py`는 발생별 SBOM 차이를 계산한다. SQL은 VerificationRepository에 있다.
`comparison.py`의 화면용 비교 집계는 Phase 10 범위로 아직 구현하지 않았다.

입력 계약, 상태·멱등성, 검증 규칙 및 남은 연동은 [검증 설계](../../docs/verification.md)를 참조한다.
