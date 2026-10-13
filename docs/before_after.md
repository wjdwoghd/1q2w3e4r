# Phase 10 Before / After 계약

Phase 10은 선택한 검증 시도의 증거를 읽어 전후 값을 구성한다. Finding 상태 전이,
검증 재판정, 과거 Snapshot 갱신을 수행하지 않는다. Phase 4 매칭, Phase 5 위험 규칙,
Phase 6 자산+CVE 식별, Phase 7 사실 검증, Phase 8 Before, Phase 9 판정은 그대로 사용한다.

## 데이터 흐름과 명시적 선택

```text
ComparisonService.compare_finding(asset_id, finding_id, remediation_id, verification_id)
→ SQLiteComparisonRepository.load(): 선택한 소속·관측·Recommendation·Before 대조
→ Phase 9 VerificationRepository.get(): 해당 시도 사본과 원래 판정 조회
→ compare_attempt(): 원본 사본의 SBOM 일치·After digest·출처·시간·범위 확인
→ 기존 core/sbom/diff.py + Finding 및 자산별 metric 구성
```

```python
from core.verification.comparison import ComparisonService
from database.repositories.comparison_repository import SQLiteComparisonRepository

service = ComparisonService(SQLiteComparisonRepository(connection))
comparison = service.compare_finding(
    asset_id=1, finding_id=1, remediation_id=1, verification_id=1,
)
asset_comparison = service.compare_asset(
    asset_id=1,
    selections=((1, 1, 1),),  # (finding_id, remediation_id, verification_id)
)
```

시도 ID는 필수다. 최신 Finding 관측, 최신 SBOM 또는 최신 검증 결과로 자동 교체하지
않는다. SQL은 Repository에만 있다. 소속 불일치는 `ComparisonSourceError` 또는
이해 가능한 `ValueError`로 거부한다. 없는 ID는 기존 Repository의 NotFound 예외다.

Before 버전·Risk는 시도에 복사된 Phase 8 Snapshot을 사용한다. Before CVSS·KEV는
해당 관측의 Recommendation **입력 사실 Snapshot**에서 저장된 SHA-256을 확인하고
읽는다. 저장소의 멱등 입력 계약을 재사용하며 손상된 digest는 거부한다. AI 개선 문장은 집계에
쓰지 않는다. Before 원본 SBOM은 시도에 복사된 문서와 발생 목록만 읽는다.
가변 Phase 4/SBOM 원본 행의 최신 내용을 읽어 보충하지 않는다.

After는 선택한 시도의 detached JSON만 읽는다. 각 재매칭 실행의 구성요소 ID,
PURL, OSV 상태·후보와 NVD/KEV 증거, 출처·참조·수집 시점을 확인한다. 하나의 발생에
여러 재매칭 실행이 있으면 최신 하나를 고르지 않고 전체 집계를 미확인으로 둔다.
After 수집 시점은 조치 적용 및 SBOM 수집 이후, After 기록 이전이어야 한다.

## 반환 형식

Finding 조회 결과는 `selection`, `finding`, `asset`, `verification`, `snapshots`,
`sbom_diff`, `basis`를 포함하는 JSON 직렬화 가능한 dict다. 원래 Before·원본 문서,
Recommendation 사실 입력, 적용 기록 및 After payload 사본도 반환한다.

각 metric은 다음 정보를 반환한다.

- `before` / `after`: `value`, `scope`, `provenance`, `unknown_reason`
- `delta`: 확인 가능한 숫자의 After − Before; 나머지는 `None`
- `comparable` / `comparison_reason`: 누락·범위 불일치에 대한 비교 가능 여부와 사유
- `basis`: 비교 단위와 집계 기준

`provenance`에는 시도·조치·관측·매칭 증거·구성요소·SBOM·Recommendation ID,
After digest, 분석 키, SBOM 출처·참조, OSV/NVD/KEV 출처·수집 시점과 Scanner 결과가
들어간다. Before 관측 기록 시점, Recommendation 기록 시점 및 시도 사본 저장 시점은
분리한다. Before 사본에는 원래 수집 시점이 없으므로 `collected_at=None`과 사유를
반환한다. 기록 시간을 수집 시간으로 대체하지 않는다. After Evidence의 PK는
`verification_id`이므로 `after_evidence_verification_id`로 표시한다.

## 집계 기준과 확인 가능한 범위

| 항목 | Finding 범위 | 자산 범위 |
| --- | --- | --- |
| 구성요소 수·버전 | Before의 버전 없는 PURL에 해당하는 패키지의 모든 발생 | 선택한 Before/After SBOM 전체 발생 |
| 취약 구성요소 수 | 선택한 CVE가 확인된 구성요소 발생 수 | 하나 이상의 CVE가 확인된 발생 수 |
| CVE 수 | 선택한 자산+CVE의 존재 1/0 | 전체 구성요소의 완전한 재매칭에서 고유 CVE 수 |
| Critical CVE 수 | 선택한 CVE의 CVSS ≥ 9.0 여부 | 고유 CVE의 CVSS ≥ 9.0 수; CVSS 누락·충돌은 미확인 |
| KEV 수 | 선택한 CVE의 확인된 KEV 등록 여부 | 고유 CVE의 KEV 등록 수; 같은 CVE의 자료 충돌은 미확인 |
| EOL 구성요소 수 | 검증된 EOL 자료가 없어 `None` | 검증된 EOL 자료가 없어 `None` |
| Priority별 Finding 수 | Before Snapshot의 내부 P1/P2/P3/P4; After는 `None` | 전체 Before/After 위험 Snapshot이 없어 `None` |
| Risk Score | 저장된 Before 점수; After는 `None` | 전체 자산 점수 정책·증거가 없어 `None` |
| Verification 상태 | 선택한 시도의 원래 In Progress/Passed/Failed와 판정 근거 | 선택한 시도들의 상태·규칙·근거 목록 |

Before 전체 취약점 분석은 시도 사본에 없다. 따라서 전체 Before CVE·Critical·KEV
수를 확정하지 않는다. Before 전체 SBOM이 단일 발생이고 그 발생이 선택한 취약
구성요소라면 취약 구성요소 수 1은 정확히 확인할 수 있다. 여러 발생이 있으면
선택하지 않은 발생의 분석을 추정하지 않고 해당 수를 `None`으로 둔다.

After 전체 분석에는 **모든 발생마다 정확히 하나의 완료된 재매칭**이 필요하다.
부분 재매칭, Error/Ambiguous/Unmatched, 모순 또는 출처·수집 시점 부족이면 전체
취약점 수는 `None`이다. 빈 SBOM에 특정 CVE의 Scanner 결과만 있으면 해당 Finding의
CVE 존재 여부만 확인할 수 있다. 자산 전체 CVE 수 0의 근거로 사용하지 않는다.
성공한 OSV `NO_MATCH`의 수 0은 해당 조회 범위의 결과이며 안전 인증이 아니다.

Scanner와 매칭이 모순되면 CVE 집계를 미확인으로 둔다. 기능 테스트만 실패한 경우
확인된 구성요소·매칭 값은 표시할 수 있지만 원래 Verification Failed는 유지한다.
After CVE가 사라져도 Risk Score 0이나 P4를 생성하지 않는다. 같은 CVE의 CVSS가
같은 심각도 구간 내에서 달라도 Critical 집계는 가능하나 구간이 충돌하면 `None`이다.
CVSS 기술적 심각도와 금융서비스 대응 우선순위는 별개다.

SBOM Diff는 버전 없는 PURL을 기준으로 추가·제거, 버전 집합 변화, 발생 수 변화를
반환한다. 중복 발생과 미식별 구성요소를 보존하며 어느 설치가 어느 설치로 바뀌었는지
추정하지 않는다. Finding/CVE 집계는 `(asset_id, cve_id)`를 중복 계산하지 않는다.

자산 조회는 명시적 선택을 정렬하고 완전히 같은 선택은 중복 제거한다. 여러 Finding을
선택해도 동일한 전체 SBOM·After payload의 구성요소 수를 반복해서 더하지 않는다.
Before SBOM 또는 After 분석 범위가 다른 시도, 같은 Finding의 서로 다른 시도는 개별
비교를 모두 반환하되 공동 집계값·변화량은 `None`과 `aggregation_reason`으로 둔다.
`selected_finding_priority_counts`는 명시적으로 선택한 Finding의 Before 우선순위
집계이며 자산 전체 Finding 수를 뜻하지 않는다. 증거 출처는 기여 시도별로 포함한다.

## 오프라인 검증과 남은 사항

```powershell
.\.venv\Scripts\python.exe -m unittest tests.unit.test_comparison tests.integration.test_comparison -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

Phase 10 신규 25개와 기존 138개를 합한 전체 163개가 통과했다. 정상 비교,
증거 누락·범위 불일치, 중복 발생·Finding·선택, 여러 Finding의 자산 집계, 소속 오류,
Failed 판정과 기능 실패, 반복 시도 명시 선택, 과거 원본 행 변경에 대한 사본 보존,
조회 무변경·반환값 분리, CVSS·버전·PURL 누락, 입력 digest 손상, 미래 수집 시점,
결정성을 오프라인으로 검증했다.

새 테이블·마이그레이션·Dependency는 없다. 전체 Before 분석 Snapshot, 검증된 After
Risk/Context와 EOL 자료의 수집·저장 연동은 남아 있다. 현재 없는 증거를 이번 비교
기능에서 소급 생성하지 않는다. Dashboard·API 화면 연결·보고서, 실제 Scanner 실행,
Risk Accepted 승인, 새 Lab 및 머신러닝은 포함하지 않는다. 실제 패치·Scanner·금융서비스
기능 테스트를 수행했다는 의미도 아니다.
