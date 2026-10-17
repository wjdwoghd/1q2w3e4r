# Phase 9 개선 효과 검증

Phase 9는 특정 Remediation의 적용 기록과 Phase 8의 불변 Before Snapshot에 검증을
연결한다. UI용 자산·Finding 집계, Dashboard 및 보고서는 포함하지 않는다.
Risk Score나 AI 문장은 판정 입력으로 사용하지 않는다.

## 데이터 흐름과 호출 계약

```text
Remediation + Recommendation + FindingObservation + Finding + Asset 소속 확인
→ VerificationService.start(remediation_id, asset_id, attempt_key, required_functional_tests)
→ 검증 시도 + Before/적용 기록 사본 + 원본 SBOM 사본 저장
→ 조치 후 SBOM 생성·Parser·Normalizer·SBOMRepository 저장 (기존 지원 기능)
→ Phase 4 Matcher·VulnerabilityRepository 저장 또는 외부 Scanner 결과 수집
→ VerificationService.record_after(verification_id, ...)
→ After Evidence 불변 저장
→ VerificationService.complete(verification_id)
→ 결정적 판정 + SBOM Diff + 규칙 버전 + 이유 + Finding 상태 이력
```

`VerificationService`는 Finding·Recommendation·Remediation·Vulnerability·Verification
Repository를 주입받는다. SQL은 Repository에 있으며 생성·매칭 도구를 서비스 안에서
중복 구현하지 않는다. `get()`과 `list_for_remediation()`으로 시도별 이력을 조회한다.

`start()`는 적용되지 않은 조치를 거부한다. Recommendation의 사실 입력, 관측의
매칭 증거·구성요소·CVE·위험 근거와 Before Snapshot을 대조하고 자산 소속도 확인한다.
검증에 필요한 기능 테스트 ID는 호출자가 **빈 목록 없이 명시적으로** 지정한다.
AI의 Verification Plan 문장으로 필수 테스트나 결과를 추측하지 않는다.

Phase 8 Before Snapshot은 수정하지 않는다. 검증 시작 시 그 사본과 적용 기록 사본을
고정하고, 해당 관측의 원본 SBOM 전체도 검증 시도에 복사한다. 원본 SBOM에 없는 수집
시점은 생성하지 않는다. 이 전체 사본은 Phase 8에서 새로 수집한 증거를 의미하지 않는다.

`record_after()`의 입력은 같은 자산의 **별도** SBOM ID, SBOM 수집 시점·참조,
해당 After SBOM 구성요소의 재매칭 실행 ID들, `ScannerEvidence` 및
`FunctionalEvidence`다. 출처·참조·시간대가 포함된 수집 시점을 보존한다.
Scanner는 기존 CVE와 자산 전체 범위(`scope='asset'`)에 대한 결과를 입력한다.
기능 테스트는 테스트 ID와 Passed/Failed/Error/Skipped 결과를 입력한다.
각 결과는 자산 ID 및 After SBOM ID로 동일한 관측 대상에 연결된다.

After Evidence에는 원본 SBOM, 발생별 구성요소, Phase 4의 OSV/NVD/KEV 재매칭
자료 전체, Scanner 및 기능 테스트 결과의 사본이 들어간다. SHA-256과 DB 기록
시점도 별도로 보존한다. 이후 원본 데이터 변경이나 조회 결과의 메모리 수정으로
저장된 사본과 과거 판정이 바뀌지 않는다.

## 결정 규칙: verification-1.0

아래 조건을 모두 만족해야 Verification Passed다.

1. After SBOM 출처·참조·수집 시점이 있고 원본 문서와 저장된 구성요소가 일치한다.
   정규화 후 식별자 또는 버전이 불명확한 구성요소가 있으면 통과시키지 않는다.
2. Before의 버전 없는 PURL 식별자에 해당하는 패키지가 제거됐거나, 남아 있는 모든
   발생의 버전이 Before와 다르다. 동일 취약 버전이 다른 발생에 남으면 실패한다.
   버전 비교는 변경 확인이며 업그레이드 순서 또는 안전한 버전의 추측이 아니다.
3. After SBOM **전체 구성요소**의 완료된 Phase 4 재매칭에서 기존 CVE가 탐지되지
   않았거나, 자산 전체 재검사에서 해당 CVE가 Not Detected다. 빈 SBOM에는 독립적인
   자산 전체 재검사 결과가 필요하다. `NO_MATCH`는 OSV 조회 결과이며 안전 인증이 아니다.
4. 제공된 재매칭·Scanner 중 기존 CVE 탐지, Error, Ambiguous, Unmatched, Inconclusive,
   출처 누락 또는 서로 모순되는 결과가 없다. 한쪽의 미탐지로 다른 쪽의 탐지를 무시하지 않는다.
5. 지정된 모든 기능 테스트의 Passed 증거가 있고 제공된 실패·오류·Skipped 결과가 없다.
6. 증거 수집 시점은 적용 이후이며 After SBOM 이후의 테스트·조회여야 한다.
   시간대 없는 시점, 증거 저장 시점보다 미래인 시점도 실패다.

구조적인 소속 오류·미지원 입력은 저장 전에 이해 가능한 예외로 거부한다.
누락·오류·불일치 등 판정용 증거 부족은 After Evidence에 보존하고 Failed 이유를 남긴다.
아무 증거도 없으면 `record_after(verification_id, asset_id=...)`로 빈 수집 결과를 기록한
후 `complete()`를 호출한다. After 기록 없이 완료를 호출하면 예외이며 In Progress가 유지된다.

`core/sbom/diff.py`는 버전을 제외한 PURL(생태계·namespace·이름·qualifier·subpath)을
기준으로 추가·제거 패키지, 버전 집합 변경, 발생 수 변경 및 미식별 구성요소를 반환한다.
같은 패키지의 중복 발생을 보존하고 어느 설치가 어느 설치로 바뀌었는지는 추측하지 않는다.
Diff는 검증 판정에 보존하는 근거이며 Phase 10은 이 함수를 재사용하여 UI와 무관한
구조화 비교를 제공한다. 화면 연결은 Phase 11 범위다.

## 상태·멱등성·반복 검증

```text
Remediation Applied → Verification In Progress → Verification Passed / Failed
Verification Passed / Failed → 새 Verification In Progress → 새 Passed / Failed
```

Finding당 진행 중인 시도는 하나다. 같은 Remediation·attempt_key와 요구사항의 재실행은
같은 시도를 반환한다. 같은 시도의 동일 After Evidence와 완료 재호출도 멱등이다.
이미 기록된 증거와 다른 내용을 보내면 충돌로 거부하며 새 attempt_key가 필요하다.
새 조치는 별도 Phase 8 계획·적용 기록으로 만들고 그 Remediation에 새 검증을 연결한다.
재분석으로 새 관측·Recommendation이 생기면 새 Before Snapshot을 가진 조치를 사용할 수 있다.

시도, After Evidence, 판정 및 상태 이력은 수정·삭제할 수 없다. 규칙 버전과 판단
이유는 판정 시점 값으로 남는다. 반복 Passed/Failed는 시도 ID가 달라 별도로 기록되며
기존 Open·Recommendation Created·Remediation Applied 이벤트와 ID를 보존한다.
시작 및 완료 시 Finding 갱신·상태 이력 저장이 실패하면 해당 트랜잭션 전체를 롤백한다.

Risk Accepted는 이번 판정 상태에 추가하지 않았다. 위험 수용은 Passed의 대체 결과가
아니며, 승인 주체·사유·시점을 검증하는 별도 절차가 구현되기 전에는 사용할 수 없다.

## 오프라인 검증과 남은 연동

```powershell
python -m unittest tests.unit.test_verification tests.integration.test_verification -v
python -m unittest discover -s tests -v
```

테스트는 합성 SBOM과 Stub OSV/NVD/KEV, 기능 테스트·Scanner 결과로 통과·실패,
증거 누락·모순·수집 시점, 전체 구성요소 범위, 소속, 상태, 멱등성, 반복·추가 조치·
새 관측의 Before 보존, DB 제약, 롤백 및 Phase 8→9 마이그레이션을 검증한다.
실제 패치·운영 Scanner 실행이나 금융서비스 기능 테스트를 수행한 증거는 아니다.
이번 작업에서 전체 오프라인 테스트 138개(기존 111개 + Phase 9 신규 27개)가 통과했다.

실제 Scanner, 운영 서비스용 기능 테스트 어댑터, API 연결과
승인 기반 위험 수용은 후속 작업이다. 첫 Lab 연결은 아래 2026-10-17 기록을 따른다.
외부 결과 입력의 진위를 확보하는 책임은
수집 도구/호출자에 있으며 출처 문자열만으로 진위를 인증하지 않는다.
기존 DB에는 `0007_verifications.sql`이 필요하고 새 DB는 최신 스키마로 초기화한다.

## Phase 10 읽기 전용 비교

`ComparisonService`는 명시적인 자산·Finding·Remediation·Verification ID를 받아
해당 시도의 사본과 원래 판정을 조회한다. 기존 Snapshot과 Finding 상태·검증 규칙·
이력을 변경하지 않는다. 전체 After 재매칭과 특정 CVE Scanner의 범위를 구분하며,
After Risk·EOL 또는 전체 Before 분석이 없으면 미확인 값과 사유를 반환한다.
반복 검증과 Failed도 시도별로 조회할 수 있다. 집계 기준·출처·수집 시점·증거 ID와
호출 계약은 [Before / After 문서](before_after.md)를 따른다.

## 2026-10-17 실제 호스트 Lab 검증 및 공통 CLI

수동 Run `lab-20261017T081606764Z`에서 자산 1, Finding 2, Remediation 1,
Verification 1, `CVE-2021-44228`을 명시적으로 선택했다. 실제 Syft SBOM의 Log4j
API/Core 각 발생은 2.14.1 → 2.25.5로 바뀌었다. Before는 실제 공개 조회에서 고유 CVE
8개와 KEV CVE 2개를 저장했고 선택한 Finding의 Risk는 60/P2였다. 두 After 발생은
각각 OSV `NO_MATCH`, 실제 health·합성 업무 HTTP 검사는 Passed였다.
기존 `verification-1.0`은 이 시도를 Passed로 판정했다. 다른 Finding 7개의 Open 상태는
자동으로 닫지 않았다. 판정·After digest·Before 원본 보존·동일 시도 비교를 읽기 전용으로
재조회했고 이후 전체 오프라인 테스트 170개가 통과했다.

공통 CLI로 별도 Run `e2e-cli-repro-20261017T085443243279Z`, 새 DB와 포트 54417에서
동일 경로를 다시 수행했다. 명시적으로 선택한 자산 1·Finding 2·조치 1·시도 1이 Passed였고,
같은 `after` 명령 재실행은 재조회·재판정 없이 저장된 증거를 재사용했다. 비교 조회 결과도
같았다. CLI 작업 후 Lab은 종료했다. 원본 수동 Run의 DB·증거는 변경하지 않았다.

두 실행 모두 Recommendation은 `local-plan-demo`다. 실제 AI 요청·별도 Scanner 실행,
검증된 After Risk/Context·EOL, Docker 기동은 확인하지 않았다. Java 패키지 2개 범위의
OSV 조회 결과를 OS·JDK·서비스 전체의 안전 판정으로 확대하지 않는다. 비교 시도에
전체 Before 취약점 분석 사본은 없으므로 자산 전체 증감은 여전히 `None`이다.

`scripts.e2e`의 `start`는 빈 목록 없는 필수 테스트 ID와 attempt key를 받고,
`after`·`compare`는 자산·조치·검증 ID를 명시적으로 받는다. 수집 중 중단되면 같은
명령으로 재개하되 저장된 Error/Failed를 새 성공 결과로 바꾸지 않는다. 새 수집은
새 attempt key로 시작한다. 진행 중 비교는 별도 preview에 보존한다.
명령과 종료 코드는 [실행 가이드](lab_e2e_runbook.md)를 따른다.

소유 서비스의 수집 전후 대조를 포함한 최종 CLI도 별도 Run
`e2e-cli-final-20261017T090107570535Z`·포트 49274에서 Passed와 동일 시도 반복·비교
일치를 확인했다. 최종 전체 오프라인 테스트는 192개(기존 170 + CLI 신규 22) 통과다.
새 테스트는 DB 저장/판정 직후 중단 복구, Failed 보존·새 시도 선택, 중복 발생·Finding,
원본 변경 거부, 비교 무변경, 잠금 해제 및 Windows 기동 후 재개를 포함한다.
