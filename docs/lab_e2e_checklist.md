# 첫 Lab End-to-End 전체 점검표

실행 방법·명령·core 호출 예제는 [실행 가이드](lab_e2e_runbook.md)를 따른다.
이 점검표는 실행자가 채우는 양식이다. 빈 항목은 미확인으로 유지한다.
문서 작성이나 오프라인 테스트 통과만으로 실 Lab 항목에 완료 표시하지 않는다.
각 항목에는 결과와 증거 파일·ID·실제 시점을 연결한다.

## 1. 실행 기록

2026-10-14 준비 검증에서는 첫 Lab의 두 호스트 빌드·실제 JAR 버전·HTTP 기능·
생성/파싱/정규화/저장/Diff와 전체 테스트 170개를 확인했다. 아래 점검표는 이후
각 실행의 담당자가 새 증거로 채운다. Docker 기동·실 API·플랫폼의 전체 조치/검증
실 시도는 자동으로 완료 처리하지 않는다.

| 기록 항목 | 실행자가 입력할 값 |
| --- | --- |
| Run ID / 담당자 / 검토자 | |
| 실행 시작·종료 시점 / 시간대 | |
| 브랜치 / 기준 커밋 / 기존 변경 | |
| 실행 모드 | 실 Lab / 오프라인; Recommendation은 실 AI / 로컬 연결 점검 구분 |
| OS / Python / packageurl / Syft / JDK / Maven / Docker / Compose 버전 | |
| Docker context / 이미지 ID·digest / 분석 대상 범위 | |
| BusinessService ID / Asset ID | |
| Before·After SBOM ID / 파일 / SHA-256 / 수집 시점 | |
| Component 발생 ID / PURL / Before·After 실제 버전 | |
| 매칭 실행 ID / analysis_key / CVE 증거 ID / 관측 ID | |
| Finding ID / 실제 CVE / CVSS / KEV / Risk 규칙·점수·Priority | |
| Recommendation ID / 모델·로컬 generator / 실제 호출 여부 | |
| Remediation ID / action_key / 적용 기록 참조 / 적용 시점 | |
| Verification ID / attempt_key / 필수 기능 테스트 ID | |
| After Evidence 시도 ID / digest / 기록 시점 | |
| 원래 판정 / 규칙 버전 / 이유 / 완료 시점 | |
| 비교 파일 / 비교 범위 / None·비교 불가 사유 | |
| 전체 테스트 명령 / 개수 / 종료 코드 / 결과 로그 | |
| 남은 사항 / 다음 담당자 / 추가 자료 | |

## 2. 시작 전 기본 점검

- [ ] 저장소 루트·현재 브랜치·기준 커밋을 기록했다.
- [ ] 작업 트리 변경을 확인하고 기존 변경을 보존했다.
- [ ] `git diff --check` 결과를 확인했다.
- [ ] 실행 Run ID·대상 자산·범위·담당자·종료/롤백 방법을 정했다.
- [ ] 실제 서비스·개인정보 없이 격리된 로컬 대상만 사용한다.
- [ ] 기존 `labs/log4shell/`부터 진행하고 추가 Lab을 병행하지 않는다.
- [ ] 실 실행·fixture/Stub·단순 도구 점검의 결과를 구분해서 기록한다.

## 3. 도구·설정·산출물

- [ ] `.venv` Python 경로·버전과 pip 경로가 같은 환경인지 확인했다.
- [ ] 기존 `requirements.txt`로 해결하고 불필요한 Dependency를 추가하지 않았다.
- [ ] `pip check`와 전체 오프라인 테스트 결과를 기록했다.
- [ ] Syft 실행 경로·버전과 CycloneDX JSON 1.6 출력 가능 여부를 확인했다.
- [ ] JDK·Maven 또는 컨테이너 빌드 도구가 선택한 Lab과 호환된다.
- [ ] Docker Client·Server와 Compose를 확인했다. CLI 설치만으로 데몬 정상 판정을 하지 않았다.
- [ ] Docker context가 로컬이고 외부 서버에 Lab을 실행하지 않는다.
- [ ] OSV·NVD·CISA KEV 연결·응답·Rate Limit·재시도 실패를 구분한다.
- [ ] 실제 적용되지 않는 `.env` 설정을 적용됐다고 표시하지 않았다.
- [ ] 실 AI 설정은 Python 시작 전에 전달했다. dotenv 자동 로딩을 가정하지 않았다.
- [ ] API Key·Token·Password·환경변수 전체를 로그·명령 이력·Git에 넣지 않는다.
- [ ] Run ID별 `data/output/`를 사용하고 Git 제외 여부를 확인했다.
- [ ] 기존 SBOM·DB·로그·선택 ID를 덮어쓰지 않는다.
- [ ] Lab의 빌드 산출물·Maven `target/`·개인 Lab 설정도 커밋 대상인지 검토했다.

## 4. Lab 구현과 분석 범위

- [ ] 빈 Compose·POM·시나리오를 실행 가능한 상태로 오해하지 않았다.
- [ ] vulnerable·patched의 소스·의존성·빌드 정의가 실제로 존재한다.
- [ ] 대상 Component·실제 Before Version·관련 CVE를 공식 자료와 실 분석으로 확인했다.
- [ ] 개선 버전은 공식 보안 공지·Java 호환성·변경 검토로 선택했고 고정했다.
- [ ] 테스트 fixture의 버전을 현재 권장 버전으로 대체 사용하지 않았다.
- [ ] Before·After가 같은 업무 기능과 같은 테스트 계약을 가진다.
- [ ] healthcheck와 업무 기능 테스트가 별도이며 두 계약을 문서화했다.
- [ ] 포트는 `127.0.0.1`에만 게시되며 host network·외부 공개를 하지 않는다.
- [ ] 플랫폼 비밀 설정·실제 데이터·Docker socket을 취약 Lab에 공유하지 않는다.
- [ ] 실제 실행 이미지·mount·classpath와 분석한 JAR 목록이 일치한다.
- [ ] 전이 의존성·fat JAR·동일 패키지의 여러 발생·이전 버전 잔존을 확인했다.
- [ ] 애플리케이션·JDK·OS의 분석 범위와 제외 대상을 명시했다.
- [ ] 성공을 위해 매칭 불가능한 구성요소를 임의로 삭제하지 않았다.
- [ ] Lab README에 빌드·기동·변경·롤백·종료·검증 방법이 있다.

## 5. 자산·Before SBOM·정규화

- [ ] 서비스·자산 ID와 이름·소속을 확인했다.
- [ ] Context는 실제 로컬 환경 또는 명시적인 가상 금융 시나리오와 맞는다.
- [ ] Production·인터넷 노출·정보 처리 여부를 실제 설치 사실처럼 허위 등록하지 않았다.
- [ ] Before의 기본 기능이 실제로 동작했고 응답·시점·참조를 보존했다.
- [ ] Syft는 실제 runtime 전체를 분석했고 오류·Timeout·빈 출력을 확인했다.
- [ ] 원본 SBOM·생성 도구·대상 경로·해시·실제 수집 시점을 보존했다.
- [ ] Parser 형식·버전·원본 필드·구성요소 수를 확인했다.
- [ ] Normalizer의 이름·버전·PURL·issues와 원본을 대조했다.
- [ ] 없는 Version·PURL·Supplier를 추정해 채우지 않았다.
- [ ] 구성요소 중복 발생과 각 ID·위치가 DB에도 보존됐다.
- [ ] 자산→SBOM→Component 소속과 DB 저장·조회 결과를 확인했다.

## 6. CVE·CVSS·KEV·Risk·Finding

- [ ] 모든 구성요소 발생의 분석 실행·analysis_key·결과·출처를 저장했다.
- [ ] MATCHED·NO_MATCH·UNMATCHED·AMBIGUOUS·ERROR를 구분했다.
- [ ] 성공한 OSV 조회만 NO_MATCH로 처리하며 안전 인증으로 해석하지 않았다.
- [ ] 실제 OSV CVE 식별자를 NVD에서 확인했고 CVSS·CWE 출처·시점을 보존했다.
- [ ] CVSS 누락·잘못된 값·API 오류를 0점으로 바꾸지 않았다.
- [ ] KEV는 완전한 카탈로그 snapshot·버전·수집 시점·등록 근거와 일치한다.
- [ ] KEV 조회 실패를 False/미등록으로 처리하지 않았다.
- [ ] Risk는 기존 Phase 5 함수·가중치·규칙 버전으로 계산했다.
- [ ] CVSS 기술 심각도와 내부 Risk Score·P1/P2/P3/P4를 구분했다.
- [ ] 점수·Priority·적용 이유·미평가 요소를 확인했다.
- [ ] EOL·패치 지연 일수 등 미검증 사실을 생성하지 않았다.
- [ ] 같은 자산+CVE는 하나의 Finding이고 발생별 관측·원본 매칭 연결은 각각 남는다.
- [ ] 멱등 재처리와 새 분석 이력이 다른 정책임을 확인했다.
- [ ] 대상 Finding·Component·match run·관측 ID를 명시적으로 선택했다.

## 7. 통제 매핑·Recommendation

- [ ] 통제 매핑은 선택 관측의 증거·규칙·참고 출처를 보존한다.
- [ ] 전체 규정 준수·공식 인증 판정으로 해석하지 않았다.
- [ ] Recommendation 입력은 저장된 Finding·관측·매칭·Risk·Context와 일치한다.
- [ ] 실 AI와 `local-plan-demo` 중 실제 사용 모드를 기록했다.
- [ ] 로컬 generator의 연결 점검을 실 AI 성공으로 표시하지 않았다.
- [ ] AI는 허용된 개선 제안·향후 Verification Plan만 선택한다.
- [ ] AI가 CVE·패치 버전·EOL·Scanner·적용·판정 사실을 만들지 않았다.
- [ ] API·출력 검증 실패를 임의 문장으로 바꿔 성공 저장하지 않았다.
- [ ] 입력 digest·Recommendation ID·모델명·생성 시점을 확인했다.

## 8. Remediation·Before·실제 적용

- [ ] Finding·관측·Recommendation·Remediation 소속이 일치한다.
- [ ] 변경 내용·대상 버전·담당자·로컬 롤백 방법을 검토했다.
- [ ] Before의 발생·버전·PURL·CVE·증거 ID·Risk·이유·규칙 버전이 보존됐다.
- [ ] 계획 저장을 실제 적용 또는 개선 성공으로 표시하지 않았다.
- [ ] 실제 빌드·교체·기동 명령과 종료 코드·로그를 보존했다.
- [ ] 실행 중인 patched 산출물이 분석할 After runtime과 일치한다.
- [ ] Before 컨테이너·오래된 이미지·중복 취약 JAR이 실행 범위에 남지 않았는지 확인했다.
- [ ] 담당자·실제 적용 시점·증거 유형·참조·출처를 기록했다.
- [ ] 적용 실패이면 적용 완료 기록을 생성하지 않았다.
- [ ] 적용 기록을 CVE 제거 증거로 해석하지 않았다.
- [ ] 과거 계획·Before·적용 기록을 수정·삭제하지 않았다.

## 9. Verification 시도·After Evidence

- [ ] 적용된 정확한 Remediation과 자산으로 Verification을 시작했다.
- [ ] 명시적인 attempt_key·시도 ID·필수 테스트 ID를 기록했다.
- [ ] 시도 내 Before·원본 SBOM·적용 기록 사본과 원본 소속을 확인했다.
- [ ] 필수 기능 테스트 ID를 AI 문장에서 자동 추정하지 않았다.
- [ ] 별도의 After SBOM을 실제로 재생성하고 다른 SBOM ID로 저장했다.
- [ ] 원본 After 문서와 저장된 구성요소 발생이 일치한다.
- [ ] 모든 After 발생의 완료된 재매칭 증거를 확보했다.
- [ ] 대상 CVE가 다른 발생·패키지에 남는지도 확인했다.
- [ ] Scanner는 실제 실행한 경우만 결과·도구·참조·시점·CVE·범위를 입력했다.
- [ ] 특정 CVE Scanner 결과를 자산 전체 CVE 수로 확대 해석하지 않았다.
- [ ] 빈 SBOM·부분 재매칭을 전체 취약점 미탐지로 표시하지 않았다.
- [ ] 필수 건강·업무 테스트를 실제 실행하고 응답·Passed/Failed/Error·참조를 저장했다.
- [ ] 기능 테스트 실패·Skipped·누락·Scanner 모순을 무시하지 않았다.
- [ ] 수집 시점은 시간대가 있고 적용 이후·SBOM 이후·Evidence 기록 이전이다.
- [ ] 과거 결과의 시점이나 시스템 clock을 임의로 바꿔 통과시키지 않았다.
- [ ] After payload·digest·기록 시점·증거 시도 ID를 보존했다.
- [ ] 분석·기능 실패 자료도 가능한 범위에서 저장하고 Failed 근거를 남겼다.

## 10. 판정·비교·집계

- [ ] 기존 Phase 9 규칙으로만 완료했고 Risk 감소·AI 문장으로 Passed를 만들지 않았다.
- [ ] Passed/Failed의 원래 규칙 버전·이유·완료 시점을 보존했다.
- [ ] ComparisonService에 asset·Finding·Remediation·Verification ID를 명시했다.
- [ ] 같은 패키지의 추가·제거·버전 집합·발생 수 변화가 기존 SBOM Diff와 맞는다.
- [ ] CVE·Finding은 자산+CVE 기준, 취약 구성요소는 발생 ID 기준으로 집계한다.
- [ ] Critical CVE의 CVSS 심각도와 내부 P1/P2 수를 구분했다.
- [ ] Before 전체 분석·After Risk·EOL 증거가 없으면 None과 사유를 유지한다.
- [ ] 범위가 다른 Before·After는 단순 차감하지 않고 비교 불가 사유를 표시한다.
- [ ] 같은 전체 목록을 여러 Finding 비교에서 반복해서 더하지 않았다.
- [ ] 선택한 Finding의 우선순위 집계를 자산 전체 집계로 표시하지 않았다.
- [ ] 출처·수집/기록 시점·관련 ID·집계 범위·계산 기준을 반환 결과에서 확인했다.
- [ ] 기능 Failed이면 유효한 CVE 감소가 있어도 원래 Verification Failed를 유지한다.
- [ ] 대상 CVE의 제거와 새/잔여 CVE를 구분하고 전체 안전을 주장하지 않았다.
- [ ] 비교 조회가 Finding 상태·판정·과거 Snapshot·상태 이력을 수정하지 않았다.

## 11. 실패·반복·결정성 검증

| 확인 사례 | 기대 처리 | 실제 결과·증거 |
| --- | --- | --- |
| 정상 조치 + 전체 재매칭 + 필수 기능 성공 | 원래 규칙에 따른 Passed | |
| 버전만 변경, 취약점 분석 증거 없음 | Failed, 부족 사유 보존 | |
| 이전 버전이 한 발생에 남음 | Failed, 잔존 근거 | |
| 대상 CVE 재탐지·Scanner 모순 | Failed, 모순/탐지 근거 | |
| 기능 Failed/Error/Skipped·누락 | Failed, 해당 테스트 근거 | |
| 부분/모호/오류 분석 | 전체 집계 미확인, 통과 조건 부족 | |
| 다른 자산·조치·시도 선택 | 소속 오류로 거부 | |
| After Risk·EOL 없음 | None·미확인 사유 | |
| CVSS 누락·같은 CVE의 심각도 충돌 | Critical 집계 미확인 | |
| Before/After 또는 여러 시도의 범위 불일치 | 비교·공동 집계 불가 사유 | |
| 같은 입력·저장된 시도 반복 조회 | 같은 구조화 결과, 상태·이력 무변경 | |
| 새 attempt_key로 재검증 | 새 시도 보존, 이전 Failed/Passed 조회 가능 | |
| 과거 원본 변경·반환 dict 메모리 수정 | 저장된 사본·판정 보존 | |

오프라인 회귀 테스트와 실 Lab에서 수행한 사례를 기록상 구분한다. 모든 실패 상황을
실 Lab에서 인위적으로 만들 필요는 없지만, 실제로 수행하지 않은 사례는 미실행으로 남긴다.

## 12. 종료·보존·완료 판단

- [ ] Python DB 연결을 닫고 일관된 SQLite 파일/backup을 보존했다.
- [ ] Before·After SBOM·실행 파일 해시와 변경·기능·분석 증거를 보존했다.
- [ ] 선택 ID만으로 과거 시도를 다시 조회할 수 있다.
- [ ] 로그에서 비밀값·실제 금융/개인정보를 제거한 공유본만 준비했다.
- [ ] 전용 Compose 프로젝트만 종료했고 외부 게시 포트가 남지 않는다.
- [ ] `down -v`·전체 prune·재귀 삭제로 기존 증거·다른 서비스를 지우지 않았다.
- [ ] 실제 구현 변경 후 전체 오프라인 테스트·diff 검사를 수행했다.
- [ ] 생성 산출물·DB·키·로그가 커밋 대상에 들어가지 않는지 점검했다.
- [ ] 수행 명령·결과·실행하지 못한 항목·Known Issues·다음 담당자를 기록했다.
- [ ] ROADMAP·Lab README·관련 기능 문서에는 실제 확인한 사실만 반영했다.
- [ ] 실 AI·Scanner·After Risk·EOL·승인 기반 위험 수용의 미검증 범위를 유지했다.

## 최종 기록 양식

```text
Run ID:
기준 커밋 / 브랜치:
대상 자산 / 분석 범위:
Before SBOM / 실제 버전 / CVE 증거:
Finding / 관측 / Recommendation 모드·ID:
Remediation / 실제 적용 기록:
After SBOM / 전체 재매칭 / 실제 기능 결과:
Verification 시도 / 원래 판정 / 규칙 / 이유:
비교 파일 / 변화량 / None·비교 불가 사유:
실제로 수행한 명령·검증:
오프라인으로만 확인한 항목:
미실행 / 장애 / 남은 자료:
검토자 / 검토 시점:
다음 작업:
```

첫 Lab의 실제 생성→분석→변경→독립 증거→판정→비교가 연결됐을 때 해당 지원 작업의
완료를 판단한다. 연결 점검용 제안을 사용했다면 실 AI 연동은 별도 미검증 항목이다.
Dashboard·보고서·새 Lab·머신러닝·실제 공격·위험 수용 승인은 별도 작업이다.
