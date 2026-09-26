# ROADMAP.md

# 금융권 특화 SBOM 기반 소프트웨어 공급망 위험평가 및 개선 검증 플랫폼

## 1. 문서 목적

이 문서는 프로젝트의 **개발 순서, 우선순위, 완료 기준, 현재 진행상태**를 관리하기 위한 로드맵이다.

프로젝트 구현은 아래 원칙을 따른다.

- 한 번에 모든 기능을 구현하지 않는다.
- 하나의 취약 Lab을 기준으로 End-to-End Pipeline을 먼저 완성한다.
- 머신러닝은 사용하지 않는다.
- Risk Priority는 Rule-based 방식으로 계산한다.
- AI는 사실정보를 생성하거나 취약 여부를 직접 판정하지 않는다.
- 개선방안 제시에서 끝나지 않고 실제 조치 후 재검증까지 수행한다.
- UI보다 분석 파이프라인의 정확성, 재현성, 설명 가능성을 우선한다.

---

# 2. 최종 목표

최종 시스템은 다음 흐름을 수행할 수 있어야 한다.

```text
Asset
↓
SBOM
↓
Component
↓
Vulnerability Intelligence
↓
Asset Context
↓
Risk Priority
↓
Finding
↓
Security Control Mapping
↓
AI Recommendation
↓
Remediation
↓
Verification
↓
Before / After
↓
Report
```

최종적으로 다음 질문에 답할 수 있어야 한다.

1. 어떤 금융서비스에서 어떤 소프트웨어를 사용하는가?
2. 어떤 Component가 취약한가?
3. 어떤 CVE가 영향을 미치는가?
4. 실제 악용이 확인된 취약점인가?
5. 어떤 금융서비스가 영향을 받는가?
6. 무엇부터 조치해야 하는가?
7. 왜 해당 항목의 우선순위가 높은가?
8. 어떤 개선방안이 필요한가?
9. 실제 개선조치가 적용되었는가?
10. 개선 이후 취약점이 제거되었는가?
11. 개선 효과를 객관적인 Evidence로 증명할 수 있는가?

---

# 3. 현재 상태

> 이 섹션은 개발 진행에 따라 지속적으로 갱신한다.

## Current Phase

**Phase 0 - 프로젝트 설계 및 저장소 초기화**

## Progress

- [ ] 디렉터리 구조 확정
- [ ] `AGENTS.md` 추가
- [ ] `ROADMAP.md` 추가
- [ ] `README.md` 초안 작성
- [ ] Architecture 문서 작성
- [ ] DB Model 초안 작성
- [ ] Risk Rule 초안 작성
- [ ] Verification 기준 초안 작성
- [ ] 첫 번째 취약 Lab 선정
- [ ] MVP 범위 확정

---

# 4. MVP 정의

첫 번째 목표는 **하나의 취약 환경을 기준으로 전체 파이프라인을 끝까지 연결하는 것**이다.

## MVP Pipeline

```text
1개 금융서비스
+
1개 취약 Lab
+
SBOM 생성
+
Component 추출
+
CVE / CVSS / CWE / KEV
+
Asset Context
+
Rule-based Risk Priority
+
Finding
+
Recommendation
+
Remediation
+
Re-scan
+
Verification
+
Before / After
```

## MVP 완료 기준

다음 조건을 모두 만족하면 1차 MVP 완료로 본다.

- [ ] Asset을 등록할 수 있다.
- [ ] 대상 애플리케이션의 SBOM을 생성할 수 있다.
- [ ] SBOM에서 Component와 Version을 추출할 수 있다.
- [ ] Component와 CVE를 연결할 수 있다.
- [ ] CVSS / CWE / KEV 정보를 조회할 수 있다.
- [ ] Asset Context를 반영할 수 있다.
- [ ] Rule-based 방식으로 P1 ~ P4를 계산할 수 있다.
- [ ] Priority 산정 근거를 사용자에게 보여줄 수 있다.
- [ ] 개선방안을 생성할 수 있다.
- [ ] 개선 전 상태를 저장할 수 있다.
- [ ] 개선 후 동일 대상을 재분석할 수 있다.
- [ ] Before / After를 비교할 수 있다.
- [ ] Verification Passed / Failed를 판정할 수 있다.
- [ ] Verification Evidence를 확인할 수 있다.

---

# 5. 개발 단계

## Phase 0. 프로젝트 설계 및 저장소 초기화

### 목표

코딩 전에 프로젝트의 구조와 범위를 고정한다.

### 작업

- [ ] Repository 기본 구조 생성
- [ ] `AGENTS.md` 작성
- [ ] `ROADMAP.md` 작성
- [ ] `README.md` 작성
- [ ] `.gitignore` 작성
- [ ] `.env.example` 작성
- [ ] Python 환경 및 의존성 관리 방식 결정
- [ ] System Architecture 작성
- [ ] DB Entity 정의
- [ ] Risk Rule 초안 작성
- [ ] Verification Rule 초안 작성
- [ ] MVP 범위 확정
- [ ] 첫 번째 취약 Lab 선정

### 산출물

```text
AGENTS.md
ROADMAP.md
README.md

docs/
├── architecture.md
├── database.md
├── risk_model.md
├── verification.md
└── scenarios.md
```

### 완료 조건

- 프로젝트 전체 흐름이 문서화되어 있다.
- 각 디렉터리의 역할이 정해져 있다.
- MVP 범위가 명확하다.
- 첫 번째 End-to-End 시나리오가 결정되어 있다.

---

# 6. Phase 1. Asset & Business Context

## 목표

금융서비스와 자산 정보를 관리한다.

## 주요 Entity

```text
BusinessService
Asset
```

## Asset Context

최소 다음 정보를 관리한다.

```text
Asset Name
Business Service
Environment
Production / Development
Internet Exposure
Business Criticality
Customer Information
Credit Information
Patch Status
Vendor
Owner
```

## 예시

```text
Business Service:
Internet Banking

Asset:
Internet Banking API

Environment:
Production

Internet Exposure:
Yes

Business Criticality:
Critical

Credit Information:
Yes
```

## 구현 위치

```text
core/assets/
database/models/
data/assets/
```

## 작업

- [ ] `BusinessService` Model
- [ ] `Asset` Model
- [ ] Asset Context Schema
- [ ] Sample 금융서비스 데이터
- [ ] Asset CRUD 또는 최소 등록/조회 기능
- [ ] DB 저장
- [ ] Validation

## 테스트

- [ ] 필수 필드 검증
- [ ] 잘못된 Criticality 값 처리
- [ ] Production / Development 구분
- [ ] Internet Exposure 정상 처리

## 완료 조건

Asset Context를 코드에서 안정적으로 조회할 수 있다.

---

# 7. Phase 2. SBOM Engine

## 목표

분석 대상 애플리케이션에서 SBOM을 생성하고 Component를 추출한다.

## 기본 형식

우선 **CycloneDX** 형식을 기준으로 한다.

## 추출 대상

```text
Component Name
Version
PURL
Dependency
Supplier
Hash
License
```

## 구현 위치

```text
core/sbom/

generator.py
parser.py
normalizer.py
diff.py
```

## 작업

- [ ] SBOM 생성 도구 선정
- [ ] SBOM 생성 Wrapper
- [ ] CycloneDX Parser
- [ ] Component Name 추출
- [ ] Version 추출
- [ ] PURL 추출
- [ ] Dependency 관계 추출
- [ ] Supplier 추출
- [ ] Hash 추출
- [ ] License 추출
- [ ] Component 정규화
- [ ] DB 저장

## 테스트

- [ ] 정상 SBOM Parsing
- [ ] 필드 일부 누락 SBOM 처리
- [ ] 중복 Component 처리
- [ ] Version 정규화
- [ ] PURL Parsing

## 완료 조건

```text
Application
↓
SBOM
↓
Normalized Component List
```

흐름이 정상적으로 작동한다.

---

# 8. Phase 3. Vulnerability Intelligence

## 목표

SBOM Component와 외부 취약점 정보를 연결한다.

## 초기 데이터

```text
CVE
CVSS
CWE
CISA KEV
EOL
```

## 구현 위치

```text
core/vulnerability/

matcher.py
cve_client.py
cvss.py
cwe.py
kev_client.py
eol_client.py
```

## 작업

- [ ] Component Normalizer 연동
- [ ] PURL / CPE Mapping 방식 결정
- [ ] CVE 조회
- [ ] CVSS 조회
- [ ] CWE 조회
- [ ] CISA KEV 조회
- [ ] EOL 조회
- [ ] Component ↔ CVE Matching
- [ ] 결과 DB 저장
- [ ] External API Error Handling
- [ ] Timeout / Retry
- [ ] Cache 전략 검토

## 테스트

- [ ] CVE Matching 성공
- [ ] CVE 없음
- [ ] KEV 등록 / 미등록
- [ ] API 응답 실패
- [ ] 잘못된 Component 입력
- [ ] CVSS 누락 처리

## 완료 조건

```text
Component
↓
CVE
↓
CVSS
↓
CWE
↓
KEV
↓
EOL
```

연결이 가능하다.

---

# 9. Phase 4. Rule-based Risk Engine

## 목표

취약점 자체의 심각도와 금융서비스 Context를 결합해 대응 우선순위를 계산한다.

## 원칙

- 머신러닝 사용 금지
- AI 판단 사용 금지
- 동일 입력 → 동일 출력
- 모든 계산 근거 추적 가능
- CVSS와 내부 Priority를 구분

## 초기 Risk Factor 후보

```text
CVSS
CISA KEV
Production 여부
Internet Exposure
Business Criticality
EOL 여부
Patch Delay
Credit Information 처리 여부
```

## 구현 위치

```text
core/risk/

rules.py
engine.py
priority.py
```

## 예시

```text
CVSS >= 9.0        +30
KEV = YES          +30
Internet Exposure  +15
Production         +10
Critical Service   +10
EOL                 +10
```

## 결과 예시

```json
{
  "score": 95,
  "priority": "P1",
  "reasons": [
    "CVSS >= 9.0: +30",
    "CISA KEV: +30",
    "Internet Exposure: +15",
    "Production: +10",
    "Critical Service: +10"
  ]
}
```

## 작업

- [ ] Risk Factor 확정
- [ ] Weight 정의
- [ ] `rules.py`
- [ ] `engine.py`
- [ ] `priority.py`
- [ ] P1 / P2 / P3 / P4 Threshold 확정
- [ ] 계산 근거 반환
- [ ] Rule Version 관리 검토

## 테스트

- [ ] 동일 입력 동일 결과
- [ ] Boundary Test
- [ ] KEV 영향 확인
- [ ] Internet Exposure 영향 확인
- [ ] Business Criticality 영향 확인
- [ ] Missing Context 처리

## 완료 조건

Priority와 그 이유를 모두 반환한다.

---

# 10. Phase 5. Finding Management

## 목표

Asset와 Vulnerability 결과를 실제 관리 가능한 Finding으로 변환한다.

## 기본 구조

```text
Asset
+
Vulnerability
+
Risk Priority
↓
Finding
```

## 구현 위치

```text
database/models/finding.py
core/
app/api/findings.py
```

## Finding Status

```text
Open
Recommendation Created
Remediation Applied
Verification In Progress
Verification Passed
Verification Failed
Risk Accepted
```

## 작업

- [ ] Finding Model
- [ ] Finding 생성 로직
- [ ] 중복 Finding 처리
- [ ] Finding Status
- [ ] Finding 조회
- [ ] Finding History 검토

## 완료 조건

취약점 탐지 결과가 관리 가능한 Finding으로 저장된다.

---

# 11. Phase 6. Financial Security Control Mapping

## 목표

발견된 Finding을 금융권 보안기준과 연결한다.

## 초기 범위

초기에는 범위를 최소화한다.

```text
전자금융 관련 기술적 보안점검 기준
ISMS-P
금융분야 오픈소스 관리 관련 기준
```

## 원칙

이 기능은 공식 규정 준수 여부를 판정하지 않는다.

목적은 다음과 같다.

```text
Finding
↓
관련 Security Control
↓
기술적 개선 관점
+
관리적 개선 관점
```

## 구현 위치

```text
core/compliance/

mapper.py
controls.py
standards/
```

## 작업

- [ ] Security Control Schema
- [ ] Control Dataset
- [ ] Finding ↔ Control Mapping
- [ ] Technical / Administrative 구분
- [ ] Mapping 근거 저장

## 완료 조건

Finding에서 관련 보안통제를 조회할 수 있다.

---

# 12. Phase 7. AI Consulting

## 목표

검증된 분석 결과를 기반으로 AI가 컨설팅 내용을 작성한다.

## AI 입력

AI에는 구조화되고 검증된 데이터만 제공한다.

```text
Asset
Component
Version
CVE
CVSS
CWE
KEV
EOL
Risk Priority
Risk Reasons
Security Control
```

## AI 출력

```text
발견사항
금융서비스 영향
우선순위가 높은 이유
기술적 개선방안
관리적 개선방안
임시 완화방안
Verification Plan
보고서 초안
```

## 금지사항

AI가 다음을 임의 생성하면 안 된다.

```text
CVE
CVSS
CWE
KEV
Component Version
Asset 관계
Scanner 결과
Verification 결과
```

## 구현 위치

```text
core/consulting/

analyzer.py
recommender.py
prompts.py
report_generator.py
```

## 작업

- [ ] Prompt Template
- [ ] Structured Input
- [ ] Structured Output
- [ ] Hallucination 방지 규칙
- [ ] Recommendation 생성
- [ ] Verification Plan 생성
- [ ] AI Error 처리

## 완료 조건

자동화 결과를 기반으로 설명 가능한 Recommendation을 생성한다.

---

# 13. Phase 8. First Vulnerable Lab

## 목표

하나의 취약 환경을 만들어 전체 Pipeline을 실제로 검증한다.

## 기본 구조

```text
labs/<lab-name>/
├── README.md
├── vulnerable/
└── patched/
```

## Lab README 필수 내용

```text
취약 Component
취약 Version
관련 CVE
Lab 목적
개선 방법
Verification 방법
실행 방법
```

## 첫 번째 Lab 선정 기준

- SBOM에서 Component 식별이 명확할 것
- CVE Mapping이 명확할 것
- 취약 버전 / 개선 버전 구분이 명확할 것
- Before / After 검증이 가능할 것
- 실습환경에서 안전하게 재현 가능할 것

## 작업

- [ ] 첫 Lab 선정
- [ ] vulnerable 환경 작성
- [ ] patched 환경 작성
- [ ] SBOM 생성 확인
- [ ] CVE Mapping 확인
- [ ] Risk 계산 확인
- [ ] 개선 시나리오 작성
- [ ] Verification 방법 작성

## 완료 조건

```text
Vulnerable
↓
Detection
↓
Recommendation
↓
Patched
↓
Re-scan
↓
Verification
```

전체 흐름이 가능하다.

---

# 14. Phase 9. Remediation Management

## 목표

Finding에 대한 개선방안과 실제 개선조치를 관리한다.

## 기본 구조

```text
Finding
↓
Recommendation
↓
Remediation
```

## 구현 위치

```text
database/models/recommendation.py
database/models/remediation.py
app/api/remediation.py
```

## 작업

- [ ] Recommendation Model
- [ ] Remediation Model
- [ ] 조치 상태 관리
- [ ] Before 상태 저장
- [ ] 조치 내용 기록
- [ ] After 분석과 연결

## 완료 조건

어떤 Finding에 어떤 개선조치가 적용되었는지 추적할 수 있다.

---

# 15. Phase 10. Verification Engine

## 목표

개선방안이 실제로 효과가 있었는지 검증한다.

## 원칙

Risk Score 감소만으로 Verification Passed를 판정하지 않는다.

가능한 경우 독립적인 Evidence를 사용한다.

## Evidence 후보

```text
SBOM Diff
Component Version 변경
취약 Component 제거
CVE Re-Matching
Vulnerability Re-scan
Functional Test
Exploit/Test Case 재실행
Risk Recalculation
```

## 구현 위치

```text
core/verification/

verifier.py
sbom_verify.py
vulnerability_verify.py
functional_verify.py
comparison.py
```

## 작업

- [ ] Before Snapshot
- [ ] After Snapshot
- [ ] SBOM Diff
- [ ] Version 비교
- [ ] CVE 재매칭
- [ ] Scanner Re-scan 연동
- [ ] Verification Rule
- [ ] Evidence 저장
- [ ] Passed 처리
- [ ] Failed 처리
- [ ] Risk Accepted 처리

## Verification 예시

```text
Before
Component A 1.0
CVE Detected
Scanner Vulnerable

↓

Remediation

↓

After
Component A 2.0
CVE Not Applicable
Scanner Not Detected

↓

Verification Passed
```

## 완료 조건

개선 성공/실패를 Evidence와 함께 반환한다.

---

# 16. Phase 11. Before / After Comparison

## 목표

개선 효과를 직관적으로 비교한다.

## 비교 항목

```text
Component Version
Vulnerable Component Count
Critical CVE
KEV
EOL Component
P1 Count
P2 Count
Risk Score
Verification Status
```

## 작업

- [ ] Before Snapshot
- [ ] After Snapshot
- [ ] Diff Engine
- [ ] 증감 계산
- [ ] Finding별 비교
- [ ] Asset별 비교
- [ ] Dashboard용 데이터 생성

## 완료 조건

사용자가 개선 전·후 차이를 한 화면에서 확인할 수 있다.

---

# 17. Phase 12. Dashboard

## 목표

전체 분석 흐름을 하나의 UI에서 확인한다.

## 구현 위치

- `app/main.py`: Flask 서버 진입점 및 화면 라우트 연결.
- `app/api/`: 화면에서 호출하는 서버 API.
- `app/templates/`: HTML 화면과 `components/`의 공통 템플릿 조각.
- `app/static/css/`: 스타일시트.
- `app/static/js/`: 브라우저 상호작용과 API 요청·결과 표시.

현재 디렉터리와 빈 HTML 골격만 준비되어 있다. 아래 Page 목록은 기능별 계획이며 파일명이나 구현 완료 상태를 의미하지 않는다.

## 초기 Page

```text
01 Assets
02 SBOM
03 Vulnerabilities
04 Risk
05 Findings
06 Remediation
07 Verification
08 Report
```

## 구현 원칙

- UI에서 핵심 비즈니스 로직을 직접 구현하지 않는다.
- 브라우저는 `app/api/`를 호출하고, 서버는 `core/`를 통해 분석을 수행한다.
- UI 완성도보다 Pipeline 정확성을 우선한다.

## 작업

- [ ] Asset 화면
- [ ] SBOM 화면
- [ ] Vulnerability 화면
- [ ] Risk 화면
- [ ] Finding 화면
- [ ] Remediation 화면
- [ ] Verification 화면
- [ ] Before / After 화면
- [ ] Report 화면

## 완료 조건

최소 Demo Flow를 Dashboard에서 수행할 수 있다.

---

# 18. Phase 13. Final Report

## 목표

분석부터 개선 검증까지의 결과를 최종 보고서 형태로 정리한다.

## 보고서 내용

```text
대상 금융서비스
Asset 정보
Component
Vulnerability
CVE / CVSS / CWE / KEV
Risk Priority
Risk 산정 근거
Security Control
Recommendation
Remediation
Verification Plan
Verification Evidence
Before / After
최종 상태
```

## 작업

- [ ] Report Data Model
- [ ] AI Report Template
- [ ] Evidence 포함
- [ ] Before / After 포함
- [ ] Export 형식 검토

## 완료 조건

한 Finding의 전체 생명주기를 보고서에서 확인할 수 있다.

---

# 19. Phase 14. Additional Scenarios

첫 번째 End-to-End Pipeline이 완료된 이후에만 진행한다.

## 후보

- [ ] 추가 취약 Component
- [ ] 장기 미패치 Scenario
- [ ] EOL Component
- [ ] Historical KEV Replay
- [ ] Vendor Risk
- [ ] Dependency Change Detection
- [ ] 악성 Package Intelligence
- [ ] Typosquatting
- [ ] CI/CD Artifact 변경
- [ ] Supply Chain Incident

## 원칙

추가 기능 때문에 MVP 안정성을 깨뜨리지 않는다.

---

# 20. Phase 15. End-to-End Integration Test

## 전체 흐름

```text
Asset 등록
↓
SBOM 생성
↓
Component 추출
↓
CVE Matching
↓
CVSS / CWE / KEV
↓
Asset Context
↓
Risk Priority
↓
Finding
↓
Control Mapping
↓
Recommendation
↓
Remediation
↓
Re-scan
↓
Verification
↓
Before / After
↓
Report
```

## 확인사항

- [ ] 전체 Pipeline 실행 가능
- [ ] 동일 입력 결과 재현 가능
- [ ] Risk 계산 근거 확인 가능
- [ ] AI Hallucination 방지
- [ ] 외부 API 장애 처리
- [ ] Verification Evidence 존재
- [ ] Verification Failed 시나리오 동작
- [ ] Risk Accepted 동작
- [ ] Secret 미포함
- [ ] Unit Test 통과
- [ ] Integration Test 통과
- [ ] 문서 최신화

---

# 21. 우선순위

## Must Have

- [ ] Asset Context
- [ ] SBOM 생성 및 Parsing
- [ ] Component Normalization
- [ ] CVE Matching
- [ ] CVSS
- [ ] CWE
- [ ] KEV
- [ ] Rule-based Risk Engine
- [ ] Finding
- [ ] Recommendation
- [ ] Remediation
- [ ] Verification
- [ ] Before / After

## Should Have

- [ ] EOL
- [ ] Security Control Mapping
- [ ] AI Consulting
- [ ] Dashboard
- [ ] Report

## Could Have

- [ ] Vendor Mapping
- [ ] Historical KEV Replay
- [ ] Supply Chain Intelligence
- [ ] Malicious Package
- [ ] Typosquatting
- [ ] Dependency Change Detection
- [ ] CI/CD Artifact Integrity
- [ ] 다중 취약 Lab

---

# 22. 개발 의존관계

기능은 아래 의존관계를 따른다.

```text
Asset Model
   │
   ├──────────────┐
   │              │
   ↓              ↓
SBOM Engine   Asset Context
   │              │
   ↓              │
Vulnerability     │
Intelligence      │
   │              │
   └──────┬───────┘
          ↓
      Risk Engine
          ↓
        Finding
          ↓
  Security Control
          ↓
    AI Consulting
          ↓
      Remediation
          ↓
     Verification
          ↓
    Before / After
          ↓
       Dashboard
          ↓
        Report
```

이 의존관계를 무시하고 후속 기능부터 구현하지 않는다.

---

# 23. 권장 Branch 전략

예시:

```text
main

feature/project-setup
feature/asset-model
feature/sbom-parser
feature/component-normalizer
feature/cve-matcher
feature/kev-client
feature/risk-engine
feature/finding
feature/compliance-mapping
feature/ai-consulting
feature/remediation
feature/verification
feature/dashboard
feature/report
```

버그 수정 예시:

```text
fix/sbom-parser
fix/risk-threshold
fix/cve-matching
fix/verification-result
```

---

# 24. 각 Phase 완료 시 확인할 내용

각 Phase 완료 전에 아래를 확인한다.

- [ ] 코드가 정상적으로 실행되는가?
- [ ] 필요한 테스트가 있는가?
- [ ] 기존 기능을 깨뜨리지 않았는가?
- [ ] Error Handling이 있는가?
- [ ] 결과가 재현 가능한가?
- [ ] 결과 근거를 설명할 수 있는가?
- [ ] Secret이 포함되어 있지 않은가?
- [ ] 관련 문서를 수정했는가?
- [ ] 다음 Phase에서 사용할 Interface가 명확한가?

---

# 25. 프로젝트 완료 기준

프로젝트는 단순히 취약점을 탐지하는 것으로 완료되지 않는다.

최종적으로 아래 흐름이 실제로 동작해야 한다.

```text
무엇이 취약한가?
↓
어떤 금융서비스가 영향을 받는가?
↓
무엇부터 조치해야 하는가?
↓
왜 먼저 조치해야 하는가?
↓
어떻게 개선해야 하는가?
↓
실제로 개선조치가 적용되었는가?
↓
기존 위험이 제거되었는가?
↓
그 결과를 어떤 Evidence로 증명할 수 있는가?
```

위 흐름이 하나의 End-to-End Scenario에서 재현 가능하면 프로젝트의 핵심 목표를 달성한 것으로 본다.
