# AGENTS.md

# 1. Project Overview

## Project Name

금융권 특화 SBOM 기반 소프트웨어 공급망 위험평가 및 개선 검증 플랫폼

## Project Goal

본 프로젝트는 가상의 금융서비스 환경에서 사용되는 소프트웨어 구성요소를
SBOM(Software Bill of Materials)을 통해 식별하고,
공개 취약점 및 위협정보와 금융서비스의 자산 Context를 결합하여
실제 대응 우선순위를 산정하는 것을 목표로 한다.

취약점 발견에서 끝나지 않고 다음 전체 과정을 구현한다.

Discover
→ Analyze
→ Prioritize
→ Recommend
→ Remediate
→ Verify
→ Report

최종적으로 시스템은 다음 질문에 답할 수 있어야 한다.

- 어떤 금융서비스에서 어떤 소프트웨어를 사용하는가?
- 어떤 Component가 취약한가?
- 어떤 CVE가 영향을 미치는가?
- 실제 악용 중인 취약점인가?
- 어떤 금융서비스가 영향을 받는가?
- 무엇을 먼저 조치해야 하는가?
- 왜 해당 항목의 우선순위가 높은가?
- 어떤 개선방안이 필요한가?
- 개선조치가 실제로 적용되었는가?
- 개선 이후 취약점이 제거되었는가?
- 개선 효과를 객관적인 Evidence로 증명할 수 있는가?


# 2. Core Design Principles

프로젝트 구현 시 다음 원칙을 반드시 지킨다.

## 2.1 머신러닝 사용 금지

현재 프로젝트에서는 머신러닝 모델을 사용하지 않는다.

다음 디렉터리 또는 기능을 임의로 추가하지 않는다.

- machine_learning/
- ml/
- model/
- training/
- datasets/
- anomaly_detection/

Risk Priority는 반드시 설명 가능한 Rule-based 방식으로 계산한다.

예:

CVSS
+
CISA KEV
+
Production 여부
+
Internet Exposure
+
Business Criticality
+
EOL 여부
+
Patch Delay

→ Risk Priority


## 2.2 CVSS와 내부 Risk Priority를 구분한다

CVSS는 취약점 자체의 기술적 심각도이다.

프로젝트에서 계산하는 값은 금융서비스 Context가 반영된
Remediation Priority 또는 Financial Service Risk Priority이다.

두 값을 같은 의미로 사용하지 않는다.

예:

CVSS = 9.8

Risk Priority = P1

위 두 값은 서로 다른 개념이다.


## 2.3 설명 가능성을 우선한다

Risk 결과는 반드시 계산 근거를 확인할 수 있어야 한다.

잘못된 예:

"AI가 위험하다고 판단하여 P1"

올바른 예:

CVSS >= 9.0        +30
KEV = YES          +30
Internet Exposure  +15
Production         +10
Critical Service   +10

Total = 95
Priority = P1

사용자는 최종 결과뿐 아니라
Priority가 결정된 이유를 확인할 수 있어야 한다.


## 2.4 AI는 판단 엔진이 아니다

AI는 다음 데이터를 직접 생성하거나 추측해서는 안 된다.

- CVE
- CVSS
- CWE
- KEV 등록 여부
- Component Version
- Asset 관계
- Scanner 결과
- EOL 여부
- Patch 적용 여부
- Verification 결과

AI는 자동화 엔진에서 검증된 데이터를 입력받아 해석하는 역할만 담당한다.

AI의 역할:

- 위험 설명
- 금융서비스 영향 설명
- 기술적 개선방안
- 관리적 개선방안
- 관련 보안기준 설명
- Verification Plan 초안
- 컨설팅 보고서 작성


# 3. System Pipeline

전체 시스템은 다음 흐름을 기준으로 구현한다.

1. 금융서비스 및 Asset 등록

2. 대상 시스템의 SBOM 생성

3. SBOM Parser를 이용하여 Component / Version / PURL 추출

4. Component 정규화

5. Component와 CVE 매칭

6. CVSS / CWE / CISA KEV / EOL 정보 수집

7. Asset Context 결합

8. Rule-based Risk Engine 실행

9. P1 / P2 / P3 / P4 Priority 결정

10. 금융권 보안기준 Mapping

11. AI 기반 개선방안 생성

12. Verification Plan 생성

13. 실제 개선조치 수행

14. SBOM 재생성

15. 취약점 재분석

16. Before / After 비교

17. Verification Passed / Failed 결정

18. 최종 컨설팅 보고서 생성


# 4. Directory Responsibilities

각 디렉터리의 책임을 명확히 구분한다.

디렉터리 간 역할을 임의로 섞지 않는다.


## 4.1 app/

사용자 인터페이스 및 API Layer.

예:

app/
├── main.py
├── api/
└── dashboard/

app/에는 핵심 분석 로직을 작성하지 않는다.

금지 예:

app/dashboard/pages/03_Vulnerabilities.py 내부에서
직접 CVE API를 호출하거나 Risk Score를 계산하지 않는다.

올바른 구조:

Dashboard
→ core 함수 호출
→ 결과 표시

app/의 책임:

- 사용자 입력
- API Request / Response
- Dashboard 렌더링
- core 호출
- 결과 표현


## 4.2 core/sbom/

SBOM 관련 기능을 담당한다.

예:

core/sbom/
├── generator.py
├── parser.py
├── normalizer.py
└── diff.py

역할:

generator.py
- SBOM 생성 도구 실행
- CycloneDX 등의 SBOM 생성

parser.py
- SBOM JSON/XML Parsing
- Component 추출

normalizer.py
- Component 이름
- Version
- PURL
- Supplier
- Package 정보 정규화

diff.py
- Before / After SBOM 비교
- 추가 Component
- 삭제 Component
- Version 변경 탐지


## 4.3 core/vulnerability/

취약점 Intelligence 처리.

예:

core/vulnerability/
├── matcher.py
├── cve_client.py
├── cvss.py
├── cwe.py
├── kev_client.py
└── eol_client.py

역할:

matcher.py
- Component ↔ Vulnerability Matching

cve_client.py
- CVE 정보 조회

cvss.py
- CVSS 정보 정규화

cwe.py
- CWE 정보 처리

kev_client.py
- CISA KEV 정보 조회

eol_client.py
- 제품/버전의 EOL 여부 확인

이 디렉터리에서는 AI를 사용하지 않는다.


## 4.4 core/assets/

금융서비스 및 Asset Context 처리.

예:

core/assets/
├── service.py
└── context.py

Asset Context 예:

- Asset Name
- Business Service
- Environment
- Production / Development
- Internet Exposure
- Business Criticality
- Customer Information
- Credit Information
- Patch Status
- Vendor
- Owner

예:

Asset:
Internet Banking API

Environment:
Production

Internet Exposure:
True

Business Criticality:
Critical

Credit Information:
True


## 4.5 core/risk/

Rule-based Risk Engine.

예:

core/risk/
├── engine.py
├── rules.py
└── priority.py

rules.py
- Risk Factor 정의
- 가중치 정의
- 조건 정의

engine.py
- Vulnerability + Asset Context 결합
- Risk Score 계산
- 계산 근거 생성

priority.py
- Score를 P1 / P2 / P3 / P4로 변환

예:

CVSS >= 9.0        +30
KEV                +30
Internet Exposure  +15
Production         +10
Critical Service   +10
EOL                +10

Priority 결과와 함께 반드시 계산 근거를 반환한다.

예:

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


## 4.6 core/compliance/

금융권 보안기준 Mapping.

예:

core/compliance/
├── mapper.py
├── controls.py
└── standards/

standards/
├── isms_p.json
├── financial.json
└── opensource.json

프로젝트는 전체 금융 규정 준수 여부를 자동으로 판정하지 않는다.

Compliance 기능의 목적은 발견된 위험에 대해
관련된 기술적·관리적 보안통제를 연결하는 것이다.

예:

취약 Component 장기 방치

→ Patch Management
→ Asset Management
→ Vulnerability Management
→ ISMS-P 관련 관리영역

Compliance 결과는 참고용 Mapping이며
공식 인증 또는 규정 준수 판정을 의미하지 않는다.


## 4.7 core/consulting/

AI 기반 컨설팅 기능.

예:

core/consulting/
├── analyzer.py
├── recommender.py
├── prompts.py
└── report_generator.py

AI 입력은 반드시 검증된 구조화 데이터를 사용한다.

예:

{
    "asset": "Internet Banking API",
    "component": "log4j-core",
    "version": "2.x",
    "cve": "CVE-XXXX-XXXX",
    "cvss": 9.8,
    "kev": true,
    "environment": "production",
    "internet_exposed": true,
    "business_criticality": "critical",
    "priority": "P1"
}

AI 출력 예:

- 발견사항
- 영향을 받는 금융서비스
- 높은 우선순위의 이유
- 기술적 개선방안
- 관리적 개선방안
- 관련 보안기준
- 임시 완화방안
- Verification Plan

AI가 입력에 없는 보안정보를 사실처럼 생성하지 않도록 한다.


## 4.8 core/verification/

개선 효과 검증.

예:

core/verification/
├── verifier.py
├── sbom_verify.py
├── vulnerability_verify.py
├── functional_verify.py
└── comparison.py

프로젝트의 핵심 기능 중 하나이다.

Risk Score 감소만으로 개선 성공을 판단하지 않는다.

가능한 Evidence:

- SBOM 재생성
- Component Version 변경
- 취약 Component 제거
- CVE 재매칭
- Scanner Re-scan
- 취약점 미탐지
- 기능 정상동작
- Before / After 비교

검증 결과:

Verification Passed

Verification Failed

Risk Accepted


## 4.9 database/

데이터 저장 및 Model 관리.

예:

database/
├── database.py
├── models/
└── migrations/

최소 Model:

BusinessService

Asset

SBOM

Component

Vulnerability

Finding

Recommendation

Remediation

Verification

ScanHistory

기본 관계:

BusinessService
→ Asset
→ SBOM
→ Component
→ Vulnerability

Asset + Vulnerability
→ Finding
→ Recommendation
→ Remediation
→ Verification


## 4.10 labs/

의도적으로 취약한 테스트 환경.

플랫폼 코드와 취약 환경을 섞지 않는다.

예:

labs/
├── log4shell/
│   ├── vulnerable/
│   └── patched/
│
├── struts2/
│   ├── vulnerable/
│   └── patched/
│
└── ...

vulnerable/

개선 전 상태.

patched/

개선 후 상태.

기본 시연:

vulnerable
→ SBOM
→ Vulnerability Detection
→ Risk Analysis
→ Recommendation
→ patched
→ SBOM Re-scan
→ Verification


## 4.11 scenarios/

금융환경 Context 및 시연 시나리오.

예:

scenarios/
├── scenario_01_patch_delay.yaml
├── scenario_02_kev_replay.yaml
└── scenario_03_vendor_risk.yaml

Scenario는 취약 애플리케이션 코드와 분리한다.

예:

scenario_id: SCN-001

asset:
  name: Internet Banking API
  environment: production
  internet_exposed: true
  business_criticality: critical
  credit_information: true

component:
  name: example-component
  version: vulnerable-version


## 4.12 data/

프로젝트 실행 중 사용하는 데이터.

예:

data/
├── assets/
├── sbom/
├── threat_intel/
└── seed/

주의:

실행 중 생성되는 대용량 파일을 전부 Git에 Commit하지 않는다.

샘플 데이터만 저장한다.


## 4.13 scripts/

독립 실행용 Utility.

예:

scripts/
├── generate_sbom.py
├── import_sbom.py
├── sync_cve.py
├── sync_kev.py
├── calculate_risk.py
└── verify_remediation.py

script 내부에 핵심 비즈니스 로직을 중복 구현하지 않는다.

올바른 방식:

script
→ core 함수 호출

잘못된 방식:

script 내부에 별도의 Risk Engine 구현


## 4.14 tests/

테스트 코드.

예:

tests/
├── unit/
├── integration/
└── fixtures/

unit/
- 개별 함수
- Risk Rule
- Parser
- Matcher

integration/
- SBOM → CVE → Risk
- Recommendation → Verification
- Before / After

fixtures/
- 테스트 SBOM
- 테스트 Asset
- 테스트 Vulnerability 정보


## 4.15 docs/

프로젝트 설계 문서.

예:

docs/
├── architecture.md
├── database.md
├── risk_model.md
├── verification.md
└── scenarios.md

코드 구현 과정에서 설계 변경이 발생하면
관련 docs 문서도 함께 수정한다.


# 5. Initial MVP Scope

초기 MVP는 모든 기능을 동시에 구현하지 않는다.

하나의 취약 환경으로 End-to-End Pipeline을 먼저 완성한다.

목표:

Vulnerable Lab
→ SBOM
→ Component
→ CVE
→ CVSS / KEV
→ Asset Context
→ Risk Priority
→ Recommendation
→ Remediation
→ Re-scan
→ Verification

첫 번째 Pipeline이 정상적으로 작동한 후
다른 취약 환경을 추가한다.


# 6. Vulnerability Lab Policy

취약 Lab은 프로젝트의 분석 대상이며
실제 서비스 코드와 분리한다.

Lab을 추가할 때 다음 구조를 권장한다.

labs/<lab-name>/
├── README.md
├── vulnerable/
└── patched/

각 Lab의 README.md에는 다음 내용을 기록한다.

- 취약 Component
- 취약 Version
- 관련 CVE
- 취약 환경의 목적
- 개선 방법
- Verification 방법

취약 Lab은 로컬 또는 격리된 테스트 환경에서만 사용한다.


# 7. Risk Engine Rules

Risk Engine은 deterministic 해야 한다.

동일 입력은 항상 동일 결과를 생성해야 한다.

AI 호출 결과에 따라 Risk Priority가 달라져서는 안 된다.

Risk 계산에 사용되는 모든 Factor는 rules.py에서 관리한다.

Magic Number를 여러 파일에 흩어놓지 않는다.

잘못된 예:

if kev:
    score += 30

위 코드가 여러 파일에 반복 존재.

올바른 예:

RISK_WEIGHTS = {
    "kev": 30,
    "internet_exposure": 15,
    "production": 10
}

Risk Rule 변경 시 테스트를 반드시 수정 또는 추가한다.


# 8. Verification Rules

Verification은 다음 질문에 답해야 한다.

"제안한 개선방안이 실제로 적용되었으며,
기존 위험이 제거 또는 감소했는가?"

Verification은 가능하면 독립적인 Evidence를 이용한다.

예:

Recommendation:
취약 Component Version Upgrade

Verification:

Before:
Component A 1.0

After:
Component A 2.0

CVE Before:
Detected

CVE After:
Not Applicable

Scanner Before:
Vulnerable

Scanner After:
Not Detected

Result:
Verification Passed


# 9. Verification Status

Finding 상태는 가능한 경우 다음 State를 사용한다.

Open

Recommendation Created

Remediation Applied

Verification In Progress

Verification Passed

Verification Failed

Risk Accepted

상태 문자열을 코드 곳곳에 직접 작성하지 않는다.

Enum 또는 상수로 관리한다.


# 10. Coding Standards

Python을 기본 Backend 언어로 사용한다.

코드는 가능한 한 다음 원칙을 따른다.

- 명확한 함수명
- 명확한 변수명
- Type Hint 사용
- 함수 하나에 하나의 책임
- 중복 로직 최소화
- 긴 함수 분리
- Exception 처리
- 의미 없는 try/except 금지
- 사용하지 않는 코드 제거
- Debug print 제거
- Secret 하드코딩 금지

예:

좋음:

calculate_risk_priority()

match_component_to_cve()

compare_sbom_versions()

verify_remediation()

나쁨:

do_it()

process_data()

func1()

test2()


# 11. Configuration Policy

환경별 설정값은 코드에 직접 작성하지 않는다.

.env를 사용한다.

예:

OPENAI_API_KEY=

DATABASE_URL=

CVE_API_URL=

KEV_URL=

.env 파일은 절대로 Git에 Commit하지 않는다.

Repository에는 .env.example만 포함한다.

.env.example에는 실제 Secret을 작성하지 않는다.


# 12. External API Policy

외부 API 사용 시 다음을 고려한다.

- Timeout 설정
- HTTP Error 처리
- Rate Limit
- Retry
- Cache 가능 여부
- API 응답 검증

외부 API가 실패했다고 전체 프로그램이 예고 없이 종료되지 않도록 한다.

가능하면 External Client를 별도 모듈로 분리한다.


# 13. Database Policy

DB Model과 비즈니스 로직을 분리한다.

Dashboard 또는 API에서 SQL을 직접 작성하지 않는다.

잘못된 구조:

dashboard
→ SQL

권장 구조:

dashboard
→ service
→ repository/database

Migration이 필요한 DB Schema 변경은
가능하면 migration 파일과 함께 수행한다.


# 14. Logging Policy

중요한 처리 단계는 logging을 사용한다.

예:

SBOM imported

Component normalized

CVE matched

KEV matched

Risk calculated

Recommendation created

Verification completed

Secret 또는 민감정보를 로그에 출력하지 않는다.

print()를 운영 로그 용도로 사용하지 않는다.


# 15. Error Handling

예상 가능한 오류는 사용자 또는 호출자가 이해할 수 있게 처리한다.

예:

SBOM Parsing Error

Unsupported SBOM Format

Component Mapping Failed

CVE API Unavailable

Invalid Asset Context

Verification Evidence Missing

Exception을 무조건 무시하지 않는다.

금지:

try:
    ...
except:
    pass


# 16. Testing Rules

새로운 핵심 기능을 추가하면 테스트를 함께 작성한다.

특히 다음 기능은 테스트가 필요하다.

- SBOM Parser
- Component Normalizer
- CVE Matcher
- Risk Engine
- Priority Mapping
- SBOM Diff
- Verification

Risk Engine은 Boundary Test를 포함한다.

예:

Score 79 → P2
Score 80 → P1

같은 경계 조건을 검증한다.


# 17. Security Rules

다음 정보를 Repository에 저장하지 않는다.

- API Key
- Access Token
- Password
- Private Key
- 실제 금융정보
- 실제 개인정보

취약 Lab은 테스트 목적으로만 사용한다.

취약 Lab 코드가 실제 플랫폼 서비스와 같이 배포되지 않도록 분리한다.

외부에서 접근 가능한 환경에 취약 Lab을 임의로 배포하지 않는다.


# 18. Git Rules

가능하면 하나의 작업 목적당 하나의 Branch를 사용한다.

예:

feature/sbom-parser

feature/cve-matcher

feature/risk-engine

feature/verification

fix/risk-score

하나의 Commit에 서로 관계없는 변경사항을 넣지 않는다.

Commit Message 예:

feat: add CycloneDX SBOM parser

feat: implement rule-based risk engine

feat: add KEV matching

fix: correct P1 priority threshold

test: add risk engine boundary tests

docs: update verification workflow


# 19. Documentation Rules

주요 기능의 설계가 변경되면 관련 문서를 같이 수정한다.

예:

Risk 계산 방식 변경

→ docs/risk_model.md 수정

DB 관계 변경

→ docs/database.md 수정

Verification 방식 변경

→ docs/verification.md 수정

새 Scenario 추가

→ docs/scenarios.md 수정


# 20. Codex Working Procedure

Codex는 작업 요청을 받을 때 다음 절차를 따른다.

## Step 1. Context 확인

작업과 관련된 파일을 먼저 읽는다.

필요하면 다음 문서를 확인한다.

- AGENTS.md
- README.md
- docs/architecture.md
- docs/database.md
- docs/risk_model.md
- docs/verification.md
- docs/scenarios.md


## Step 2. 기존 구현 확인

새 코드를 작성하기 전에
같은 기능이 이미 구현되어 있는지 확인한다.

중복 구현하지 않는다.


## Step 3. 변경 범위 결정

요청을 수행하는 데 필요한 최소 범위를 수정한다.

요청되지 않은 대규모 Refactoring을 임의로 수행하지 않는다.


## Step 4. 구현

현재 Architecture와 Directory Responsibility를 따른다.

핵심 비즈니스 로직은 core/에 구현한다.


## Step 5. 테스트

가능하면 관련 테스트를 실행한다.

새 기능에는 필요한 테스트를 추가한다.


## Step 6. 결과 보고

작업 완료 후 다음 내용을 요약한다.

Changed Files

Implementation

Tests

Known Issues

Next Steps


# 21. Things Codex Must Not Do

다음 행동을 사용자의 명시적인 요청 없이 수행하지 않는다.

- 전체 Repository 구조 대규모 변경
- 머신러닝 모델 추가
- Risk Engine을 AI 판단으로 변경
- 기존 Risk Rule 임의 변경
- 기존 DB Schema 대규모 변경
- Dependency 대량 추가
- 새로운 Framework 도입
- Docker 구조 대규모 변경
- 취약 Lab과 플랫폼 코드 통합
- 테스트 삭제
- 기존 기능 삭제
- Secret 생성 또는 저장
- 실제 취약 시스템을 외부에 노출


# 22. Dependency Policy

새 Python Package를 추가하기 전에
표준 라이브러리 또는 기존 Dependency로 해결 가능한지 확인한다.

새 Dependency가 필요한 경우 다음을 설명한다.

- Package 이름
- 사용 이유
- 사용 위치

불필요한 대형 Framework를 도입하지 않는다.

특히 머신러닝 관련 Dependency를 추가하지 않는다.

예:

금지 대상:

tensorflow

torch

scikit-learn

xgboost

현재 프로젝트에서는 필요하지 않다.


# 23. Architecture Priority

구현 시 다음 우선순위를 유지한다.

1. 재현 가능성

2. 설명 가능성

3. 정확성

4. 모듈 분리

5. 테스트 가능성

6. UI 편의성

멋진 Dashboard보다
정확하고 재현 가능한 분석 Pipeline이 우선이다.


# 24. MVP Development Order

현재 권장 구현 순서는 다음과 같다.

Phase 1

Asset Model

↓

Phase 2

SBOM Parser

↓

Phase 3

Component Normalizer

↓

Phase 4

CVE / CVSS / CWE / KEV Matcher

↓

Phase 5

Rule-based Risk Engine

↓

Phase 6

Finding 생성

↓

Phase 7

Recommendation

↓

Phase 8

Remediation

↓

Phase 9

Verification

↓

Phase 10

Before / After

↓

Phase 11

Dashboard

↓

Phase 12

AI Consulting Report


# 25. Definition of Done

기능을 완료했다고 판단하려면 가능한 범위에서 다음 조건을 만족해야 한다.

1. 코드가 정상적으로 실행된다.

2. 기존 기능을 깨뜨리지 않는다.

3. 필요한 테스트가 존재한다.

4. 테스트가 통과한다.

5. 오류 상황을 처리한다.

6. 결과의 근거를 설명할 수 있다.

7. Risk 계산은 재현 가능하다.

8. AI가 사실 데이터를 임의로 생성하지 않는다.

9. 민감정보가 코드에 포함되어 있지 않다.

10. 필요 시 관련 문서가 업데이트되었다.


# 26. Final Project Principle

이 프로젝트의 핵심은 단순 취약점 Scanner가 아니다.

다음 흐름을 완성하는 것이 목적이다.

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

실제로 개선되었는가?

↓

그 개선 효과를 어떤 Evidence로 증명할 수 있는가?

모든 구현은 이 목적에 기여해야 한다.