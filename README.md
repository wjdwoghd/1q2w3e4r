# 금융권 특화 SBOM 기반 소프트웨어 공급망 위험평가 및 개선 검증 플랫폼

가상의 금융사를 대상으로 SBOM, 취약점·공급망 위협정보, 금융서비스 자산정보를 결합하여 대응 우선순위를 산정하는 프로젝트이다. 금융권 보안기준을 참고해 개선방안을 제시하고, 조치 후 재검증을 통해 실제 개선 효과까지 확인하는 컨설팅 지원 플랫폼을 목표로 한다.

> Phase 1~10의 core·Repository와 첫 호스트 Lab E2E를 검증했다. 2026-10-17에는
> 공통 CLI의 새 Run에서도 선택한 CVE의 Verification Passed와 반복 조회를 확인했다.
> Recommendation은 로컬 연결 점검 모드다. 실 AI·Scanner·After Risk·EOL,
> API·Dashboard·보고서는 남아 있다. 상세 상태는 ROADMAP.md를 따른다.

기획 기준: [프로젝트 Notion 문서](https://app.notion.com/p/SBOM-3e24a9a6169880f6bc91dd3d61a376ac)

## 주요 문서

- [개발 로드맵](./ROADMAP.md)
- [첫 Lab End-to-End 실행 가이드](./docs/lab_e2e_runbook.md)
- [첫 Lab 전체 점검표](./docs/lab_e2e_checklist.md)
- [GitHub 협업 원칙](./docs/github_collaboration.md)
- [코드 작성 원칙](./docs/coding_conventions.md)
- [GitHub 협업 설정](./.github/OVERVIEW.md)

## 프로젝트 방향

- SBOM의 구성요소와 버전을 기준으로 알려진 취약점과 공급망 정보를 연결한다.
- 운영 환경, 인터넷 노출, 금융업무 중요도, 신용정보 처리 여부를 함께 고려한다.
- 설명 가능한 규칙으로 대응 우선순위인 `P1`~`P4`를 계산한다.
- 머신러닝 학습·추론·모델 저장 디렉터리는 두지 않는다. `database/models/`는 데이터베이스 엔티티를 정의하는 영역이다.
- AI는 확인된 분석 결과를 해석하고 기술적·관리적 개선안과 검증방법을 작성한다.
- 개선 조치 이후 SBOM, 재스캔 결과, 서비스 정상동작 증적을 비교한다.
- 금융권 보안기준은 컨설팅의 근거로 활용하며, 최종 판단과 승인은 사람이 수행한다.

## 전체 흐름

```mermaid
flowchart TD
    A[가상 금융서비스와 자산정보] --> B[SBOM 생성 및 구성요소 식별]
    B --> C[취약점 및 위협정보 결합]
    C --> D[자산 맥락 기반 대응 우선순위 산정]
    D --> E[금융권 보안기준 매핑]
    E --> F[AI 개선안 및 검증계획 작성]
    F --> G[개선 조치]
    G --> H[SBOM 재생성 및 재스캔]
    H --> I[개선 전후 비교 및 검증 판정]
    I --> J[대시보드 및 최종 보고서]
```

`Discover -> Analyze -> Prioritize -> Recommend -> Remediate -> Verify -> Report`

## 주요 기능 계획

| 영역 | 역할 | 디렉터리 |
| --- | --- | --- |
| SBOM | CycloneDX 기반 구성요소·버전·PURL·의존성 식별 및 전후 비교 | `core/sbom/` |
| 취약점 정보 | CVE·CVSS·CWE·CISA KEV 매칭, EOL·패치 정보 확장 | `core/vulnerability/` |
| 자산 맥락 | 금융서비스와 자산 연결, 운영 여부·외부 노출·중요도·신용정보 처리 관리 | `core/assets/` |
| 대응 우선순위 | 규칙 기반 점수 및 P1~P4 산정, 계산 근거 제공 | `core/risk/` |
| 보안기준 매핑 | 발견사항과 기술적·관리적 통제항목 연결 | `core/compliance/` |
| AI 컨설팅 | 영향 설명, 개선안, 검증방법, 보고서 초안 작성 | `core/consulting/` |
| 개선 검증 | SBOM·취약점·기능 점검 결과 비교 및 검증 상태 관리 | `core/verification/` |
| API·대시보드 | 자산·분석 결과·조치 상태 조회 및 개선 전후 비교 | `app/` |

### 대응 우선순위

CVSS는 취약점 자체의 기술적 심각도이다. 본 프로젝트의 **Remediation Priority**는 여기에 금융서비스 맥락을 더한 대응 우선순위로, CVSS와 구분한다.

CVSS, KEV 등록 여부, 운영 환경, 인터넷 노출, 금융업무 중요도, 패치 지연 기간 등을 규칙 기반으로 조합한다. EOL 정보 연계는 확장 범위로 둔다. 기획 문서의 가중치는 예시이며, 최종 가중치와 등급 경계는 구현 단계에서 정의하고 검증한다.

| 등급 | 의미 |
| --- | --- |
| P1 | 최우선 대응 |
| P2 | 높은 대응 우선순위 |
| P3 | 중간 대응 우선순위 |
| P4 | 낮은 대응 우선순위 |

`core/risk/`의 책임은 다음과 같이 나눈다.

| 파일 | 역할 |
| --- | --- |
| `engine.py` | 취약점 정보와 자산 맥락을 결합한 전체 계산 흐름 |
| `rules.py` | CVSS, KEV, 인터넷 노출, 운영 여부, 중요도 등의 점수 규칙 |
| `priority.py` | 계산 결과를 P1 / P2 / P3 / P4로 변환 |

다음은 설계를 설명하기 위한 점수 예시이다. 확정된 정책이나 CVSS 산식이 아니며, P1~P4 경계값은 별도로 정한다.

| 조건 | 예시 가점 |
| --- | --- |
| CVSS >= 9.0 | +30 |
| CISA KEV 등록 | +30 |
| 인터넷 노출 | +15 |
| 운영 환경 | +10 |
| 핵심 금융서비스 | +10 |
| EOL 구성요소 | +10 |

### AI와 보안기준의 역할

취약점 매칭과 우선순위 계산은 자동화 도구와 규칙 기반 엔진이 담당한다. AI에는 확인된 데이터와 계산 근거를 전달하여 영향 설명, 기술적·관리적 개선안, 검증방법을 작성하게 한다.

전자금융기반시설 취약점 분석·평가 기준, ISMS-P, 금융분야 오픈소스 활용·관리 관련 가이드를 참고 대상으로 삼는다. 통제항목의 출처와 버전을 관리하며, 매핑 결과를 모든 규정의 준수 여부에 대한 자동 판정으로 사용하지 않는다.

### 개선 검증

점수 하락만으로 조치 성공을 판정하지 않는다. 변경된 구성요소·버전, CVE 재매칭, 재스캔 결과, 서비스 기능 점검을 증적으로 활용한다. 관리적 조치는 승인 기록이나 절차 등 이행 증적을 확인한다.

```text
Open -> Recommendation Created -> Remediation Applied
     -> Verification In Progress -> Verification Passed / Verification Failed
```

대시보드에서는 취약 구성요소, 심각한 CVE, KEV, P1/P2 건수, 검증 완료 조치 등을 개선 전후로 비교할 계획이다. EOL 현황은 확장 범위에 포함한다.

## MVP 및 확장 범위

### MVP

- 가상 금융서비스 3개 이상과 Asset Inventory 구성
- SBOM 생성, 구성요소·버전 추출, CVE·CVSS 매칭 및 CISA KEV 확인
- 자산 맥락을 결합한 P1~P4 대응 우선순위 산정
- 금융권 보안기준 매핑, AI 개선안 및 검증계획 생성
- 개선 조치 후 SBOM 재생성·재스캔, 검증 성공·실패 판정
- 개선 전후 결과를 비교하는 대시보드

### 확장

EOL 정보, Vendor Mapping, Historical KEV Replay, 악성 패키지·Typosquatting 분석, 의존성 변경 탐지, AI 추천 의존성 검증, CI/CD 공급망 변경 분석, 보안기준 매핑 고도화, 중복 통제항목 통합, PDF 보고서 생성을 고려한다.

기획의 실습 구성에는 EOL이 포함되어 있지만 MVP 목록에서는 확장으로 분류되어 있다. 저장소에는 실습용 자리를 마련하고 구현 순서는 MVP 이후로 구분한다.

## 실습 및 시연 계획

분석 플랫폼과 취약 실습환경을 한 저장소에서 분리해 관리한다. 실습은 격리된 로컬 환경에서 수행하며, 취약 상태와 개선 상태의 구성정보 및 점검 결과를 비교한다.

| 실습 디렉터리 | 목적 |
| --- | --- |
| `labs/log4shell/` | 대표적인 의존성 취약점의 발견부터 패치 후 검증까지 비교 |
| `labs/struts2/` | 장기간 미패치 구성요소와 대응 우선순위 분석 |
| `labs/snakeyaml/` | 간접 의존성 식별과 개선 전후 비교 |
| `labs/eol-component/` | 지원 종료 소프트웨어의 수명주기 위험 분석, 확장 범위 |

각 실습의 `vulnerable/`와 `patched/`는 비교 대상의 위치이다. 기존 Log4Shell Lab에는
공통 Java 서비스·두 의존성 빌드·호스트 실행 도구·Compose 정의가 준비됐고 실제
호스트 기능·SBOM 경로를 검증했다. 나머지 Lab은 자리 파일이며 전체 취약점 분석·
조치·검증 연결은 남아 있다. [바로 실행하기](./labs/log4shell/README.md)를 따른다.

분석 플랫폼의 의존성과 실습환경의 의존성은 분리한다. 루트 `docker-compose.yml`은 플랫폼 구성용으로 계획하고, 실습별 Compose 파일은 각 `labs/` 하위 환경을 관리한다.

```text
vulnerable/ -> SBOM 생성 -> 취약점 발견 -> 개선방안
           -> patched/ -> SBOM 재생성 -> 재검증
```

시연 정의는 `scenarios/`에서 관리한다. `scenario_01_patch_delay.yaml`은 발견·개선·검증의 기본 흐름, `scenario_02_kev_replay.yaml`은 과거 KEV 정보 변화에 따른 재평가, `scenario_03_vendor_risk.yaml`은 공급업체 관계를 통한 영향범위 분석을 위한 자리이다. 뒤의 두 시나리오는 확장 범위이다.

## 목표 디렉터리 구조

아래는 확정한 구현 방향에 맞춘 목표 구조이다. 이번 변경은 README에만 반영했으며 실제 파일 생성·이동·삭제는 아직 수행하지 않았다. 디렉터리별 README는 트리에서 생략한다.

```text
1q2w3e4r/
├── README.md
├── .gitignore
├── .env.example
├── requirements.txt
├── docker-compose.yml
├── app/
│   ├── main.py
│   ├── api/
│   │   ├── assets.py
│   │   ├── scans.py
│   │   ├── findings.py
│   │   ├── remediation.py
│   │   └── reports.py
│   └── dashboard/
│       ├── Home.py
│       └── pages/
│           ├── 01_Assets.py
│           ├── 02_SBOM.py
│           ├── 03_Vulnerabilities.py
│           ├── 04_Risk.py
│           ├── 05_Remediation.py
│           ├── 06_Verification.py
│           └── 07_Report.py
├── core/
│   ├── sbom/
│   │   ├── generator.py
│   │   ├── parser.py
│   │   ├── normalizer.py
│   │   └── diff.py
│   ├── vulnerability/
│   │   ├── matcher.py
│   │   ├── cve_client.py
│   │   ├── cvss.py
│   │   ├── cwe.py
│   │   ├── kev_client.py
│   │   └── eol_client.py
│   ├── assets/
│   │   ├── service.py
│   │   └── context.py
│   ├── risk/
│   │   ├── engine.py
│   │   ├── rules.py
│   │   └── priority.py
│   ├── compliance/
│   │   ├── mapper.py
│   │   ├── controls.py
│   │   └── standards/
│   │       ├── isms_p.json
│   │       ├── financial.json
│   │       └── opensource.json
│   ├── consulting/
│   │   ├── analyzer.py
│   │   ├── recommender.py
│   │   ├── prompts.py
│   │   └── report_generator.py
│   └── verification/
│       ├── verifier.py
│       ├── sbom_verify.py
│       ├── vulnerability_verify.py
│       ├── functional_verify.py
│       └── comparison.py
├── database/
│   ├── database.py
│   ├── models/
│   │   ├── business_service.py
│   │   ├── asset.py
│   │   ├── sbom.py
│   │   ├── component.py
│   │   ├── vulnerability.py
│   │   ├── finding.py
│   │   ├── recommendation.py
│   │   ├── remediation.py
│   │   └── verification.py
│   └── migrations/
├── labs/
│   ├── log4shell/
│   │   ├── vulnerable/
│   │   ├── patched/
│   │   └── docker-compose.yml
│   ├── struts2/
│   │   ├── vulnerable/
│   │   ├── patched/
│   │   └── docker-compose.yml
│   ├── snakeyaml/
│   │   ├── vulnerable/
│   │   ├── patched/
│   │   └── docker-compose.yml
│   └── eol-component/
│       ├── vulnerable/
│       └── patched/
├── scenarios/
│   ├── scenario_01_patch_delay.yaml
│   ├── scenario_02_kev_replay.yaml
│   └── scenario_03_vendor_risk.yaml
├── data/
│   ├── assets/
│   │   └── sample_assets.json
│   ├── sbom/
│   │   ├── before/
│   │   └── after/
│   ├── threat_intel/
│   └── seed/
├── scripts/
│   ├── generate_sbom.py
│   ├── import_sbom.py
│   ├── sync_cve.py
│   ├── sync_kev.py
│   ├── calculate_risk.py
│   └── verify_remediation.py
├── tests/
│   ├── unit/
│   │   ├── test_sbom.py
│   │   ├── test_vulnerability.py
│   │   ├── test_risk.py
│   │   └── test_verification.py
│   └── integration/
├── reports/
│   └── .gitkeep
└── docs/
    ├── architecture.md
    ├── database.md
    ├── risk_model.md
    ├── verification.md
    └── scenarios.md
```

각 디렉터리의 README에서 세부 역할을 설명한다. 데이터 관계는 금융서비스·자산·SBOM·구성요소·취약점과 발견사항·개선안·조치·검증으로 구분한다. `database/models/`에는 이 관계를 저장하는 엔티티만 둔다.

현재 파일 중 `asset_service.py`, `opensource_guide.json`, `test_matcher.py`, `test_risk_engine.py`, `labs/eol_component/` 등은 목표 구조와 이름이 다르다. 루트 Compose, 보고서 화면, 추가 DB 모델도 향후 구조 반영 시 준비할 대상이다. 기존 보조 디렉터리와 설정 파일은 이번 문서 변경에서 삭제하지 않았다.

## 기술 구성 및 준비 상태

| 구분 | 계획 |
| --- | --- |
| 분석 플랫폼 | Python, Flask API, Streamlit 대시보드 |
| SBOM | CycloneDX를 기본 형식으로 고려, Syft 등 기존 생성 도구 활용 검토 |
| 위험평가 | 설명 가능한 규칙 기반 엔진 |
| AI 컨설팅 | OpenAI API로 검증된 분석 결과 해석 및 문서 생성 |
| 데이터베이스 | 연결 설정, 도메인 엔티티, 마이그레이션 관리; DB 제품 및 라이브러리 미확정 |
| 실습환경 | 플랫폼과 분리된 Docker Compose 구성 계획 |

현재 Python 요구사항은 `packageurl-python`이며 core·Repository와 오프라인 테스트가
구현돼 있다. 일반 분석 CLI는 아직 자리 파일이고 첫 Lab에는 별도 PowerShell 빌드·
호스트 실행 도구와 Compose 정의가 있다. 실조회 보조 CLI,
기본 환경 점검과 Lab 준비 이후의 실행 절차는 [실행 가이드](./docs/lab_e2e_runbook.md)를 따른다.

API 키 등 실제 비밀값은 로컬 `.env`에만 등록한다. `.env.example`에는 변수명과 공개 가능한 기본값만 둔다.

## 개발 컨벤션

상세 기준은 [코드 작성 원칙](./docs/coding_conventions.md)을 참조한다.

- Python 코드는 PEP 8을 따른다.
- 디렉터리·Python 파일·변수·함수는 `snake_case`, 클래스는 `PascalCase`, 상수·환경 변수는 `UPPER_SNAKE_CASE`를 사용한다.
- 파일명 예: `service.py`, `kev_client.py`, `report_generator.py`, `verify_remediation.py`.
- 확정 구조의 `labs/eol-component/`, `Home.py`, `01_Assets.py`~`07_Report.py`는 명명 규칙의 예외로 유지한다.
- import는 표준 라이브러리, 외부 라이브러리, 프로젝트 모듈 순으로 구분한다.
- 주석은 규칙의 근거나 판단 이유를 설명한다.
- 요청·화면 처리는 `app/`, 분석은 `core/`, 영속성 처리는 `database/`에 둔다.
- 분석 입력, 적용 규칙, 외부 데이터 기준시점, 계산 근거, 검증 증적을 추적할 수 있도록 설계한다.

## Git 브랜치 전략

작업 등록부터 PR 리뷰, 커밋과 증적 관리까지의 절차는 [GitHub 협업 원칙](./docs/github_collaboration.md)을 참조한다.

경량 Git Flow를 사용하며 별도 `release` 브랜치는 운영하지 않는다.

| 브랜치 | 역할 |
| --- | --- |
| `main` | 최종 배포 및 발표 버전 |
| `develop` | 기능 통합 |
| `feat/*` | `develop`에서 분기하는 기능 개발 |
| `fix/*` | `develop`에서 분기하는 일반 오류 수정 |
| `docs/*` | `develop`에서 분기하는 문서 작성 및 수정 |
| `hotfix/*` | 배포 후 긴급 수정이 필요할 때 생성 |

기능 개발은 `feat/*`에서 진행하고 PR로 `develop`에 병합한다. 최종 버전은 `develop`에서 `main`으로 병합한다. 긴급 수정은 `main`에서 분기하여 수정 후 `main`과 `develop` 모두에 반영한다.

기능 브랜치명 예시는 `feat/sbom-parser`, `feat/risk-engine`, `feat/verification`, `feat/dashboard`, `feat/openai-report`이다. 이는 작업 주제별 예시이며 실제 브랜치 변경은 별도로 진행한다.

## 커밋 컨벤션

커밋 제목은 `<type>: <한글 설명>` 형식을 사용한다. 병합 커밋에도 같은 규칙을 적용한다.

| Type | 용도 |
| --- | --- |
| `feat` | 새로운 기능 |
| `fix` | 버그 수정 |
| `hotfix` | 긴급 수정 |
| `refactor` | 리팩토링 |
| `style` | 코드 스타일 및 UI |
| `docs` | 문서 |
| `test` | 테스트 |
| `comment` | 주석 |
| `rename` | 파일·폴더 이름 변경 |
| `remove` | 파일 삭제 |
| `chore` | 빌드·환경설정 등 기타 작업 |

```text
feat: CycloneDX SBOM 파서 구현
feat: 금융서비스 대응 우선순위 계산 추가
fix: 구성요소 버전 매칭 오류 수정
docs: SBOM 프로젝트 기획에 맞게 README 수정
test: 개선 전후 검증 결과 비교 테스트 추가
```

현재 저장소에 `commit-msg` Hook은 구현되어 있지 않다. 커밋 작성과 PR 리뷰에서 규칙을 확인한다.

## 협업 및 파일 관리

- 기능 개발 전 Issue를 만들고 기능 단위로 커밋한다.
- 병합 전 PR을 생성하고 공통 코드 변경은 팀원과 공유한다.
- 충돌은 관련 작업자와 협의하여 해결한다.
- 설계·동작 변경에 영향을 받는 README와 문서를 함께 수정한다.
- 실제 API 키, 운영 데이터, 개인정보는 커밋하지 않는다.

현재 `.gitignore`는 `.env`, `.venv/`, Python 캐시, `data/raw/`·`data/output/`, DB 파일, 로그, 생성 보고서 등을 제외한다. `reports/README.md`와 `.gitkeep`은 예외로 관리한다.

`data/assets/`, `data/sbom/`, `data/threat_intel/`는 현재 자동 제외되지 않는다. 이 경로에는 공유 가능한 샘플만 커밋하고, 실행 산출물은 별도 제외 규칙을 정한 뒤 저장한다.
