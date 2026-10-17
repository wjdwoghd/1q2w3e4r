# 첫 Lab End-to-End 실행 가이드

작성 기준: 2026-10-14, Windows PowerShell, 저장소 `C:\1q2w3e4r`, 커밋 `f373307`.
실행할 때는 현재 브랜치·커밋과 도구 버전을 다시 기록한다.

이 문서는 **준비된 로컬 Lab 점검**과 **아직 실행하지 않은 전체 분석·검증 절차**를 구분한다.
기존 Log4Shell Lab의 서비스·빌드·호스트 실행 도구가 준비됐다. 단계별 확인 기록은
[첫 Lab 전체 점검표](lab_e2e_checklist.md)를 함께 사용한다.

## 1. 현재 준비 상태

| 항목 | 이번에 확인한 결과 | 해석 |
| --- | --- | --- |
| 작업 트리 | 앞서 작성한 미커밋 문서 변경 보존 | Lab 준비는 추가 변경으로 남김 |
| Python | `.venv`의 Python 3.12.10 | 프로젝트의 Python 3.10 이상 조건 충족 |
| 패키지 | `packageurl-python==0.17.6`, `pip check` 정상 | 기존 의존성 유지 |
| 전체 테스트 | 170개 통과 | 기존 163 + Lab 신규 7; 실제 Java·Syft 경로 포함 |
| Docker | Docker 29.7.2, Compose v5.5.1 | Compose config 정상; 데몬·WSL2 조건 미충족으로 컨테이너 기동 미검증 |
| Syft·Java·Maven | Git 제외 경로에 휴대용 도구 준비 | Syft 1.54.1, JDK 17.0.20.1, Maven 3.9.11; 시스템 PATH 변경 없음 |
| Log4Shell Lab | 공통 서비스·Before/After 빌드·호스트 도구·Compose 준비 | 두 실제 버전·HTTP·SBOM 경로 검증 |
| 기본 시나리오 | 선언된 가상 금융 Context·범위·버전·테스트 ID 작성 | 실제 CVSS·KEV·판정·위험 결과는 미확인 |
| 일반 CLI | 생성·가져오기·동기화·위험 계산·검증 스크립트 0바이트 | 호출 종료 코드 0을 기능 성공으로 해석 금지 |
| 실조회 점검 CLI | `scripts/verify_phase4_live.py` 구현됨 | fixture + 외부 조회 + 메모리 DB 점검; 실제 Lab E2E가 아님 |

초기 문서 작업은 읽기·기본 점검만 수행했다. 이후 Lab 준비에서 공식 체크섬이 확인된
휴대용 도구 다운로드, 두 빌드, localhost 기동·기능·버전·포트 충돌·종료, 실제 Syft
생성→파싱→정규화→저장→Diff를 확인했다. 실제 CVE/KEV 조회·AI API·플랫폼의 전체
조치·Verification 시도는 이번 준비에서 실행하지 않았다.

### 지금 시작할 명령: Docker 없이 호스트에서 실행

```powershell
Set-Location -LiteralPath 'C:\1q2w3e4r'
. .\labs\log4shell\tools.ps1
$taskLabTools = Get-LabToolchain
$taskLabTools | Format-List
$env:SYFT_CONFIG = (Resolve-Path -LiteralPath 'labs/log4shell/syft.yaml').Path
$env:LAB_PORT = '18081'
.\labs\log4shell\build.ps1 -Variant all
.\labs\log4shell\host.ps1 -Action Start -Variant vulnerable -Port ([int]$env:LAB_PORT)
.\labs\log4shell\host.ps1 -Action Smoke -Variant vulnerable
.\labs\log4shell\host.ps1 -Action Runtime -Variant vulnerable
```

현재 18080은 기존 Python 프로세스가 사용 중이다. 이를 종료하지 않고 다른 빈 포트를
사용한다. 터미널 A/B에 같은 `LAB_PORT`를 설정한다. 실제 실행 중인 runtime 전체가
SBOM 대상이다. Before 분석·증거·계획을 보존한 뒤 13절의 실제 교체를 진행한다.
기동과 증거 범위의 상세 설명은 [Lab README](../labs/log4shell/README.md)를 따른다.
호스트 방식에서는 9절 Docker 기동 블록을 건너뛴다.

첫 Lab 후보는 기존 `labs/log4shell/`이다. 기존 fixture의 `log4j-core 2.14.1`과
`CVE-2021-44228`을 출발점으로 삼을 수 있다. 해당 버전의 영향 범위는
[Apache 보안 공지](https://logging.apache.org/security.html#CVE-2021-44228)를 확인한다.
실제 Component Version·CVE·CVSS·KEV는 실행 시 SBOM과 기존 Matcher로 확인한다.
다른 Lab은 이 첫 End-to-End 경로가 검증된 이후로 둔다.

## 2. 전체 순서와 터미널 사용법

```text
기본 점검 → 도구 준비 → Lab 구현 → 실제 Before 기동
→ 자산 등록 → Before SBOM·전체 매칭 → Finding·통제 매핑
→ Recommendation → Remediation 계획·Before 보존
→ 실제 변경 → 적용 기록 → Verification 시도 시작
→ After SBOM·전체 재매칭·실제 기능 테스트
→ After Evidence 저장 → 기존 규칙으로 판정 → 시도별 비교
→ 실패/반복 검증 점검 → 증거 보존·Lab 종료 → 완료 조건 검토
```

- 터미널 A: 기본 점검 이후 Python 대화형 세션에서 분석 파이프라인 실행.
- 터미널 B: Lab 빌드·기동·교체·로그·종료. A와 같은 저장소 루트에서 실행.
- PowerShell 변수는 터미널 사이에서 공유되지 않는다. B에는 A의 실행 디렉터리를 입력한다.
- `powershell` 블록은 PowerShell에서, `python` 블록은 Python에서 실행한다.
- Python REPL에 함수·루프를 붙여 넣을 때는 블록 끝에 빈 줄을 넣는다.
- A가 변경 수행을 기다릴 때는 Python 세션을 종료하지 않고 B에서 조치한다.
- 네이티브 프로그램은 `$ErrorActionPreference='Stop'`만으로 실패가 차단되지 않을 수
  있으므로 `$LASTEXITCODE`도 확인한다. 실패하면 다음 단계로 넘어가지 않는다.

## 3. 기본 명령어와 작업 트리 점검

```powershell
# 터미널 A: 지금 실행 가능한 읽기 전용 점검
Set-Location -LiteralPath 'C:\1q2w3e4r'
$ErrorActionPreference = 'Stop'
Get-Location
git status --short
git branch --show-current
git rev-parse HEAD
git log -3 --oneline
git diff --check
Get-Command python, py, git, syft, docker, java, mvn -ErrorAction SilentlyContinue
Get-Item scripts/*.py, labs/log4shell/docker-compose.yml, scenarios/scenario_01_patch_delay.yaml |
    Select-Object Name, Length
```

`git status --short`에 변경이 있으면 소유자·목적을 확인하고 보존한다. 정리를 위해
`reset --hard`, `clean`, 강제 덮어쓰기 또는 임의 stash를 사용하지 않는다.
작업 브랜치·공유·병합은 [협업 원칙](github_collaboration.md)을 따른다.
이 가이드의 실행은 커밋·푸시 또는 외부 배포를 뜻하지 않는다.

## 4. Python 환경과 오프라인 기준 테스트

```powershell
# .venv가 없는 경우에만 생성. 기존 환경은 삭제하지 않는다.
if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) {
    py -3.12 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw '가상환경 생성 실패: 설치된 Python 버전 확인' }
}
$taskPython = (Resolve-Path -LiteralPath '.\.venv\Scripts\python.exe').Path
& $taskPython --version
& $taskPython -m pip --version
```

3.12가 없으면 설치된 3.10 이상 버전으로 생성 명령을 바꾼다. 활성화 스크립트의 실행
정책을 바꾸지 않고 `$taskPython` 절대경로로 실행해도 된다.

```powershell
# 요구 패키지가 없는 경우에만 설치. 네트워크 다운로드가 발생할 수 있다.
& $taskPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw '프로젝트 의존성 설치 실패' }
& $taskPython -m pip check
if ($LASTEXITCODE -ne 0) { throw '의존성 충돌' }
& $taskPython -m unittest discover -s tests -q
if ($LASTEXITCODE -ne 0) { throw '오프라인 기준 테스트 실패' }
```

현재 기준은 170개 통과다. 테스트 추가 이후에는 고정 개수보다 실제 실행 개수와 통과
여부를 기록한다. Stub 오류 주입의 `Vulnerability intelligence lookup failed` 로그가
나와도 마지막 `OK`와 종료 코드가 기준이다. 이를 실조회 장애로 기록하지 않는다.
문제가 난 영역을 구분해서 점검할 때는 다음 명령을 쓴다.

```powershell
& $taskPython -m unittest tests.unit.test_sbom tests.unit.test_normalizer -v
& $taskPython -m unittest tests.unit.test_matcher tests.unit.test_risk_engine -v
& $taskPython -m unittest tests.integration.test_findings tests.integration.test_remediation -v
& $taskPython -m unittest tests.unit.test_verification tests.integration.test_verification -v
& $taskPython -m unittest tests.unit.test_comparison tests.integration.test_comparison -v
& $taskPython -m unittest tests.integration.test_log4shell_lab -v
```

## 5. Syft·Java·Maven·Docker와 공개 조회 준비

현재 PC에서는 앞서 준비한 휴대용 도구로 아래 점검을 실행할 수 있다. 시스템 PATH의
`java`·`mvn`·`syft`가 없는 것은 이 방식의 실패가 아니다.

```powershell
. .\labs\log4shell\tools.ps1
$taskLabTools = Get-LabToolchain
& $taskLabTools.Java -version
$taskPreviousJavaHome = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $taskLabTools.JavaHome
    & $taskLabTools.Maven -version
}
finally { $env:JAVA_HOME = $taskPreviousJavaHome }
& $taskLabTools.Syft version
```

아래 일반 설치·PATH 명령은 도구가 없는 다른 PC나 시스템 설치 방식을 택한 경우에
사용한다. 현재 준비한 도구를 사용한다면 다시 설치할 필요가 없다.

| 도구 | 준비 방법 | 확인 조건 |
| --- | --- | --- |
| Syft | [Anchore Windows 설치 안내](https://oss.anchore.com/docs/guides/sbom/getting-started/) | `syft version`; 과거 저장소 실생성 검증은 1.54.1 |
| JDK | 승인한 JDK 배포의 공식 설치 절차 | `java -version`, `javac -version`; 선택한 Log4j·빌드와 호환 |
| Maven | [Apache 설치 안내](https://maven.apache.org/install.html) | `mvn -version`; 사용할 JDK가 출력되는지 확인 |
| Docker | 로컬 Linux 컨테이너 환경 | `docker version`에 Client·Server 모두 출력 |
| Compose | Docker Compose 플러그인 | `docker compose version`; Lab 설정 유효성은 별도 확인 |

Syft를 winget으로 설치할 환경이면 공식 안내의 다음 명령을 선택적으로 쓸 수 있다.
이번 문서 작성에서는 설치하지 않았다.

```powershell
winget install --id Anchore.Syft --exact
```

설치 후 새 PowerShell에서 PATH를 확인한다. PATH에 없으면 검증된 실행 파일의
절대경로를 사용한다. 임의 설치 스크립트를 다운로드해서 파이프로 실행하지 않는다.

```powershell
syft version
java -version
javac -version
mvn -version
docker context show
docker context ls
docker version
docker compose version
```

Docker context가 로컬인지 먼저 확인한다. 외부 context에서 취약 Lab을 실행하지 않는다.
TLS 검증 해제나 방화벽 전체 해제로 해결하지 않는다.
공개 조회는 기존 OSV·NVD·CISA KEV 클라이언트의 출처·수집 시점을 보존한다.
현재 클라이언트는 임의 `.env`의 `CVE_API_URL`·`KEV_URL`·NVD 키를 자동 적용하지 않는다.
미구현 설정을 넣고 적용됐다고 해석하지 않는다.

```powershell
# 연결 가능성 점검: HTTP 응답·쿼터·매칭 성공을 증명하지 않는다.
Test-NetConnection api.osv.dev -Port 443
Test-NetConnection services.nvd.nist.gov -Port 443
Test-NetConnection www.cisa.gov -Port 443

# 선택적 실조회: fixture를 쓰며 DB는 메모리에만 유지된다.
& $taskPython -m scripts.verify_phase4_live
if ($LASTEXITCODE -ne 0) { throw 'Phase 4 실조회 점검 실패' }
```

실조회 CLI의 종료 코드 0만으로 원하는 CVE가 매칭됐다고 판단하지 않는다.
`status=matched`, 식별자, CVSS·KEV와 누락 여부도 확인한다. Lab의 설치 상태·패치·
재검증을 증명하는 점검은 아니다. 반복 조회는 순차 실행하고 429가 나면 쿼터 회복 후
새 분석으로 재시도한다. 캐시는 현재 구현돼 있지 않다.

## 6. Recommendation 설정과 두 가지 실행 모드

실 AI 모드는 현재 `OpenAIRecommendationClient`를 사용한다. 키·모델·timeout은
Python 시작 전 부모 PowerShell의 환경변수에 설정한다. `.env`는 Git 제외 대상이지만
현재 클라이언트에 자동 dotenv 로더는 없다. 새 패키지 없이 키를 화면·명령 이력에
남기지 않는 입력 예는 다음과 같다. Transcript가 실행 중일 때 입력하지 않는다.

```powershell
# 실 AI 호출을 선택하는 경우만, Python 시작 전에 실행
$taskSecureKey = Read-Host 'OpenAI API Key' -AsSecureString
$taskKeyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecureKey)
try { $env:OPENAI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskKeyPointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskKeyPointer) }
$env:OPENAI_RECOMMENDATION_MODEL = Read-Host '사용 가능한 Recommendation 모델명'
$env:OPENAI_TIMEOUT_SECONDS = '30'
Remove-Variable taskSecureKey, taskKeyPointer
```

실 AI 호출이 준비되지 않으면 뒤의 로컬 제안 선택 예로 저장·연결만 점검할 수 있다.
실행 기록에 `local-plan-demo`를 남기고 실제 AI 연동을 검증했다고 표시하지 않는다.
어느 모드에서도 CVE·CVSS·KEV·패치 적용·Verification 결과를 AI나 Stub가 만들지 않는다.
AI 출력은 허용된 개선 제안·향후 검증 단계에만 사용한다.

## 7. 먼저 구현해야 하는 Lab 계약

아래 계약은 기존 Log4Shell Lab에 구현됐다. 실행 환경·실제 산출물·증거를 다시 확인한
이후 전체 분석·조치·검증을 진행한다. 다른 Lab의 구현 상태를 뜻하지 않는다.

| 위치·영역 | 첫 Lab에 필요한 최소 내용 |
| --- | --- |
| `vulnerable/` | Maven 프로젝트, 실제 Java 서비스, Log4j API/Core 의존성, 재현 가능한 빌드 |
| `patched/` | 동일 기능·테스트를 유지하는 프로젝트, 검토한 변경 버전, 별도 빌드 산출물 |
| Compose | `vulnerable`·`patched` 서비스, 고정한 런타임·이미지 기준, healthcheck |
| 분석 대상 | 실제 애플리케이션 JAR·전체 classpath 의존성의 실행 범위·배치 경로 |
| 포트 | 호스트 `127.0.0.1:18080`; 같은 포트에 두 상태를 동시에 기동하지 않음 |
| 기본 기능 | `GET /health` → HTTP 200 + `{"status":"ok"}` |
| 업무 점검 | `GET /banking/smoke` → HTTP 200 + `{"result":"ok","mode":"synthetic"}` |
| 데이터 | 가상의 고정 데이터만 사용; 실제 계좌·고객·신용정보 없음 |
| 시나리오 | Context, 범위, 변경 목표, 검증 테스트 ID, 담당자, 증거 정책 |
| README | 실제 버전·CVE·목적·빌드·기동·종료·변경·롤백·검증 방법 |

두 HTTP 경로·응답은 공통 Java 서비스에 구현돼 있고 호스트 방식에서 실제 검증했다.
건강 점검만으로 업무 기능 검증을 대체하지 않도록 별도 테스트를 둔다.
Compose 포트는 `ports: ["127.0.0.1:18080:8080"]`처럼 호스트 주소를 명시한다.
주소를 생략하면 전체 인터페이스에 게시될 수 있다.
[Docker 서비스·포트 문서](https://docs.docker.com/reference/compose-file/services/).
host network·privileged 모드·플랫폼 `.env`·Docker socket 마운트는 필요하지 않다.

개선 버전은 실행 시점의 [Apache 보안 공지](https://logging.apache.org/security.html)와
Java 호환성을 검토해 고정한다. 특정 CVE를 고친 최초 버전이나 기존 테스트 버전을
전체 취약점이 없는 버전으로 해석하지 않는다. 새 CVE도 그대로 기록한다.

POM만 분석해서 실행 JAR을 검증했다고 하지 않는다. 전이 의존성·중복 설치·실제
mount/classpath를 확인한다. 빌드 출력과 실행 파일이 다르면 중단한다.
자산 범위가 Java 애플리케이션이면 JDK·컨테이너 OS의 별도 범위를 명시한다.
매칭 불가능한 구성요소를 임의로 제외해 전체 분석 성공을 만들지 않는다.

## 8. 실행별 산출물 디렉터리

```powershell
# 터미널 A: 실제 실행 시작 시 한 번 생성
$taskRunId = 'lab-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$taskRunDir = Join-Path (Get-Location) ('data\output\lab-e2e\' + $taskRunId)
New-Item -ItemType Directory -Path $taskRunDir | Out-Null
$env:LAB_E2E_RUN_DIR = $taskRunDir
$taskRunDir
git check-ignore -- data/output/lab-e2e/probe.json
git check-ignore -- .env .venv/probe.txt
```

기존 Git 제외 경로인 `data/output/`를 사용한다. 실행마다 별도 디렉터리를 만들고
기존 Before·After·선택 ID·로그를 덮어쓰지 않는다.

```text
data/output/lab-e2e/<run-id>/
├── environment.txt             # 커밋·도구·담당자·실행 모드·분석 범위
├── lab.db                      # 이번 실행 전용 SQLite
├── before-sbom.json            # 실제 생성 결과
├── before-matches.json         # 발생별 실행·출처·수집 시점
├── before-functional.json      # 개선 전 실제 기능 결과
├── before-selection.json       # 자산·발생·실행·Finding·관측·조치 ID
├── application.log             # 실제 변경 명령의 수행 기록
├── application.json            # 담당자·적용 시점·참조
├── after-sbom.json
├── after-matches.json
├── after-functional.json
├── verification-selection.json # 선택한 시도 ID와 필수 테스트
├── comparison.json             # Phase 10 결과
├── asset-comparison.json
└── runtime-hashes.csv          # 실행 JAR SHA-256·경로
```

`environment.txt`는 확인한 명령 결과와 담당자 메모로 작성한다. 버전·성공 결과를
미리 채우지 않는다. API Key·Token·환경변수 전체를 로그에 출력하지 않는다.
대형 SBOM·DB·로그는 Git에 추가하지 않고 공유할 작은 샘플만 민감정보를 제거해 준비한다.

## 9. Lab 구현 후 Before 빌드·기동

Docker를 쓰는 경우의 절차다. 현재 PC에서는 데몬·WSL2 조건이 준비되지 않아 이 기동
경로는 미검증이다. 호스트 방식을 쓰면 앞의 빠른 시작 명령 후 10절로 진행한다.

```powershell
# 터미널 B
Set-Location -LiteralPath 'C:\1q2w3e4r'
$ErrorActionPreference = 'Stop'
$taskRunDir = Read-Host '터미널 A의 실행 디렉터리 절대경로'
if (-not (Test-Path -LiteralPath $taskRunDir -PathType Container)) { throw '실행 디렉터리 없음' }
$taskCompose = 'labs/log4shell/docker-compose.yml'
if ((Get-Item -LiteralPath $taskCompose).Length -eq 0) { throw 'Lab Compose 미구현' }
if (-not (Test-Path -LiteralPath 'labs/log4shell/vulnerable/pom.xml')) { throw 'Before Maven 프로젝트 미구현' }
docker compose -p sbom-log4shell -f $taskCompose config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose 설정 오류' }
mvn -B -f labs/log4shell/vulnerable/pom.xml clean package dependency:copy-dependencies '-DincludeScope=runtime'
if ($LASTEXITCODE -ne 0) { throw 'Before 빌드 실패' }
mvn -B -f labs/log4shell/vulnerable/pom.xml dependency:tree
if ($LASTEXITCODE -ne 0) { throw '의존성 트리 확인 실패' }
docker compose -p sbom-log4shell -f $taskCompose up -d --build --wait --wait-timeout 120 vulnerable
if ($LASTEXITCODE -ne 0) { throw 'Before 기동·healthcheck 실패' }
docker compose -p sbom-log4shell -f $taskCompose ps
docker compose -p sbom-log4shell -f $taskCompose port vulnerable 8080
Invoke-RestMethod -Uri ('http://127.0.0.1:' + $env:LAB_PORT + '/health') -TimeoutSec 10
```

Maven `copy-dependencies`는 실제 의존 JAR을 복사하는 목표이며 SBOM 생성 명령이
아니다.[ Maven 공식 설명](https://maven.apache.org/plugins/maven-dependency-plugin/copy-dependencies-mojo.html).
최종 runtime 배치는 Lab의 빌드 계약으로 정한다. Docker 내부에서 빌드하는 계약이면
호스트 Maven 명령을 생략하고 사용한 빌드 이미지 digest·도구를 기록한다.
이 Lab의 준비된 호스트 런타임 경로는 `vulnerable/target/runtime`과
`patched/target/runtime`이다. 다른 배치 방식을 택하면 실제 실행 파일과 다시 대조한다.

`port`가 선택한 `127.0.0.1:<LAB_PORT>` 이외의 외부 공개 주소면 중단한다. 실제 runtime 전체
경로·classpath·JAR 해시를 기록한다. 파일 해시는 실행 파일과 같은지 확인하는 근거다.

```powershell
$taskRuntime = Read-Host '실제 Before runtime 전체 디렉터리 절대경로'
$taskRuntime = (Resolve-Path -LiteralPath $taskRuntime).Path
Get-ChildItem -LiteralPath $taskRuntime -Filter '*.jar' -Recurse -File |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv -LiteralPath (Join-Path $taskRunDir 'runtime-hashes.csv') -NoTypeInformation -Encoding UTF8
```

## 10. Python 파이프라인 공통 준비

터미널 A에서 Python을 시작한다. 뒤의 Python 블록은 같은 세션에서 순서대로 실행한다.

```powershell
& $taskPython
```

아래 예제는 현재 core의 호출 계약을 사용한다. **실제 Lab을 대상으로 한 일괄 실행은
아직 검증하지 않았다.** 차후 실행 orchestrator는 `scripts/`에서 core를 호출해야 하며,
Matcher·Risk·Verification을 중복 구현하지 않는다. 지금 비어 있는 CLI에 존재하지 않는
옵션을 붙이지 않는다.

```python
import json
import os
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from core.assets.asset_service import AssetService
from core.compliance.service import ControlMappingService
from core.consulting.openai_client import OpenAIRecommendationClient
from core.consulting.recommender import RecommendationService
from core.findings.service import FindingService
from core.remediation.service import RemediationService
from core.sbom.generator import generate_cyclonedx_json
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom
from core.verification.comparison import ComparisonService
from core.verification.service import VerificationService
from core.vulnerability.cve_client import NVDClient, OSVClient
from core.vulnerability.kev_client import KEVClient
from core.vulnerability.matcher import MatchStatus, match_component_to_cves
from database.database import connect_database, initialize_database
from database.models.verification import FunctionalEvidence, FunctionalStatus
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.comparison_repository import SQLiteComparisonRepository
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.remediation_repository import SQLiteRemediationRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.verification_repository import SQLiteVerificationRepository, evidence_json
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository

run_dir = Path(os.environ['LAB_E2E_RUN_DIR']).resolve()
run_id = run_dir.name
lab_port = int(os.environ.get('LAB_PORT', '18080'))
if not 1024 <= lab_port <= 65535:
    raise ValueError('잘못된 로컬 Lab 포트')
lab_address = f'http://127.0.0.1:{lab_port}'
os.environ['SYFT_CONFIG'] = str(Path.cwd() / 'labs/log4shell/syft.yaml')
db_path = run_dir / 'lab.db'
if db_path.exists():
    raise RuntimeError('기존 실행 DB 있음: 신규 실행과 재개를 구분하세요')
connection = connect_database(db_path)
initialize_database(connection)
assets = SQLiteAssetRepository(connection)
sboms = SQLiteSBOMRepository(connection)
matches = SQLiteVulnerabilityRepository(connection)
findings = SQLiteFindingRepository(connection)
mappings = SQLiteControlMappingRepository(connection)
recommendations = SQLiteRecommendationRepository(connection)
remediations = SQLiteRemediationRepository(connection)
verifications = SQLiteVerificationRepository(connection)
asset_service = AssetService(assets)
finding_service = FindingService(findings, matches, assets)
mapping_service = ControlMappingService(findings, mappings)
remediation_service = RemediationService(findings=findings, recommendations=recommendations,
                                       remediations=remediations)
verification_service = VerificationService(findings=findings, recommendations=recommendations,
                                           remediations=remediations, matches=matches,
                                           verifications=verifications)
comparison_service = ComparisonService(SQLiteComparisonRepository(connection))
osv, nvd, kev = OSVClient(), NVDClient(), KEVClient()
required_tests = ('health-contract', 'banking-api-smoke')

def write_once(name, value):
    with (run_dir / name).open('x', encoding='utf-8') as output:
        output.write(evidence_json(value))

def collect_functional(sbom_id):
    contracts = (
        ('health-contract', '/health', {'status': 'ok'}),
        ('banking-api-smoke', '/banking/smoke', {'result': 'ok', 'mode': 'synthetic'}),
    )
    evidence = []
    observations = []
    for test_id, route, expected in contracts:
        address = lab_address + route
        try:
            with urlopen(address, timeout=10) as response:
                body = json.load(response)
                status = FunctionalStatus.PASSED if response.status == 200 and body == expected else FunctionalStatus.FAILED
            detail = {'response': body, 'expected': expected}
        except HTTPError as error:
            status, detail = FunctionalStatus.FAILED, {'http_status': error.code}
        except (URLError, TimeoutError, OSError) as error:
            status, detail = FunctionalStatus.ERROR, {'error_type': type(error).__name__}
        except (ValueError, UnicodeError) as error:
            status, detail = FunctionalStatus.FAILED, {'invalid_response': type(error).__name__}
        collected = datetime.now(timezone.utc).isoformat()
        reference = str(run_dir / f'functional-{sbom_id}-{test_id}.json')
        observations.append((Path(reference).name, {'url': address, 'test_id': test_id,
                             'asset_id': asset.id, 'sbom_id': sbom_id, 'status': status.value,
                             'collected_at': collected, **detail}))
        evidence.append(FunctionalEvidence(asset.id, sbom_id, test_id, status,
                        'local HTTP contract check', reference, collected))
    for filename, observation in observations:
        write_once(filename, observation)
    return tuple(evidence)
```

기능 테스트 예제는 실제 HTTP 결과로 상태를 만들며 고정 Passed를 입력하지 않는다.
Lab의 업무 계약이 바뀌면 필수 테스트·기대 응답을 먼저 검토한다. 빈 필수 테스트 목록을
쓰거나 AI의 계획 문장을 실행된 증거로 바꾸지 않는다.

## 11. 자산 등록·Before SBOM·전체 발생 분석

이 예제의 Context는 로컬 개발 환경이다. 고위험 금융서비스 모의 Context가 필요하면
별도 시나리오에 그 가정을 명시한다. `production`·인터넷 공개를 실제 Lab의 사실로
잘못 등록하지 않는다. 실제 금융·개인정보는 사용하지 않는다.

```python
business = asset_service.register_business_service('Synthetic Banking Lab')
asset = asset_service.register_asset(
    business.id, name='Local Log4j Banking API', environment='development',
    internet_exposed=False, business_criticality='low', customer_information=False,
    credit_information=False, patch_status='unknown', vendor='Isolated lab', owner='Lab operator',
)
before_runtime = Path(input('실제 Before runtime 전체 디렉터리: ')).resolve()
if not before_runtime.is_dir():
    raise ValueError('Before runtime 디렉터리 없음')
syft_executable = input('검증한 Syft 실행 파일 절대경로 또는 PATH 이름: ').strip()
if not syft_executable:
    raise ValueError('Syft 실행 파일 필요')
generated_before = generate_cyclonedx_json(before_runtime, executable=syft_executable)
before_collected = datetime.now(timezone.utc).isoformat()
with (run_dir / 'before-sbom.json').open('x', encoding='utf-8') as output:
    output.write(generated_before.content)
parsed_before = parse_sbom(generated_before.content)
normalized_before = normalize_components(parsed_before.components)
before_sbom = sboms.save(asset_id=asset.id, source=generated_before.source,
                        raw_document=generated_before.content, parsed=parsed_before, normalized=normalized_before)
before_components = sboms.list_components(before_sbom.id)
before_runs = []
for component, normalized in zip(before_components, normalized_before.components):
    result = match_component_to_cves(normalized, osv=osv, nvd=nvd, kev=kev)
    before_runs.append(matches.save(component_id=component.id, analysis_key=run_id + ':before', result=result))
write_once('before-matches.json', [asdict(run) for run in before_runs])
print(Counter(run.result.status.value for run in before_runs))
if not before_components or any(run.result.status not in (MatchStatus.MATCHED, MatchStatus.NO_MATCH) for run in before_runs):
    raise RuntimeError('Before 전체 분석 부족: 저장된 상태·이유 확인 필요')
for run in before_runs:
    if run.result.status is MatchStatus.MATCHED:
        finding_service.create_from_match_run(asset_id=asset.id, match_run_id=run.id)
before_functional = collect_functional(before_sbom.id)
write_once('before-functional.json', [asdict(item) for item in before_functional])
if any(item.status is not FunctionalStatus.PASSED for item in before_functional):
    raise RuntimeError('Before 기본 기능 실패: 정상 비교 기준을 준비하세요')
```

Wrapper는 `cyclonedx-json@1.6`을 사용한다. 현재 Parser는 1.4/1.5/1.6 JSON을 지원하며,
Syft의 기본 최신 형식이나 XML을 그대로 넣지 않는다.
[Anchore 출력 형식](https://oss.anchore.com/docs/guides/sbom/formats/).
빈 `generate_sbom.py`에 `--target` 같은 미구현 옵션을 붙이지 않는다.

MATCHED라도 CVSS가 없으면 Finding 생성이 중단된다. 0점으로 대체하지 않는다.
NO_MATCH는 OSV 조회 결과이며 안전 인증이 아니다. 중복 발생도 각각 저장한다.
원래 수집 시점은 별도 실행 기록에 남길 수 있지만 현행 Before Snapshot에 없는
필드를 소급해 넣지 않는다.

## 12. 특정 Finding·관측 선택·Recommendation·조치 계획

```python
target_cve = 'CVE-2021-44228'
candidates = [run for run in before_runs if any(match.cve.cve_id == target_cve for match in run.result.matches)]
print([(run.id, run.component_id, run.result.component_purl) for run in candidates])
selected_run_id = int(input('위 목록에서 조사할 정확한 match run ID: '))
selected_run = next(run for run in candidates if run.id == selected_run_id)
target_finding = findings.get_by_asset_cve(asset.id, target_cve)
observation = next(item for item in target_finding.observations if item.match_run_id == selected_run.id)
print(observation.id, observation.risk.cvss_score, observation.risk.score,
      observation.risk.priority, observation.risk.reasons, observation.risk.unassessed_factors)
mapping_service.map_finding(target_finding.id)
```

후보가 없으면 대상 CVE를 아직 확인하지 못한 것이다. 코드·README의 CVE 문자열을
근거로 Finding을 추가하지 않는다. 같은 자산·CVE는 하나의 Finding이지만 분석 관측은
각각 남는다. 최신 관측을 자동 선택하지 않는다. CVSS와 내부 점수·Priority를 구분하고
위험 가중치·경계값은 [Risk 문서](risk_model.md)와 기존 core에 맡긴다.

실 AI 모드를 선택했다면 다음을 사용한다.

```python
generator = OpenAIRecommendationClient()
recommendation_mode = 'live-openai'
```

로컬 연결 점검 모드를 선택했다면 위 블록 대신 아래를 사용한다. 실 AI 호출의 검증
결과가 아니며 CVE·Scanner·기능 결과를 생성하는 Stub도 아니다.

```python
from core.consulting.prompts import ACTION_OPTIONS

class LocalPlanGenerator:
    model = 'local-plan-demo'
    def generate(self, input_data):
        return {field: [options[0]] for field, options in ACTION_OPTIONS.items()}

generator = LocalPlanGenerator()
recommendation_mode = 'local-plan-demo'
```

선택한 generator로 기존 서비스를 호출한다. API 실패·출력 검증 오류는 임의 문장으로
바꿔 성공 처리하지 않는다. 공식 인증·규정 준수 판정으로 통제 매핑을 해석하지 않는다.

```python
recommendation_service = RecommendationService(findings=findings, mappings=mappings,
                           matches=matches, recommendations=recommendations, generator=generator)
recommendation = recommendation_service.create_for_observation(observation.id)
planned_action = input('검토한 변경 내용·대상 버전·롤백 방법 요약: ').strip()
owner = input('변경 담당자: ').strip()
plan = remediation_service.create_plan(
    finding_id=target_finding.id, observation_id=observation.id,
    recommendation_id=recommendation.id, action_key=run_id + ':upgrade',
    planned_action=planned_action, owner=owner,
)
write_once('before-selection.json', {
    'run_id': run_id, 'asset_id': asset.id, 'before_sbom_id': before_sbom.id,
    'before_collected_at': before_collected, 'component_id': selected_run.component_id,
    'match_run_id': selected_run.id, 'finding_id': target_finding.id,
    'observation_id': observation.id, 'recommendation_id': recommendation.id,
    'recommendation_mode': recommendation_mode, 'remediation_id': plan.id,
    'before': asdict(plan.before),
})
```

계획 작성은 실제 적용을 의미하지 않는다. Before의 Component·Version·PURL·CVE,
관측·증거 ID, Risk·이유·규칙 버전이 맞는지 확인한다. 여기서 A는 대기하고 B에서
실제로 조치한다. Before를 After 버전으로 덮어쓰지 않는다.

## 13. 실제 변경·적용 증거·Verification 시작

patched 코드·POM·런타임 배치를 먼저 준비한다. 아래 예제는 7절의 Lab 계약에 따른다.

```powershell
# 터미널 B, 호스트 방식. A와 같은 LAB_PORT를 설정한다.
# Docker 방식이면 아래 build/Stop/Start/Smoke를 Lab README의 Docker 명령으로 바꾼다.
$env:LAB_PORT = '18081'
Start-Transcript -LiteralPath (Join-Path $taskRunDir 'application.log') -NoClobber
try {
    .\labs\log4shell\build.ps1 -Variant patched
    .\labs\log4shell\host.ps1 -Action Stop -Variant vulnerable
    .\labs\log4shell\host.ps1 -Action Start -Variant patched -Port ([int]$env:LAB_PORT)
    .\labs\log4shell\host.ps1 -Action Smoke -Variant patched
    $taskAppliedAt = [DateTime]::UtcNow.ToString('o')
}
finally { Stop-Transcript }
```

실패하면 아래 적용 완료 기록을 만들지 않는다. 실제 실행 이미지·mount/classpath와
새 산출물이 일치하는지 확인한다. 롤백은 Lab의 정해진 절차로 수행하고 실패 로그를 보존한다.
호스트 Maven 대신 컨테이너 빌드 계약이면 해당 Maven 명령은 생략한다.

```powershell
$taskApplication = @{
    action = 'Lab의 patched 빌드를 같은 서비스 대상으로 적용하고 기동함'
    actor = (Read-Host '실제 변경 담당자')
    applied_at = $taskAppliedAt
    evidence_type = 'change_execution_log'
    evidence_reference = (Join-Path $taskRunDir 'application.log')
    evidence_source = 'local Lab operation transcript'
}
$taskApplicationPath = Join-Path $taskRunDir 'application.json'
if (Test-Path -LiteralPath $taskApplicationPath) { throw '적용 증거 존재: 덮어쓰기 금지' }
[IO.File]::WriteAllText($taskApplicationPath, ($taskApplication | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
```

Python의 A에서 실제 기록을 등록한다. 소스 내용이나 단순 계획을 적용 증거로 대체하지
않는다. 날짜를 과거로 바꾸거나 수집 시점을 임의 조정해 판정을 맞추지 않는다.

```python
application = json.loads((run_dir / 'application.json').read_text(encoding='utf-8'))
applied = remediation_service.record_application(plan.id, **application)
attempt = verification_service.start(remediation_id=plan.id, asset_id=asset.id,
          attempt_key=run_id + ':verify-1', required_functional_tests=required_tests)
write_once('verification-selection.json', {'asset_id': asset.id, 'finding_id': target_finding.id,
           'remediation_id': plan.id, 'verification_id': attempt.id,
           'attempt_key': attempt.attempt_key, 'required_functional_tests': list(required_tests)})
```

적용 증거는 변경을 수행했다는 기록이며 CVE 제거를 증명하지 않는다. 검증 시작 시
Before·원본 SBOM·적용 기록 사본이 고정된다. 필수 테스트 ID는 실행자가 명시한다.

## 14. After 생성·전체 재매칭·실제 기능 검사·판정·비교

```python
after_runtime = Path(input('실제 After runtime 전체 디렉터리: ')).resolve()
if not after_runtime.is_dir():
    raise ValueError('After runtime 디렉터리 없음')
generated_after = generate_cyclonedx_json(after_runtime, executable=syft_executable)
after_collected = datetime.now(timezone.utc).isoformat()
with (run_dir / 'after-sbom.json').open('x', encoding='utf-8') as output:
    output.write(generated_after.content)
parsed_after = parse_sbom(generated_after.content)
normalized_after = normalize_components(parsed_after.components)
after_sbom = sboms.save(asset_id=asset.id, source=generated_after.source,
                       raw_document=generated_after.content, parsed=parsed_after, normalized=normalized_after)
after_components = sboms.list_components(after_sbom.id)
after_runs = []
for component, normalized in zip(after_components, normalized_after.components):
    result = match_component_to_cves(normalized, osv=osv, nvd=nvd, kev=kev)
    after_runs.append(matches.save(component_id=component.id, analysis_key=run_id + ':after', result=result))
write_once('after-matches.json', [asdict(run) for run in after_runs])
after_functional = collect_functional(after_sbom.id)
write_once('after-functional.json', [asdict(item) for item in after_functional])
verification_service.record_after(
    attempt.id, asset_id=asset.id, sbom_id=after_sbom.id,
    sbom_collected_at=after_collected, sbom_reference=str(run_dir / 'after-sbom.json'),
    match_run_ids=tuple(run.id for run in after_runs), scanner_results=(),
    functional_tests=after_functional,
)
completed = verification_service.complete(attempt.id)
print(completed.id, completed.status.value, completed.decision.rule_version)
print(completed.decision.reasons)
comparison = comparison_service.compare_finding(
    asset_id=asset.id, finding_id=target_finding.id,
    remediation_id=plan.id, verification_id=attempt.id,
)
write_once('comparison.json', comparison)
asset_comparison = comparison_service.compare_asset(
    asset_id=asset.id, selections=((target_finding.id, plan.id, attempt.id),),
)
write_once('asset-comparison.json', asset_comparison)
print({name: metric['delta'] for name, metric in comparison['finding'].items()})
connection.close()
```

After 분석의 Error/Ambiguous/Unmatched나 기능 Failed/Error는 그대로 Evidence에
저장해 Failed 이유를 남긴다. 문제 있는 결과를 삭제해서 성공으로 만들지 않는다.
SBOM 생성 자체가 실패했다면 진단 로그를 보존한다. 빈 After 수집 결과를 기록하고
Failed로 완료하는 계약은 [검증 문서](verification.md)를 따른다.

이 예제는 전체 발생 재매칭을 사용하며 Scanner는 실행하지 않았으므로 빈 tuple로
표시한다. 미실행 Scanner의 `Not Detected`를 만들지 않는다. 실제 Scanner를 추가하려면
실제 결과와 adapter가 필요하며 현재 실행 도구는 미구현이다. 필수 입력은 다음과 같다.

| Scanner 필드 | 확인할 내용 |
| --- | --- |
| asset_id / sbom_id | 같은 자산·정확한 After SBOM의 실제 ID |
| cve_id / status | 검사한 CVE, 실제 결과에 대응하는 ScannerStatus |
| source / reference | 실행 도구·버전·작업 및 실제 결과 파일 참조 |
| collected_at | 실제 수집 시점, 시간대 포함 |
| scope | 대상 CVE에 대한 전체 자산 검사이면 `asset`; 부분 검사는 전체 증거로 바꾸지 않음 |

원래 규칙의 Passed 조건은 [Verification 계약](verification.md)을 따른다. 적어도
구성요소 변경, 기존 CVE의 완전 재분석 또는 독립 재검사, 필수 기능 Passed,
출처·시점이 필요하다. 제공된 탐지·Error·모순을 무시하지 않는다.

```text
실제 적용 시점 <= After SBOM 수집 <= 재매칭·기능/Scanner 수집 <= After Evidence 기록
```

Before와 별도의 After SBOM ID를 사용한다. 남아 있는 동일 패키지의 모든 발생을
확인한다. 시간대 없는 값·미래 수집·오래된 결과를 새 수집으로 바꾸는 행위는 금지한다.

Phase 10은 [비교 계약](before_after.md)에 따라 선택한 시도만 읽는다. After Risk·EOL이나
전체 Before 취약점 분석 사본이 없으면 `None`과 이유가 정상 출력이다. 이번 외부 파일에
저장한 Before 전체 매칭을 현행 비교가 자동으로 시도 내 불변 자료로 사용하는 것은 아니다.
대상 CVE의 Scanner 미탐지는 자산 전체 CVE 수 0을 증명하지 않는다. CVE 제거만으로
Risk 0·P4·EOL False를 만들지 않는다. 기능 실패이면 유효한 CVE 감소와 Failed가 공존할 수 있다.

## 15. Failed·반복 검증·조회 재개

- Failed는 원래 판정·이유를 보존한다. 같은 시도의 증거를 수정해 성공으로 바꾸지 않는다.
- 재시도는 새 `attempt_key`와 실제로 재수집한 After 증거를 사용한다.
- 추가 변경은 별도 Remediation 계획·적용 기록으로 관리한다.
- 다른 CVE가 남으면 대상 CVE 검증과 잔여 위험을 구분한다.
- Risk Accepted는 승인 절차가 미구현이므로 Failed의 대체 상태로 사용하지 않는다.
- REPL이 종료되면 저장한 선택 ID로 재개한다. 증거 DB를 삭제해 다시 성공을 만들지 않는다.
- 실조회 자료는 시간에 따라 바뀐다. 결정성은 같은 저장된 시도·증거로 조회해서 점검한다.

과거 결과를 조회하는 예제다. 최신 시도나 최신 데이터를 자동 선택하지 않는다.

```python
# 새 Python 세션에서 읽기 전용 비교
import json
from pathlib import Path
from database.database import connect_database
from database.repositories.comparison_repository import SQLiteComparisonRepository
from core.verification.comparison import ComparisonService

run_dir = Path(input('조회할 기존 실행 디렉터리: ')).resolve()
db_path = run_dir / 'lab.db'
if not db_path.is_file():
    raise ValueError('선택한 실행 DB 없음')
selected = json.loads((run_dir / 'verification-selection.json').read_text(encoding='utf-8'))
connection = connect_database(db_path)
service = ComparisonService(SQLiteComparisonRepository(connection))
selection = {name: selected[name] for name in ('asset_id', 'finding_id', 'remediation_id', 'verification_id')}
first = service.compare_finding(**selection)
second = service.compare_finding(**selection)
assert first == second
print(first['verification'])
connection.close()
```

`connect_database`는 없는 파일을 만들 수 있으므로 재개 전에 존재 여부를 확인한다.
같은 Before/After 범위가 아닌 시도는 공동 집계하지 않고 비교 불가 사유를 남긴다.
진행 중 시도의 재개는 기존 서비스 계약·선택 ID를 확인한 후 빠진 단계부터 실행한다.
이미 저장된 파일에 `write_once`가 실패하면 덮어쓰지 않고 기존 증거를 확인한다.

## 16. 장애별 점검 항목

| 증상 | 점검·처리 |
| --- | --- |
| ModuleNotFoundError | 저장소 루트, `.venv` Python, pip check, 요구 패키지 |
| 빈 CLI가 출력 없이 종료 | 0바이트 미구현 여부; 종료 코드 0을 기능 성공으로 해석 금지 |
| SBOM generator not found | Syft PATH·절대경로·권한·version |
| SBOM 형식 비지원 | JSON·specVersion·Wrapper의 1.6 출력 |
| 이름·Version·PURL 부족 | 실제 JAR metadata, 분석 범위, 중복 ref, Normalizer issues |
| 429·Timeout·HTTP 오류 | 출처·이유 보존, 쿼터·연결·TLS, 이후 새 분석 키로 재수집 |
| UNMATCHED·AMBIGUOUS | 지원 생태계, 버전 PURL, OSV alias; CPE를 추측하지 않음 |
| CVSS·KEV 부족 | NVD metric·완전 KEV snapshot; Risk 0으로 대체 금지 |
| Before에서 대상 CVE 없음 | 실 JAR·SBOM·PURL·실조회 대조; 임의 CVE 생성 금지 |
| After에 이전 버전 잔존 | 오래된 image/tag·mount·fat JAR·중복 의존·실 classpath |
| Finding 중복 증가 | 같은 asset+CVE인지, 새 자산을 임의 등록했는지 |
| 소속 오류 | Asset→SBOM→Component→Match→Finding→관측→Recommendation→Remediation ID |
| 기존 DB 초기화 오류 | [DB 문서](database.md)의 필요 migration·백업; 새 실행 전용 DB와 구분 |
| Verification Failed | 저장된 이유별로 변경·전체 분석·수집 시점·기능 결과 점검 |
| After 내용 충돌 | 같은 시도 수정 불가; 새 시도와 실제 재수집 자료 |
| delta가 None | unknown_reason·comparison_reason 확인; 0으로 치환 금지 |
| 포트 충돌 | Before 종료·기존 서비스 확인; 외부 공개로 회피하지 않음 |
| Docker 연결 실패 | 데몬·로컬 Linux context·플러그인; 외부 서버로 임의 이전 금지 |

## 17. 증거 보존·종료·최종 확인

Python 연결을 닫고 로그·DB·JSON·실행 파일 해시를 보존한다. 동작 중 SQLite 파일을
단순 복사하지 않는다. 연결 종료 후 복사하거나 필요한 경우 표준 SQLite backup API를
사용한다. After runtime 해시도 별도 파일에 저장해 Before 해시를 덮어쓰지 않는다.

```powershell
# 터미널 B: 호스트 방식 종료
.\labs\log4shell\host.ps1 -Action Stop -Variant vulnerable
.\labs\log4shell\host.ps1 -Action Stop -Variant patched

# Docker 방식에서만 이 전용 Compose 프로젝트 종료
docker compose -p sbom-log4shell -f $taskCompose logs --no-color --tail 200
docker compose -p sbom-log4shell -f $taskCompose down
if ($LASTEXITCODE -ne 0) { throw 'Lab 종료 실패' }
docker compose -p sbom-log4shell -f $taskCompose ps
Get-FileHash -LiteralPath (Join-Path $taskRunDir 'before-sbom.json') -Algorithm SHA256
Get-FileHash -LiteralPath (Join-Path $taskRunDir 'after-sbom.json') -Algorithm SHA256
git status --short
git diff --check
```

호스트 방식만 사용했다면 Docker 종료·logs 명령은 실행하지 않는다. 호스트 도구는
기동별 stdout/stderr를 `data/output/log4shell-host/`에 보존한다.
로그는 실제 파일에 저장하고 출처·시점을 적는다. 필요 시 Compose `logs`의 결과를
새 파일로 보존하되 민감정보를 출력하지 않는다.
[Compose logs](https://docs.docker.com/reference/cli/docker/compose/logs/),
[Compose down](https://docs.docker.com/reference/cli/docker/compose/down/).
`down -v`, 전체 prune, 재귀 삭제는 기본 절차에 포함하지 않는다.

Lab·연계 코드를 바꾼 작업에서는 마지막에 전체 오프라인 테스트도 실행한다.
점검표의 완료 항목마다 실제 증거 경로·ID·시점을 연결한다. ROADMAP은 확인한 항목만
갱신한다. 문서 작성·도구 설치·오프라인 테스트·실 Lab SBOM·실 API·실제 조치·실제 기능
테스트·Evidence 판정은 서로 다른 실적이다. 첫 Lab E2E 증거가 갖춰진 뒤 Phase 11
Dashboard로 진행하고 Phase 12 보고서는 별도 작업으로 둔다.
공격 실행·외부 공개·새 Lab·머신러닝·위험 수용 승인은 이 절차에 포함하지 않는다.
