# 첫 Log4Shell Lab

동일한 가상 금융서비스에서 Log4j 의존성 변경과 독립 증거 수집을 점검하는 기존 Lab이다.
플랫폼 core와 분리하며 공격 payload·LDAP 서버·원격 코드 실행 도구는 포함하지 않는다.
요청의 사용자 입력은 Log4j에 기록하지 않고 고정된 합성 업무 메시지만 기록한다.

## 구성과 대상

| 항목 | Before | After |
| --- | --- | --- |
| Maven 위치 | `vulnerable/pom.xml` | `patched/pom.xml` |
| 선언한 Log4j API/Core 버전 | 2.14.1 | 2.25.5 |
| 소스·기능 | `common/`의 동일 Java 서비스 | 동일 |
| runtime | `vulnerable/target/runtime` | `patched/target/runtime` |
| 조사 대상 CVE | CVE-2021-44228 | 실제 재매칭으로 존재 여부 확인 |

Before 영향 범위와 개선 후보는 [Apache 보안 공지](https://logging.apache.org/security.html)를
확인했다. 2.25.5는 공식 Maven 배포에서 존재를 확인한 고정된 시연용 변경 버전이다.
CVSS·KEV·EOL·모든 CVE의 제거·검증 성공을 이 버전 표에서 판정하지 않는다.
실제 설치 버전은 `/runtime`의 JAR Manifest와 재생성한 SBOM으로 확인한다.

`target/runtime/classes`는 이 Lab의 직접 작성 코드와 설정,
`target/runtime/lib`는 실제 실행되는 전체 Java 의존 JAR이다. 실행되지 않는 별도
애플리케이션 JAR·빌드 플러그인을 이 경로에 복사하지 않는다. JDK·OS는 별도 분석 범위다.
Maven 플러그인 버전은 고정했고 Before/After 모두 `clean package`로 이전 산출물을 정리한다.
Before 증거는 재빌드 전에 실행별 출력 경로에 복사해 보존한다.

## 현재 PC에서 바로 시작하기: Docker 없는 호스트 방식

2026-10-14 공식 배포 체크섬을 확인한 휴대용 도구를 `data/output/lab-tooling/`에 준비했다.
JDK 17.0.20.1, Maven 3.9.11, Syft 1.54.1이며 시스템 PATH·Windows 기능은 변경하지 않았다.
`toolchain.json`도 Git 제외 경로에 있다. 다른 PC에서는 도구 설치 또는
`LAB_JAVA_HOME`·`LAB_MAVEN_EXECUTABLE`·`LAB_SYFT_EXECUTABLE` 환경변수가 필요하다.

```powershell
Set-Location -LiteralPath 'C:\1q2w3e4r'
.\labs\log4shell\build.ps1 -Variant all

# 현재 18080은 기존 Python 프로세스가 사용하므로 다른 빈 로컬 포트를 사용한다.
# 포트가 점유됐으면 기존 프로세스를 임의로 종료하지 말고 빈 포트를 선택한다.
$env:LAB_PORT = '18081'
.\labs\log4shell\host.ps1 -Action Start -Variant vulnerable -Port ([int]$env:LAB_PORT)
.\labs\log4shell\host.ps1 -Action Smoke -Variant vulnerable
.\labs\log4shell\host.ps1 -Action Runtime -Variant vulnerable
```

출력된 runtime 경로를 Before Syft 대상에 사용한다. 원본 SBOM·분석·기능 결과와
Remediation 계획을 먼저 보존한 다음 실제 서비스 교체를 진행한다.

```powershell
.\labs\log4shell\host.ps1 -Action Stop -Variant vulnerable
.\labs\log4shell\host.ps1 -Action Start -Variant patched -Port ([int]$env:LAB_PORT)
.\labs\log4shell\host.ps1 -Action Smoke -Variant patched
.\labs\log4shell\host.ps1 -Action Runtime -Variant patched
.\labs\log4shell\host.ps1 -Action Stop -Variant patched
```

`host.ps1`은 숨김 창으로 자기 Java 프로세스만 시작한다. PID·시작 시점·실행 파일·
runtime을 대조한 후에만 제어한다. 실제 기동 완료 표식과 HTTP 응답을 함께 확인하므로
같은 포트의 다른 서버를 Lab 기동 성공으로 오인하지 않는다. 로그·프로세스 기록은
`data/output/log4shell-host/`에 보존한다. `Status`로 자기 프로세스를 조회할 수 있다.

## HTTP 계약

| 경로 | 정상 결과 |
| --- | --- |
| `/health` | HTTP 200, `{"status":"ok"}` |
| `/banking/smoke` | HTTP 200, `{"result":"ok","mode":"synthetic"}` |
| `/runtime` | 실제 Log4j API/Core Manifest 버전; 없으면 null |
| 다른 경로 / GET 이외 메서드 | 404 / 405 |

호스트 기본 주소는 `127.0.0.1`이다. wildcard 바인딩은 호스트 실행에서 거부한다.
Smoke는 실제 응답 확인이며 플랫폼의 Verification Passed를 대신하지 않는다.

## Java 패키지 SBOM 범위와 도구 경로

```powershell
. .\labs\log4shell\tools.ps1
$taskLabTools = Get-LabToolchain
$taskLabTools | Format-List
$env:SYFT_CONFIG = (Resolve-Path -LiteralPath 'labs/log4shell/syft.yaml').Path
```

이 환경에서 Python을 시작하면 기존 `generate_cyclonedx_json()`에
`$taskLabTools.Syft`의 절대경로를 전달할 수 있다. 출력은 CycloneDX JSON 1.6이다.

`syft.yaml`은 **모든 발견 패키지를 유지**하면서 별도의 `type=file` 메타데이터 출력만
비활성화한다. 기본 Syft 출력은 패키지 2개와 그 JAR의 파일 레코드 2개를 함께 내보내며,
파일은 PURL·Version이 없어 현행 전체 구성요소 매칭에서 미확인이 된다.
패키지를 임의 삭제하거나 Parser·Matcher·Verification 규칙을 완화하지 않는다.
Before/After에 같은 설정을 쓰고 설정 파일 해시를 실행 기록에 남긴다. 물리적 JAR·
class 파일 해시는 별도 증거로 보존한다.
[Syft 파일 메타데이터 설정](https://oss.anchore.com/docs/reference/syft/configuration/).

## Docker 방식

현재 PC의 `desktop-linux` 데몬이 없고 WSL2 가상화 조건이 충족되지 않아 실제 컨테이너
빌드·기동은 검증하지 않았다. Compose의 두 프로필·로컬 포트·내부 네트워크 설정은
실제 Docker CLI `config`로 검증했다. Windows 기능·BIOS·재부팅은 자동 변경하지 않았다.

로컬 Docker 데몬을 별도로 준비한 이후 다음 명령을 사용한다.

```powershell
$taskCompose = 'labs/log4shell/docker-compose.yml'
$env:LAB_PORT = '18081'
docker compose -p sbom-log4shell -f $taskCompose --profile before config --quiet
docker compose -p sbom-log4shell -f $taskCompose up -d --build --wait --wait-timeout 120 vulnerable
docker compose -p sbom-log4shell -f $taskCompose port vulnerable 8080
docker compose -p sbom-log4shell -f $taskCompose stop vulnerable
docker compose -p sbom-log4shell -f $taskCompose up -d --build --wait --wait-timeout 120 patched
docker compose -p sbom-log4shell -f $taskCompose down
```

호스트 방식을 종료한 후 Docker 방식을 쓴다. Before/After가 같은 포트를 사용하므로
한 번에 하나만 기동한다. Docker는 Lab 디렉터리만 build context로 사용하며,
플랫폼 코드·비밀값을 포함하지 않는다. 런타임은 비root·read-only·cap_drop·내부
네트워크·localhost 게시를 사용한다. 이미지 digest는 실제 빌드 후 별도 기록해야 한다.
컨테이너 분석은 실제 실행 컨테이너의 `/opt/lab/runtime`을 새 출력 폴더로 복사해
진행한다. 호스트 빌드가 컨테이너 파일과 같다는 가정으로 대체하지 않는다.

## 검증 결과와 다음 수동 점검

이번에 실제로 확인한 범위:

- 두 Maven 빌드와 실제 JAR 버전·공통 소스의 self-test
- localhost의 건강·합성 업무·버전 API, 404/405, 외부 호스트 바인딩 거부
- 호스트 도구의 기동·종료·동일 포트 충돌 거부; 기존 Python 프로세스는 보존
- Syft 생성 → Parser → Normalizer → 메모리 SQLite 저장 → 기존 SBOM Diff
- 명시한 패키지 범위에서 Before/After 각 2개 구성요소, API/Core 버전 변경
- 전체 오프라인 테스트 170개 통과(기존 163 + Lab 신규 7)

실제 CVE/KEV 조회, Recommendation API, Remediation·Verification 전체 실 시도는
이번 준비 작업에서 실행하지 않았다. [실행 가이드](../../docs/lab_e2e_runbook.md)의
자산 등록 이후 절차와 [점검표](../../docs/lab_e2e_checklist.md)로 이어간다.
계획·시나리오의 기대값을 실제 판정으로 입력하지 않는다. rollback은 patched를
종료하고 보존된 Before runtime을 같은 로컬 포트로 다시 기동하는 절차이며, 수행하면
그 변경을 별도 기록한다. `target/`·도구 ZIP·JAR·로그·DB는 Git에 넣지 않는다.
