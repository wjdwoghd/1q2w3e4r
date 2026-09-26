# 웹 애플리케이션 구조

Python Flask 서버와 HTML·CSS·JavaScript 화면을 하나의 `app/`에서 관리한다.

```text
브라우저 → app/main.py → templates/ 및 static/ 제공
브라우저 JavaScript → app/api/ → core/ → database/
                              ← 검증된 분석 결과
```

## 디렉터리 책임

- `app/main.py`: 서버 진입점과 라우트 연결.
- `app/api/`: 입력 및 응답 처리, core 서비스 호출.
- `app/templates/`: HTML 화면. 공통 템플릿 조각은 `components/`에 둔다.
- `app/static/css/`: 스타일시트.
- `app/static/js/`: 브라우저 상호작용, API 호출과 결과 표시.
- `app/config/`: 서버 설정.
- `core/`: SBOM, 취약점, 자산 맥락, 규칙 기반 위험도, 개선 및 검증 로직.
- `database/`: DB 모델과 데이터 접근.

HTML과 JavaScript에서 Risk Priority나 Verification 결과를 자체 판정하지 않는다. 서버가 반환한 결과와 계산 근거를 표시한다. 외부 취약점 정보 수집과 DB 접근은 서버의 해당 계층에서 수행한다.

## 구현 상태

기존 `app/dashboard/`의 빈 Python 화면 파일을 `app/templates/`의 HTML 골격으로 이동했다. 보고서 화면 골격과 정적 파일 디렉터리도 추가했다. 기존 화면 동작은 없었으며 API·서버 실행·템플릿 렌더링과 스타일은 후속 구현 대상이다.

이번 변경은 디렉터리 구조와 문서에 한정한다. Flask 의존성 설치나 실행 명령은 서버 구현 시 확정한다. `core/`, `database/`, `labs/`의 책임과 위치는 유지한다.
