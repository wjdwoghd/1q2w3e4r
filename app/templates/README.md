# templates

Flask에서 렌더링할 HTML 템플릿을 관리한다.

`home.html`은 시작 화면이다. 자산, SBOM, 취약점, 위험 우선순위, 개선 조치, 검증, 보고서 화면을 각각 별도 HTML 파일로 구성한다. 공통 UI 조각은 `components/`에 둔다.

현재 HTML 파일은 구현 전의 빈 골격이다. CSS와 JavaScript는 `app/static/`에서 관리한다. 템플릿은 검증된 결과를 표시하며 위험도 계산, 외부 취약점 API 호출, SQL 실행은 담당하지 않는다.
