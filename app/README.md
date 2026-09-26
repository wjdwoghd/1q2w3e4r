# app

Python Flask 서버와 HTML·CSS·JavaScript 화면을 관리한다.

- `main.py`: 서버 진입점, API 등록, 화면 라우트 연결.
- `api/`: 기능별 API 요청·응답과 core 서비스 호출.
- `templates/`: HTML 화면. 공통 템플릿 조각은 `components/`에 둔다.
- `static/css/`: 화면 스타일.
- `static/js/`: 브라우저 상호작용, API 호출과 결과 표시.
- `config/`: 서버 설정과 로깅 설정.

분석은 `core/`, 영속성 처리는 `database/`가 담당한다.
현재는 빈 파일과 디렉터리 골격이다. 서버 실행, API, 화면 렌더링은 아직 구현하지 않았다. 새 의존성은 추가하지 않았다.
