# dashboard

Streamlit Dashboard를 관리한다.

Phase 11 읽기 전용 MVP는 `Home.py`의 명시적 navigation과 `view.py`의 조회 섹션으로
구성한다. 기존 빈 `pages/`·`components/`는 보존하며 자동 페이지 노출은 사용하지 않는다.
`client.py`는 HTTP API만 호출하고 `presentation.py`는 미확인값 등 출력 형식만 담당한다.

`python -m streamlit run app/dashboard/Home.py --server.address 127.0.0.1`로 실행한다.
서버 설정의 DB를 고르고 자산·Finding·Remediation·시도를 각각 선택한다.
설정과 조회 범위는 [Dashboard 가이드](../../docs/dashboard.md)를 따른다.
