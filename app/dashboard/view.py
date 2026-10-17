"""Read-only views. All joins, comparison and aggregation come from the API."""

import os

import streamlit as st

from app.config.dashboard import load_local_env
from app.dashboard.client import DashboardAPIError, DashboardClient
from app.dashboard.presentation import display_value, metric_rows


def choose(label: str, rows: list[dict], key: str, *, label_field: str = "id") -> dict | None:
    if not rows:
        st.info(f"{label}: 저장된 데이터가 없습니다.")
        return None
    by_id = {item["id"]: item for item in rows}

    def option_label(value: int) -> str:
        item = by_id[value]
        title = item.get(label_field, value)
        if isinstance(title, dict):
            title = title.get("name", title)
        status = f" · {item['status']}" if "status" in item else ""
        return f"{value} · {title}{status}"

    selected = st.selectbox(label, list(by_id), index=None, key=key,
                            placeholder="명시적으로 선택하세요", format_func=option_label)
    return by_id[selected] if selected is not None else None


def show_json(title: str, value: object) -> None:
    with st.expander(title):
        st.caption("원본 JSON의 null은 미확인입니다. 기록 시점과 수집 시점은 구분합니다.")
        st.json(value, expanded=False)


def show_attempt(detail: dict) -> None:
    comparison = detail["comparison"]
    st.subheader("선택한 Verification 시도")
    st.json(detail["selection"], expanded=True)
    st.metric("저장된 Verification 상태", detail["status"], border=True)
    st.caption("이 판정은 선택한 CVE와 지정된 검증 범위에 한정됩니다. 자산 전체의 안전 판정이 아닙니다.")
    decision = comparison["verification"]["decision"]
    if decision is None:
        st.info("진행 중: 저장된 최종 판정이 없습니다. After Evidence가 있어도 완료 판정으로 바꾸지 않습니다.")
    else:
        st.write("판정 규칙 버전: " + decision["rule_version"])
        for reason in decision["reasons"]:
            st.text(reason)
    st.write("필수 기능 테스트", detail["required_functional_tests"])
    if detail["functional_tests"]:
        st.dataframe(detail["functional_tests"], hide_index=True)
    else:
        st.info("기능 검증 결과 미확인: " + (detail["functional_unknown_reason"] or "선택한 After Evidence에 기능 테스트 결과가 없습니다."))

    st.subheader("Before / After")
    st.caption("CVSS는 기술적 심각도이고 P1~P4와 Risk Score는 내부 대응 우선순위입니다. 미확인은 0으로 환산하지 않습니다.")
    finding_tab, asset_tab, evidence_tab = st.tabs(["선택한 Finding", "선택한 시도의 자산 범위", "증거·출처·원본 사본"])
    with finding_tab:
        st.dataframe(metric_rows(comparison["finding"]), hide_index=True)
        show_json("Finding 지표별 분석 범위·출처·수집 시점·증거 ID", comparison["finding"])
    with asset_tab:
        asset_comparison = detail["asset_comparison"]
        st.caption("현재 Finding 목록으로 과거 지표를 재구성하지 않습니다. 선택한 시도의 SBOM·분석 사본 범위입니다.")
        if asset_comparison["aggregation_reason"]:
            st.info(asset_comparison["aggregation_reason"])
        st.dataframe(metric_rows(asset_comparison["metrics"]), hide_index=True)
        show_json("자산 지표별 분석 범위·출처·수집 시점·증거 ID", asset_comparison["metrics"])
    with evidence_tab:
        show_json("비교 기준 및 원래 판정", {"basis": comparison["basis"], "verification": comparison["verification"]})
        for side, key in (("Before", "before_sbom"), ("After", "after")):
            snapshot = comparison["snapshots"][key]
            sbom = snapshot if side == "Before" else (snapshot or {}).get("sbom")
            st.write(f"{side} 구성요소 발생 목록")
            if sbom is None:
                st.info(f"{side} SBOM 증거 미확인")
            elif sbom.get("components"):
                st.dataframe([{key: display_value(value) for key, value in item.items()}
                              for item in sbom["components"]], hide_index=True)
            else:
                st.info("저장된 SBOM 구성요소 목록이 비어 있습니다.")
        show_json("Before Snapshot·원본 SBOM 사본·After Evidence·적용 기록", comparison["snapshots"])
    show_diff(comparison["sbom_diff"])


def show_diff(diff: dict | None) -> None:
    st.subheader("구성요소 변경")
    if diff is None:
        st.info("SBOM 비교 불가: Before / After 지표의 미확인 사유를 확인하세요.")
        return
    st.caption("버전 없는 PURL 기준입니다. 같은 패키지의 발생을 보존하며 설치 간 대응 관계는 추정하지 않습니다.")
    for key, title in (("added", "추가 구성요소"), ("removed", "제거 구성요소"),
                       ("version_changes", "버전 집합 변경"),
                       ("occurrence_count_changes", "발생 수 변경"),
                       ("unresolved_before", "Before 식별 미확인"), ("unresolved_after", "After 식별 미확인")):
        with st.expander(title):
            if diff[key]:
                st.dataframe([{name: display_value(value) for name, value in item.items()}
                              for item in diff[key]], hide_index=True)
            else:
                st.caption("해당 항목 없음 (확인 가능한 선택 증거 범위)")
    show_json("원본 SBOM Diff", diff)


def render() -> None:
    load_local_env()
    client = DashboardClient(os.getenv("DASHBOARD_API_URL", "http://127.0.0.1:5000"))
    st.title("소프트웨어 공급망 위험 조회")
    st.caption("읽기 전용 MVP · 저장된 분석, 조치와 검증 시도의 증거를 조회합니다.")
    try:
        _render_selection(client)
    except DashboardAPIError as exc:
        st.error(str(exc))


def _render_selection(client: DashboardClient) -> None:
    databases = client.get("databases")
    if not databases:
        st.info("등록된 실행 DB가 없습니다. 서버의 DASHBOARD_DATABASES 설정에 DB 이름과 경로를 등록하세요.")
        return
    database = st.sidebar.selectbox("실행 DB", [item["name"] for item in databases], index=None,
                                    placeholder="실행 DB를 선택하세요", key="database")
    if database is None:
        st.info("실행 DB를 먼저 선택하세요.")
        return
    _reset_children("database_selection", (database,),
                    ("service", "asset", "sbom", "finding", "observation", "recommendation", "remediation", "verification"))
    st.sidebar.text(next(item["path"] for item in databases if item["name"] == database))
    scope = {"database": database}
    services = client.get("services", **scope)
    st.subheader("금융서비스와 자산")
    service = choose("금융서비스", services, "service", label_field="name")
    if service is None:
        return
    _reset_children("service_selection", (database, service["id"]),
                    ("asset", "sbom", "finding", "observation", "recommendation", "remediation", "verification"))
    assets = client.get("assets", **scope, service_id=service["id"])
    st.dataframe([{**{key: value for key, value in item.items() if key != "context"}, **item["context"]}
                  for item in assets], hide_index=True)
    asset = choose("자산", assets, "asset", label_field="context")
    if asset is None:
        return
    scope["asset_id"] = asset["id"]
    st.json(client.get("asset", **scope))
    # A parent signature resets all child selections, even when returning to a previous DB.
    signature = (database, service["id"], asset["id"])
    if st.session_state.get("parent_selection") != signature:
        for key in ("sbom", "finding", "observation", "recommendation", "remediation", "verification"):
            st.session_state.pop(key, None)
        st.session_state["parent_selection"] = signature

    sbom_tab, finding_tab = st.tabs(["SBOM·구성요소", "Finding·개선·검증"])
    with sbom_tab:
        sboms = client.get("sboms", **scope)
        st.dataframe(sboms, hide_index=True)
        sbom = choose("SBOM", sboms, "sbom", label_field="source")
        if sbom:
            detail = client.get("sbom", **scope, sbom_id=sbom["id"])
            st.caption("현재 DB의 SBOM 목록입니다. 과거 시도 비교에는 해당 시도의 불변 사본을 사용합니다.")
            st.dataframe([{key: display_value(value) for key, value in item.items()}
                          for item in detail["components"]], hide_index=True)
            show_json("선택한 SBOM 원본·메타데이터", detail)
    with finding_tab:
        findings = client.get("findings", **scope)
        st.caption("현재 Finding 목록: 자산+CVE당 한 건이며 관측은 개별 이력입니다.")
        st.dataframe(findings, hide_index=True)
        finding = choose("Finding", findings, "finding", label_field="cve_id")
        if finding is None:
            return
        scope["finding_id"] = finding["id"]
        _reset_children("finding_selection", (*signature, finding["id"]),
                        ("observation", "recommendation", "remediation", "verification"))
        _render_finding(client, scope)


def _reset_children(state_key: str, signature: tuple, children: tuple[str, ...]) -> None:
    if st.session_state.get(state_key) != signature:
        for key in children:
            st.session_state.pop(key, None)
        st.session_state[state_key] = signature


def _render_finding(client: DashboardClient, scope: dict) -> None:
    detail = client.get("finding", **scope)
    st.subheader(detail["cve_id"])
    st.write("현재 Finding 상태: " + detail["status"])
    observation = choose("분석 관측 (Risk·CVE 근거)", detail["observations"], "observation", label_field="analysis_key")
    if observation:
        risk = observation["risk"]
        with st.container(horizontal=True):
            st.metric("CVSS 기술적 심각도", display_value(risk["cvss_score"]), border=True)
            st.metric("내부 Risk Score", display_value(risk["score"]), border=True)
            st.metric("내부 대응 우선순위", display_value(risk["priority"]), border=True)
        st.write("Risk 규칙 버전: " + risk["rule_version"])
        for reason in observation["risk_reasons"]:
            st.text(reason)
        for match in observation["match_run"]["result"]["matches"]:
            if match["cve"]["cve_id"] == detail["cve_id"]:
                st.write("CISA KEV 등록: " + display_value(match["kev"]))
                show_json("CVE·CVSS·CWE·KEV 출처와 수집 시점", match)
        show_json("선택한 관측 전체 (미평가 요소 포함)", observation)
    show_json("Finding 이력·보안통제 참고용 매핑", detail)
    recommendations = client.get("recommendations", **scope)
    recommendation = choose("Recommendation", recommendations, "recommendation", label_field="observation_id")
    if recommendation:
        st.json(recommendation, expanded=False)
    remediations = client.get("remediations", **scope)
    st.dataframe([{key: item[key] for key in ("id", "recommendation_id", "observation_id", "status", "action_key")}
                  for item in remediations], hide_index=True)
    remediation = choose("Remediation", remediations, "remediation", label_field="action_key")
    if remediation is None:
        return
    scope = {**scope, "remediation_id": remediation["id"]}
    _reset_children("remediation_selection", tuple(scope.values()), ("verification",))
    st.json(client.get("remediation", **scope), expanded=False)
    linked = next((item for item in recommendations if item["id"] == remediation["recommendation_id"]), None)
    show_json("선택한 Remediation에 연결된 Recommendation", linked)
    attempts = client.get("attempts", **scope)
    st.dataframe(attempts, hide_index=True)
    attempt = choose("Verification 시도", attempts, "verification", label_field="attempt_key")
    if attempt:
        show_attempt(client.get("attempt", **scope, verification_id=attempt["id"]))
