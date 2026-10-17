"""Formatting only: preserve the service's values, scopes and comparison decisions."""

import json

LABELS = {
    "component_count": "구성요소 발생 수",
    "vulnerable_component_count": "취약 구성요소 발생 수",
    "cve_count": "고유 CVE 수",
    "critical_cve_count": "Critical CVE 수 (CVSS ≥ 9.0)",
    "kev_cve_count": "KEV CVE 수",
    "eol_component_count": "EOL 구성요소 수",
    "finding_priority_counts": "내부 대응 우선순위별 Finding 수",
    "selected_finding_priority_counts": "선택한 Finding의 내부 우선순위별 수",
    "risk_score": "내부 Risk Score",
}


def display_value(value: object) -> str:
    if value is None:
        return "미확인"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def metric_rows(metrics: dict) -> list[dict]:
    return [{"지표": LABELS.get(name, name),
             "Before": display_value(item["before"]["value"]),
             "After": display_value(item["after"]["value"]),
             "증감 (After − Before)": display_value(item["delta"]) if item["comparable"] and item["delta"] is not None else "비교 불가",
             "Before 미확인 사유": item["before"]["unknown_reason"] or "",
             "After 미확인 사유": item["after"]["unknown_reason"] or "",
             "비교 불가 사유": item["comparison_reason"] or ("수치 증감 대상이 아님" if item["delta"] is None else ""),
             "집계 기준": item["basis"]}
            for name, item in metrics.items() if name != "component_versions"]
