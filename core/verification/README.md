# verification

개선 조치 검증 로직을 관리한다.

패치 후 SBOM 재생성, 구성요소·버전 변경 확인, CVE 재매칭, 재스캔, 서비스 기능 점검 및 이전 결과와의 비교를 통해 개선 완료 여부를 판단할 계획이다. 점수가 낮아졌다는 이유만으로 성공 처리하지 않는다.

검증 상태는 `Verification In Progress`에서 `Verification Passed` 또는 `Verification Failed`로 기록하고 판단 근거를 남긴다. 관리적 조치는 승인 기록이나 절차 등 이행 증적으로 확인한다. 현재 파일은 구현 전의 빈 파일이다.
