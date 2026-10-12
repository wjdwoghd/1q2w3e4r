# consulting

AI 기반 개선안 추천 로직을 관리한다.

`RecommendationService.create_for_observation(observation_id)`는 저장된 Finding 관측,
구성요소·CVE 증거, CVSS·CWE·KEV, 당시 위험·자산 Context와 해당 관측의 통제 매핑을
확인한다. EOL은 `unknown`으로 입력한다. 통제 매핑이 없거나 소속·증거가 불일치하면
API를 호출하지 않는다.

OpenAI 클라이언트는 표준 라이브러리로 Responses API의 `text.format`에 `json_schema`,
`strict: true`를 사용한다. `OPENAI_API_KEY`, `OPENAI_RECOMMENDATION_MODEL`,
`OPENAI_TIMEOUT_SECONDS`를 환경에서 읽는다. 실제 호출 없이 생성기를 주입해 테스트할
수 있다. 모델은 기술적·관리적 개선안, 임시 완화방안, Verification Plan의 향후 조치만
선택한다. AI가 선택할 수 있는 문장은 사실을 주장하지 않는 승인된 조치 문장으로
제한한다. 발견사항, 금융서비스 영향, 우선순위 이유와 통제 목록은 검증된 입력을
기반으로 코드가 구성한다. 허용 문장 밖의 출력이나 숫자·식별자·완료 상태 주장은
저장 전에 거부한다. 운영 사용 전 담당자 검토가 필요하다.

AI가 취약점 존재 여부나 우선순위를 직접 판정하지 않는다. 확인되지 않은 정보는
구분하고 최종 판단과 승인은 사람이 수행한다. 실제 검증 결과와 보고서 생성은 후속 단계다.

Structured Outputs 계약은 [OpenAI 공식 문서](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses)의 Responses API `text.format`을 따른다.
